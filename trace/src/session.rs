// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

use std::{
   collections::{
      BTreeMap,
      BTreeSet,
   },
   fs,
   io,
   os::{
      fd::{
         AsRawFd as _,
         FromRawFd as _,
         OwnedFd,
      },
      unix::fs::FileExt as _,
   },
};

use crate::{
   command::{
      Location,
      ProcessTrace,
      ProcessTrap,
      SystemTrace,
      WatchAccess,
      WatchLocation,
      WatchTrace,
   },
   maps,
   perf,
   ring,
   sites,
   target,
};

const RESCAN_MS: libc::c_int = 200;

pub struct Edge {
   pub module: String,
   pub vaddr:  u64,
   pub count:  u64,
}

pub struct ThreadHits {
   pub pid:   u32,
   pub tid:   u32,
   pub count: u64,
   pub name:  String,
}

pub struct Group {
   label:   String,
   probe:   ProbeSpec,
   hits:    u64,
   callers: Vec<Edge>,
   threads: Vec<ThreadHits>,
   stack:   u32,
   probes:  BTreeMap<Attachment, perf::Probe>,
}

pub struct Drain {
   pub group:     usize,
   pub samples:   Vec<ring::Sample>,
   pub lost:      u64,
   pub malformed: u64,
}

pub struct Batch {
   pub drains:   Vec<Drain>,
   pub finished: bool,
}

pub struct Session {
   groups: Vec<Group>,
   pages:  usize,
   target: Option<Target>,
   polls:  Vec<libc::pollfd>,
}

enum ProbeSpec {
   TaskUprobe {
      path:     String,
      offset:   u64,
      retprobe: bool,
   },
   SystemUprobe {
      path:     String,
      offset:   u64,
      retprobe: bool,
   },
   Hardware {
      site: ProbeSite,
      kind: u32,
      len:  u64,
   },
}

enum ProbeSite {
   File { path: String, offset: u64 },
   Runtime(u64),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Attachment {
   Task(i32),
   Cpu(usize),
   HardwareCpu { address: u64, cpu: usize },
}

struct ArmPlan {
   attachments: BTreeSet<Attachment>,
   failure:     Option<io::Error>,
}

struct ArmResult {
   added:     usize,
   attempted: usize,
   removed:   bool,
   failure:   Option<io::Error>,
}

struct AddressSpace {
   pid:      i32,
   tids:     Vec<i32>,
   mappings: Vec<maps::Mapping>,
}

struct Target {
   pid:                  i32,
   pidfd:                OwnedFd,
   selected:             Vec<i32>,
   follow:               bool,
   reported_arm_failure: bool,
   spaces:               Vec<AddressSpace>,
}

impl Session {
   pub fn process(request: &ProcessTrace, pid: i32) -> io::Result<Self> {
      let mut target = Target::open(pid, &request.tids, request.follow)?;
      let spaces = target.scan()?;
      let (groups, pages) = build_process(request, pid, &spaces)?;
      target.spaces = spaces;
      Ok(Self::new(groups, pages, Some(target)))
   }

   pub fn system(request: &SystemTrace) -> io::Result<Self> {
      let (groups, pages) = build_system(request)?;
      Ok(Self::new(groups, pages, None))
   }

   pub fn watch(request: &WatchTrace, pid: i32) -> io::Result<Self> {
      if request.emit.is_some() && matches!(request.location, WatchLocation::Runtime(_)) {
         return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a runtime watch address has no ASLR-stable artifact location",
         ));
      }
      if request.follow && matches!(request.location, WatchLocation::Runtime(_)) {
         return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a runtime address cannot be followed across new address spaces",
         ));
      }
      let mut target = Target::open(pid, &request.tids, request.follow)?;
      let spaces = target.scan()?;
      let (groups, pages) = build_watch(request, pid, &spaces)?;
      target.spaces = spaces;
      Ok(Self::new(groups, pages, Some(target)))
   }

   fn new(groups: Vec<Group>, pages: usize, target: Option<Target>) -> Self {
      let polls = poll_set(&groups);
      Self {
         groups,
         pages,
         target,
         polls,
      }
   }

   pub fn wait(&mut self) -> io::Result<Batch> {
      let timeout = if self.target.as_ref().is_some_and(|target| target.follow) {
         RESCAN_MS
      } else {
         -1_i32
      };
      // SAFETY: polls is a live slice of pollfds and its length is passed with it.
      let ready = unsafe {
         libc::poll(
            self.polls.as_mut_ptr(),
            self.polls.len() as libc::nfds_t,
            timeout,
         )
      };
      if ready < 0_i32 {
         return Err(io::Error::last_os_error());
      }
      let (drains, removed) = self.drain_and_prune();
      let (changed, target_gone) = match self.target.as_mut() {
         Some(target) if target.follow => {
            match rescan(&mut self.groups, target, self.pages) {
               Ok(changed) => (changed, false),
               Err(err) if err.kind() == io::ErrorKind::NotFound => (false, true),
               Err(err) => return Err(err),
            }
         },
         Some(target) => (false, target.exited()?),
         None => (false, false),
      };
      if removed || changed {
         self.polls = poll_set(&self.groups);
      }
      let no_probes = self.groups.iter().all(|group| group.probes.is_empty());
      let following = self.target.as_ref().is_some_and(|target| target.follow);
      let finished = no_probes && (target_gone || !following);
      Ok(Batch { drains, finished })
   }

   pub fn finish(&mut self) -> Batch {
      let (drains, _removed) = self.drain_and_prune();
      for group in &mut self.groups {
         group.probes.clear();
      }
      self.polls.clear();
      Batch {
         drains,
         finished: true,
      }
   }

   fn drain_and_prune(&mut self) -> (Vec<Drain>, bool) {
      let mut drains = Vec::new();
      let mut poll_index = 0_usize;
      let mut removed = false;
      for (group_index, group) in self.groups.iter_mut().enumerate() {
         let before = group.probes.len();
         let filter_target = group.probe.needs_target_filter();
         let target = self.target.as_ref();
         group.probes.retain(|_attachment, probe| {
            let revents = self
               .polls
               .get(poll_index)
               .map_or(libc::POLLNVAL, |poll| poll.revents);
            poll_index += 1;
            let perf::Records {
               samples,
               lost,
               malformed,
            } = probe.drain();
            let kept = if filter_target {
               samples
                  .into_iter()
                  .filter(|sample| {
                     target.is_some_and(|active| active.accepts(sample.pid, sample.tid))
                  })
                  .collect()
            } else {
               samples
            };
            if lost > 0 || malformed > 0 || !kept.is_empty() {
               drains.push(Drain {
                  group: group_index,
                  samples: kept,
                  lost,
                  malformed,
               });
            }
            revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) == 0_i16
         });
         removed |= group.probes.len() != before;
      }
      (drains, removed)
   }

   #[must_use]
   pub fn label(&self, group: usize) -> &str {
      &self.groups[group].label
   }

   pub fn record(&mut self, group_index: usize, pid: u32, tid: u32, caller: Option<(&str, u64)>) {
      let group = &mut self.groups[group_index];
      group.hits += 1;
      if let Some(entry) = group
         .threads
         .iter_mut()
         .find(|entry| entry.pid == pid && entry.tid == tid)
      {
         entry.count += 1;
      } else {
         let name = fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm"))
            .map_or_else(|_error| "?".to_owned(), |name| name.trim_end().to_owned());
         group.threads.push(ThreadHits {
            pid,
            tid,
            count: 1,
            name,
         });
      }
      if let Some((module, vaddr)) = caller {
         note_edge(&mut group.callers, module, vaddr);
      }
   }

   #[must_use]
   pub fn groups(&self) -> &[Group] {
      &self.groups
   }

   pub fn mappings(&self) -> impl Iterator<Item = (i32, &[maps::Mapping])> {
      self
         .target
         .iter()
         .flat_map(|target| target.spaces.iter())
         .map(|space| (space.pid, space.mappings.as_slice()))
   }
}

impl Group {
   #[must_use]
   pub fn label(&self) -> &str {
      &self.label
   }

   #[must_use]
   pub fn path(&self) -> Option<&str> {
      self.probe.file().map(|(path, _offset)| path)
   }

   #[must_use]
   pub const fn offset(&self) -> u64 {
      self.probe.offset()
   }

   #[must_use]
   pub const fn hits(&self) -> u64 {
      self.hits
   }

   #[must_use]
   pub fn callers(&self) -> &[Edge] {
      &self.callers
   }

   #[must_use]
   pub fn threads(&self) -> &[ThreadHits] {
      &self.threads
   }

   fn arm(&mut self, plan: ArmPlan, pages: usize) -> ArmResult {
      let attempted = plan.attachments.len();
      let mut added = 0_usize;
      let mut failure = plan.failure;
      let before = self.probes.len();
      if self.probe.needs_target_filter() {
         self
            .probes
            .retain(|attachment, _probe| plan.attachments.contains(attachment));
      }
      let removed = self.probes.len() != before;
      for attachment in plan.attachments {
         if self.probes.contains_key(&attachment) {
            continue;
         }
         match self.probe.open(attachment, pages, self.stack) {
            Ok(probe) => {
               self.probes.insert(attachment, probe);
               added += 1;
            },
            Err(err) => failure = failure.or(Some(err)),
         }
      }
      ArmResult {
         added,
         attempted,
         removed,
         failure,
      }
   }
}

impl ProbeSpec {
   fn plan(&self, spaces: &[AddressSpace]) -> ArmPlan {
      let mut attachments = BTreeSet::new();
      let mut failure = None;
      match self {
         Self::TaskUprobe { .. } => {
            attachments.extend(
               spaces
                  .iter()
                  .flat_map(|space| space.tids.iter().copied())
                  .map(Attachment::Task),
            );
         },
         Self::SystemUprobe { .. } => {
            attachments.extend((0..perf::cpu_count()).map(Attachment::Cpu));
         },
         Self::Hardware { site, .. } => {
            let mut addresses = BTreeSet::new();
            for space in spaces {
               match site.address(space) {
                  Ok(address) => {
                     addresses.insert(address);
                  },
                  Err(err) => failure = failure.or(Some(err)),
               }
            }
            let cpus = perf::cpu_count();
            for address in addresses {
               attachments.extend((0..cpus).map(|cpu| Attachment::HardwareCpu { address, cpu }));
            }
         },
      }
      ArmPlan {
         attachments,
         failure,
      }
   }

   fn open(&self, attachment: Attachment, pages: usize, stack: u32) -> io::Result<perf::Probe> {
      match (self, attachment) {
         (
            Self::TaskUprobe {
               path,
               offset,
               retprobe,
            },
            Attachment::Task(tid),
         ) => perf::Probe::open(path, *offset, tid, pages, *retprobe, stack),
         (
            Self::SystemUprobe {
               path,
               offset,
               retprobe,
            },
            Attachment::Cpu(cpu),
         ) => perf::Probe::open_system(path, *offset, cpu, pages, *retprobe, stack),
         (Self::Hardware { kind, len, .. }, Attachment::HardwareCpu { address, cpu }) => {
            perf::Probe::open_hw_system(address, cpu, pages, *kind, *len, stack)
         },
         _ => {
            Err(io::Error::other(
               "probe attachment does not match its specification",
            ))
         },
      }
   }

   const fn needs_target_filter(&self) -> bool {
      matches!(self, Self::Hardware { .. })
   }

   fn file(&self) -> Option<(&str, u64)> {
      match self {
         Self::TaskUprobe { path, offset, .. } | Self::SystemUprobe { path, offset, .. } => {
            Some((path, *offset))
         },
         Self::Hardware { site, .. } => site.file(),
      }
   }

   const fn offset(&self) -> u64 {
      match self {
         Self::TaskUprobe { offset, .. } | Self::SystemUprobe { offset, .. } => *offset,
         Self::Hardware { site, .. } => site.offset(),
      }
   }
}

impl ProbeSite {
   fn file(&self) -> Option<(&str, u64)> {
      match self {
         Self::File { path, offset } => Some((path, *offset)),
         Self::Runtime(_) => None,
      }
   }

   const fn offset(&self) -> u64 {
      match *self {
         Self::File { offset, .. } | Self::Runtime(offset) => offset,
      }
   }

   fn address(&self, space: &AddressSpace) -> io::Result<u64> {
      match self {
         Self::File { path, offset } => mapped_address(&space.mappings, path, *offset),
         Self::Runtime(address) => Ok(*address),
      }
   }
}

fn note_edge(callers: &mut Vec<Edge>, module: &str, vaddr: u64) {
   if let Some(edge) = callers
      .iter_mut()
      .find(|edge| edge.vaddr == vaddr && edge.module == module)
   {
      edge.count += 1;
      return;
   }
   callers.push(Edge {
      module: module.to_owned(),
      vaddr,
      count: 1,
   });
}

fn rescan(groups: &mut [Group], target: &mut Target, pages: usize) -> io::Result<bool> {
   if target.exited()? {
      return Err(io::Error::new(
         io::ErrorKind::NotFound,
         "the followed process exited",
      ));
   }
   let spaces = target.scan()?;
   if target.exited()? {
      return Err(io::Error::new(
         io::ErrorKind::NotFound,
         "the followed process exited",
      ));
   }
   let mut added = 0_usize;
   let mut changed = false;
   let mut failure = None;
   for group in groups.iter_mut() {
      let plan = group.probe.plan(&spaces);
      let result = group.arm(plan, pages);
      added += result.added;
      changed |= result.added > 0 || result.removed;
      failure = failure.or(result.failure);
   }
   if added > 0 {
      eprintln!("  +{added} new attachments");
   }
   if let Some(err) = failure
      && !target.reported_arm_failure
   {
      target.reported_arm_failure = true;
      eprintln!("  a new task could not be armed, so it is untraced ({err})");
   }
   target.spaces = spaces;
   Ok(changed)
}

impl Target {
   fn open(pid: i32, selected: &[i32], follow: bool) -> io::Result<Self> {
      // SAFETY: pidfd_open takes a process ID and zero flags without pointers.
      let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
      if raw_fd < 0 {
         return Err(io::Error::last_os_error());
      }
      // SAFETY: pidfd_open returned a fresh descriptor owned here.
      let pidfd = unsafe { OwnedFd::from_raw_fd(raw_fd as i32) };
      Ok(Self {
         pid,
         pidfd,
         selected: selected.to_vec(),
         follow,
         reported_arm_failure: false,
         spaces: Vec::new(),
      })
   }

   fn exited(&self) -> io::Result<bool> {
      let mut poll = libc::pollfd {
         fd:      self.pidfd.as_raw_fd(),
         events:  libc::POLLIN,
         revents: 0,
      };
      // SAFETY: poll is a live single pollfd and the zero timeout never blocks.
      let ready = unsafe { libc::poll(&raw mut poll, 1, 0) };
      if ready < 0_i32 {
         return Err(io::Error::last_os_error());
      }
      Ok(ready > 0)
   }

   fn scan(&self) -> io::Result<Vec<AddressSpace>> {
      let groups = if self.follow {
         target::task_tree(self.pid)?
      } else {
         vec![target::task_group(self.pid)?]
      };
      let mut spaces = Vec::new();
      for mut group in groups {
         if !self.selected.is_empty() {
            group.tids.retain(|tid| self.selected.contains(tid));
         }
         if group.tids.is_empty() && group.pid != self.pid {
            continue;
         }
         match maps::read_for_pid(group.pid) {
            Ok(mappings) => {
               spaces.push(AddressSpace {
                  pid: group.pid,
                  tids: group.tids,
                  mappings,
               });
            },
            Err(err) if group.pid == self.pid => return Err(err),
            Err(_child_exited) => {},
         }
      }
      Ok(spaces)
   }

   fn accepts(&self, process: u32, thread: u32) -> bool {
      let (Ok(pid), Ok(tid)) = (i32::try_from(process), i32::try_from(thread)) else {
         return false;
      };
      self.spaces.iter().any(|space| space.pid == pid)
         && (self.selected.is_empty() || self.selected.contains(&tid))
   }
}

fn mapped_address(mappings: &[maps::Mapping], path: &str, offset: u64) -> io::Result<u64> {
   maps::runtime_address(mappings, path, offset).ok_or_else(|| {
      io::Error::new(
         io::ErrorKind::NotFound,
         "the target has not mapped that part of the file",
      )
   })
}

fn hardware_probe(site: ProbeSite, addr: u64, kind: u32, len: u64) -> io::Result<ProbeSpec> {
   if !addr.is_multiple_of(len) {
      return Err(io::Error::new(
         io::ErrorKind::InvalidInput,
         format!(
            "a {len}-byte hardware trap needs an address aligned to {len}, and {addr:#x} is not"
         ),
      ));
   }
   Ok(ProbeSpec::Hardware { site, kind, len })
}

const fn new_group(label: String, probe: ProbeSpec, stack: u32) -> Group {
   Group {
      label,
      probe,
      stack,
      hits: 0,
      callers: Vec::new(),
      threads: Vec::new(),
      probes: BTreeMap::new(),
   }
}

fn report_arming(added: usize, total: usize, first_err: Option<io::Error>) -> io::Result<()> {
   if added == 0 {
      return Err(first_err.unwrap_or_else(|| {
         io::Error::new(
            io::ErrorKind::NotFound,
            "the target has no live attachments",
         )
      }));
   }
   match first_err {
      Some(err) => eprintln!("  {added}/{total} attachments ({err})"),
      None => eprintln!("  {added}/{total} attachments"),
   }
   Ok(())
}

fn arm_groups(
   mut groups: Vec<Group>,
   spaces: &[AddressSpace],
   stack: u32,
) -> io::Result<(Vec<Group>, usize)> {
   let plans = groups
      .iter()
      .map(|group| group.probe.plan(spaces))
      .collect::<Vec<_>>();
   let events = plans.iter().map(|plan| plan.attachments.len()).sum();
   let pages = sites::ring_pages(events, perf::sample_size(stack));
   for (group, plan) in groups.iter_mut().zip(plans) {
      let result = group.arm(plan, pages);
      report_arming(result.added, result.attempted, result.failure)?;
   }
   Ok((groups, pages))
}

fn location_label(location: &Location, offset: u64) -> String {
   match location {
      Location::Symbol(symbol) => symbol.clone(),
      Location::VirtualAddress(_) | Location::FileOffset(_) => format!("{offset:#x}"),
   }
}

fn root_space(spaces: &[AddressSpace], pid: i32) -> io::Result<&AddressSpace> {
   spaces
      .iter()
      .find(|space| space.pid == pid)
      .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "target address space disappeared"))
}

fn build_process(
   request: &ProcessTrace,
   pid: i32,
   spaces: &[AddressSpace],
) -> io::Result<(Vec<Group>, usize)> {
   let selected_sites = sites::load(&request.probes, request.trap)?;
   raise_limits();
   let root = root_space(spaces, pid)?;

   let mut groups = Vec::new();
   for entry in selected_sites {
      let path = target::resolve_library(&entry.library, &root.mappings)?;
      let offset = match &entry.location {
         sites::SiteLocation::Selected(location) => target::probe_site(location, &path)?,
         sites::SiteLocation::Named(site) => target::site_offset(&path, site)?,
      };
      let label = entry.label.unwrap_or_else(|| {
         match &entry.location {
            sites::SiteLocation::Selected(location) => location_label(location, offset),
            sites::SiteLocation::Named(_) => format!("{offset:#x}"),
         }
      });
      let probe = match request.trap {
         ProcessTrap::Uprobe { retprobe } => {
            refuse_if_text_differs(pid, &root.mappings, &path, offset)?;
            eprintln!("{label} -> {path} +{offset:#x}");
            ProbeSpec::TaskUprobe {
               path,
               offset,
               retprobe,
            }
         },
         ProcessTrap::Breakpoint => {
            let addr = mapped_address(&root.mappings, &path, offset)?;
            eprintln!("{label} -> {addr:#x} in pid {pid}");
            hardware_probe(
               ProbeSite::File { path, offset },
               addr,
               perf::HW_BREAKPOINT_X,
               perf::HW_BREAKPOINT_EXEC_LEN,
            )?
         },
      };
      groups.push(new_group(label, probe, request.report.stack()));
   }
   arm_groups(groups, spaces, request.report.stack())
}

fn build_system(request: &SystemTrace) -> io::Result<(Vec<Group>, usize)> {
   raise_limits();
   let offset = target::probe_site(&request.location, &request.library)?;
   let label = location_label(&request.location, offset);
   eprintln!("{label} -> {} +{offset:#x}", request.library);
   let group = new_group(
      label,
      ProbeSpec::SystemUprobe {
         path: request.library.clone(),
         offset,
         retprobe: request.retprobe,
      },
      request.report.stack(),
   );
   arm_groups(vec![group], &[], request.report.stack())
}

impl From<WatchAccess> for u32 {
   #[inline]
   fn from(access: WatchAccess) -> Self {
      match access {
         WatchAccess::Read => perf::HW_BREAKPOINT_R,
         WatchAccess::Write => perf::HW_BREAKPOINT_W,
         WatchAccess::Rw => perf::HW_BREAKPOINT_RW,
      }
   }
}

fn build_watch(
   request: &WatchTrace,
   pid: i32,
   spaces: &[AddressSpace],
) -> io::Result<(Vec<Group>, usize)> {
   raise_limits();
   let root = root_space(spaces, pid)?;
   let (site, addr) = match &request.location {
      WatchLocation::Runtime(address) => (ProbeSite::Runtime(*address), *address),
      WatchLocation::VirtualAddress { library, address } => {
         let path = target::resolve_library(library, &root.mappings)?;
         let offset = target::probe_site(&Location::VirtualAddress(*address), &path)?;
         let addr = mapped_address(&root.mappings, &path, offset)?;
         (ProbeSite::File { path, offset }, addr)
      },
      WatchLocation::FileOffset { library, offset } => {
         let path = target::resolve_library(library, &root.mappings)?;
         let addr = mapped_address(&root.mappings, &path, *offset)?;
         (
            ProbeSite::File {
               path,
               offset: *offset,
            },
            addr,
         )
      },
   };
   let offset = site.offset();
   let label = format!("{offset:#x}");
   let probe = hardware_probe(site, addr, request.access.into(), request.length)?;
   eprintln!("{label} -> {addr:#x} in pid {pid}");
   let group = new_group(label, probe, request.report.stack());
   arm_groups(vec![group], spaces, request.report.stack())
}

fn refuse_if_text_differs(
   pid: i32,
   mappings: &[maps::Mapping],
   path: &str,
   offset: u64,
) -> io::Result<()> {
   const WIDTH: usize = perf::HW_BREAKPOINT_EXEC_LEN as usize;

   let runtime = mapped_address(mappings, path, offset)?;
   let memory = target::read_remote(pid, runtime, WIDTH)?;
   if memory.len() != WIDTH {
      return Err(io::Error::new(
         io::ErrorKind::UnexpectedEof,
         "the target text could not be read completely",
      ));
   }
   let mut disk = [0_u8; WIDTH];
   fs::File::open(path)?.read_exact_at(&mut disk, offset)?;
   if memory == disk {
      return Ok(());
   }

   let show = |bytes: &[u8]| {
      bytes
         .iter()
         .map(|byte| format!("{byte:02x}"))
         .collect::<Vec<_>>()
         .join(" ")
   };
   Err(io::Error::other(format!(
      "the text at {path}+{offset:#x} does not match the file, so this library rewrites its own \
       code.\n  in memory: {}\n  on disk:   {}\nA uprobe would execute the on-disk bytes in place \
       of the real instruction on every hit, and write them back when it is removed, which \
       corrupts the target. Use --hw for a hardware breakpoint, which modifies nothing.",
      show(&memory),
      show(&disk)
   )))
}

fn poll_set(groups: &[Group]) -> Vec<libc::pollfd> {
   groups
      .iter()
      .flat_map(|group| group.probes.values())
      .map(|probe| {
         libc::pollfd {
            fd:      probe.as_raw_fd(),
            events:  libc::POLLIN,
            revents: 0,
         }
      })
      .collect()
}

fn raise_limits() {
   let unlimited = libc::rlimit {
      rlim_cur: libc::RLIM_INFINITY,
      rlim_max: libc::RLIM_INFINITY,
   };
   // SAFETY: unlimited is a live rlimit, so a refusal only costs us headroom.
   unsafe {
      libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const unlimited);
   }

   let mut limit = libc::rlimit {
      rlim_cur: 0,
      rlim_max: 0,
   };
   // SAFETY: limit is a live rlimit and getrlimit only writes into it.
   if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } == 0_i32 {
      limit.rlim_cur = limit.rlim_max;
      // SAFETY: limit remains live and rlim_cur is clamped to the hard limit.
      unsafe {
         libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit);
      }
   }

   // SAFETY: limit is a live rlimit and getrlimit only writes into it.
   if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) } == 0_i32
      && limit.rlim_cur < limit.rlim_max
   {
      limit.rlim_cur = limit.rlim_max;
      // SAFETY: limit remains live and rlim_cur is clamped to the hard limit.
      unsafe {
         libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit);
      }
   }
}
