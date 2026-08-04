// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

use core::time::Duration;
use std::{
   fs::File,
   sync::Arc,
   thread,
};

use app_benzeneos_benzened::aidl::app::benzeneos::benzened::{
   IBenzened::{
      BnBenzened,
      IBenzened,
      SERVICE_NAME,
   },
   IBenzenedGrants::{
      IBenzenedGrants,
      SERVICE_NAME as GRANTS_SERVICE,
   },
   ShellRequest::ShellRequest,
   ShellSession::ShellSession,
};
use binder::{
   BinderFeatures,
   ExceptionCode,
   Interface,
   ParcelFileDescriptor,
   Result,
   Status,
   Strong,
};
use log::{
   error,
   info,
};

use crate::{
   children::Registry,
   grant::{
      self,
      Decision,
      Source,
      Tier,
   },
   pty,
   ratelimit::RateLimiter,
};

/// An empty environment leaves the shell with no PATH, so callers that pass
/// nothing get a usable minimum rather than a broken session.
const DEFAULT_ENV: [&str; 3] = [
   "PATH=/product/bin:/apex/com.android.runtime/bin:/system/bin:/system_ext/bin",
   "HOME=/",
   "TERM=xterm-256color",
];

fn resolve_env(environment: &[String]) -> Result<Vec<String>> {
   if environment.is_empty() {
      return Ok(DEFAULT_ENV
         .iter()
         .map(|entry| (*entry).to_owned())
         .collect());
   }
   if environment.iter().any(|entry| {
      entry.as_bytes().contains(&0)
         || entry
            .split_once('=')
            .is_none_or(|(name, _value)| name.is_empty())
   }) {
      return Err(Status::new_exception_str(
         ExceptionCode::ILLEGAL_ARGUMENT,
         Some("environment entries must be non-empty KEY=VALUE pairs without NUL bytes"),
      ));
   }
   Ok(environment.to_vec())
}

fn resolve_cwd(working_directory: Option<&str>) -> Result<Option<&str>> {
   match working_directory.filter(|dir| !dir.is_empty()) {
      Some(dir) if dir.as_bytes().contains(&0) => {
         Err(Status::new_exception_str(
            ExceptionCode::ILLEGAL_ARGUMENT,
            Some("workingDirectory must not contain a NUL byte"),
         ))
      },
      Some(dir) if !dir.starts_with('/') => {
         Err(Status::new_exception_str(
            ExceptionCode::ILLEGAL_ARGUMENT,
            Some("workingDirectory must be absolute"),
         ))
      },
      other => Ok(other),
   }
}

/// The chdir has to happen after the exec. The forked child is still in the
/// `benzened` domain, which has no filesystem access to speak of.
fn with_cwd(command: &str, cwd: Option<&str>) -> String {
   let Some(dir) = cwd else {
      return command.to_owned();
   };
   let quoted = format!("'{}'", dir.replace('\'', r"'\''"));
   if command.is_empty() {
      format!("cd {quoted} && exec /system/bin/sh")
   } else {
      format!("cd {quoted} || exit\n{command}")
   }
}

struct Request<'req> {
   argv:     &'req [&'req str],
   want_pty: bool,
   columns:  i32,
   rows:     i32,
   env:      &'req [String],
   tier:     Tier,
   caller:   u32,
}

fn spawn(req: &Request, registry: &Registry) -> Result<ShellSession> {
   let opts = pty::SpawnOpts {
      argv:         req.argv,
      exec_context: req.tier.exec_context(),
      env:          req.env,
   };
   let spawned = if req.want_pty {
      pty::spawn_on_terminal(&opts, req.columns, req.rows)
   } else {
      pty::spawn_on_socketpair(&opts)
   };
   match spawned {
      Ok(child) => {
         let (caller, tier) = (req.caller, req.tier);
         let pid = child.child.pid();
         info!(
            "uid {caller} tier {tier:?}: spawned {} as pid {}",
            req.argv[0], pid
         );
         let status = match registry.track(caller, child.child, tier) {
            Ok(status) => status,
            Err(err) => {
               error!("could not monitor pid {pid}: {err}");
               return Err(Status::new_exception_str(
                  ExceptionCode::SERVICE_SPECIFIC,
                  Some("could not monitor the shell"),
               ));
            },
         };
         Ok(ShellSession {
            inputOutput:   Some(ParcelFileDescriptor::new(File::from(child.master))),
            standardError: child
               .stderr
               .map(|stderr| ParcelFileDescriptor::new(File::from(stderr))),
            exitStatus:    Some(ParcelFileDescriptor::new(File::from(status))),
         })
      },
      Err(err) => {
         error!("spawn failed: {err}");
         Err(Status::new_exception_str(
            ExceptionCode::SERVICE_SPECIFIC,
            Some("failed to spawn shell"),
         ))
      },
   }
}

struct SystemServerGrants;

impl Source for SystemServerGrants {
   fn tier(&self, uid: u32) -> Option<i32> {
      let svc: Strong<dyn IBenzenedGrants> = binder::get_interface(GRANTS_SERVICE).ok()?;
      svc.getRootTier(i32::try_from(uid).ok()?).ok()
   }
}

pub struct Benzened {
   grants:   SystemServerGrants,
   limiter:  RateLimiter,
   registry: Arc<Registry>,
}

impl Interface for Benzened {}

impl Benzened {
   fn check_caller(&self) -> Result<(u32, Tier)> {
      let caller = binder::ThreadState::get_calling_uid();
      if !self.limiter.allow(caller) {
         error!("rate limited uid {caller}");
         return Err(Status::new_exception_str(
            ExceptionCode::SECURITY,
            Some("too many shell requests"),
         ));
      }
      let tier = match grant::decide(&self.grants, caller) {
         Decision::Allow(tier) => tier,
         other @ (Decision::DenyNotGranted | Decision::DenyUnknownCaller) => {
            error!("denied uid {caller}: {other:?}");
            return Err(Status::new_exception_str(
               ExceptionCode::SECURITY,
               Some("benzened access not granted"),
            ));
         },
      };
      Ok((caller, tier))
   }
}

impl IBenzened for Benzened {
   fn openShell(&self, request: &ShellRequest) -> Result<ShellSession> {
      let (caller, tier) = self.check_caller()?;
      if request.command.as_bytes().contains(&0) {
         return Err(Status::new_exception_str(
            ExceptionCode::ILLEGAL_ARGUMENT,
            Some("command must not contain a NUL byte"),
         ));
      }
      let cwd = resolve_cwd(request.workingDirectory.as_deref())?;
      let env = resolve_env(&request.environment)?;
      let script = with_cwd(&request.command, cwd);
      let argv = if script.is_empty() {
         vec!["/system/bin/sh"]
      } else {
         vec!["/system/bin/sh", "-c", &script]
      };
      spawn(
         &Request {
            argv: &argv,
            want_pty: request.terminal,
            columns: request.columns,
            rows: request.rows,
            env: &env,
            tier,
            caller,
         },
         &self.registry,
      )
   }
}

pub fn register() -> Result<Arc<Registry>> {
   let registry = Arc::new(Registry::new().map_err(|err| {
      error!("could not start child reaper: {err}");
      Status::new_exception_str(
         ExceptionCode::SERVICE_SPECIFIC,
         Some("could not start child reaper"),
      )
   })?);
   let svc = Benzened {
      grants:   SystemServerGrants,
      limiter:  RateLimiter::new(),
      registry: Arc::clone(&registry),
   };
   let binder = BnBenzened::new_binder(svc, BinderFeatures::default());
   binder::add_service(SERVICE_NAME, binder.as_binder())?;
   info!("Registered {SERVICE_NAME}");
   Ok(registry)
}

/// Polls because nothing pushes a tier change to this process. The interval is
/// the window a revoked shell keeps running for.
pub const REVOCATION_INTERVAL: Duration = Duration::from_secs(2);

pub fn watch_grants(registry: &Registry) -> ! {
   let grants = SystemServerGrants;
   loop {
      thread::sleep(REVOCATION_INTERVAL);
      registry.sweep(&grants);
   }
}
