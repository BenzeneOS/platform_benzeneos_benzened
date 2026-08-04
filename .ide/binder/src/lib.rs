// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

//! Stand-in for `libbinder_rs`, which only exists inside an Android build.

#![allow(
   clippy::all,
   clippy::nursery,
   clippy::pedantic,
   clippy::restriction,
   non_camel_case_types,
   reason = "scaffolding, not code under review"
)]

use core::result;
use std::{
   error,
   ffi::CStr,
   fmt,
   io::{
      Read,
      Write,
   },
   ops::Deref,
   os::fd::{
      AsFd,
      AsRawFd,
      BorrowedFd,
      IntoRawFd,
      OwnedFd,
      RawFd,
   },
};

pub type Result<T> = result::Result<T, Status>;

/// Upstream's crate-internal `error::Result`. `Interface::dump`,
/// `Interface::shell_command` and the service-manager entry points use this
/// one, and getting it wrong resolves as `E0053` only under Soong.
type StatusResult<T> = result::Result<T, StatusCode>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionCode {
   NONE,
   SECURITY,
   BAD_PARCELABLE,
   ILLEGAL_ARGUMENT,
   NULL_POINTER,
   ILLEGAL_STATE,
   NETWORK_MAIN_THREAD,
   UNSUPPORTED_OPERATION,
   SERVICE_SPECIFIC,
   TRANSACTION_FAILED,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
   OK,
   UNKNOWN_ERROR,
   NO_MEMORY,
   INVALID_OPERATION,
   BAD_VALUE,
   BAD_TYPE,
   NAME_NOT_FOUND,
   PERMISSION_DENIED,
   NO_INIT,
   ALREADY_EXISTS,
   DEAD_OBJECT,
   FAILED_TRANSACTION,
   BAD_INDEX,
   NOT_ENOUGH_DATA,
   WOULD_BLOCK,
   TIMED_OUT,
   UNKNOWN_TRANSACTION,
   FDS_NOT_ALLOWED,
   UNEXPECTED_NULL,
}

#[derive(Debug)]
pub struct Status(String);

impl Status {
   pub fn new_exception(exception: ExceptionCode, message: Option<&CStr>) -> Self {
      Self(format!(
         "{exception:?}: {}",
         message.map_or_else(String::new, |msg| msg.to_string_lossy().into_owned())
      ))
   }

   pub fn new_exception_str<T: AsRef<str>>(exception: ExceptionCode, message: Option<T>) -> Self {
      Self(format!(
         "{exception:?}: {}",
         message.as_ref().map_or("", AsRef::as_ref)
      ))
   }
}

impl fmt::Display for Status {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(&self.0)
   }
}

impl error::Error for Status {}

impl From<ExceptionCode> for Status {
   fn from(code: ExceptionCode) -> Self {
      Self(format!("{code:?}"))
   }
}

impl From<StatusCode> for Status {
   fn from(status: StatusCode) -> Self {
      Self(format!("{status:?}"))
   }
}

/// Upstream is `Send + Sync + DowncastSync`. `downcast-rs` is not reachable
/// off-tree, and `'static` is the part of that bound this module can trip on.
pub trait Interface: Send + Sync + 'static {
   fn as_binder(&self) -> SpIBinder {
      panic!("This object was not a Binder object and cannot be converted into an SpIBinder.")
   }

   fn dump(&self, _writer: &mut dyn Write, _args: &[&CStr]) -> StatusResult<()> {
      Ok(())
   }

   fn shell_command(
      &self,
      _stdin: &mut dyn Read,
      _stdout: &mut dyn Write,
      _stderr: &mut dyn Write,
      _args: &[&CStr],
   ) -> StatusResult<()> {
      Ok(())
   }
}

pub trait FromIBinder: Interface {
   fn try_from(ibinder: SpIBinder) -> StatusResult<Strong<Self>>;
}

pub struct SpIBinder;

#[derive(Default)]
pub struct BinderFeatures {
   pub set_requesting_sid: bool,
   pub set_inherit_rt:     bool,
}

pub struct Strong<I: FromIBinder + ?Sized>(Box<I>);

impl<I: FromIBinder + ?Sized> Strong<I> {
   pub fn new(binder: Box<I>) -> Self {
      Self(binder)
   }
}

impl<I: FromIBinder + ?Sized> Deref for Strong<I> {
   type Target = I;

   fn deref(&self) -> &I {
      &self.0
   }
}

#[derive(Debug)]
pub struct ParcelFileDescriptor(OwnedFd);

impl ParcelFileDescriptor {
   pub fn new<F: Into<OwnedFd>>(fd: F) -> Self {
      Self(fd.into())
   }

   pub fn try_clone(&self) -> std::io::Result<Self> {
      Ok(Self(self.0.try_clone()?))
   }
}

impl AsRef<OwnedFd> for ParcelFileDescriptor {
   fn as_ref(&self) -> &OwnedFd {
      &self.0
   }
}

impl From<ParcelFileDescriptor> for OwnedFd {
   fn from(fd: ParcelFileDescriptor) -> Self {
      fd.0
   }
}

impl AsFd for ParcelFileDescriptor {
   fn as_fd(&self) -> BorrowedFd<'_> {
      self.0.as_fd()
   }
}

impl AsRawFd for ParcelFileDescriptor {
   fn as_raw_fd(&self) -> RawFd {
      self.0.as_raw_fd()
   }
}

impl IntoRawFd for ParcelFileDescriptor {
   fn into_raw_fd(self) -> RawFd {
      self.0.into_raw_fd()
   }
}

pub fn get_interface<T: FromIBinder + ?Sized>(name: &str) -> StatusResult<Strong<T>> {
   let _ = name;
   Err(StatusCode::NAME_NOT_FOUND)
}

pub fn add_service(identifier: &str, binder: SpIBinder) -> StatusResult<()> {
   let _ = (identifier, binder);
   Ok(())
}

pub struct ProcessState;

impl ProcessState {
   pub fn start_thread_pool() {}

   pub fn join_thread_pool() {}
}

pub struct ThreadState;

impl ThreadState {
   pub fn get_calling_uid() -> u32 {
      0
   }

   pub fn get_calling_pid() -> i32 {
      0
   }
}
