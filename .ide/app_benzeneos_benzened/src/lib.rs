// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

//! Stand-in for the crate the `aidl_interface` rule generates from `aidl/`.
//! The reference is `app_benzeneos_benzened.rs` under
//! `out-<device>/soong/.intermediates/benzeneos/benzened/`.
//!
//! `get_descriptor` and `try_as_async_server` are spelled out as defaults
//! because `clippy::missing_trait_methods` only fires on defaults that exist.

#![allow(
   clippy::all,
   clippy::nursery,
   clippy::pedantic,
   clippy::restriction,
   non_snake_case,
   reason = "scaffolding, not code under review"
)]

pub mod aidl {
   pub mod app {
      pub mod benzeneos {
         pub mod benzened {
            pub mod ShellRequest {
               #[derive(Default)]
               pub struct ShellRequest {
                  pub command:          String,
                  pub terminal:         bool,
                  pub columns:          i32,
                  pub rows:             i32,
                  pub workingDirectory: Option<String>,
                  pub environment:      Vec<String>,
               }
            }

            pub mod ShellSession {
               use binder::ParcelFileDescriptor;

               pub struct ShellSession {
                  pub inputOutput:   Option<ParcelFileDescriptor>,
                  pub standardError: Option<ParcelFileDescriptor>,
                  pub exitStatus:    Option<ParcelFileDescriptor>,
               }
            }

            pub mod IBenzened {
               use binder::{
                  BinderFeatures,
                  FromIBinder,
                  Interface,
                  Result,
                  SpIBinder,
                  StatusCode,
                  Strong,
               };

               use super::{
                  ShellRequest::ShellRequest,
                  ShellSession::ShellSession,
               };

               pub const r#SERVICE_NAME: &str = "app.benzeneos.benzened.IBenzened/default";

               pub trait IBenzened: Interface + Send {
                  fn get_descriptor() -> &'static str
                  where
                     Self: Sized,
                  {
                     "app.benzeneos.benzened.IBenzened"
                  }

                  fn r#openShell<'a, 'l1>(
                     &'a self,
                     _arg_request: &'l1 ShellRequest,
                  ) -> Result<ShellSession>;

                  fn try_as_async_server<'a>(
                     &'a self,
                  ) -> Option<&'a (dyn IBenzenedAsyncServer + Send + Sync)> {
                     None
                  }
               }

               pub trait IBenzenedAsyncServer: Interface + Send {
                  fn get_descriptor() -> &'static str
                  where
                     Self: Sized,
                  {
                     "app.benzeneos.benzened.IBenzened"
                  }
               }

               impl FromIBinder for dyn IBenzened {
                  fn try_from(
                     _ibinder: SpIBinder,
                  ) -> core::result::Result<Strong<Self>, StatusCode> {
                     Err(StatusCode::NAME_NOT_FOUND)
                  }
               }

               pub struct BnBenzened;

               impl BnBenzened {
                  pub fn new_binder<T: IBenzened + Sync + Send + 'static>(
                     inner: T,
                     features: BinderFeatures,
                  ) -> Strong<dyn IBenzened> {
                     let _ = features;
                     Strong::new(Box::new(inner))
                  }
               }
            }

            pub mod IBenzenedGrants {
               use binder::{
                  FromIBinder,
                  Interface,
                  Result,
                  SpIBinder,
                  StatusCode,
                  Strong,
               };

               pub const r#SERVICE_NAME: &str = "app.benzeneos.benzened.IBenzenedGrants/default";
               pub const r#TIER_NONE: i32 = 0;
               pub const r#TIER_STANDARD: i32 = 1;
               pub const r#TIER_UNRESTRICTED: i32 = 2;

               pub trait IBenzenedGrants: Interface + Send {
                  fn get_descriptor() -> &'static str
                  where
                     Self: Sized,
                  {
                     "app.benzeneos.benzened.IBenzenedGrants"
                  }

                  fn r#getRootTier<'a>(&'a self, _arg_uid: i32) -> Result<i32>;

                  fn try_as_async_server<'a>(
                     &'a self,
                  ) -> Option<&'a (dyn IBenzenedGrantsAsyncServer + Send + Sync)>
                  {
                     None
                  }
               }

               pub trait IBenzenedGrantsAsyncServer: Interface + Send {
                  fn get_descriptor() -> &'static str
                  where
                     Self: Sized,
                  {
                     "app.benzeneos.benzened.IBenzenedGrants"
                  }
               }

               impl FromIBinder for dyn IBenzenedGrants {
                  fn try_from(
                     _ibinder: SpIBinder,
                  ) -> core::result::Result<Strong<Self>, StatusCode> {
                     Err(StatusCode::NAME_NOT_FOUND)
                  }
               }

               pub struct BnBenzenedGrants;
            }
         }
      }
   }
}
