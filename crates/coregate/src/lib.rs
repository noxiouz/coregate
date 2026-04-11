//! Coregate collector library.
//!
//! Downstream binaries compose a `Runtime` from module implementations. The
//! shipped binary in the repository root uses the default module set, but it is
//! intentionally just another consumer of this library API.

pub mod bpf;
pub mod config;
pub mod corefile;
pub mod defaults;
pub mod ingress;
pub mod kernel;
pub mod limit;
pub mod meta;
pub mod modules;
pub mod runtime;
pub mod setup;
pub mod store;
pub mod telemetry;

#[allow(dead_code)]
mod dump;
pub use modules::{EnrichmentContext, HandleRequest, TelemetryEvent};
pub use runtime::{Missing, Runtime, RuntimeBuilder};

pub const DEFAULT_CONFIG_PATH: &str = setup::DEFAULT_CONFIG_PATH;
