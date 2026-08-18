//! Strict public contracts for File Guardian processing jobs.

pub mod acquisition;
pub mod actions;
pub mod adjudication;
pub mod artifact;
pub mod builtin_backend;
pub mod catalog;
pub mod completion;
pub mod config;
pub mod domain;
pub mod engine;
pub mod executor;
pub mod external_backend;
pub mod findings;
pub mod job;
pub mod pi_backend;
pub mod pi_report;
pub mod policy;
pub mod report;
pub mod report_builder;
pub mod retention;
pub mod runtime;

pub use domain::*;
