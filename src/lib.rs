//! Static IP Manager core logic (parsing, validation, command generation).
//! Everything here is OS-independent and testable with mock command runners.

pub mod apply;
pub mod linux;
pub mod model;
pub mod probe;
pub mod runner;
pub mod safety;
pub mod store;
pub mod validate;
pub mod windows;
