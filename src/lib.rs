//! Crate root.
//!
//! TODO: Replace this placeholder with the actual public API
//! and module layout as described in the crate's README.
//!
//! ## Tracing
//!
//! The [`telemetry`] module defines standard auth span attributes. This crate does **not**
//! re-export [`tracing`]; embed your own subscriber.

pub mod telemetry;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_test() {
        // TODO: Add real tests for the crate's public API once it is defined.
    }
}
