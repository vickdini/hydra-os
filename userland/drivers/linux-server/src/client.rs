//! The call being served: who made it, and its memory. Since wave 6 this lives in the
//! service runtime every service shares (`hydra_rt::svcrt`); linux-server uses it from here.

pub use hydra_rt::svcrt::{now_ms, Caller, Cx};
