//! Pure, chain/IO-free domain logic: fee math, supply arithmetic,
//! timing/phase-window calculations, and the normalized cross-protocol
//! stage model. Everything here is deterministic and exhaustively
//! unit-tested without any network or process dependency.

pub mod fees;
pub mod stage;
pub mod supply;
pub mod timing;
