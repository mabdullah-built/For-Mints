//! Pure, chain/IO-free domain logic: fee math, supply arithmetic, and
//! timing/phase-window calculations. Everything here is deterministic and
//! exhaustively unit-tested without any network or process dependency.

pub mod fees;
pub mod supply;
pub mod timing;
