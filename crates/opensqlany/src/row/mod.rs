//! Row-page framing, sector reconstruction and forwarded physical records.
//!
//! Header and directory checks establish slot boundaries before sector and tail
//! recovery. Forwarded records retain both the source and terminal addresses.

pub(crate) mod directory;
pub(crate) mod forwarded;
pub(crate) mod header;
pub(crate) mod physical;
pub(crate) mod sector;
pub(crate) mod tail;
