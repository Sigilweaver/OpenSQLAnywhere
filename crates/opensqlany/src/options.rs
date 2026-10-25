use std::ops::{BitOr, BitOrAssign};

/// The set of checks a read is allowed to relax.
///
/// The default, [`Leniency::STRICT`], relaxes nothing: any input the reader
/// cannot decode with confidence is an error. Each flag turns one family of
/// errors into a [`Warning`](crate::Warning) on the returned result, so the
/// caller can see exactly what was accepted without confirmation.
///
/// New flags are added in minor releases; combine flags with `|` and test
/// with [`Leniency::contains`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Leniency {
    bits: u32,
}

impl Leniency {
    /// Relax nothing.
    pub const STRICT: Leniency = Leniency { bits: 0 };
    /// Accept an AP keystream (`bv`, step) that no structural check
    /// confirmed, or whose per-sector confidence is low.
    pub const KEYSTREAM: Leniency = Leniency { bits: 1 };
    /// Accept a slot directory that no page prelude confirmed.
    pub const DIRECTORY: Leniency = Leniency { bits: 1 << 1 };
    /// Accept pages that fail their stored CRC or trailer checks.
    pub const INTEGRITY: Leniency = Leniency { bits: 1 << 2 };
    /// Accept a store whose superblock names an unsupported format version.
    pub const FORMAT: Leniency = Leniency { bits: 1 << 3 };

    /// Every relaxation this release knows.
    ///
    /// **This set widens**: a later minor release that adds a flag adds it
    /// here, so a caller that stores or depends on this value accepts more
    /// kinds of problem after upgrading. Name the flags instead (`KEYSTREAM |
    /// DIRECTORY`) unless that is what you want.
    pub const fn every_known() -> Leniency {
        Leniency { bits: 0b1111 }
    }

    /// `true` when no check is relaxed.
    pub const fn is_strict(self) -> bool {
        self.bits == 0
    }

    /// `true` when every flag set in `other` is also set in `self`.
    pub const fn contains(self, other: Leniency) -> bool {
        self.bits & other.bits == other.bits
    }

    /// The union of two sets.
    pub const fn union(self, other: Leniency) -> Leniency {
        Leniency {
            bits: self.bits | other.bits,
        }
    }
}

impl BitOr for Leniency {
    type Output = Leniency;

    fn bitor(self, rhs: Leniency) -> Leniency {
        self.union(rhs)
    }
}

impl BitOrAssign for Leniency {
    fn bitor_assign(&mut self, rhs: Leniency) {
        *self = self.union(rhs);
    }
}

/// Options shared by every read entry point.
///
/// `ReadOptions::default()` is strict. The struct is `#[non_exhaustive]`:
/// build it with [`ReadOptions::strict`], [`ReadOptions::lenient`] or
/// [`ReadOptions::with_leniency`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadOptions {
    /// Which checks may be relaxed.
    pub leniency: Leniency,
}

impl ReadOptions {
    /// Strict options (the default).
    pub fn strict() -> Self {
        ReadOptions::default()
    }

    /// Options that relax exactly [`Leniency::KEYSTREAM`],
    /// [`Leniency::DIRECTORY`], [`Leniency::INTEGRITY`] and
    /// [`Leniency::FORMAT`]. A flag added in a later release is *not* added
    /// to this set, so upgrading never accepts a new kind of problem. Each
    /// accepted problem is reported as a [`Warning`](crate::Warning) on the
    /// result.
    pub fn lenient() -> Self {
        ReadOptions::default().with_leniency(
            Leniency::KEYSTREAM | Leniency::DIRECTORY | Leniency::INTEGRITY | Leniency::FORMAT,
        )
    }

    /// Options that relax every check this release knows.
    ///
    /// **This set widens** with each flag a later release adds; see
    /// [`Leniency::every_known`].
    pub fn widest() -> Self {
        ReadOptions::default().with_leniency(Leniency::every_known())
    }

    /// These options with `leniency` in place of the current set.
    pub fn with_leniency(mut self, leniency: Leniency) -> Self {
        self.leniency = leniency;
        self
    }
}
