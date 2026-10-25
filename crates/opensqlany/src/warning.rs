use std::fmt;

/// Something the reader accepted under [`ReadOptions`](crate::ReadOptions)
/// leniency that strict mode would have rejected.
///
/// Results carry their warnings; an empty list means every check passed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Warning {
    /// What was accepted.
    pub kind: WarningKind,
    /// Zero-based page number, when the warning is about one page.
    pub page: Option<u64>,
    /// Sector index within the page, when the warning is about one sector.
    pub sector: Option<usize>,
}

#[allow(dead_code)] // constructors are used once the decoders emit warnings
impl Warning {
    /// A warning of `kind` that is not yet tied to a page or sector.
    ///
    /// Public so that crates built on this one can add their own warnings
    /// (with [`WarningKind::Other`]) to the lists they return.
    pub fn new(kind: WarningKind) -> Self {
        Warning {
            kind,
            page: None,
            sector: None,
        }
    }

    /// This warning, attached to page `page`.
    pub fn on_page(mut self, page: u64) -> Self {
        self.page = Some(page);
        self
    }

    /// This warning, attached to sector `sector` of its page.
    pub fn on_sector(mut self, sector: usize) -> Self {
        self.sector = Some(sector);
        self
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(page) = self.page {
            write!(f, "page {page}: ")?;
        }
        if let Some(sector) = self.sector {
            write!(f, "sector {sector}: ")?;
        }
        write!(f, "{}", self.kind)
    }
}

/// The kind of a [`Warning`].
///
/// New kinds are added in minor releases; match with a wildcard arm. Kinds
/// that have no variant of their own use [`WarningKind::Other`] with a stable
/// short code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WarningKind {
    /// The keystream was chosen by histogram score alone; no structural check
    /// confirmed it.
    #[non_exhaustive]
    UnverifiedKeystream {
        /// The `bv` that was used.
        bv: u8,
    },
    /// A sector's step was chosen with a thin lead over its runner-up.
    #[non_exhaustive]
    LowConfidenceSector {
        /// Histogram peak of the chosen step.
        peak: usize,
        /// Histogram peak of the best competing step.
        runner_up: usize,
    },
    /// Calibration evidence pointed at more than one `bv`; the strongest was
    /// used.
    #[non_exhaustive]
    AmbiguousCalibration {
        /// The `bv` that was used.
        chosen: u8,
        /// The other candidates.
        others: Vec<u8>,
    },
    /// The page failed its stored CRC.
    BadCrc,
    /// The page failed its reserved-byte trailer check.
    BadTrailer,
    /// The superblock names a format version this reader does not decode.
    #[non_exhaustive]
    UnsupportedVersion {
        /// `format_major`.
        major: u32,
        /// `version_a`.
        a: u16,
        /// `version_b`.
        b: u16,
    },
    /// The slot directory was found by scanning and no prelude confirmed it.
    UnverifiedDirectory,
    /// The prelude declares more slot-directory entries than could be read.
    #[non_exhaustive]
    SlotDirectoryTruncated {
        /// Entries read.
        found: usize,
        /// Entries the prelude declares.
        expected: usize,
    },
    /// More than one slot directory candidate fits the page.
    AmbiguousSlotDirectory,
    /// Live slots point into the directory itself; they were left out of the
    /// rows.
    #[non_exhaustive]
    SlotOffsetsInDirectory {
        /// Slots left out.
        dropped: usize,
    },
    /// The bytes before the slot directory could not be interpreted.
    UnknownPrelude,
    /// `flags_06` lacks the base bits every SA17 file carries.
    #[non_exhaustive]
    UnsupportedFlags {
        /// The byte at superblock offset 0x06.
        flags_06: u8,
    },
    /// No page calibrated the keystream.
    NoCalibration,
    /// The calibration pages read as plaintext.
    NotObfuscated,
    /// Any other accepted condition, named by a stable short code. The crate
    /// itself never produces this kind; it is for crates built on this one.
    Other(&'static str),
}

impl fmt::Display for WarningKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WarningKind::UnverifiedKeystream { bv } => {
                write!(f, "keystream bv 0x{bv:02X} is unverified")
            }
            WarningKind::LowConfidenceSector { peak, runner_up } => write!(
                f,
                "low-confidence step (peak {peak}, runner-up {runner_up})"
            ),
            WarningKind::AmbiguousCalibration { chosen, others } => write!(
                f,
                "ambiguous calibration: used bv 0x{chosen:02X}, also {others:?}"
            ),
            WarningKind::BadCrc => write!(f, "stored CRC does not match"),
            WarningKind::BadTrailer => write!(f, "reserved trailer bytes are non-zero"),
            WarningKind::UnsupportedVersion { major, a, b } => {
                write!(f, "unsupported format version {major}.{a}.{b}")
            }
            WarningKind::UnverifiedDirectory => write!(f, "slot directory is unverified"),
            WarningKind::SlotDirectoryTruncated { found, expected } => write!(
                f,
                "slot directory holds {found} of the {expected} declared entries"
            ),
            WarningKind::AmbiguousSlotDirectory => {
                write!(f, "more than one slot directory candidate fits")
            }
            WarningKind::SlotOffsetsInDirectory { dropped } => {
                write!(f, "{dropped} slot offsets inside the directory left out")
            }
            WarningKind::UnknownPrelude => write!(f, "page prelude could not be interpreted"),
            WarningKind::UnsupportedFlags { flags_06 } => {
                write!(f, "unsupported superblock flags 0x{flags_06:02X}")
            }
            WarningKind::NoCalibration => write!(f, "no pure-AP page calibrated the keystream"),
            WarningKind::NotObfuscated => write!(f, "store does not look AP-obfuscated"),
            WarningKind::Other(code) => write!(f, "{code}"),
        }
    }
}
