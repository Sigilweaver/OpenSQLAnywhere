//! Physical fields in a length-delimited SQL Anywhere row.
//!
//! The caller selects the column layout explicitly. Referenced byte chains,
//! terminal chunks and compressed streams have separate framing checks.
//! An exact walk is structural evidence. Choosing the live row and the layout
//! version applicable to it requires additional evidence from the database.
//!
//! See `SPECIFICATION.md` sections 8.2 and 8.3 and the
//! [record-layout observations](https://github.com/Sigilweaver/OpenQBW/issues/22).

pub(crate) mod byte_chain;
pub(crate) mod compression;
pub(crate) mod long_value;

use std::fmt;

/// A column of a single selected physical catalog layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordColumn {
    /// One-based physical ordinal in the table.
    pub column_id: u32,
    /// Domain identifier recorded in ISYSTABCOL.
    pub domain_id: u16,
    /// Logical column width from the catalog. Stored byte markers determine
    /// inline and indirect framing independently of this declared width.
    pub width: u32,
    /// Nullable columns have one bit in the row's presence bitmap.
    pub nullable: bool,
}

/// A complete column list in physical ordinal order. Construct each observed
/// schema version separately; a failed walk never retries a shorter schema.
///
/// ```
/// use opensqlany::{PhysicalValue, RecordColumn, RecordLayout};
///
/// let layout = RecordLayout::new(vec![RecordColumn {
///     column_id: 1,
///     domain_id: 2, // INTEGER
///     width: 4,
///     nullable: false,
/// }])?;
/// let row = layout.decode(&[7, 0, 0, 42, 0, 0, 0])?;
/// assert_eq!(row.fields, [PhysicalValue::Integer(42)]);
/// # Ok::<(), opensqlany::RecordError>(())
/// ```
#[derive(Debug, Clone)]
pub struct RecordLayout {
    columns: Vec<RecordColumn>,
    bitmap_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ByteDescriptors {
    Original,
    Linked,
    Stored,
}

impl RecordLayout {
    /// Sort caller-selected columns into physical order; reject empty lists,
    /// duplicates, gaps, unsupported domains and layouts starting after one.
    /// XML (32) and LONG NVARCHAR (36) currently support only absent values.
    /// A present value in either domain fails its field walk.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] for an empty or noncontiguous layout, an
    /// unsupported domain, or a width outside the supported domain layout.
    pub fn new(columns: Vec<RecordColumn>) -> Result<Self, RecordError> {
        Self::build(columns, true)
    }

    /// Construct a current layout from a separately verified complete catalog.
    /// Ordinals may have gaps, but must be positive and unique. The caller
    /// must account for all current definitions before using this constructor.
    /// This supplies no evidence for the layout of an older record.
    pub fn from_complete_catalog(columns: Vec<RecordColumn>) -> Result<Self, RecordError> {
        Self::build(columns, false)
    }

    fn build(mut columns: Vec<RecordColumn>, contiguous: bool) -> Result<Self, RecordError> {
        if columns.is_empty() {
            return Err(RecordError::EmptyLayout);
        }
        columns.sort_unstable_by_key(|column| column.column_id);
        for (i, column) in columns.iter().enumerate() {
            if contiguous && column.column_id as usize != i + 1 {
                return Err(RecordError::ColumnOrder {
                    expected: i + 1,
                    found: column.column_id,
                });
            }
            if !contiguous
                && (column.column_id == 0 || i > 0 && column.column_id == columns[i - 1].column_id)
            {
                return Err(RecordError::ColumnIdentity {
                    column: column.column_id,
                });
            }
            if !matches!(column.domain_id, 1..=14 | 19..=24 | 27..=28 | 31..=32 | 36) {
                return Err(RecordError::UnsupportedDomain {
                    column: column.column_id,
                    domain: column.domain_id,
                });
            }
            // ISYSTABCOL's own physical records distinguish this one-byte
            // unsigned domain from the four-byte unsigned integer (21).
            if column.domain_id == 19 && column.width != 1 {
                return Err(RecordError::UnsupportedWidth {
                    column: column.column_id,
                    domain: column.domain_id,
                    width: column.width,
                });
            }
        }
        let bitmap_bytes = columns.iter().filter(|c| c.nullable).count().div_ceil(8);
        Ok(Self {
            columns,
            bitmap_bytes,
        })
    }

    /// Columns in the same order as the returned field values.
    pub fn columns(&self) -> &[RecordColumn] {
        &self.columns
    }

    /// Decode exactly one physical record. Every field must fit and the last
    /// field must end at the stored row length.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] for unsupported flags or field framing, an
    /// incomplete value, or a length that does not match the complete walk.
    pub fn decode<'a>(&self, row: &'a [u8]) -> Result<PhysicalRecord<'a>, RecordError> {
        self.decode_complete(row, ByteDescriptors::Original)
    }

    /// Decode the separately verified high-tag byte-chain descriptors in
    /// VARCHAR and LONG BINARY fields. Resolution and row visibility remain
    /// separate checks. Catalog bootstrap reads keep their existing decoder.
    pub fn decode_linked_bytes<'a>(
        &self,
        row: &'a [u8],
    ) -> Result<PhysicalRecord<'a>, RecordError> {
        self.decode_complete(row, ByteDescriptors::Linked)
    }

    /// Explicit recognition of supported raw and compressed byte streams
    /// and serialized domain-31 inline storage. Compressed descriptors retain
    /// the encoded length and separate decoded length. Inline bitset bytes
    /// still need explicit RLE decoding to obtain their decoded logical bytes.
    /// This does not resolve references or establish row visibility. Earlier
    /// decoders and catalog bootstrap retain their existing descriptor policy.
    pub fn decode_stored_bytes<'a>(
        &self,
        row: &'a [u8],
    ) -> Result<PhysicalRecord<'a>, RecordError> {
        self.decode_complete(row, ByteDescriptors::Stored)
    }

    fn decode_complete<'a>(
        &self,
        row: &'a [u8],
        descriptors: ByteDescriptors,
    ) -> Result<PhysicalRecord<'a>, RecordError> {
        let (record, rest) = self.decode_fields(row, descriptors)?;
        if !rest.is_empty() {
            return Err(RecordError::TrailingBytes { count: rest.len() });
        }
        Ok(record)
    }

    /// Decode the observed nine-byte minimum allocation for a short ordinary
    /// record. The flags must be zero, every field of this layout must decode,
    /// and the remaining one to six bytes must all be zero.
    ///
    /// Use [`Self::decode`] first for exact records. Before using this
    /// alternative, establish the live slot and its complete applicable layout
    /// independently: an omitted zero-valued field can resemble padding.
    pub fn decode_minimum_padded<'a>(
        &self,
        row: &'a [u8],
    ) -> Result<MinimumPaddedRecord<'a>, RecordError> {
        if row.len() != 9 || row[2] != 0 {
            return Err(RecordError::NotMinimumPadded);
        }
        self.decode_minimum_padded_live(row)
    }

    /// Explicit minimum-allocation decoder for supported live flags zero
    /// and 0x08. The original flag is preserved. The caller must independently
    /// establish row visibility and the complete current layout, including
    /// when the table also contains separately accounted-for deleted records.
    /// Catalog bootstrap and [`Self::decode_minimum_padded`] remain flag-zero.
    pub fn decode_minimum_padded_live<'a>(
        &self,
        row: &'a [u8],
    ) -> Result<MinimumPaddedRecord<'a>, RecordError> {
        if row.len() != 9 || !matches!(row[2], 0 | 8) {
            return Err(RecordError::NotMinimumPadded);
        }
        let (record, padding) = self.decode_fields(row, ByteDescriptors::Original)?;
        if !(1..=6).contains(&padding.len()) || padding.iter().any(|&byte| byte != 0) {
            return Err(RecordError::NotMinimumPadded);
        }
        Ok(MinimumPaddedRecord { record, padding })
    }

    fn decode_fields<'a>(
        &self,
        row: &'a [u8],
        descriptors: ByteDescriptors,
    ) -> Result<(PhysicalRecord<'a>, &'a [u8]), RecordError> {
        let Some((&[lo, hi, flags], mut rest)) = row.split_first_chunk::<3>() else {
            return Err(RecordError::TruncatedHeader);
        };
        let length = u16::from_le_bytes([lo, hi]);
        if usize::from(length) != row.len() {
            return Err(RecordError::Length {
                stored: length,
                actual: row.len(),
            });
        }
        let extra = if flags & 0x40 != 0 {
            let Some((&extra, tail)) = rest.split_first() else {
                return Err(RecordError::TruncatedHeader);
            };
            rest = tail;
            Some(extra)
        } else {
            None
        };
        let (bitmap, mut rest) =
            rest.split_at_checked(self.bitmap_bytes)
                .ok_or(RecordError::TruncatedBitmap {
                    needed: self.bitmap_bytes,
                    available: rest.len(),
                })?;
        let mut nullable_index = 0;
        let mut fields = Vec::with_capacity(self.columns.len());
        for column in &self.columns {
            if column.nullable {
                let present = bitmap[nullable_index / 8] & (0x80 >> (nullable_index % 8)) != 0;
                nullable_index += 1;
                if !present {
                    fields.push(PhysicalValue::Null);
                    continue;
                }
            }
            fields.push(decode_value(&mut rest, column, descriptors)?);
        }
        let record = PhysicalRecord {
            flags,
            extra,
            bitmap,
            fields,
        };
        Ok((record, rest))
    }
}

/// A complete typed field walk and its zero padding within a nine-byte slot.
#[derive(Debug, PartialEq, Eq)]
pub struct MinimumPaddedRecord<'a> {
    /// Fields decoded using the entire caller-selected layout.
    pub record: PhysicalRecord<'a>,
    /// Exact unused suffix borrowed from the original record.
    pub padding: &'a [u8],
}

/// A physical record after an exact field walk with one specific schema.
#[derive(Debug, PartialEq, Eq)]
pub struct PhysicalRecord<'a> {
    /// Stored record flags.
    pub flags: u8,
    /// Uninterpreted extra byte when flags have the 0x40 bit.
    pub extra: Option<u8>,
    /// Raw MSB-first presence bitmap for nullable columns only.
    pub bitmap: &'a [u8],
    /// One value for each column in `RecordLayout::columns()`.
    pub fields: Vec<PhysicalValue<'a>>,
}

/// Value read from the physical row. Byte strings retain their domain so
/// text/binary distinctions survive without assuming a database encoding.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PhysicalValue<'a> {
    /// Nullable column whose presence bit was clear.
    Null,
    /// Little-endian signed 16-bit integer.
    SmallInt(i16),
    /// Little-endian unsigned 16-bit integer.
    UnsignedSmallInt(u16),
    /// Little-endian signed 32-bit integer.
    Integer(i32),
    /// Unsigned one-byte integer (domain 19, width one).
    TinyInt(u8),
    /// Little-endian unsigned 32-bit integer.
    UnsignedInteger(u32),
    /// Little-endian signed 64-bit integer.
    BigInt(i64),
    /// Little-endian unsigned 64-bit integer.
    UnsignedBigInt(u64),
    /// Exact IEEE-754 bits; preserves NaN payloads and signed zero.
    FloatBits(u32),
    /// Exact IEEE-754 bits of a double.
    DoubleBits(u64),
    /// Stored byte in a bit column.
    Bit(u8),
    /// Stored minutes since the SQL Anywhere epoch of 1600-02-29.
    DateMinutes(u32),
    /// Physical pair shared by observed domains 13 and 14. A field's domain
    /// is retained separately from its on-disk representation.
    MinuteMicros {
        /// Original catalog domain.
        domain: u16,
        /// Stored minute counter.
        minutes: u32,
        /// Sub-minute component from the second u32.
        microseconds: u32,
    },
    /// An exact, base-100 numeric in its original scale and sign.
    Numeric(PhysicalNumeric<'a>),
    /// Inline string or binary bytes (including a present, empty value).
    InlineBytes {
        /// Raw domain identifier.
        domain: u16,
        /// Exact payload bytes.
        bytes: &'a [u8],
    },
    /// Long value with a prefix stored locally and a reference to further bytes.
    OutOfRow(LongDescriptor<'a>),
    /// Encoded byte stream with a separately recorded decoded byte length.
    CompressedBytes(CompressedDescriptor<'a>),
}

/// A supported compressed descriptor; lengths have distinct units.
#[derive(Debug, PartialEq, Eq)]
pub struct CompressedDescriptor<'a> {
    /// Reference to encoded storage. Its prefix belongs to the decoded value;
    /// its total length bounds the encoded stream, not that decoded value.
    pub storage: LongDescriptor<'a>,
    /// Exact decoded byte length, stored after the ordinary locator fields.
    pub logical_len: u32,
}

/// Signed base-100 value whose digits are stored least significant first.
#[derive(Debug, PartialEq, Eq)]
pub struct PhysicalNumeric<'a> {
    /// Raw sign/exponent byte. Bit 7 set means positive; exponent is low seven bits minus 64.
    pub control: u8,
    /// Base-100 digits, range 0..99, in on-disk order.
    pub digits: &'a [u8],
}

impl fmt::Display for PhysicalNumeric<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write;
        let mut digits = self.digits.iter().rev().copied().skip_while(|&d| d == 0);
        let Some(first) = digits.next() else {
            return f.write_str("0");
        };
        let mut decimal = first.to_string();
        for digit in digits {
            write!(decimal, "{digit:02}")?;
        }
        if self.control & 0x80 == 0 {
            f.write_str("-")?;
        }
        let exponent = i16::from(self.control & 0x7F) - 64;
        if exponent >= 0 {
            return write!(f, "{decimal}{}", "0".repeat(exponent as usize * 2));
        }
        let places = (-exponent) as usize * 2;
        if decimal.len() <= places {
            write!(f, "0.{}{decimal}", "0".repeat(places - decimal.len()))
        } else {
            let (integer, fraction) = decimal.split_at(decimal.len() - places);
            write!(f, "{integer}.{fraction}")
        }
    }
}

/// A long-value reference. Its existence alone does not establish that a
/// referenced chunk or the value's complete contents have been recovered.
#[derive(Debug, PartialEq, Eq)]
pub struct LongDescriptor<'a> {
    /// Raw string/binary domain identifier.
    pub domain: u16,
    /// Raw descriptor marker. Explicit stored-byte decoding also recognizes
    /// extended raw domains and compressed wrappers; catalog domain 31 has
    /// its separate 0x80 locator interpretation.
    pub tag: u8,
    /// In-row prefix (may be empty).
    pub prefix: &'a [u8],
    /// Stored byte length advertised by the descriptor. For domain 31 this
    /// bounds the serialized RLE bytes, rather than the dense logical output.
    pub total_len: u32,
    /// Physical page referenced for the first chunk.
    pub first_page: u32,
    /// Unidentified descriptor word before the slot.
    pub unknown: u16,
    /// Slot on the first referenced page.
    pub slot: u16,
}

/// Why a physical column layout or row did not produce an exact field walk.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordError {
    /// The caller supplied no physical columns.
    #[error("a physical record layout requires at least one column")]
    EmptyLayout,
    /// Physical column IDs must be distinct and contiguous, starting at one.
    #[error("expected physical column ID {expected}, found {found}")]
    ColumnOrder {
        /// Expected next physical ID.
        expected: usize,
        /// Supplied catalog ID.
        found: u32,
    },
    /// A complete-catalog layout still requires positive, unique IDs.
    #[error("physical column ID {column} is zero or duplicated")]
    ColumnIdentity {
        /// Invalid ordinal.
        column: u32,
    },
    /// The selected layout contains an unrecognized physical domain.
    #[error("column {column} has unsupported domain {domain}")]
    UnsupportedDomain {
        /// Column ID.
        column: u32,
        /// Stored domain ID.
        domain: u16,
    },
    /// Domain 19 was declared with a width other than the observed one byte.
    #[error("column {column} has unsupported width {width} for domain {domain}")]
    UnsupportedWidth {
        /// Column ID.
        column: u32,
        /// Stored domain ID.
        domain: u16,
        /// Width stated by the catalog.
        width: u32,
    },
    /// The fixed header or the flags-dependent extra byte is incomplete.
    #[error("incomplete physical row header")]
    TruncatedHeader,
    /// The stored length differs from the supplied byte range.
    #[error("physical row length is {actual} bytes, stored length is {stored}")]
    Length {
        /// Length word in the row.
        stored: u16,
        /// Number of bytes supplied.
        actual: usize,
    },
    /// The row ends inside the layout's nullable-column bitmap.
    #[error("null bitmap needs {needed} bytes, only {available} remain")]
    TruncatedBitmap {
        /// Bitmap size required for this layout.
        needed: usize,
        /// Bytes after the header.
        available: usize,
    },
    /// The row ends inside a column or its descriptor.
    #[error("column {column} needs {needed} bytes, only {available} remain")]
    TruncatedValue {
        /// Column ID.
        column: u32,
        /// Bytes needed for this part of the field.
        needed: usize,
        /// Remaining bytes in the record.
        available: usize,
    },
    /// A numeric digit lies outside the base-100 range.
    #[error("column {column} contains invalid base-100 digit {digit}")]
    NumericDigit {
        /// Column ID.
        column: u32,
        /// Invalid digit byte.
        digit: u8,
    },
    /// An indirect value has an unrecognized descriptor header.
    #[error("column {column} has a long descriptor with marker {marker:#04x}")]
    DescriptorMarker {
        /// Column ID.
        column: u32,
        /// First byte of the descriptor.
        marker: u8,
    },
    /// An indirect value's declared total omits part of the stored prefix.
    #[error("column {column} has a long descriptor shorter than its in-row prefix")]
    DescriptorLength {
        /// Column ID.
        column: u32,
    },
    /// Domain 31's indirect descriptor form is recognized on catalog pages,
    /// but its inline value representation has not been established.
    #[error("column {column} has unrecognized domain-31 inline marker {marker:#04x}")]
    Domain31Inline {
        /// Column ID.
        column: u32,
        /// First byte of the value.
        marker: u8,
    },
    /// The selected column layout consumed fewer bytes than the stored record length.
    #[error("{count} bytes remain after the selected column layout")]
    TrailingBytes {
        /// Remaining bytes.
        count: usize,
    },
    /// The row lacks the required nine-byte allocation, zero flags, or
    /// nonempty all-zero suffix for [`RecordLayout::decode_minimum_padded`].
    #[error("expected a nine-byte flags-zero record with a nonempty zero suffix")]
    NotMinimumPadded,
}

fn take<'a>(rest: &mut &'a [u8], size: usize, column: u32) -> Result<&'a [u8], RecordError> {
    let (value, tail) = rest
        .split_at_checked(size)
        .ok_or(RecordError::TruncatedValue {
            column,
            needed: size,
            available: rest.len(),
        })?;
    *rest = tail;
    Ok(value)
}

fn take_array<const N: usize>(rest: &mut &[u8], column: u32) -> Result<[u8; N], RecordError> {
    let Some((value, tail)) = rest.split_first_chunk::<N>() else {
        return Err(RecordError::TruncatedValue {
            column,
            needed: N,
            available: rest.len(),
        });
    };
    *rest = tail;
    Ok(*value)
}

fn decode_value<'a>(
    rest: &mut &'a [u8],
    c: &RecordColumn,
    descriptors: ByteDescriptors,
) -> Result<PhysicalValue<'a>, RecordError> {
    let id = c.column_id;
    Ok(match c.domain_id {
        1 => PhysicalValue::SmallInt(i16::from_le_bytes(take_array(rest, id)?)),
        22 => PhysicalValue::UnsignedSmallInt(u16::from_le_bytes(take_array(rest, id)?)),
        2 => PhysicalValue::Integer(i32::from_le_bytes(take_array(rest, id)?)),
        19 => PhysicalValue::TinyInt(take_array::<1>(rest, id)?[0]),
        21 => PhysicalValue::UnsignedInteger(u32::from_le_bytes(take_array(rest, id)?)),
        20 => PhysicalValue::BigInt(i64::from_le_bytes(take_array(rest, id)?)),
        23 => PhysicalValue::UnsignedBigInt(u64::from_le_bytes(take_array(rest, id)?)),
        4 => PhysicalValue::FloatBits(u32::from_le_bytes(take_array(rest, id)?)),
        5 => PhysicalValue::DoubleBits(u64::from_le_bytes(take_array(rest, id)?)),
        24 => PhysicalValue::Bit(take_array::<1>(rest, id)?[0]),
        6 => PhysicalValue::DateMinutes(u32::from_le_bytes(take_array(rest, id)?)),
        13 | 14 => PhysicalValue::MinuteMicros {
            domain: c.domain_id,
            minutes: u32::from_le_bytes(take_array(rest, id)?),
            microseconds: u32::from_le_bytes(take_array(rest, id)?),
        },
        3 | 27 => {
            let [count, control] = take_array(rest, id)?;
            let digits = take(rest, usize::from(count), id)?;
            if let Some(&digit) = digits.iter().find(|&&d| d > 99) {
                return Err(RecordError::NumericDigit { column: id, digit });
            }
            PhysicalValue::Numeric(PhysicalNumeric { control, digits })
        }
        7..=12 | 28 | 31 => {
            let marker = take_array::<1>(rest, id)?[0];
            if c.domain_id == 31
                && descriptors != ByteDescriptors::Stored
                && !(0x80..0xff).contains(&marker)
            {
                return Err(RecordError::Domain31Inline { column: id, marker });
            }
            let length = if marker == 0xff {
                usize::from(u16::from_be_bytes(take_array(rest, id)?))
            } else if marker < 0x80 {
                usize::from(marker)
            } else {
                let prefix = take(rest, usize::from(marker & 0x7f), id)?;
                let [tag] = take_array(rest, id)?;
                let stored = descriptors == ByteDescriptors::Stored
                    && matches!(c.domain_id, 9 | 10 | 12 | 28);
                let compressed = stored && matches!(tag, 0x40 | 0xc0);
                if tag != 0
                    && !compressed
                    && !(tag == 0x80
                        && (c.domain_id == 31
                            || stored
                            || descriptors == ByteDescriptors::Linked
                                && matches!(c.domain_id, 9 | 12)))
                {
                    return Err(RecordError::DescriptorMarker {
                        column: id,
                        marker: tag,
                    });
                }
                let total_len = u32::from_le_bytes(take_array(rest, id)?);
                if !compressed && c.domain_id != 31 && (total_len as usize) < prefix.len() {
                    return Err(RecordError::DescriptorLength { column: id });
                }
                let storage = LongDescriptor {
                    domain: c.domain_id,
                    tag,
                    prefix,
                    total_len,
                    first_page: u32::from_le_bytes(take_array(rest, id)?),
                    unknown: u16::from_le_bytes(take_array(rest, id)?),
                    slot: u16::from_le_bytes(take_array(rest, id)?),
                };
                return if compressed {
                    let logical_len = u32::from_le_bytes(take_array(rest, id)?);
                    if logical_len == 0 || (logical_len as usize) < prefix.len() || total_len == 0 {
                        return Err(RecordError::DescriptorLength { column: id });
                    }
                    Ok(PhysicalValue::CompressedBytes(CompressedDescriptor {
                        storage,
                        logical_len,
                    }))
                } else {
                    Ok(PhysicalValue::OutOfRow(storage))
                };
            };
            PhysicalValue::InlineBytes {
                domain: c.domain_id,
                bytes: take(rest, length, id)?,
            }
        }
        domain => return Err(RecordError::UnsupportedDomain { column: id, domain }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_byte_columns_preserve_exact_indirect_descriptors_and_following_fields() {
        for domain_id in [9, 28] {
            for prefix in [&b""[..], &b"abcdefgh"[..]] {
                let layout = RecordLayout::new(vec![
                    RecordColumn {
                        column_id: 1,
                        domain_id: 2,
                        width: 4,
                        nullable: false,
                    },
                    RecordColumn {
                        column_id: 2,
                        domain_id,
                        width: 64,
                        nullable: true,
                    },
                    RecordColumn {
                        column_id: 3,
                        domain_id: 2,
                        width: 4,
                        nullable: false,
                    },
                ])
                .unwrap();
                let mut body = vec![0, 0x80];
                body.extend_from_slice(&7i32.to_le_bytes());
                body.push(0x80 + prefix.len() as u8);
                body.extend_from_slice(prefix);
                body.push(0);
                body.extend_from_slice(&16u32.to_le_bytes());
                body.extend_from_slice(&17u32.to_le_bytes());
                body.extend_from_slice(&0u16.to_le_bytes());
                body.extend_from_slice(&3u16.to_le_bytes());
                body.extend_from_slice(&(-1234567i32).to_le_bytes());
                let mut raw = ((body.len() + 2) as u16).to_le_bytes().to_vec();
                raw.extend_from_slice(&body);
                for record in [
                    layout.decode(&raw),
                    layout.decode_linked_bytes(&raw),
                    layout.decode_stored_bytes(&raw),
                ] {
                    let record = record.unwrap();
                    assert_eq!(
                        record.fields,
                        [
                            PhysicalValue::Integer(7),
                            PhysicalValue::OutOfRow(LongDescriptor {
                                domain: domain_id,
                                tag: 0,
                                prefix,
                                total_len: 16,
                                first_page: 17,
                                unknown: 0,
                                slot: 3
                            }),
                            PhysicalValue::Integer(-1234567)
                        ]
                    );
                }
            }
        }
    }

    #[test]
    fn extended_inline_lengths_apply_to_short_and_wide_byte_columns() {
        for domain_id in [8, 9, 11, 28] {
            for width in [255, 1024] {
                let layout = RecordLayout::new(vec![
                    RecordColumn {
                        column_id: 1,
                        domain_id: 2,
                        width: 4,
                        nullable: false,
                    },
                    RecordColumn {
                        column_id: 2,
                        domain_id,
                        width,
                        nullable: true,
                    },
                    RecordColumn {
                        column_id: 3,
                        domain_id: 2,
                        width: 4,
                        nullable: false,
                    },
                ])
                .unwrap();
                for length in [128u16, 129, 254, 255] {
                    let payload: Vec<_> = (0..length).map(|i| (i as u8).wrapping_mul(17)).collect();
                    let mut body = vec![0, 0x80];
                    body.extend_from_slice(&7i32.to_le_bytes());
                    body.push(0xff);
                    body.extend_from_slice(&length.to_be_bytes());
                    body.extend_from_slice(&payload);
                    body.extend_from_slice(&(-1234567i32).to_le_bytes());
                    let mut raw = ((body.len() + 2) as u16).to_le_bytes().to_vec();
                    raw.extend_from_slice(&body);
                    for record in [
                        layout.decode(&raw),
                        layout.decode_linked_bytes(&raw),
                        layout.decode_stored_bytes(&raw),
                    ] {
                        let record = record.unwrap();
                        assert_eq!(
                            record.fields,
                            [
                                PhysicalValue::Integer(7),
                                PhysicalValue::InlineBytes {
                                    domain: domain_id,
                                    bytes: &payload
                                },
                                PhysicalValue::Integer(-1234567)
                            ]
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn null_only_domains_consume_presence_bits_and_refuse_present_values() {
        for domain in [32, 36] {
            let layout = RecordLayout::new(vec![
                RecordColumn {
                    column_id: 1,
                    domain_id: domain,
                    width: 4096,
                    nullable: true,
                },
                RecordColumn {
                    column_id: 2,
                    domain_id: 21,
                    width: 4,
                    nullable: false,
                },
            ])
            .unwrap();
            let absent = [8, 0, 0, 0, 23, 0, 0, 0];
            assert_eq!(
                layout.decode(&absent).unwrap().fields,
                vec![PhysicalValue::Null, PhysicalValue::UnsignedInteger(23)]
            );
            let present = [8, 0, 0, 0x80, 23, 0, 0, 0];
            assert!(matches!(layout.decode(&present),
                Err(RecordError::UnsupportedDomain { column: 1, domain: d }) if d == domain));
            let required = RecordLayout::new(vec![RecordColumn {
                column_id: 1,
                domain_id: domain,
                width: 4096,
                nullable: false,
            }])
            .unwrap();
            assert!(matches!(required.decode(&[3, 0, 0]),
                Err(RecordError::UnsupportedDomain { column: 1, domain: d }) if d == domain));
        }
    }

    #[test]
    fn complete_catalog_constructor_checks_identity_and_walks_sorted_current_columns() {
        let first = RecordColumn {
            column_id: 1,
            domain_id: 19,
            width: 1,
            nullable: false,
        };
        let fourth = RecordColumn {
            column_id: 4,
            domain_id: 21,
            width: 4,
            nullable: true,
        };
        assert!(matches!(
            RecordLayout::new(vec![first, fourth]),
            Err(RecordError::ColumnOrder { .. })
        ));
        let layout = RecordLayout::from_complete_catalog(vec![fourth, first]).unwrap();
        assert_eq!(
            layout
                .decode(&[9, 0, 0, 0x80, 7, 23, 0, 0, 0])
                .unwrap()
                .fields,
            [
                PhysicalValue::TinyInt(7),
                PhysicalValue::UnsignedInteger(23)
            ]
        );
        assert!(matches!(
            RecordLayout::from_complete_catalog(vec![fourth, fourth]),
            Err(RecordError::ColumnIdentity { column: 4 })
        ));
        assert!(matches!(
            RecordLayout::from_complete_catalog(vec![RecordColumn {
                column_id: 0,
                ..first
            }]),
            Err(RecordError::ColumnIdentity { column: 0 })
        ));
    }

    fn column(id: u32, domain: u16, width: u32, nullable: bool) -> RecordColumn {
        RecordColumn {
            column_id: id,
            domain_id: domain,
            width,
            nullable,
        }
    }

    fn record(flags: u8, data: &[u8]) -> Vec<u8> {
        let mut row = ((3 + data.len()) as u16).to_le_bytes().to_vec();
        row.push(flags);
        row.extend_from_slice(data);
        row
    }

    #[test]
    fn nullable_column_order_bitmap_and_flags_are_exact() {
        let mut cols: Vec<_> = (1..=9).map(|id| column(id, 24, 1, true)).collect();
        cols.push(column(10, 1, 2, false));
        cols.reverse();
        let layout = RecordLayout::new(cols).unwrap();
        // First, third and ninth nullable fields are present; the NOT NULL field has no bit.
        let input = record(0x40, &[0x41, 0b1010_0000, 0b1000_0000, 1, 0, 1, 0xfe, 0xff]);
        let rec = layout.decode(&input).unwrap();
        assert_eq!(rec.flags, 0x40);
        assert_eq!(rec.extra, Some(0x41));
        assert_eq!(rec.bitmap, [0xA0, 0x80]);
        assert_eq!(
            rec.fields,
            [
                PhysicalValue::Bit(1),
                PhysicalValue::Null,
                PhysicalValue::Bit(0),
                PhysicalValue::Null,
                PhysicalValue::Null,
                PhysicalValue::Null,
                PhysicalValue::Null,
                PhysicalValue::Null,
                PhysicalValue::Bit(1),
                PhysicalValue::SmallInt(-2)
            ]
        );
    }

    #[test]
    fn minimum_allocation_preserves_fixed_width_zero_bytes() {
        let layout = RecordLayout::new(vec![column(1, 2, 4, false)]).unwrap();
        let raw = [9, 0, 0, 42, 0, 0, 0, 0, 0];
        assert_eq!(
            layout.decode(&raw),
            Err(RecordError::TrailingBytes { count: 2 })
        );
        let decoded = layout.decode_minimum_padded(&raw).unwrap();
        assert_eq!(decoded.record.fields, [PhysicalValue::Integer(42)]);
        assert_eq!(decoded.padding, &raw[7..]);
        assert!(std::ptr::eq(decoded.padding, &raw[7..]));
        let mut alternate = raw;
        alternate[2] = 8;
        assert_eq!(
            layout.decode_minimum_padded(&alternate),
            Err(RecordError::NotMinimumPadded)
        );
        let decoded = layout.decode_minimum_padded_live(&alternate).unwrap();
        assert_eq!(decoded.record.flags, 8);
        assert_eq!(decoded.record.fields, [PhysicalValue::Integer(42)]);
        assert_eq!(decoded.padding, [0, 0]);
        for flag in [1, 4, 9, 32, 0x40, 0x48] {
            alternate[2] = flag;
            assert_eq!(
                layout.decode_minimum_padded_live(&alternate),
                Err(RecordError::NotMinimumPadded)
            );
        }
    }

    #[test]
    fn minimum_allocation_walks_nullable_and_variable_fields_before_padding() {
        let layout = RecordLayout::new(vec![
            column(1, 19, 1, false),
            column(2, 9, 12, true),
            column(3, 2, 4, true),
        ])
        .unwrap();
        let raw = [9, 0, 0, 0x80, 0, 1, b'X', 0, 0];
        let decoded = layout.decode_minimum_padded(&raw).unwrap();
        assert_eq!(decoded.record.bitmap, &[0x80]);
        assert_eq!(
            decoded.record.fields,
            [
                PhysicalValue::TinyInt(0),
                PhysicalValue::InlineBytes {
                    domain: 9,
                    bytes: b"X"
                },
                PhysicalValue::Null,
            ]
        );
        assert_eq!(decoded.padding, &raw[7..]);

        let empty = [9, 0, 0, 0x80, 0, 0, 0, 0, 0];
        let decoded = layout.decode_minimum_padded(&empty).unwrap();
        assert_eq!(
            decoded.record.fields[1],
            PhysicalValue::InlineBytes {
                domain: 9,
                bytes: b""
            }
        );
        assert_eq!(decoded.padding, &empty[6..]);

        let nulls = [9, 0, 0, 0, 0, 0, 0, 0, 0];
        let decoded = layout.decode_minimum_padded(&nulls).unwrap();
        assert_eq!(
            decoded.record.fields[1..],
            [PhysicalValue::Null, PhysicalValue::Null]
        );
        assert_eq!(decoded.padding, &nulls[5..]);
    }

    #[test]
    fn minimum_allocation_rejects_other_record_shapes() {
        let layout = RecordLayout::new(vec![column(1, 9, 12, false)]).unwrap();
        // Exact nine-byte row, with field bytes that end in zeros.
        let exact = [9, 0, 0, 5, b'a', 0, 0, 0, 0];
        assert!(layout.decode(&exact).is_ok());
        assert_eq!(
            layout.decode_minimum_padded(&exact),
            Err(RecordError::NotMinimumPadded)
        );
        for flag in [0x01, 0x04, 0x40, 0x80] {
            let nonordinary = [9, 0, flag, 1, b'a', 0, 0, 0, 0];
            assert_eq!(
                layout.decode_minimum_padded(&nonordinary),
                Err(RecordError::NotMinimumPadded)
            );
        }
        for raw in [
            &[][..],                             // no bytes for a deleted slot
            &[8, 0, 0, 1, b'a', 0, 0, 0],        // shorter allocation
            &[10, 0, 0, 1, b'a', 0, 0, 0, 0, 0], // larger allocation
            &[9, 0, 0, 1, b'a', 0, 0xff, 0, 0],  // nonzero suffix byte
        ] {
            assert_eq!(
                layout.decode_minimum_padded(raw),
                Err(RecordError::NotMinimumPadded)
            );
        }
        assert!(matches!(
            layout.decode_minimum_padded(&[8, 0, 0, 1, b'a', 0, 0, 0, 0]),
            Err(RecordError::Length {
                stored: 8,
                actual: 9
            })
        ));
        assert!(matches!(
            layout.decode_minimum_padded(&[9, 0, 0, 6, b'a', 0, 0, 0, 0]),
            Err(RecordError::TruncatedValue {
                column: 1,
                needed: 6,
                available: 5
            })
        ));

        let numeric = RecordLayout::new(vec![column(1, 3, 12, false)]).unwrap();
        assert!(matches!(
            numeric.decode_minimum_padded(&[9, 0, 0, 1, 0x40, 100, 0, 0, 0]),
            Err(RecordError::NumericDigit {
                column: 1,
                digit: 100
            })
        ));
    }

    #[test]
    fn numeric_is_an_exact_decimal_with_original_sign_exponent_and_digits() {
        let layout = RecordLayout::new(vec![column(1, 3, 12, false)]).unwrap();
        for (encoded, want) in [
            (&[2, 0xc0, 8, 2][..], "208"),
            (&[1, 0xc1, 3], "300"),
            (&[2, 0xbf, 47, 75], "75.47"),
            (&[2, 0x3d, 40, 0], "-0.000040"),
            (&[0, 0xc0], "0"),
            (&[2, 0xc0, 0, 1], "100"),
        ] {
            let input = record(0, encoded);
            let parsed = layout.decode(&input).unwrap();
            let PhysicalValue::Numeric(n) = &parsed.fields[0] else {
                panic!()
            };
            assert_eq!(n.to_string(), want);
            assert_eq!(n.control, encoded[1]);
            assert_eq!(n.digits, &encoded[2..]);
        }
        assert!(matches!(
            layout.decode(&record(0, &[1, 0x40, 100])),
            Err(RecordError::NumericDigit {
                column: 1,
                digit: 100
            })
        ));
    }

    #[test]
    fn numeric_sign_and_scale_preserve_encoded_digits() {
        // NUMERIC(38,12) sign and scale controls,
        // and CRC/directory-checked physical frames; no generated encoder.
        for (control, digits, expected) in [
            (0x81, &[][..], "0"),
            (0xc0, &[1], "1"),
            (0x40, &[1], "-1"),
            (0xbf, &[25, 1], "1.25"),
            (0x3f, &[25, 1], "-1.25"),
            (0xbf, &[47, 75], "75.47"),
            (0x3f, &[50, 1], "-1.50"),
            (0xbf, &[1], "0.01"),
            (0xbe, &[1], "0.0001"),
            (0xbd, &[1], "0.000001"),
            (0x3a, &[1], "-0.000000000001"),
        ] {
            assert_eq!(PhysicalNumeric { control, digits }.to_string(), expected);
        }
    }

    #[test]
    fn distinguishes_long_short_inline_and_indirect_values_without_transcoding() {
        let layout = RecordLayout::new(vec![
            column(1, 7, 255, false),
            column(2, 10, 4096, false),
            column(3, 28, 4096, false),
        ])
        .unwrap();
        // Short byte columns also use the extended escape at 128 bytes.
        let mut data = vec![0xff, 0, 0x80];
        data.extend([0xff; 128]);
        data.extend([0xff, 0, 2, 0x81, 0xf3]); // wide field: big-endian length
        data.extend([
            0x82, 0xff, 0xc0, 0, 7, 0, 0, 0, 114, 0, 0, 0, 0x34, 0x12, 2, 0,
        ]);
        let input = record(0, &data);
        assert_eq!(
            layout.decode(&input).unwrap().fields,
            [
                PhysicalValue::InlineBytes {
                    domain: 7,
                    bytes: &[0xff; 128]
                },
                PhysicalValue::InlineBytes {
                    domain: 10,
                    bytes: &[0x81, 0xf3]
                },
                PhysicalValue::OutOfRow(LongDescriptor {
                    domain: 28,
                    tag: 0,
                    prefix: &[0xff, 0xc0],
                    total_len: 7,
                    first_page: 114,
                    unknown: 0x1234,
                    slot: 2
                })
            ]
        );
        let layout = RecordLayout::new(vec![column(1, 11, 1024, true)]).unwrap();
        let input = record(0, &[0x80, 0]);
        assert_eq!(
            layout.decode(&input).unwrap().fields,
            [PhysicalValue::InlineBytes {
                domain: 11,
                bytes: &[]
            }]
        );
        let input = record(0, &[0]);
        assert_eq!(layout.decode(&input).unwrap().fields, [PhysicalValue::Null]);
    }

    #[test]
    fn stored_byte_descriptors_keep_both_lengths_and_the_following_field() {
        let prefix = [b'Z'; 32];
        for domain in [9, 10, 12, 28] {
            let layout = RecordLayout::new(vec![
                column(1, domain, 32767, false),
                column(2, 2, 4, false),
            ])
            .unwrap();
            for tag in [0x40, 0xc0] {
                let mut body = vec![0xa0];
                body.extend(prefix);
                body.push(tag);
                body.extend(24u32.to_le_bytes());
                body.extend(17u32.to_le_bytes());
                body.extend(0u16.to_le_bytes());
                body.extend(3u16.to_le_bytes());
                body.extend(1000u32.to_le_bytes());
                body.extend((-1234567i32).to_le_bytes());
                let bytes = record(0, &body);
                assert!(matches!(
                    layout.decode(&bytes),
                    Err(RecordError::DescriptorMarker { .. })
                ));
                assert!(matches!(
                    layout.decode_linked_bytes(&bytes),
                    Err(RecordError::DescriptorMarker { .. })
                ));
                assert_eq!(
                    layout.decode_stored_bytes(&bytes).unwrap().fields,
                    [
                        PhysicalValue::CompressedBytes(CompressedDescriptor {
                            storage: LongDescriptor {
                                domain,
                                tag,
                                prefix: &prefix,
                                total_len: 24,
                                first_page: 17,
                                unknown: 0,
                                slot: 3
                            },
                            logical_len: 1000,
                        }),
                        PhysicalValue::Integer(-1234567),
                    ]
                );
                for logical in [0u32, 31] {
                    let mut invalid = body.clone();
                    invalid[46..50].copy_from_slice(&logical.to_le_bytes());
                    assert!(layout.decode_stored_bytes(&record(0, &invalid)).is_err());
                }
                let mut short = body;
                short.truncate(49);
                assert!(layout.decode_stored_bytes(&record(0, &short)).is_err());
            }
        }
    }

    #[test]
    fn stored_byte_support_does_not_expand_earlier_decoder_policies() {
        let body = [0x80, 0x80, 6, 0, 0, 0, 17, 0, 0, 0, 0, 0, 3, 0];
        for domain in [10, 28] {
            let layout = RecordLayout::new(vec![column(1, domain, 32767, false)]).unwrap();
            let bytes = record(0, &body);
            assert!(layout.decode(&bytes).is_err());
            assert!(layout.decode_linked_bytes(&bytes).is_err());
            assert!(matches!(
                layout.decode_stored_bytes(&bytes).unwrap().fields[0],
                PhysicalValue::OutOfRow(_)
            ));
        }
        for domain in [7, 8, 11, 31] {
            let layout = RecordLayout::new(vec![column(1, domain, 32767, false)]).unwrap();
            let mut invalid = body.to_vec();
            invalid[1] = 0x40;
            invalid.extend(6u32.to_le_bytes());
            assert!(layout.decode_stored_bytes(&record(0, &invalid)).is_err());
        }
    }

    #[test]
    fn linked_byte_descriptors_require_explicit_domain_specific_opt_in() {
        // Prefix + tag + logical length + page + auxiliary word + slot.
        let data = [0x82, b'a', b'b', 0x80, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 7, 0];
        let input = record(0, &data);
        for domain in [9, 12] {
            let layout = RecordLayout::new(vec![column(1, domain, 32767, false)]).unwrap();
            assert!(matches!(
                layout.decode(&input),
                Err(RecordError::DescriptorMarker { marker: 0x80, .. })
            ));
            assert_eq!(
                layout.decode_linked_bytes(&input).unwrap().fields,
                [PhysicalValue::OutOfRow(LongDescriptor {
                    domain,
                    tag: 0x80,
                    prefix: b"ab",
                    total_len: 6,
                    first_page: 1,
                    unknown: 0,
                    slot: 7
                })]
            );
            let mut compressed = input.clone();
            compressed[6] = 0xc0;
            assert!(matches!(
                layout.decode_linked_bytes(&compressed),
                Err(RecordError::DescriptorMarker { marker: 0xc0, .. })
            ));
            let mut extra = input.clone();
            extra.push(0);
            let len = extra.len() as u16;
            extra[..2].copy_from_slice(&len.to_le_bytes());
            assert_eq!(
                layout.decode_linked_bytes(&extra),
                Err(RecordError::TrailingBytes { count: 1 })
            );
        }
        for domain in [10, 28] {
            let layout = RecordLayout::new(vec![column(1, domain, 32767, false)]).unwrap();
            assert!(matches!(
                layout.decode_linked_bytes(&input),
                Err(RecordError::DescriptorMarker { marker: 0x80, .. })
            ));
        }
    }

    #[test]
    fn fixed_width_types_preserve_numeric_bits_and_date_parts() {
        let domains = [1, 22, 2, 19, 21, 20, 23, 4, 5, 6, 14];
        let layout = RecordLayout::new(
            domains
                .into_iter()
                .enumerate()
                .map(|(i, d)| column(i as u32 + 1, d, u32::from(d == 19), false))
                .collect(),
        )
        .unwrap();
        let mut body = Vec::new();
        body.extend((-347i16).to_le_bytes());
        body.extend(65530u16.to_le_bytes());
        body.extend((-723i32).to_le_bytes());
        body.push(0x91);
        body.extend(129u32.to_le_bytes());
        body.extend((-8124i64).to_le_bytes());
        body.extend((u64::MAX - 3).to_le_bytes());
        body.extend(0x80000000u32.to_le_bytes());
        body.extend(0x7ff8000000000023u64.to_le_bytes());
        body.extend(1440u32.to_le_bytes());
        body.extend(50_000u32.to_le_bytes());
        body.extend(59_999_999u32.to_le_bytes());
        let input = record(0, &body);
        assert_eq!(
            layout.decode(&input).unwrap().fields,
            [
                PhysicalValue::SmallInt(-347),
                PhysicalValue::UnsignedSmallInt(65530),
                PhysicalValue::Integer(-723),
                PhysicalValue::TinyInt(0x91),
                PhysicalValue::UnsignedInteger(129),
                PhysicalValue::BigInt(-8124),
                PhysicalValue::UnsignedBigInt(u64::MAX - 3),
                PhysicalValue::FloatBits(0x80000000),
                PhysicalValue::DoubleBits(0x7ff8000000000023),
                PhysicalValue::DateMinutes(1440),
                PhysicalValue::MinuteMicros {
                    domain: 14,
                    minutes: 50_000,
                    microseconds: 59_999_999
                }
            ]
        );
    }

    #[test]
    fn domain31_only_accepts_null_and_observed_descriptor_forms() {
        let layout = RecordLayout::new(vec![column(1, 31, 0, true)]).unwrap();
        let empty = record(0, &[0]);
        assert_eq!(layout.decode(&empty).unwrap().fields, [PhysicalValue::Null]);
        let input = record(
            0,
            &[0x80, 0x81, 0xa6, 0x80, 0, 0, 0, 0, 82, 0, 0, 0, 5, 0, 1, 0],
        );
        let decoded = layout.decode(&input).unwrap();
        assert_eq!(
            decoded.fields,
            [PhysicalValue::OutOfRow(LongDescriptor {
                domain: 31,
                tag: 0x80,
                prefix: &[0xa6],
                total_len: 0,
                first_page: 82,
                unknown: 5,
                slot: 1,
            })]
        );
        for marker in [0, 0x7f, 0xff] {
            assert_eq!(
                layout.decode(&record(0, &[0x80, marker])).unwrap_err(),
                RecordError::Domain31Inline { column: 1, marker }
            );
        }
    }

    #[test]
    fn explicit_stored_policy_preserves_inline_bitset_storage_and_following_field() {
        let layout =
            RecordLayout::new(vec![column(1, 31, 32767, false), column(2, 2, 4, false)]).unwrap();
        for encoded in [vec![0; 4], vec![0xa6; 128]] {
            let mut body = if encoded.len() < 128 {
                vec![encoded.len() as u8]
            } else {
                vec![0xff, 0, 128]
            };
            body.extend_from_slice(&encoded);
            body.extend_from_slice(&(-1234567i32).to_le_bytes());
            let bytes = record(0, &body);
            assert_eq!(
                layout.decode_stored_bytes(&bytes).unwrap().fields,
                [
                    PhysicalValue::InlineBytes {
                        domain: 31,
                        bytes: &encoded
                    },
                    PhysicalValue::Integer(-1234567)
                ]
            );
            assert!(matches!(
                layout.decode(&bytes),
                Err(RecordError::Domain31Inline { .. })
            ));
            assert!(matches!(
                layout.decode_linked_bytes(&bytes),
                Err(RecordError::Domain31Inline { .. })
            ));
        }
    }

    #[test]
    fn rejects_incomplete_or_conflicting_layouts_and_rows() {
        assert!(matches!(
            RecordLayout::new(vec![column(1, 19, 4, false)]),
            Err(RecordError::UnsupportedWidth {
                domain: 19,
                width: 4,
                ..
            })
        ));
        for ids in [vec![], vec![2], vec![1, 3], vec![1, 1]] {
            assert!(
                RecordLayout::new(ids.into_iter().map(|i| column(i, 24, 1, false)).collect())
                    .is_err()
            );
        }
        assert!(matches!(
            RecordLayout::new(vec![column(1, 30, 0, true)]),
            Err(RecordError::UnsupportedDomain { domain: 30, .. })
        ));
        let layout = RecordLayout::new(vec![column(1, 2, 4, true)]).unwrap();
        assert!(matches!(
            layout.decode(&[3, 0, 0x40]),
            Err(RecordError::TruncatedHeader)
        ));
        assert!(matches!(
            layout.decode(&[9, 0, 0]),
            Err(RecordError::Length { .. })
        ));
        assert!(matches!(
            layout.decode(&record(0, &[])),
            Err(RecordError::TruncatedBitmap { .. })
        ));
        assert!(matches!(
            layout.decode(&record(0, &[0x80, 1])),
            Err(RecordError::TruncatedValue { column: 1, .. })
        ));
        assert!(matches!(
            layout.decode(&record(0, &[0, 1])),
            Err(RecordError::TrailingBytes { count: 1 })
        ));
        let long = RecordLayout::new(vec![column(1, 11, 1000, false)]).unwrap();
        assert!(matches!(
            long.decode(&record(0, &[0xff, 1, 0, 0])),
            Err(RecordError::TruncatedValue { needed: 256, .. })
        ));
        assert!(matches!(
            long.decode(&record(0, &[0x80, 2])),
            Err(RecordError::DescriptorMarker { marker: 2, .. })
        ));
        assert!(matches!(
            long.decode(&record(0, &[0x81, 42, 0, 0, 0, 0, 0])),
            Err(RecordError::DescriptorLength { .. })
        ));
    }
}
