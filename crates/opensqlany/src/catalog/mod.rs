//! Physical ISYSTAB and ISYSTABCOL catalog records.
//!
//! Inline definitions supply table and column identities. Schema history
//! selects catalog-attested layouts; recovery checks sparse records against
//! a fixed first-pass context. Page maps and chunk witnesses establish where
//! additional definitions may be read. None of these alone establishes that
//! an occupied physical slot is a current SQL row.
//!
//! See `SPECIFICATION.md` section 8.2 and the
//! [record-layout observations](https://github.com/Sigilweaver/OpenQBW/issues/22).

pub(crate) mod bootstrap;
pub(crate) mod columns;
pub(crate) mod recovery;
pub(crate) mod schema_history;
pub(crate) mod witness;

/// One recognizable physical catalog definition. Older definitions can coexist
/// with current ones. The page and slot remain the caller's provenance.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CatalogFragment<'a> {
    /// An inline table definition from an owner-1 page.
    Table {
        /// Catalog table identifier.
        table_id: u32,
        /// Inline identifier in the record.
        name: &'a str,
    },
    /// An inline column definition from an owner-2 page.
    Column {
        /// Table to which the column belongs.
        table_id: u32,
        /// Physical column number.
        column_id: u32,
        /// Raw SQL Anywhere domain identifier.
        domain_id: u16,
        /// Whether the record explicitly declares the column nullable.
        nullable: bool,
        /// Declared column width.
        width: u32,
        /// Declared scale.
        scale: u16,
        /// Object identifier in this physical definition.
        object_id: u64,
        /// Inline identifier in the record.
        name: &'a str,
    },
}

fn inline_identifier(bytes: &[u8], offset: usize) -> Option<&str> {
    let len = usize::from(*bytes.get(offset)?);
    if !(1..128).contains(&len) {
        return None;
    }
    let name = bytes.get(offset + 1..offset + 1 + len)?;
    // Keep only the observed single-byte identifier subset. Other encodings
    // and indirect values need the catalog's declared charset / blob chain.
    if !name
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b"_$#@".contains(&b))
    {
        return None;
    }
    std::str::from_utf8(name).ok()
}

impl<'a> CatalogFragment<'a> {
    /// Recognize an inline catalog definition from a whole, length-delimited
    /// physical row. Unsupported owners, blob pages, indirect names and
    /// unrecognized layouts return `None`.
    pub fn parse(owner_id: u32, page_kind: u8, bytes: &'a [u8]) -> Option<Self> {
        if !(1..=4).contains(&page_kind)
            || usize::from(u16::from_le_bytes(*bytes.first_chunk()?)) != bytes.len()
        {
            return None;
        }
        let flags = *bytes.get(2)?;
        // Offsets in the layout include a length word, a flags byte and the
        // bitmap. Shift the field view by one if an extra header byte exists.
        let fields = &bytes[usize::from(flags & 0x40 != 0)..];
        let table_id = u32::from_le_bytes(fields.get(4..8)?.try_into().ok()?);
        match owner_id {
            1 => Some(Self::Table {
                table_id,
                name: inline_identifier(fields, 54)?,
            }),
            2 => {
                let nullable = match fields.get(14..16)? {
                    b"\x01Y" => true,
                    b"\x01N" => false,
                    _ => return None,
                };
                Some(Self::Column {
                    table_id,
                    column_id: u32::from_le_bytes(fields.get(8..12)?.try_into().ok()?),
                    domain_id: u16::from_le_bytes(fields.get(12..14)?.try_into().ok()?),
                    nullable,
                    width: u32::from_le_bytes(fields.get(16..20)?.try_into().ok()?),
                    scale: u16::from_le_bytes(fields.get(20..22)?.try_into().ok()?),
                    object_id: u64::from_le_bytes(fields.get(22..30)?.try_into().ok()?),
                    name: inline_identifier(fields, 38)?,
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_flag_byte_keeps_column_fields_aligned() {
        let mut row = vec![0; 44];
        row[0] = 44;
        row[2] = 0x40;
        row[3] = 0x99;
        row[5] = 24;
        row[9] = 6;
        row[13] = 3;
        row[15..17].copy_from_slice(b"\x01Y");
        row[17] = 19;
        row[21] = 2;
        row[23] = 101;
        row[39..44].copy_from_slice(b"\x04cost");
        assert_eq!(
            CatalogFragment::parse(2, 3, &row),
            Some(CatalogFragment::Column {
                table_id: 24,
                column_id: 6,
                domain_id: 3,
                nullable: true,
                width: 19,
                scale: 2,
                object_id: 101,
                name: "cost",
            })
        );
        assert!(CatalogFragment::parse(2, 0x11, &row).is_none());
        row[16] = b'?';
        assert!(CatalogFragment::parse(2, 3, &row).is_none());
    }

    #[test]
    fn rejects_truncation_and_indirect_names() {
        let mut row = vec![0; 59];
        row[0] = 59;
        row[4] = 7;
        row[54..].copy_from_slice(b"\x04demo");
        assert_eq!(
            CatalogFragment::parse(1, 4, &row),
            Some(CatalogFragment::Table {
                table_id: 7,
                name: "demo"
            })
        );
        assert!(CatalogFragment::parse(1, 4, &row[..58]).is_none());
        row[54] = 0x81;
        assert!(CatalogFragment::parse(1, 4, &row).is_none());
    }
}
