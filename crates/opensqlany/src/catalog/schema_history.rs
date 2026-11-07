//! Select physical QBW row layouts using their catalog-declared versions.
//! The complete ISYSTAB and ISYSTABCOL records identify a table's current
//! version and each observed column's introduction version. These are
//! physical candidates; catalog coverage and row liveness remain separate.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CatalogFragment, PhysicalRecord, PhysicalValue, RecordColumn, RecordError, RecordLayout,
};

#[derive(Debug, Default)]
enum Evidence<T> {
    #[default]
    Missing,
    One(T),
    Conflicting,
    Unreadable,
}

impl<T: PartialEq> Evidence<T> {
    fn observe(&mut self, value: T) {
        match self {
            Self::Missing => *self = Self::One(value),
            Self::One(existing) if *existing != value => *self = Self::Conflicting,
            _ => {}
        }
    }

    fn unique(&self) -> Option<&T> {
        if let Self::One(value) = self {
            Some(value)
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq)]
struct ColumnIdentity {
    column: RecordColumn,
    name: String,
    scale: u16,
    object_id: u64,
}

#[derive(Debug, Default)]
struct ColumnObservation {
    identity: Evidence<ColumnIdentity>,
    start: Evidence<u32>,
}

#[derive(Debug, Default)]
struct OwnerObservation {
    name: Evidence<String>,
    current: Evidence<u32>,
    columns: BTreeMap<u32, ColumnObservation>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LayoutScope {
    Contiguous,
    CurrentOnly,
    CompleteCatalog,
}

/// Evidence collected in two passes over recovered physical catalog records.
/// First collect the definitions. Then decode each recognized record with the
/// complete observed layout of its catalog and record its version field.
/// Unreadable duplicates and conflicting observations prevent selection.
#[derive(Debug, Default)]
pub struct CatalogSchemaVersions {
    owners: BTreeMap<u32, OwnerObservation>,
}

impl CatalogSchemaVersions {
    /// Collect an inline table or column definition from the catalog pass.
    pub fn observe_definition(&mut self, fragment: &CatalogFragment<'_>) {
        match fragment {
            CatalogFragment::Table { table_id, name } => {
                self.owners
                    .entry(*table_id)
                    .or_default()
                    .name
                    .observe((*name).to_owned());
            }
            CatalogFragment::Column {
                table_id,
                column_id,
                name,
                domain_id,
                nullable,
                width,
                scale,
                object_id,
            } => {
                let column = self
                    .owners
                    .entry(*table_id)
                    .or_default()
                    .columns
                    .entry(*column_id)
                    .or_default();
                column.identity.observe(ColumnIdentity {
                    column: RecordColumn {
                        column_id: *column_id,
                        nullable: *nullable,
                        domain_id: *domain_id,
                        width: *width,
                    },
                    name: (*name).to_owned(),
                    scale: *scale,
                    object_id: *object_id,
                });
            }
        }
    }

    /// Every owner for which a table or column definition was seen.
    pub fn owners(&self) -> impl Iterator<Item = u32> + '_ {
        self.owners.keys().copied()
    }

    /// Locate a uniquely named column in the observed catalog. Conflicting
    /// definitions or duplicate names leave the lookup unresolved.
    pub fn column_by_name(&self, owner: u32, name: &str) -> Option<RecordColumn> {
        let mut found = None;
        for observation in self.owners.get(&owner)?.columns.values() {
            let identity = observation.identity.unique()?;
            if identity.name.eq_ignore_ascii_case(name) {
                if found.is_some() {
                    return None;
                }
                found = Some(identity.column);
            }
        }
        found
    }

    /// Build the full observed column layout, rejecting conflicts and gaps.
    /// This bootstraps decoding the two catalog tables. A contiguous prefix
    /// on its own cannot prove that the last catalog column was recovered.
    pub fn full_layout(&self, owner: u32) -> Result<RecordLayout, SchemaHistoryError> {
        Ok(RecordLayout::new(self.observed_columns(owner)?)?)
    }

    fn observed_columns(&self, owner: u32) -> Result<Vec<RecordColumn>, SchemaHistoryError> {
        let observation = self
            .owners
            .get(&owner)
            .ok_or(SchemaHistoryError::MissingOwner(owner))?;
        observation
            .columns
            .iter()
            .map(|(&id, observation)| {
                observation
                    .identity
                    .unique()
                    .map(|c| c.column)
                    .ok_or(SchemaHistoryError::ColumnConflict { owner, column: id })
            })
            .collect()
    }

    /// Check for unique, unsigned 32-bit `current_schema` and `start_schema`
    /// field definitions in the two observed catalog schemas.
    pub fn version_sources(&self) -> Result<(), SchemaHistoryError> {
        self.source_ordinal(1)?;
        self.source_ordinal(2)?;
        Ok(())
    }

    fn source_ordinal(&self, catalog: u32) -> Result<usize, SchemaHistoryError> {
        let name = if catalog == 1 {
            "current_schema"
        } else {
            "start_schema"
        };
        let mut ordinal = None;
        if let Some(owner) = self.owners.get(&catalog) {
            for (&id, c) in &owner.columns {
                let definition = c
                    .identity
                    .unique()
                    .ok_or(SchemaHistoryError::ColumnConflict {
                        owner: catalog,
                        column: id,
                    })?;
                if definition.name == name {
                    if ordinal.is_some()
                        || definition.column.domain_id != 21
                        || definition.column.width != 4
                    {
                        return Err(SchemaHistoryError::VersionSource {
                            catalog,
                            field: name,
                        });
                    }
                    ordinal = id.checked_sub(1).map(|v| v as usize);
                }
            }
        }
        ordinal.ok_or(SchemaHistoryError::VersionSource {
            catalog,
            field: name,
        })
    }

    /// Collect the version for an inline definition from the *same* decoded
    /// catalog row. Pass `None` if that recognized row could not be decoded;
    /// that owner/column then remains unresolved even if a duplicate decodes.
    pub fn observe_version(
        &mut self,
        fragment: &CatalogFragment<'_>,
        decoded: Option<&PhysicalRecord<'_>>,
    ) -> Result<(), SchemaHistoryError> {
        let (catalog, owner, column) = match fragment {
            CatalogFragment::Table { table_id, .. } => (1, *table_id, None),
            CatalogFragment::Column {
                table_id,
                column_id,
                ..
            } => (2, *table_id, Some(*column_id)),
        };
        self.observe_definition(fragment);
        let result = self.source_ordinal(catalog).and_then(|ordinal| {
            let record = decoded.ok_or(SchemaHistoryError::UnreadableVersion { owner,column })?;
            if !matches!(record.fields.first(), Some(PhysicalValue::UnsignedInteger(id)) if *id == owner)
                || column.is_some_and(|col| !matches!(record.fields.get(1), Some(PhysicalValue::UnsignedInteger(id)) if *id == col))
            {
                return Err(SchemaHistoryError::CatalogIdentity { owner,column });
            }
            match record.fields.get(ordinal) {
                Some(PhysicalValue::UnsignedInteger(version)) => Ok(*version),
                _ => Err(SchemaHistoryError::UnreadableVersion { owner,column }),
            }
        });
        let obs = self.owners.entry(owner).or_default();
        let evidence = match column {
            Some(id) => &mut obs.columns.entry(id).or_default().start,
            None => &mut obs.current,
        };
        match result {
            Ok(v) => {
                evidence.observe(v);
                if evidence.unique().is_none() {
                    Err(SchemaHistoryError::UnresolvedVersion { owner, column })
                } else {
                    Ok(())
                }
            }
            Err(err) => {
                *evidence = Evidence::Unreadable;
                Err(err)
            }
        }
    }

    /// Build the variants named by this owner's recovered metadata. A layout
    /// exists only at an observed column introduction or at the current
    /// version. Every such column sequence must have contiguous ordinals.
    pub fn history(&self, owner: u32) -> Result<SchemaHistory, SchemaHistoryError> {
        self.version_sources()?;
        let full = self.full_layout(owner)?;
        self.build_history(owner, full, LayoutScope::Contiguous)
    }

    /// Read the current epoch after every physical column definition has been
    /// independently accounted for. Gaps in current ordinals are allowed.
    /// Earlier epochs remain unattested through this entry point.
    pub fn current_from_complete_catalog(
        &self,
        owner: u32,
    ) -> Result<SchemaHistory, SchemaHistoryError> {
        self.version_sources()?;
        let full = RecordLayout::from_complete_catalog(self.observed_columns(owner)?)?;
        self.build_history(owner, full, LayoutScope::CurrentOnly)
    }

    /// Build observed introduction epochs after every current physical column
    /// definition has been independently accounted for. A column drop can remove
    /// the field and reset stored epochs; remaining column IDs
    /// need not be contiguous. Gaps do not introduce placeholder fields.
    /// Unknown epochs and conflicting or unreadable metadata remain errors.
    pub fn history_from_complete_catalog(
        &self,
        owner: u32,
    ) -> Result<SchemaHistory, SchemaHistoryError> {
        self.version_sources()?;
        let full = RecordLayout::from_complete_catalog(self.observed_columns(owner)?)?;
        self.build_history(owner, full, LayoutScope::CompleteCatalog)
    }

    fn build_history(
        &self,
        owner: u32,
        full: RecordLayout,
        scope: LayoutScope,
    ) -> Result<SchemaHistory, SchemaHistoryError> {
        let observation = &self.owners[&owner];
        if observation.name.unique().is_none() {
            return Err(SchemaHistoryError::UnresolvedTable(owner));
        }
        let current =
            *observation
                .current
                .unique()
                .ok_or(SchemaHistoryError::UnresolvedVersion {
                    owner,
                    column: None,
                })?;
        if current > u32::from(u8::MAX) {
            return Err(SchemaHistoryError::VersionWidth { owner, current });
        }
        let mut introductions = Vec::with_capacity(full.columns().len());
        let mut epochs = BTreeSet::from([current]);
        for column in full.columns() {
            let id = column.column_id;
            let start = *observation.columns[&id].start.unique().ok_or(
                SchemaHistoryError::UnresolvedVersion {
                    owner,
                    column: Some(id),
                },
            )?;
            if start > current {
                return Err(SchemaHistoryError::StartAfterCurrent {
                    owner,
                    column: id,
                    start,
                    current,
                });
            }
            introductions.push((start, *column));
            epochs.insert(start);
        }
        if scope == LayoutScope::CurrentOnly {
            return Ok(SchemaHistory {
                current,
                layouts: BTreeMap::from([(current, full)]),
            });
        }
        let mut layouts = BTreeMap::new();
        for epoch in epochs {
            let columns = introductions
                .iter()
                .filter(|(s, _)| *s <= epoch)
                .map(|(_, c)| *c)
                .collect();
            let layout = if scope == LayoutScope::CompleteCatalog {
                RecordLayout::from_complete_catalog(columns)?
            } else {
                RecordLayout::new(columns)?
            };
            layouts.insert(epoch, layout);
        }
        Ok(SchemaHistory { current, layouts })
    }
}

/// Physical layouts attested by a table's observed catalog history.
#[derive(Debug, Clone)]
pub struct SchemaHistory {
    current: u32,
    layouts: BTreeMap<u32, RecordLayout>,
}

impl SchemaHistory {
    /// Current schema version declared by the complete observed table record.
    pub fn current_schema(&self) -> u32 {
        self.current
    }

    /// Look up the exact catalog-declared epoch. Intermediate unobserved
    /// epochs are unresolved, even if a nearby layout looks plausible.
    pub fn layout_for(&self, version: u32) -> Result<&RecordLayout, SchemaHistoryError> {
        self.layouts
            .get(&version)
            .ok_or(SchemaHistoryError::UnattestedVersion {
                version,
                current: self.current,
            })
    }

    /// Read the row's own version and decode only that layout. With bit 0x40
    /// clear the version is zero; set, the following byte carries its version.
    pub fn decode<'a>(&self, bytes: &'a [u8]) -> Result<PhysicalRecord<'a>, SchemaHistoryError> {
        let flags = bytes.get(2).ok_or(RecordError::TruncatedHeader)?;
        let version = if flags & 0x40 != 0 {
            u32::from(*bytes.get(3).ok_or(RecordError::TruncatedHeader)?)
        } else {
            0
        };
        Ok(self.layout_for(version)?.decode(bytes)?)
    }

    /// Select the recorded epoch, then recognize the verified high-tag
    /// byte-chain descriptor family without changing catalog bootstrap.
    pub fn decode_linked_bytes<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<PhysicalRecord<'a>, SchemaHistoryError> {
        let flags = bytes.get(2).ok_or(RecordError::TruncatedHeader)?;
        let version = if flags & 0x40 != 0 {
            u32::from(*bytes.get(3).ok_or(RecordError::TruncatedHeader)?)
        } else {
            0
        };
        Ok(self.layout_for(version)?.decode_linked_bytes(bytes)?)
    }

    /// Select the exact recorded epoch and explicitly recognize supported
    /// raw and compressed byte-stream descriptors. Resolution, complete column
    /// accounting and visible-row selection remain caller responsibilities.
    pub fn decode_stored_bytes<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<PhysicalRecord<'a>, SchemaHistoryError> {
        let flags = bytes.get(2).ok_or(RecordError::TruncatedHeader)?;
        let version = if flags & 0x40 != 0 {
            u32::from(*bytes.get(3).ok_or(RecordError::TruncatedHeader)?)
        } else {
            0
        };
        Ok(self.layout_for(version)?.decode_stored_bytes(bytes)?)
    }
}

/// Why a catalog version or a version-selected record remains unresolved.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchemaHistoryError {
    /// No physical definitions were encountered for this owner.
    #[error("no catalog definition for owner {0}")]
    MissingOwner(u32),
    /// Physical table definitions were absent or conflicting.
    #[error("owner {0} lacks one unambiguous table definition")]
    UnresolvedTable(u32),
    /// Two physical definitions of the column have different metadata.
    #[error("conflicting physical definitions for owner {owner} column {column}")]
    ColumnConflict {
        /// Table owner.
        owner: u32,
        /// Column ordinal.
        column: u32,
    },
    /// The catalog's version field was missing, conflicting, or had the wrong domain.
    #[error("catalog owner {catalog} lacks one unsigned u32 {field} field")]
    VersionSource {
        /// Catalog owner.
        catalog: u32,
        /// Required field name.
        field: &'static str,
    },
    /// A recognized catalog row did not yield a readable physical version.
    #[error("unreadable catalog version for owner {owner}, column {column:?}")]
    UnreadableVersion {
        /// Data table owner.
        owner: u32,
        /// Column ordinal, or None for the table definition.
        column: Option<u32>,
    },
    /// The catalog fragment and decoded row refer to different objects.
    #[error("decoded catalog row does not match owner {owner}, column {column:?}")]
    CatalogIdentity {
        /// Data table owner.
        owner: u32,
        /// Column ordinal for column metadata.
        column: Option<u32>,
    },
    /// Version evidence is missing, unreadable, or contradictory.
    #[error("missing or conflicting version for owner {owner}, column {column:?}")]
    UnresolvedVersion {
        /// Data table owner.
        owner: u32,
        /// Column ordinal, or None for the current version.
        column: Option<u32>,
    },
    /// The on-disk extra-byte convention cannot cover the complete version range.
    #[error("owner {owner} current version {current} exceeds the observed one-byte range")]
    VersionWidth {
        /// Data table owner.
        owner: u32,
        /// Declared current schema.
        current: u32,
    },
    /// One column appears to have been introduced after the table's current version.
    #[error("owner {owner} column {column} starts at {start} after current version {current}")]
    StartAfterCurrent {
        /// Data table owner.
        owner: u32,
        /// Column ordinal.
        column: u32,
        /// Column introduction version.
        start: u32,
        /// Declared current schema.
        current: u32,
    },
    /// No recovered layout attests the requested row version.
    #[error("no attested layout for row version {version}; current schema is {current}")]
    UnattestedVersion {
        /// Requested version.
        version: u32,
        /// Declared current schema.
        current: u32,
    },
    /// The declared layout or the selected row's field walk is invalid.
    #[error(transparent)]
    Record(#[from] RecordError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: u32 = 42;

    fn col(
        table: u32,
        id: u32,
        name: &'static str,
        domain: u16,
        width: u32,
        nullable: bool,
    ) -> CatalogFragment<'static> {
        CatalogFragment::Column {
            table_id: table,
            column_id: id,
            name,
            domain_id: domain,
            width,
            nullable,
            scale: 0,
            object_id: u64::from(table) * 100 + u64::from(id),
        }
    }

    fn table() -> CatalogFragment<'static> {
        CatalogFragment::Table {
            table_id: OWNER,
            name: "example",
        }
    }

    fn record(flags: u8, data: &[u8]) -> Vec<u8> {
        let mut row = ((data.len() + 3) as u16).to_le_bytes().to_vec();
        row.push(flags);
        row.extend_from_slice(data);
        row
    }

    fn catalog() -> CatalogSchemaVersions {
        let mut evidence = CatalogSchemaVersions::default();
        for f in [
            col(1, 1, "table_id", 21, 4, false),
            col(1, 2, "current_schema", 21, 4, false),
            col(2, 1, "table_id", 21, 4, false),
            col(2, 2, "column_id", 21, 4, false),
            col(2, 3, "start_schema", 21, 4, false),
            table(),
            col(OWNER, 1, "first", 19, 1, true),
            col(OWNER, 2, "appended", 19, 1, true),
        ] {
            evidence.observe_definition(&f);
        }
        evidence
    }

    fn observe(
        evidence: &mut CatalogSchemaVersions,
        f: &CatalogFragment<'_>,
        args: &[u32],
    ) -> Result<(), SchemaHistoryError> {
        let source = if matches!(f, CatalogFragment::Table { .. }) {
            1
        } else {
            2
        };
        let layout = evidence.full_layout(source).unwrap();
        let data: Vec<_> = args.iter().flat_map(|v| v.to_le_bytes()).collect();
        let bytes = record(0, &data);
        let row = layout.decode(&bytes)?;
        evidence.observe_version(f, Some(&row))
    }

    fn versioned() -> CatalogSchemaVersions {
        let mut c = catalog();
        observe(&mut c, &table(), &[OWNER, 2]).unwrap();
        observe(&mut c, &col(OWNER, 1, "first", 19, 1, true), &[OWNER, 1, 0]).unwrap();
        observe(
            &mut c,
            &col(OWNER, 2, "appended", 19, 1, true),
            &[OWNER, 2, 2],
        )
        .unwrap();
        c
    }

    #[test]
    fn complete_catalog_history_uses_observed_epochs_without_gap_placeholders() {
        let mut catalog = versioned();
        let owner = catalog.owners.get_mut(&OWNER).unwrap();
        let mut column = owner.columns.remove(&2).unwrap();
        if let Evidence::One(identity) = &mut column.identity {
            identity.column.column_id = 4;
        }
        owner.columns.insert(4, column);
        let history = catalog.history_from_complete_catalog(OWNER).unwrap();
        assert_eq!(history.layout_for(0).unwrap().columns().len(), 1);
        assert_eq!(history.layout_for(2).unwrap().columns()[1].column_id, 4);
        assert_eq!(
            history.decode(&record(0, &[0])).unwrap().fields,
            [PhysicalValue::Null]
        );
        assert_eq!(
            history.decode(&record(0x40, &[2, 0])).unwrap().fields.len(),
            2
        );
        assert!(matches!(
            history.decode(&record(0x40, &[1, 0])),
            Err(SchemaHistoryError::UnattestedVersion { version: 1, .. })
        ));
        catalog
            .owners
            .get_mut(&OWNER)
            .unwrap()
            .columns
            .get_mut(&4)
            .unwrap()
            .start = Evidence::Unreadable;
        assert!(matches!(
            catalog.history_from_complete_catalog(OWNER),
            Err(SchemaHistoryError::UnresolvedVersion {
                column: Some(4),
                ..
            })
        ));
    }

    #[test]
    fn complete_current_catalog_can_keep_ordinal_gaps_without_inventing_history() {
        let mut catalog = versioned();
        let owner = catalog.owners.get_mut(&OWNER).unwrap();
        let mut column = owner.columns.remove(&2).unwrap();
        if let Evidence::One(identity) = &mut column.identity {
            identity.column.column_id = 4;
        }
        owner.columns.insert(4, column);
        assert!(matches!(
            catalog.history(OWNER),
            Err(SchemaHistoryError::Record(RecordError::ColumnOrder { .. }))
        ));
        let history = catalog.current_from_complete_catalog(OWNER).unwrap();
        assert_eq!(
            history
                .layout_for(2)
                .unwrap()
                .columns()
                .iter()
                .map(|c| c.column_id)
                .collect::<Vec<_>>(),
            [1, 4]
        );
        assert!(history.decode(&record(0x40, &[2, 0])).is_ok());
        assert!(matches!(
            history.decode(&record(0, &[0])),
            Err(SchemaHistoryError::UnattestedVersion { version: 0, .. })
        ));
        catalog
            .owners
            .get_mut(&OWNER)
            .unwrap()
            .columns
            .get_mut(&4)
            .unwrap()
            .start = Evidence::Unreadable;
        assert!(matches!(
            catalog.current_from_complete_catalog(OWNER),
            Err(SchemaHistoryError::UnresolvedVersion {
                column: Some(4),
                ..
            })
        ));
    }

    #[test]
    fn header_selects_exactly_one_catalog_epoch_even_if_both_walks_would_fit() {
        let history = versioned().history(OWNER).unwrap();
        assert_eq!(history.current_schema(), 2);
        let old = record(0, &[0]);
        let new = record(0x40, &[2, 0]);
        // Both bitmaps occupy a byte. The old record has no second field; its
        // absence is different from a NULL in that field in the newer layout.
        assert_eq!(
            history
                .layout_for(2)
                .unwrap()
                .decode(&old)
                .unwrap()
                .fields
                .len(),
            2
        );
        assert_eq!(
            history
                .layout_for(0)
                .unwrap()
                .decode(&new)
                .unwrap()
                .fields
                .len(),
            1
        );
        assert_eq!(history.decode(&old).unwrap().fields, [PhysicalValue::Null]);
        assert_eq!(
            history.decode(&new).unwrap().fields,
            [PhysicalValue::Null, PhysicalValue::Null]
        );
        let mismatch = record(0x40, &[2, 0x40]);
        assert!(history.layout_for(0).unwrap().decode(&mismatch).is_ok());
        assert!(matches!(
            history.decode(&mismatch),
            Err(SchemaHistoryError::Record(RecordError::TruncatedValue {
                column: 2,
                ..
            }))
        ));
        for version in [1, 3, 200] {
            assert!(matches!(
                history.decode(&record(0x40, &[version, 0])),
                Err(SchemaHistoryError::UnattestedVersion { .. })
            ));
        }
        assert!(matches!(
            history.decode(&[3, 0, 0x40]),
            Err(SchemaHistoryError::Record(RecordError::TruncatedHeader))
        ));
    }

    #[test]
    fn linked_byte_opt_in_preserves_the_recorded_epoch_and_full_field_walk() {
        let first = crate::RecordColumn {
            column_id: 1,
            domain_id: 9,
            width: 32767,
            nullable: false,
        };
        let added = crate::RecordColumn {
            column_id: 2,
            domain_id: 19,
            width: 1,
            nullable: false,
        };
        let history = SchemaHistory {
            current: 2,
            layouts: BTreeMap::from([
                (0, RecordLayout::new(vec![first]).unwrap()),
                (2, RecordLayout::new(vec![first, added]).unwrap()),
            ]),
        };
        let descriptor = [0x80, 0x80, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 7, 0];
        let old = record(0, &descriptor);
        let mut current = vec![2];
        current.extend(descriptor);
        current.push(42);
        let current = record(0x40, &current);
        assert_eq!(history.decode_linked_bytes(&old).unwrap().fields.len(), 1);
        let fields = history.decode_linked_bytes(&current).unwrap().fields;
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1], PhysicalValue::TinyInt(42));
        assert!(matches!(
            history.decode(&old),
            Err(SchemaHistoryError::Record(
                RecordError::DescriptorMarker { .. }
            ))
        ));
        let mut unknown = current.clone();
        unknown[3] = 1;
        assert!(matches!(
            history.decode_linked_bytes(&unknown),
            Err(SchemaHistoryError::UnattestedVersion { version: 1, .. })
        ));
        let missing = record(0x40, &[&[2][..], &descriptor].concat());
        assert!(matches!(
            history.decode_linked_bytes(&missing),
            Err(SchemaHistoryError::Record(RecordError::TruncatedValue {
                column: 2,
                ..
            }))
        ));
    }

    #[test]
    fn unresolved_duplicate_or_conflicting_identity_cannot_be_overwritten() {
        let mut c = versioned();
        let f = col(OWNER, 1, "first", 19, 1, true);
        assert!(matches!(
            observe(&mut c, &f, &[OWNER, 1, 1]),
            Err(SchemaHistoryError::UnresolvedVersion {
                owner: OWNER,
                column: Some(1)
            })
        ));
        assert!(observe(&mut c, &f, &[OWNER, 1, 0]).is_err());
        assert!(matches!(
            c.history(OWNER),
            Err(SchemaHistoryError::UnresolvedVersion { .. })
        ));
        let mut c = versioned();
        assert!(matches!(
            c.observe_version(&table(), None),
            Err(SchemaHistoryError::UnreadableVersion { .. })
        ));
        assert!(observe(&mut c, &table(), &[OWNER, 2]).is_err());
        let mut c = versioned();
        assert!(matches!(
            observe(&mut c, &f, &[OWNER + 1, 1, 0]),
            Err(SchemaHistoryError::CatalogIdentity { .. })
        ));
        assert!(c.history(OWNER).is_err());
    }

    #[test]
    fn an_unavailable_source_or_noncontiguous_version_rejects_the_history() {
        let mut c = CatalogSchemaVersions::default();
        c.observe_definition(&col(1, 1, "current_schema", 21, 4, false));
        assert!(matches!(
            c.version_sources(),
            Err(SchemaHistoryError::VersionSource { catalog: 2, .. })
        ));
        c.observe_definition(&col(2, 2, "start_schema", 19, 1, false));
        assert!(c.version_sources().is_err());

        let mut c = catalog();
        observe(&mut c, &table(), &[OWNER, 2]).unwrap();
        observe(&mut c, &col(OWNER, 1, "first", 19, 1, true), &[OWNER, 1, 2]).unwrap();
        observe(
            &mut c,
            &col(OWNER, 2, "appended", 19, 1, true),
            &[OWNER, 2, 0],
        )
        .unwrap();
        assert!(matches!(
            c.history(OWNER),
            Err(SchemaHistoryError::Record(RecordError::ColumnOrder {
                expected: 1,
                found: 2
            }))
        ));
        let mut c = catalog();
        observe(&mut c, &table(), &[OWNER, 2]).unwrap();
        observe(&mut c, &col(OWNER, 1, "first", 19, 1, true), &[OWNER, 1, 3]).unwrap();
        assert!(matches!(
            c.history(OWNER),
            Err(SchemaHistoryError::StartAfterCurrent {
                start: 3,
                current: 2,
                ..
            })
        ));
    }
}
