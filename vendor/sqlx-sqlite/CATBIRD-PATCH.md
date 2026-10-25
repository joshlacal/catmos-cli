# SQLx SQLite compatibility patch

Baseline: sqlx-sqlite 0.9.0 from https://crates.io/api/v1/crates/sqlx-sqlite/0.9.0/download.
Archive SHA-256: `488e99c397a62007e4229aec669a179816339afc6d2620ca6fa420dbee2e982c`.

The sole initial patch widens libsqlite3-sys >=0.30.1,<0.38.0 to >=0.30.1,<0.40.0 so this client and its shared MLS provider link one SQLCipher library through rusqlite 0.41 / libsqlite3-sys 0.39.1. Source and query behavior are retained; successful resolution alone does not validate the FFI boundary. The dependency refresh report records compile, migration, query and copied-store checks. Remove the patch when upstream accepts this library family.
