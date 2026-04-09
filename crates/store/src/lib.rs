use anyhow::{Context, Result};
use collector_core::CoreWriteResult;
use collector_limit::Decision;
use collector_meta::CrashMetadata;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[cfg(feature = "sqlite")]
use rusqlite::{Connection, params};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashRecord {
    pub schema_version: u32,
    pub metadata: CrashMetadata,
    pub core: Option<CoreWriteResult>,
    pub rate_limit: Decision,
    pub dump: DumpRecord,
    pub telemetry: TelemetryRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpRecord {
    pub stored: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetryRecord {
    pub stage_ms: Vec<(String, u64)>,
}

pub fn append_json_line(path: &Path, record: &CrashRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create json parent dir")?;
    }

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;

    f.lock_exclusive().context("lock jsonl file")?;
    let payload = format!(
        "{}\n",
        serde_json::to_string(record).context("serialize crash record")?
    );
    let write_result = f.write_all(payload.as_bytes()).context("write json line");
    let unlock_result = f.unlock().context("unlock jsonl file");
    write_result?;
    unlock_result?;
    Ok(())
}

#[cfg(feature = "sqlite")]
pub fn insert_sqlite(path: &Path, record: &CrashRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create sqlite parent dir")?;
    }

    let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
    ensure_schema(&conn).context("ensure sqlite schema")?;

    let payload = serde_json::to_string(record).context("serialize crash record")?;
    let metadata = &record.metadata;
    let core_location = record.core.as_ref().map(|c| c.location.as_str());
    let core_size = record.core.as_ref().map(|c| c.uncompressed_bytes as i64);
    let stored = record.core.is_some() as i64;
    let allowed = record.rate_limit.allowed as i64;

    conn.execute(
        "INSERT INTO crash_records (
            captured_at,
            pid,
            tid,
            ns_pid,
            pid_initial_ns,
            tid_initial_ns,
            comm,
            signal,
            si_code,
            uid,
            gid,
            cpu_num,
            thread_name,
            hostname,
            cmdline,
            runtime,
            arch,
            uname,
            kernel_version,
            cwd,
            root_dir,
            coredump_filter,
            rlimit_core,
            binary_name,
            binary_path,
            binary_build_id,
            uptime_ms,
            cgroup_name,
            binary_removed,
            dumpable,
            package_version,
            core_stored,
            core_location,
            core_size,
            dump_stored,
            dump_reason,
            rate_limit_allowed,
            rate_limit_reason,
            payload_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39)",
        params![
            metadata.captured_at.to_rfc3339(),
            metadata.pid,
            metadata.tid,
            metadata.ns_pid,
            metadata.pid_initial_ns,
            metadata.tid_initial_ns,
            metadata.comm,
            metadata.signal,
            metadata.si_code,
            metadata.uid.map(i64::from),
            metadata.gid.map(i64::from),
            metadata.cpu_num.map(i64::from),
            metadata.thread_name,
            metadata.hostname,
            metadata.cmdline,
            metadata.runtime,
            metadata.arch,
            metadata.uname,
            metadata.kernel_version,
            metadata.cwd,
            metadata.root_dir,
            metadata.coredump_filter,
            metadata.rlimit_core,
            metadata.binary_name,
            metadata.binary_path,
            metadata.binary_build_id,
            metadata.uptime_ms.map(|v| v as i64),
            metadata.cgroup,
            metadata.binary_removed.map(|v| v as i64),
            metadata.dumpable.map(|v| v as i64),
            metadata.package_version,
            stored,
            core_location,
            core_size,
            record.dump.stored as i64,
            &record.dump.reason,
            allowed,
            &record.rate_limit.reason,
            payload,
        ],
    )
    .context("insert sqlite crash record")?;

    Ok(())
}

#[cfg(feature = "sqlite")]
fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS crash_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            captured_at TEXT NOT NULL,
            pid INTEGER NOT NULL,
            tid INTEGER,
            ns_pid INTEGER,
            pid_initial_ns INTEGER,
            tid_initial_ns INTEGER,
            comm TEXT,
            signal INTEGER,
            si_code INTEGER,
            uid INTEGER,
            gid INTEGER,
            cpu_num INTEGER,
            thread_name TEXT,
            hostname TEXT,
            cmdline TEXT,
            runtime TEXT,
            arch TEXT,
            uname TEXT,
            kernel_version TEXT,
            cwd TEXT,
            root_dir TEXT,
            coredump_filter TEXT,
            rlimit_core TEXT,
            binary_name TEXT,
            binary_path TEXT,
            binary_build_id TEXT,
            uptime_ms INTEGER,
            cgroup_name TEXT,
            binary_removed INTEGER,
            dumpable INTEGER,
            package_version TEXT,
            core_stored INTEGER NOT NULL,
            core_location TEXT,
            core_size INTEGER,
            dump_stored INTEGER NOT NULL,
            dump_reason TEXT NOT NULL,
            rate_limit_allowed INTEGER NOT NULL,
            rate_limit_reason TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_crash_records_captured_at
            ON crash_records(captured_at);
        CREATE INDEX IF NOT EXISTS idx_crash_records_binary_name
            ON crash_records(binary_name);
        CREATE INDEX IF NOT EXISTS idx_crash_records_cgroup_name
            ON crash_records(cgroup_name);
        CREATE INDEX IF NOT EXISTS idx_crash_records_build_id
            ON crash_records(binary_build_id);
        ",
    )?;

    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN pid_initial_ns INTEGER")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN tid_initial_ns INTEGER")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN comm TEXT")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN signal INTEGER")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN si_code INTEGER")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN uid INTEGER")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN gid INTEGER")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN cpu_num INTEGER")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN hostname TEXT")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN cmdline TEXT")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN runtime TEXT")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN arch TEXT")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN uname TEXT")?;
    ensure_optional_column(
        conn,
        "ALTER TABLE crash_records ADD COLUMN kernel_version TEXT",
    )?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN cwd TEXT")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN root_dir TEXT")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN coredump_filter TEXT")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN rlimit_core TEXT")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN core_location TEXT")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN dump_stored INTEGER")?;
    ensure_optional_column(conn, "ALTER TABLE crash_records ADD COLUMN dump_reason TEXT")?;

    Ok(())
}

#[cfg(feature = "sqlite")]
fn ensure_optional_column(conn: &Connection, sql: &str) -> rusqlite::Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(_, Some(msg))) if msg.contains("duplicate column name") => {
            Ok(())
        }
        Err(err) => Err(err),
    }
}
