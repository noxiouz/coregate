use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use xz2::write::XzEncoder;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    None,
    Zstd,
    Xz,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreWriteOptions {
    pub output_dir: PathBuf,
    pub file_name: String,
    pub compression: Compression,
    pub sparse: bool,
    pub min_free_percent: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreWriteResult {
    pub location: String,
    pub uncompressed_bytes: u64,
    pub on_disk_bytes: u64,
    pub sparse: bool,
    pub compression: Compression,
}

pub fn write_core<R: Read + ?Sized>(
    reader: &mut R,
    opts: &CoreWriteOptions,
) -> Result<CoreWriteResult> {
    fs::create_dir_all(&opts.output_dir).context("create output dir")?;
    let path = opts.output_dir.join(&opts.file_name);
    let mount_root = &opts.output_dir;

    let write_result = match opts.compression {
        Compression::None => write_uncompressed(
            reader,
            &path,
            mount_root,
            opts.sparse,
            opts.min_free_percent,
        ),
        Compression::Zstd => write_zstd(reader, &path, mount_root, opts.min_free_percent),
        Compression::Xz => write_xz(reader, &path, mount_root, opts.min_free_percent),
    };
    let uncompressed = match write_result {
        Ok(value) => value,
        Err(err) => {
            let _ = fs::remove_file(&path);
            return Err(err);
        }
    };

    let on_disk = fs::metadata(&path).context("stat output core")?.len();

    Ok(CoreWriteResult {
        location: file_uri(&path),
        uncompressed_bytes: uncompressed,
        on_disk_bytes: on_disk,
        sparse: opts.sparse && matches!(opts.compression, Compression::None),
        compression: opts.compression,
    })
}

pub async fn write_core_async<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    opts: &CoreWriteOptions,
) -> Result<CoreWriteResult> {
    tokio::fs::create_dir_all(&opts.output_dir)
        .await
        .context("create output dir")?;
    let path = opts.output_dir.join(&opts.file_name);
    let mount_root = &opts.output_dir;

    let write_result = match opts.compression {
        Compression::None => {
            write_uncompressed_async(
                reader,
                &path,
                mount_root,
                opts.sparse,
                opts.min_free_percent,
            )
            .await
        }
        Compression::Zstd => {
            write_zstd_async(reader, &path, mount_root, opts.min_free_percent).await
        }
        Compression::Xz => write_xz_async(reader, &path, mount_root, opts.min_free_percent).await,
    };
    let uncompressed = match write_result {
        Ok(value) => value,
        Err(err) => {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(err);
        }
    };

    let on_disk = tokio::fs::metadata(&path)
        .await
        .context("stat output core")?
        .len();

    Ok(CoreWriteResult {
        location: file_uri(&path),
        uncompressed_bytes: uncompressed,
        on_disk_bytes: on_disk,
        sparse: opts.sparse && matches!(opts.compression, Compression::None),
        compression: opts.compression,
    })
}

fn file_uri(path: &Path) -> String {
    format!("file://{}", path.to_string_lossy())
}

fn write_uncompressed<R: Read + ?Sized>(
    reader: &mut R,
    path: &Path,
    mount_root: &Path,
    sparse: bool,
    min_free_percent: Option<u8>,
) -> Result<u64> {
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = SpaceGuardWriter::new(file, mount_root.to_path_buf(), min_free_percent)?;
    if sparse {
        write_sparse(reader, &mut writer)
    } else {
        copy_stream(reader, &mut writer)
    }
}

async fn write_uncompressed_async<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    path: &Path,
    mount_root: &Path,
    sparse: bool,
    min_free_percent: Option<u8>,
) -> Result<u64> {
    let mut file = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("create {}", path.display()))?;
    let reserved_bytes = reserved_bytes(mount_root, min_free_percent)?;
    if sparse {
        write_sparse_async(reader, &mut file, mount_root, reserved_bytes).await
    } else {
        copy_stream_async(reader, &mut file, mount_root, reserved_bytes).await
    }
}

fn write_sparse<R: Read + ?Sized>(
    reader: &mut R,
    writer: &mut SpaceGuardWriter<File>,
) -> Result<u64> {
    const BLOCK: usize = 64 * 1024;
    let mut buf = [0u8; BLOCK];
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buf).context("read core stream")?;
        if n == 0 {
            break;
        }
        total += n as u64;

        if buf[..n].iter().all(|b| *b == 0) {
            writer
                .seek(SeekFrom::Current(n as i64))
                .context("seek sparse hole")?;
        } else {
            writer.write_all(&buf[..n]).context("write core block")?;
        }
    }

    writer
        .inner
        .set_len(total)
        .context("finalize sparse file length")?;
    writer.flush().context("flush sparse writer")?;
    Ok(total)
}

async fn write_sparse_async<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    writer: &mut tokio::fs::File,
    mount_root: &Path,
    reserved_bytes: Option<u64>,
) -> Result<u64> {
    const BLOCK: usize = 64 * 1024;
    let mut buf = [0u8; BLOCK];
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buf).await.context("read core stream")?;
        if n == 0 {
            break;
        }
        total += n as u64;

        if buf[..n].iter().all(|b| *b == 0) {
            writer
                .seek(SeekFrom::Current(n as i64))
                .await
                .context("seek sparse hole")?;
        } else {
            ensure_capacity_for(mount_root, reserved_bytes, n)?;
            writer
                .write_all(&buf[..n])
                .await
                .context("write core block")?;
        }
    }

    writer
        .set_len(total)
        .await
        .context("finalize sparse file length")?;
    writer.flush().await.context("flush sparse writer")?;
    Ok(total)
}

fn write_zstd<R: Read + ?Sized>(
    reader: &mut R,
    path: &Path,
    mount_root: &Path,
    min_free_percent: Option<u8>,
) -> Result<u64> {
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let guarded = SpaceGuardWriter::new(file, mount_root.to_path_buf(), min_free_percent)?;
    let mut encoder =
        zstd::stream::write::Encoder::new(guarded, 3).context("create zstd encoder")?;
    let n = copy_stream(reader, &mut encoder)?;
    encoder.finish().context("finish zstd stream")?;
    Ok(n)
}

async fn write_zstd_async<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    path: &Path,
    mount_root: &Path,
    min_free_percent: Option<u8>,
) -> Result<u64> {
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let guarded = SpaceGuardWriter::new(file, mount_root.to_path_buf(), min_free_percent)?;
    let mut encoder =
        zstd::stream::write::Encoder::new(guarded, 3).context("create zstd encoder")?;
    let n = copy_stream_to_sync_writer_async(reader, &mut encoder).await?;
    encoder.finish().context("finish zstd stream")?;
    Ok(n)
}

fn write_xz<R: Read + ?Sized>(
    reader: &mut R,
    path: &Path,
    mount_root: &Path,
    min_free_percent: Option<u8>,
) -> Result<u64> {
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let guarded = SpaceGuardWriter::new(file, mount_root.to_path_buf(), min_free_percent)?;
    let mut encoder = XzEncoder::new(guarded, 6);
    let n = copy_stream(reader, &mut encoder)?;
    encoder.finish().context("finish xz stream")?;
    Ok(n)
}

async fn write_xz_async<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    path: &Path,
    mount_root: &Path,
    min_free_percent: Option<u8>,
) -> Result<u64> {
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let guarded = SpaceGuardWriter::new(file, mount_root.to_path_buf(), min_free_percent)?;
    let mut encoder = XzEncoder::new(guarded, 6);
    let n = copy_stream_to_sync_writer_async(reader, &mut encoder).await?;
    encoder.finish().context("finish xz stream")?;
    Ok(n)
}

fn copy_stream<R: Read + ?Sized, W: Write>(reader: &mut R, writer: &mut W) -> Result<u64> {
    std::io::copy(reader, writer).context("copy core stream")
}

async fn copy_stream_async<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    writer: &mut tokio::fs::File,
    mount_root: &Path,
    reserved_bytes: Option<u64>,
) -> Result<u64> {
    const BLOCK: usize = 64 * 1024;
    let mut buf = [0u8; BLOCK];
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buf).await.context("read core stream")?;
        if n == 0 {
            break;
        }
        ensure_capacity_for(mount_root, reserved_bytes, n)?;
        writer
            .write_all(&buf[..n])
            .await
            .context("write core block")?;
        total += n as u64;
    }

    writer.flush().await.context("flush core writer")?;
    Ok(total)
}

async fn copy_stream_to_sync_writer_async<R, W>(reader: &mut R, writer: &mut W) -> Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: Write,
{
    const BLOCK: usize = 64 * 1024;
    let mut buf = [0u8; BLOCK];
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buf).await.context("read core stream")?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).context("write core block")?;
        total += n as u64;
    }

    writer.flush().context("flush core writer")?;
    Ok(total)
}

struct SpaceGuardWriter<W> {
    inner: W,
    mount_root: PathBuf,
    reserved_bytes: Option<u64>,
}

impl<W> SpaceGuardWriter<W> {
    fn new(inner: W, mount_root: PathBuf, min_free_percent: Option<u8>) -> Result<Self> {
        let reserved_bytes = reserved_bytes(&mount_root, min_free_percent)?;

        Ok(Self {
            inner,
            mount_root,
            reserved_bytes,
        })
    }

    fn ensure_capacity_for(&self, requested_bytes: usize) -> Result<()> {
        ensure_capacity_for(&self.mount_root, self.reserved_bytes, requested_bytes)
    }
}

fn reserved_bytes(mount_root: &Path, min_free_percent: Option<u8>) -> Result<Option<u64>> {
    match min_free_percent {
        Some(percent) if percent > 100 => anyhow::bail!("min_free_percent must be <= 100"),
        Some(percent) => {
            let stats = statvfs(mount_root)?;
            Ok(Some(stats.total_bytes.saturating_mul(percent as u64) / 100))
        }
        None => Ok(None),
    }
}

fn ensure_capacity_for(
    mount_root: &Path,
    reserved_bytes: Option<u64>,
    requested_bytes: usize,
) -> Result<()> {
    let Some(reserved_bytes) = reserved_bytes else {
        return Ok(());
    };

    let stats = statvfs(mount_root)?;
    let requested_bytes = requested_bytes as u64;
    let remaining = stats.available_bytes.saturating_sub(requested_bytes);
    anyhow::ensure!(
        remaining >= reserved_bytes,
        "refusing to store core: filesystem {} would drop below {}% free (available={}B requested={}B reserved={}B)",
        mount_root.display(),
        reserved_bytes
            .saturating_mul(100)
            .checked_div(stats.total_bytes.max(1))
            .unwrap_or(0),
        stats.available_bytes,
        requested_bytes,
        reserved_bytes,
    );
    Ok(())
}

impl<W: Write> Write for SpaceGuardWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.ensure_capacity_for(buf.len())
            .map_err(std::io::Error::other)?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Seek> Seek for SpaceGuardWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

struct FsStats {
    total_bytes: u64,
    available_bytes: u64,
}

fn statvfs(path: &Path) -> Result<FsStats> {
    let path_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .context("encode path for statvfs")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(path_c.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("statvfs output dir");
    }
    let stat = unsafe { stat.assume_init() };
    let block_size = stat.f_frsize.max(stat.f_bsize);
    Ok(FsStats {
        total_bytes: block_size.saturating_mul(stat.f_blocks),
        available_bytes: block_size.saturating_mul(stat.f_bavail),
    })
}
