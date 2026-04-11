use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

const CONTROL_WAIT_TIMEOUT: Duration = Duration::from_secs(120);

pub struct ControlChannel {
    reader: BufReader<UnixStream>,
}

impl ControlChannel {
    pub fn connect(
        qemu: &mut Child,
        socket_path: &Path,
        serial_stderr_tail: impl Fn() -> String,
    ) -> Result<Self> {
        let deadline = Instant::now() + CONTROL_WAIT_TIMEOUT;
        loop {
            if let Some(status) = qemu
                .try_wait()
                .context("check qemu status while waiting for control socket")?
            {
                bail!(
                    "qemu exited before control socket became ready (status: {status}).{}",
                    serial_stderr_tail()
                );
            }
            if socket_path.exists() {
                let stream = UnixStream::connect(socket_path)
                    .with_context(|| format!("connect control socket {}", socket_path.display()))?;
                let mut channel = Self {
                    reader: BufReader::new(stream),
                };
                let ready = channel.read_line()?;
                if ready.trim() != "BOOT_READY" {
                    bail!("unexpected boot notification: {ready:?}");
                }
                return Ok(channel);
            }
            if Instant::now() > deadline {
                bail!(
                    "timed out waiting for control socket {}.{}",
                    socket_path.display(),
                    serial_stderr_tail()
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn request<TReq, TResp>(&mut self, request: &TReq) -> Result<TResp>
    where
        TReq: Serialize,
        TResp: DeserializeOwned,
    {
        let payload = serde_json::to_vec(request).context("serialize control request")?;
        let stream = self.reader.get_mut();
        stream
            .write_all(&payload)
            .context("write control request payload")?;
        stream
            .write_all(b"\n")
            .context("write control request newline")?;
        stream.flush().context("flush control request")?;

        let line = self.read_line()?;
        serde_json::from_str(&line).context("parse control reply")
    }

    fn read_line(&mut self) -> Result<String> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .context("read control line")?;
        if line.is_empty() {
            bail!("control channel closed unexpectedly");
        }
        Ok(line)
    }
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    Ok(())
}
