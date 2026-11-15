//! Input selection and protected configuration reads. Resource files are never opened here.
use crate::output::{Refusal, refuse};
use anyhow::{Context, Result};
use backup_domain::{Config, ConfigV1};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

const LIMIT: u64 = 64 * 1024;
pub(crate) enum Configuration {
    Legacy(Config),
    V1(ConfigV1),
}

pub(crate) fn load(path: &Path) -> Result<Configuration> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Refusal("CONFIG_INVALID"))?;
    let meta = file.metadata().map_err(|_| Refusal("CONFIG_INVALID"))?;
    if !meta.is_file() || meta.len() > LIMIT {
        return refuse("CONFIG_INVALID");
    }
    let mut content = String::new();
    file.take(LIMIT + 1)
        .read_to_string(&mut content)
        .map_err(|_| Refusal("CONFIG_INVALID"))?;
    if content.len() as u64 > LIMIT {
        return refuse("CONFIG_INVALID");
    }
    // Never attach the parser error: its source excerpt can include secrets.
    let value: toml::Value = toml::from_str(&content).map_err(|_| Refusal("CONFIG_INVALID"))?;
    if let Some(version) = value.get("config_version") {
        let Some(version) = version.as_integer() else {
            return refuse("CONFIG_INVALID");
        };
        if version != 1 {
            return refuse("CONFIG_VERSION_UNSUPPORTED");
        }
        protected(path, &meta).map_err(|_| Refusal("CREDENTIAL_UNSAFE"))?;
        let config: ConfigV1 = value.try_into().map_err(|_| Refusal("CONFIG_INVALID"))?;
        config.validate().map_err(|_| Refusal("CONFIG_INVALID"))?;
        Ok(Configuration::V1(config))
    } else {
        let config: Config = value.try_into().map_err(|_| Refusal("CONFIG_INVALID"))?;
        config.validate().context("CONFIG_INVALID")?;
        Ok(Configuration::Legacy(config))
    }
}

fn protected(path: &Path, original: &std::fs::Metadata) -> Result<()> {
    // Reject literal dot components too: Path::components normalizes those away.
    if !path.is_absolute()
        || path
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .any(|c| c == b".")
    {
        return refuse("CREDENTIAL_UNSAFE");
    }
    let components: Vec<_> = path.components().collect();
    let mut directory = File::open("/")?;
    // SAFETY: geteuid has no preconditions and does not transfer ownership.
    let uid = unsafe { libc::geteuid() };
    for (index, component) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = component else {
            return refuse("CREDENTIAL_UNSAFE");
        };
        let parent = directory.metadata()?;
        if (parent.uid() != 0 && parent.uid() != uid) || parent.mode() & 0o022 != 0 {
            return refuse("CREDENTIAL_UNSAFE");
        }
        let name = std::ffi::CString::new(name.as_bytes())?;
        let last = index == components.len() - 1;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        // SAFETY: live directory descriptor, valid NUL-terminated name, no O_CREAT.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return refuse("CREDENTIAL_UNSAFE");
        }
        // SAFETY: openat returned a new owned descriptor; File closes it once.
        let opened = unsafe { File::from_raw_fd(fd) };
        if last {
            let meta = opened.metadata()?;
            if !meta.is_file()
                || meta.uid() != uid
                || meta.mode() & 0o7777 != 0o600
                || meta.dev() != original.dev()
                || meta.ino() != original.ino()
            {
                return refuse("CREDENTIAL_UNSAFE");
            }
            return Ok(());
        }
        directory = opened;
    }
    refuse("CREDENTIAL_UNSAFE")
}
