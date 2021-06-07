use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, USER_AGENT};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::{fs, io};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DownloadError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP download error: {0}")]
    Download(#[from] reqwest::Error),
    #[error("Got bad crate: {0}")]
    BadCrate(String),
    #[error("Mismatched hash - expected '{expected}', got '{actual}'")]
    MismatchedHash { expected: String, actual: String },
    #[error("HTTP not found. Status: {status}, URL: {url}, data: {data}")]
    NotFound {
        status: u16,
        url: String,
        data: String,
    },
}

thread_local!(static CLIENT: Client = Client::new());

/// Download a URL and return it as a string.
fn download_string(from: &str, user_agent: &HeaderValue) -> Result<String, DownloadError> {
    Ok(CLIENT.with(|client| {
        client
            .get(from)
            .header(USER_AGENT, user_agent)
            .send()?
            .text()
    })?)
}

/// Append a string to a path.
pub fn append_to_path(path: &Path, suffix: &str) -> PathBuf {
    let mut new_path = path.as_os_str().to_os_string();
    new_path.push(suffix);
    PathBuf::from(new_path)
}

/// Write a string to a file, creating directories if needed.
pub fn write_file_create_dir(path: &Path, contents: &str) -> Result<(), DownloadError> {
    let mut res = fs::write(path, contents);

    if let Err(e) = &res {
        if e.kind() == io::ErrorKind::NotFound {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            res = fs::write(path, contents);
        }
    }

    Ok(res?)
}

/// Create a file, creating directories if needed.
pub fn create_file_create_dir(path: &Path) -> Result<File, DownloadError> {
    let mut file_res = File::create(path);
    if let Err(e) = &file_res {
        if e.kind() == io::ErrorKind::NotFound {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            file_res = File::create(path);
        }
    }

    Ok(file_res?)
}

pub fn move_if_exists(from: &Path, to: &Path) -> Result<(), DownloadError> {
    if from.exists() {
        fs::rename(from, to)?;
    }
    Ok(())
}

pub fn move_if_exists_with_sha256(from: &Path, to: &Path) -> Result<(), DownloadError> {
    let sha256_from_path = append_to_path(from, ".sha256");
    let sha256_to_path = append_to_path(to, ".sha256");
    move_if_exists(&sha256_from_path, &sha256_to_path)?;
    move_if_exists(&from, &to)?;
    Ok(())
}

/// Copy a file and its .sha256, creating `to`'s directory if it doesn't exist.
/// Fails if the source .sha256 does not exist.
pub fn copy_file_create_dir_with_sha256(from: &Path, to: &Path) -> Result<(), DownloadError> {
    let sha256_from_path = append_to_path(from, ".sha256");
    let sha256_to_path = append_to_path(to, ".sha256");
    copy_file_create_dir(&sha256_from_path, &sha256_to_path)?;
    copy_file_create_dir(from, to)?;
    Ok(())
}

/// Copy a file, creating `to`'s directory if it doesn't exist.
pub fn copy_file_create_dir(from: &Path, to: &Path) -> Result<(), DownloadError> {
    if to.exists() {
        return Ok(());
    }
    if let Some(parent) = to.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    fs::copy(from, to)?;
    Ok(())
}

fn one_download(
    url: &str,
    path: &Path,
    hash: Option<&str>,
    user_agent: &HeaderValue,
) -> Result<(), DownloadError> {
    CLIENT.with(|client| {
        let mut http_res = client.get(url).header(USER_AGENT, user_agent).send()?;
        let part_path = append_to_path(path, ".part");
        let mut sha256 = Sha256::new();
        {
            let mut f = create_file_create_dir(&part_path)?;
            let mut buf = [0u8; 65536];
            let status = http_res.status();
            if status == 403 || status == 404 {
                let forbidden_path = append_to_path(path, ".notfound");
                let text = http_res.text()?;
                fs::write(
                    forbidden_path,
                    format!("Server returned {}: {}", status, &text),
                )?;
                return Err(DownloadError::NotFound {
                    status: status.as_u16(),
                    url: url.to_string(),
                    data: text,
                });
            }
            loop {
                let byte_count = http_res.read(&mut buf)?;
                if byte_count == 0 {
                    break;
                }
                if hash.is_some() {
                    sha256.update(&buf[..byte_count]);
                }
                f.write_all(&buf[..byte_count])?;
            }
        }

        let f_hash = format!("{:x}", sha256.finalize());

        if let Some(h) = hash {
            if f_hash == h {
                move_if_exists(&part_path, &path)?;
                Ok(())
            } else {
                let badsha_path = append_to_path(path, ".badsha256");
                fs::write(badsha_path, &f_hash)?;
                Err(DownloadError::MismatchedHash {
                    expected: h.to_string(),
                    actual: f_hash,
                })
            }
        } else {
            fs::rename(part_path, path)?;
            Ok(())
        }
    })
}

/// Download file, verifying its hash, and retrying if needed
pub fn download(
    url: &str,
    path: &Path,
    hash: Option<&str>,
    retries: usize,
    force_download: bool,
    user_agent: &HeaderValue,
) -> Result<(), DownloadError> {
    if path.exists() && !force_download {
        Ok(())
    } else {
        let mut res = Ok(());
        for _ in 0..=retries {
            res = match one_download(url, path, hash, user_agent) {
                Ok(_) => break,
                Err(e) => Err(e),
            }
        }
        if res.is_err() {
            return res;
        }
        Ok(())
    }
}

/// Download file and associated .sha256 file, verifying the hash, and retrying if needed
pub fn download_with_sha256_file(
    url: &str,
    path: &Path,
    retries: usize,
    force_download: bool,
    user_agent: &HeaderValue,
) -> Result<(), DownloadError> {
    let sha256_url = format!("{}.sha256", url);
    let sha256_data = download_string(&sha256_url, user_agent)?;

    let sha256_hash = &sha256_data[..64];
    let res = download(
        url,
        path,
        Some(sha256_hash),
        retries,
        force_download,
        user_agent,
    );
    if res.is_err() {
        return res;
    }

    let sha256_path = append_to_path(path, ".sha256");
    write_file_create_dir(&sha256_path, &sha256_data)?;

    Ok(())
}
