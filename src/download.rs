use reqwest::header::{HeaderValue, USER_AGENT};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Error, Debug)]
pub enum DownloadError {
    #[error("unable to opne the file {1:?}: {0}")]
    OpenFile(OpenFileError, PathBuf),
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

/// Download a URL and return it as a string.
pub async fn download_string(
    from: &str,
    user_agent: &HeaderValue,
) -> Result<String, DownloadError> {
    let client = Client::new();

    Ok(client
        .get(from)
        .header(USER_AGENT, user_agent)
        .send()
        .await?
        .text()
        .await?)
}

/// Append a string to a path.
pub fn append_to_path(path: &Path, suffix: &str) -> PathBuf {
    let mut new_path = path.as_os_str().to_os_string();
    new_path.push(suffix);
    PathBuf::from(new_path)
}

#[derive(Debug, thiserror::Error)]
pub enum OpenFileError {
    #[error("opening the file: {0}")]
    Open(#[source] std::io::Error),
    #[error("creating directory for the file: {0}")]
    DirectoryCreation(#[source] std::io::Error),
}

async fn with_dir_creation_fallback<Func, Fut, T>(mut op: Func, file_path: &Path) -> Fut::Output
where
    Func: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, std::io::Error>>,
{
    let result = op().await;
    let err = match result {
        Err(err) if err.kind() == io::ErrorKind::NotFound => err,
        result => return result,
    };

    // If the path don't have a parent - don't do anything, just return
    // the error we already got.
    let parent = file_path.parent().ok_or(err)?;

    fs::create_dir_all(parent).await?;

    op().await
}

pub async fn open_file(
    mut opts: tokio::fs::OpenOptions,
    path: &Path,
) -> Result<tokio::fs::File, OpenFileError> {
    let opts = opts.create(true);
    let open = || opts.open(path);
    with_dir_creation_fallback(open, path)
        .await
        .map_err(OpenFileError::Open)
}

/// Write a string to a file, creating directories if needed.
pub async fn write_file_create_dir(path: &Path, contents: &str) -> Result<(), DownloadError> {
    let mut file = open_file(OpenOptions::new(), path)
        .await
        .map_err(|err| DownloadError::OpenFile(err, path.into()))?;
    file.write_all(contents.as_bytes()).await?;
    Ok(())
}

/// Create a file, creating directories if needed.
pub async fn create_file_create_dir(path: &Path) -> Result<File, DownloadError> {
    let file = open_file(OpenOptions::new(), path)
        .await
        .map_err(|err| DownloadError::OpenFile(err, path.into()))?;
    Ok(file)
}

pub async fn move_if_exists(from: &Path, to: &Path) -> Result<(), DownloadError> {
    match fs::rename(from, to).await {
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(DownloadError::Io(err)),
        Ok(()) => Ok(()),
    }
}

pub async fn move_if_exists_with_sha256(from: &Path, to: &Path) -> Result<(), DownloadError> {
    let sha256_from_path = append_to_path(from, ".sha256");
    let sha256_to_path = append_to_path(to, ".sha256");
    move_if_exists(&sha256_from_path, &sha256_to_path).await?;
    move_if_exists(from, to).await?;
    Ok(())
}

/// Copy a file and its .sha256, creating `to`'s directory if it doesn't exist.
/// Fails if the source .sha256 does not exist.
pub async fn copy_file_create_dir_with_sha256(from: &Path, to: &Path) -> Result<(), DownloadError> {
    let sha256_from_path = append_to_path(from, ".sha256");
    let sha256_to_path = append_to_path(to, ".sha256");
    copy_file_create_dir(&sha256_from_path, &sha256_to_path).await?;
    copy_file_create_dir(from, to).await?;
    Ok(())
}

/// Copy a file, creating `to`'s directory if it doesn't exist.
pub async fn copy_file_create_dir(from: &Path, to: &Path) -> Result<(), DownloadError> {
    let copy = || fs::copy(from, to);
    with_dir_creation_fallback(copy, to)
        .await
        .map_err(DownloadError::Io)?;
    Ok(())
}

async fn one_download(
    url: &str,
    path: &Path,
    hash: Option<&str>,
    user_agent: &HeaderValue,
) -> Result<(), DownloadError> {
    let client = Client::new();

    let mut http_res = client
        .get(url)
        .header(USER_AGENT, user_agent)
        .send()
        .await?;
    let part_path = append_to_path(path, ".part");
    let mut sha256 = Sha256::new();
    {
        let mut f = create_file_create_dir(&part_path).await?;
        let status = http_res.status();
        if status == 403 || status == 404 {
            let forbidden_path = append_to_path(path, ".notfound");
            let text = http_res.text().await?;
            fs::write(
                forbidden_path,
                format!("Server returned {}: {}", status, &text),
            )
            .await?;
            return Err(DownloadError::NotFound {
                status: status.as_u16(),
                url: url.to_string(),
                data: text,
            });
        }

        while let Some(chunk) = http_res.chunk().await? {
            if hash.is_some() {
                sha256.update(&chunk);
            }
            f.write_all(&chunk).await?;
        }
    }

    let f_hash = format!("{:x}", sha256.finalize());

    if let Some(h) = hash {
        if f_hash == h {
            move_if_exists(&part_path, path).await?;
            Ok(())
        } else {
            let badsha_path = append_to_path(path, ".badsha256");
            fs::write(badsha_path, &f_hash).await?;
            Err(DownloadError::MismatchedHash {
                expected: h.to_string(),
                actual: f_hash,
            })
        }
    } else {
        fs::rename(part_path, path).await?;
        Ok(())
    }
}

/// Download file, verifying its hash, and retrying if needed
pub async fn download(
    url: &str,
    path: &Path,
    hash: Option<&str>,
    retries: usize,
    force_download: bool,
    user_agent: &HeaderValue,
) -> Result<(), DownloadError> {
    if !force_download {
        let result = tokio::fs::File::open(path).await;
        let is_not_found = matches!(result, Err(ref err @ std::io::Error { .. }) if err.kind() == ErrorKind::NotFound);

        let file_exists = !is_not_found;

        if file_exists {
            let h = match hash {
                Some(hash) => hash,
                None => return Ok(()),
            };

            // Verify SHA-256 hash on the filesystem.
            let mut file = result?;
            let mut buf = [0u8; 4096];
            let mut sha256 = Sha256::new();

            loop {
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }

                sha256.update(&buf[..n]);
            }

            let f_hash = format!("{:x}", sha256.finalize());
            if h == f_hash {
                // Calculated hash matches specified hash.
                return Ok(());
            }
        }
    }

    let mut res = Ok(());
    for _ in 0..=retries {
        res = match one_download(url, path, hash, user_agent).await {
            Ok(_) => break,
            Err(e) => Err(e),
        }
    }

    res
}

/// Download file and associated .sha256 file, verifying the hash, and retrying if needed
pub async fn download_with_sha256_file(
    url: &str,
    path: &Path,
    retries: usize,
    force_download: bool,
    user_agent: &HeaderValue,
) -> Result<(), DownloadError> {
    let sha256_url = format!("{url}.sha256");
    let sha256_data = download_string(&sha256_url, user_agent).await?;

    let sha256_hash = &sha256_data[..64];
    download(
        url,
        path,
        Some(sha256_hash),
        retries,
        force_download,
        user_agent,
    )
    .await?;

    let sha256_path = append_to_path(path, ".sha256");
    write_file_create_dir(&sha256_path, &sha256_data).await?;

    Ok(())
}
