// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

mod hexsum;

use curl::easy::Easy;
use log::{debug, error, info};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unknown error happened in transfer")]
    Unknown,
    #[error("Error from Libcurl when fetching certificate")]
    LibCurl,
    #[error("The certificate was not found.")]
    NotFound,
}

impl From<curl::Error> for Error {
    fn from(error: curl::Error) -> Self {
        let desc = error.description();
        let code = error.code();
        let extra = error.extra_description();
        error!(
            "Error from libcurl. code='{}', description='{}', extra_description='{}'",
            code,
            desc,
            extra.unwrap_or("")
        );
        Error::LibCurl
    }
}

/// Enumeration reflecting the current state of this CSR
///
/// Pending: data has been posted to the server, but there is no signed cert to fetch
/// Rejected: Server has rejected our certificate, thus our key and csr are invalid and we should regenerate them
/// Downloaded: We got a certificate from the server that can be used.
pub enum CertState {
    Pending,
    Rejected,
    Downloaded(Vec<u8>),
}

/// Inner function that uses the curl api enr errors for `fetch_root_cert`
/// `url` is a complete url
/// `content` is where the resulting data will be saved
/// Result is a status code and the same  `content` that got passed in
///
/// Errors:
/// passes all curl errors through.
fn curl_fetch_root_cert(url: &str, mut content: Vec<u8>) -> Result<(u32, Vec<u8>), curl::Error> {
    let mut handle = Easy::new();
    handle.url(&url)?;
    handle.ssl_verify_host(true)?;
    handle.ssl_verify_peer(true)?;
    handle.ssl_min_max_version(
        curl::easy::SslVersion::Tlsv11,
        curl::easy::SslVersion::Tlsv13,
    )?;

    // Start a new block scope here, that allows it to access our buffer `content` exclusive or
    // not, and then we can once more use it after the block scope.
    // Lifetimes are fun, but this basically means that even if curl sends our buffers into a
    // thread or similar, the compiler can track it and know that once we're out of this block,
    // it's safe to access it again.
    // At least that's how I'm sort of currently understanding how this works.
    {
        let mut transfer = handle.transfer();
        transfer.write_function(|data| {
            content.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
    }
    let status_code = handle.response_code()?;
    Ok((status_code, content))
}

/// Fetch the root certificate if we do not have it already.
/// Will fail if the server is not valid against our default CA-store
///
pub fn fetch_root_cert(server: &str) -> Result<Vec<u8>, Error> {
    // 1. Connect to server
    // 2. Verify that TLS checks are _enabled_
    // 3. Fail if not using _public_ (ie, LetsEncrypt or other public PKI infra) cert for this
    //    server.
    // 4. Download the cert, return it
    let url = format!("https://{}/root.crt", server);
    info!("Attempting to fetch CA cert from {}", url);

    // Certificates are usually around 2100-2300 bytes
    // A 4k allocation should be good for this
    let content = Vec::<u8>::with_capacity(4096);

    let (status_code, content) = curl_fetch_root_cert(&url, content)?;
    match status_code {
        200 => Ok(content),
        404 => Err(Error::NotFound),
        _ => Err(Error::Unknown),
    }
}

/// Creates a curl handle, attempting connections to the server using both public PKI keys and if
/// that fails, the local  `ca_cert ` from the path.
/// Returns either a handle, or the last connection error from curl
///
fn curl_get_handle(server: &str, ca_cert: &Path) -> Result<Easy, curl::Error> {
    // First we start by getting https://{server}/
    // Then, if that succeeds, we are done and return the handle
    // If that _fails_ because fex. SSL certificate failure, we add the ca_cert to the SSL
    // connection path, and try again.
    // If that succeeds, we return success.
    // Otherwise, fail hard as we cannot continue
    //
    let url = format!("https://{}/", server);
    let mut handle = Easy::new();
    handle.ssl_verify_host(true)?;
    handle.ssl_verify_peer(true)?;
    handle.ssl_min_max_version(
        curl::easy::SslVersion::Tlsv11,
        curl::easy::SslVersion::Tlsv13,
    )?;
    handle.url(&url)?;
    match handle.perform() {
        Ok(_) => {
            debug!("Got a handle on the first attempt.");
            return Ok(handle);
        }
        Err(e) => error!("Failed to connect with default TLS settings. \n{}", e),
    };
    // Force a re-connect on the next run
    handle.fresh_connect(true)?;
    handle.cainfo(ca_cert)?;

    match handle.perform() {
        Ok(_) => {
            debug!("Got a handle on second attempt");
            Ok(handle)
        }
        Err(e) => {
            error!(
                "Failed to connect with {:?} as certificate. \n{}",
                ca_cert, e
            );
            Err(e)
        }
    }
}

/// Internal function that downloads the certificate
/// Using `handle`  and assumes that our setup is complete.
///
/// Result is the status code and a vector of data.
///
/// Errors:
/// returns all curl errors
///
fn curl_get_crt(handle: &mut Easy, url: &str, content: &mut Vec<u8>) -> Result<u32, curl::Error> {
    handle.url(&url)?;
    handle.post(false)?;
    // Start a new block scope here, that allows it to access our buffer `content` exclusive or
    // not, and then we can once more use it after the block scope.
    {
        let mut transfer = handle.transfer();
        transfer.write_function(|data| {
            content.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
    }
    let status_code = handle.response_code()?;
    debug!("GET {}, status={}", url, status_code);
    Ok(status_code)
}

/// Internal function that downloads the certificate
/// Using `handle` and assumes that our setup is complete.
/// Mostly only does memory allocation and parsing of status code into results or error.
///
fn inner_get_crt(handle: &mut Easy, url: &str) -> Result<CertState, Error> {
    // Certificates are usually around 2100-2300 bytes
    // A 4k allocation should be good for this.
    let mut content = Vec::<u8>::with_capacity(4096);
    let status_code = curl_get_crt(handle, url, &mut content)?;
    match status_code {
        200 => Ok(CertState::Downloaded(content)),
        202 | 304 => Ok(CertState::Pending),
        403 => Ok(CertState::Rejected),
        404 => Err(Error::NotFound),
        _ => Err(Error::Unknown),
    }
}

/// Get crt _only_ attempts to fetch the certificate, and only attempts to do so once.
/// 1. Get the required connection information (tls, curl handle, etc)
/// 2. Calculate sha256sum of our csr to post to the server.
/// 3. Attempt to download a fresh certificate and return it.
///
#[allow(dead_code)]
pub fn get_crt(server: &str, ca_cert: &Path, csr_data: &[u8]) -> Result<CertState, Error> {
    // Try GET on the url:
    //     if 200:  return
    //     if 202: Do nothing, we are waiting for the server to sign
    //     if 304: Do nothing. We are waiting for the server
    //     if 404:  post csr to url and re-do
    //
    //     Other return codes? Treat as an error
    //
    let hexname = hexsum::sha256hex(csr_data);
    let url = format!("https://{}/{}", server, hexname);
    info!("Attempting to download certificate from: {}", url);
    let mut handle = curl_get_handle(&server, &ca_cert)?;
    inner_get_crt(&mut handle, &url)
}
