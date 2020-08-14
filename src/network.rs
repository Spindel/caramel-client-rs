// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

mod hexsum;

use curl::easy::Easy;
use log::{debug, error, info};
use std::path::Path;

use crate::CaramelClientLibError;

impl From<curl::Error> for CaramelClientLibError {
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
        CaramelClientLibError::LibCurl
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
    NotFound,
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
pub fn fetch_root_cert(server: &str) -> Result<Vec<u8>, CaramelClientLibError> {
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
        404 => Err(CaramelClientLibError::CaNotFound),
        _ => Err(CaramelClientLibError::Network),
    }
}

/// Creates a curl handle, attempting connections to the server using both public PKI keys and if
/// that fails, the local  `ca_cert ` from the path.
/// Returns either a handle, or the last connection error from curl
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
                "Failed to connect with {:?} as CA certificate. \n{}",
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
fn inner_get_crt(handle: &mut Easy, url: &str) -> Result<CertState, CaramelClientLibError> {
    // Certificates are usually around 2100-2300 bytes
    // A 4k allocation should be good for this.
    let mut content = Vec::<u8>::with_capacity(4096);
    let status_code = curl_get_crt(handle, url, &mut content)?;
    match status_code {
        200 => Ok(CertState::Downloaded(content)),
        202 | 304 => Ok(CertState::Pending),
        403 => Ok(CertState::Rejected),
        404 => Ok(CertState::NotFound),
        _ => Err(CaramelClientLibError::Network),
    }
}

/// Get crt _only_ attempts to fetch the certificate, and only attempts to do so once.
/// 1. Get the required connection information (tls, curl handle, etc)
/// 2. Calculate sha256sum of our csr to post to the server.
/// 3. Attempt to download a fresh certificate and return it.
#[allow(dead_code)]
pub fn get_crt(
    server: &str,
    ca_cert: &Path,
    csr_data: &[u8],
) -> Result<CertState, CaramelClientLibError> {
    let hexname = hexsum::sha256hex(csr_data);
    let url = format!("https://{}/{}", server, hexname);
    info!("Attempting to download certificate from: {}", url);
    let mut handle = curl_get_handle(&server, &ca_cert)?;
    inner_get_crt(&mut handle, &url)
}

/// Internal function that posts a CSR to the url
///
/// Returns status code
///
/// Errors:
/// returns all curl errors
fn curl_post_csr(handle: &mut Easy, url: &str, mut csr_data: &[u8]) -> Result<u32, curl::Error> {
    use std::io::Read;
    handle.url(&url)?;
    handle.post(true)?;
    handle.post_field_size(csr_data.len() as u64)?;
    // Start a scope here. Since the `transfer` is created inside this scope, and then transfer
    // gets the closure which posts the data, and after this block, `transfer` is no more.
    // For the compiler, that means that `csr_data` is no longer accessed outside this block, and
    // the lifetime is thus managed.
    {
        let mut transfer = handle.transfer();
        transfer.read_function(|into| {
            // "as_slice" means that we can use the Reader protocol on a vector
            // https://doc.rust-lang.org/std/io/trait.Read.html
            let len = csr_data.read(into).unwrap_or(0);
            Ok(len)
        })?;
        transfer.perform()?;
    }
    let status_code = handle.response_code()?;
    debug!("POST {}, status={}", url, status_code);
    Ok(status_code)
}

/// Internal function to post a CSR to the server, using an already configured `handle`
/// Mainly exists to parse the resulting status code into a proper state and error handoff.
fn inner_post_csr(
    handle: &mut Easy,
    url: &str,
    csr_data: &[u8],
) -> Result<CertState, CaramelClientLibError> {
    let status_code = curl_post_csr(handle, url, csr_data)?;
    match status_code {
        200 | 202 => Ok(CertState::Pending),
        _ => Err(CaramelClientLibError::Network),
    }
}

/// Assuming that a certificate file does not exist on the `server`, post `csr_data` to a name
/// calculated by the contents of `csr_data`
#[allow(dead_code)]
pub fn post_csr(
    server: &str,
    ca_cert: &Path,
    csr_data: &[u8],
) -> Result<CertState, CaramelClientLibError> {
    let hexname = hexsum::sha256hex(csr_data);
    let url = format!("https://{}/{}", server, hexname);

    let mut handle = curl_get_handle(&server, &ca_cert)?;

    info!("About to post CSR to: {}", url);
    inner_post_csr(&mut handle, &url, csr_data)
}

/// Calculate an exponential backoff.
fn calculate_backoff(count: usize) -> std::time::Duration {
    use std::cmp::{max, min};
    use std::convert::TryInto;
    use std::time::Duration;
    // Note, this could be improved by adding a jitter to it
    // https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/

    const MAX: Duration = Duration::from_secs(15);
    const BASE: Duration = Duration::from_millis(25);
    const TWO: u32 = 2;

    let count = max(1, count);
    // If count overflows into a u32, attempt it's a big number.
    let attempt: u32 = count.try_into().unwrap_or(100);
    let duration: u32 = TWO.saturating_pow(attempt);

    let delay: Duration = BASE * duration;
    min(MAX, delay)
}

/// Tries to ensure we can get a certificate
/// 1. A get attempt is made to the server, if succesful, early exit
/// 2. If not found, POST it to the server
/// 3. If POST was succesful, iterate loop times:
/// 4   Attempt to download and return the certificate
/// 5. If all attempts fail (no signed certificate exists) error out
pub fn post_and_get_crt(
    server: &str,
    ca_cert: &Path,
    csr_data: &[u8],
    loops: usize,
) -> Result<CertState, CaramelClientLibError> {
    use std::thread::sleep;

    let hexname = hexsum::sha256hex(csr_data);
    let url = format!("https://{}/{}", server, hexname);

    let mut handle = curl_get_handle(&server, &ca_cert)?;

    for attempt in 0..loops {
        match inner_get_crt(&mut handle, &url) {
            // Pending, We sleep for a bit and try again
            Ok(CertState::Pending) => {
                let delay = calculate_backoff(attempt);
                debug!("Sleeping for: {:?}", delay);
                sleep(delay);
            }
            // Cert not found? Attempt to upload it.
            Ok(CertState::NotFound) => {
                info!("CSR not found on server, posting.");
                let _discard_post_status = inner_post_csr(&mut handle, &url, csr_data)?;
            }
            // all other Ok states ( Rejected, Downloaded, etc..  are passed out of this function
            Ok(c) => return Ok(c),
            Err(e) => return Err(e),
        }
    }
    Ok(CertState::Pending)
}

#[cfg(test)]
mod tests {
    use super::calculate_backoff;
    use std::time::Duration;

    #[test]
    fn test_backoff() {
        const BIG_DUR: Duration = Duration::from_secs(60);
        const SMALL_DUR: Duration = Duration::from_millis(25);

        let zero = calculate_backoff(0);
        assert!(zero < BIG_DUR);
        assert!(zero > SMALL_DUR);

        let one = calculate_backoff(1);
        assert!(one < BIG_DUR);
        assert!(one > SMALL_DUR);
        assert!(one >= zero);

        let thousand = calculate_backoff(1000);
        assert!(thousand < BIG_DUR);
        assert!(thousand > SMALL_DUR);
        assert!(thousand >= one);

        // number is larger than u32, make sure wrap logic works
        let bignum = calculate_backoff(8589934592);
        assert!(bignum < BIG_DUR);
        assert!(bignum > SMALL_DUR);
        assert!(bignum >= thousand);
    }
}
