// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

//! Network handling API for a Caramel Client.

mod hexsum;

use curl::easy::Easy;
use log::{debug, error, info, warn};
use rand::prelude::*;
use std::path::Path;
use std::time::Duration;

use crate::CcError;

impl From<curl::Error> for CcError {
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
        CcError::LibCurl
    }
}

/// Enumeration reflecting the current state of this CSR.
///
/// Pending: data has been posted to the server, but there is no signed certificate to fetch.
/// Rejected: Server has rejected our certificate, thus our key and csr are invalid and we should regenerate them.
/// Downloaded: We got a certificate from the server that can be used.
#[derive(Debug, PartialEq, Eq)]
pub enum CertState {
    Pending,
    Rejected,
    NotFound,
    Downloaded(Vec<u8>),
}

/// Struct for Curl replies.
struct CurlReply {
    status_code: u32,
    data: Vec<u8>,
}

/// Inner function that uses the curl api enr errors for `fetch_root_cert`.
/// * `url` is a complete url.
/// * `content` is where the resulting data will be saved.
/// Result is a status code and the same `content` that got passed in.
///
/// # Errors
/// * Passes all `curl::Error` through.
fn curl_fetch_root_cert(url: &str, mut data: Vec<u8>) -> Result<CurlReply, curl::Error> {
    let mut handle = Easy::new();
    handle.url(url)?;
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
        transfer.write_function(|from_server| {
            data.extend_from_slice(from_server);
            Ok(from_server.len())
        })?;
        transfer.perform()?;
    }
    let status_code = handle.response_code()?;
    debug!("GET {}, status={}", url, status_code);
    Ok(CurlReply { status_code, data })
}

/// Fetch the CA certificate from the server.
///
/// Will fail if the server is not valid against our default CA-store.
///
/// # Errors
/// * `CcError::Network` for most HTTP status-codes that we do not know what to do with.
/// * `CcError::LibCurl` for curl internal errors. (DNS, timeout, etc.)
/// * `CcError::CaNotFound` this server has no CA file and it is probably not running caramel.
pub fn fetch_root_cert(server: &str) -> Result<Vec<u8>, CcError> {
    // 1. Connect to server.
    // 2. Verify that TLS checks are _enabled_.
    // 3. Fail if not using _public_ (ie, LetsEncrypt or other public PKI infra) certificate for this
    //    server.
    // 4. Download the cert, return it.
    let url = format!("https://{}/root.crt", server);
    debug!("Fetching CA certificate from '{}'", server);

    // Certificates are usually around 2100-2300 bytes
    // A 4k allocation should be good for this
    let content = Vec::<u8>::with_capacity(4096);

    let res = curl_fetch_root_cert(&url, content)?;
    match res.status_code {
        200 => Ok(res.data),
        404 => Err(CcError::CaNotFound),
        _ => Err(CcError::Network),
    }
}

/// Creates a curl handle, attempting connections to the server using both public PKI keys and if
/// that fails, the local  `ca_cert` from the path.
/// Returns either a handle, or the last connection error from curl.
///
/// # Errors
/// * Passes all `curl::Error` through.
fn curl_get_handle(server: &str, ca_cert: &Path) -> Result<Easy, curl::Error> {
    // First we start by getting https://{server}/
    // Then, if that succeeds, we are done and return the handle
    // If that _fails_ because fex. SSL certificate failure, we add the `ca_cert` to the SSL
    // connection path, and try again.
    // If that succeeds, we return success.
    // Otherwise, fail hard as we cannot continue.
    let url = format!("https://{}/", server);
    let mut handle = Easy::new();
    handle.ssl_verify_host(true)?;
    handle.ssl_verify_peer(true)?;
    handle.ssl_min_max_version(
        curl::easy::SslVersion::Tlsv11,
        curl::easy::SslVersion::Tlsv13,
    )?;
    handle.url(&url)?;
    debug!("Probing: '{}' using default TLS settings", &server);
    match handle.perform() {
        Ok(_) => return Ok(handle),
        Err(e) => debug!("Failed to connect with default TLS settings.\n {}", e),
    };
    // Force a re-connect on the next run
    handle.fresh_connect(true)?;
    handle.cainfo(ca_cert)?;

    debug!(
        "Probing '{}' using '{:?}' as CA certificate",
        &server, ca_cert
    );
    match handle.perform() {
        Ok(_) => Ok(handle),
        Err(e) => {
            error!(
                "Failed to connect to server '{}' with {:?} as CA certificate.\n {}",
                &server, ca_cert, e
            );
            Err(e)
        }
    }
}

/// Internal function that downloads the certificate.
/// Using `handle` and assumes that our setup is complete.
///
/// Result is the status code and a vector of data.
///
/// # Errors
/// * Passes all `curl::Error` through.
fn curl_get_crt(handle: &mut Easy, url: &str) -> Result<CurlReply, curl::Error> {
    // Certificates are usually around 2100-2300 bytes
    // A 4k allocation should be good for this.
    let mut data = Vec::<u8>::with_capacity(4096);

    handle.url(url)?;
    handle.post(false)?;
    // Start a new block scope here, that allows it to access our buffer `content` exclusive or
    // not, and then we can once more use it after the block scope.
    {
        let mut transfer = handle.transfer();
        // See https://docs.rs/curl/0.4.33/curl/easy/struct.Easy.html#method.write_function
        transfer.write_function(|from_server| {
            data.extend_from_slice(from_server);
            Ok(from_server.len())
        })?;

        transfer.perform()?;
    }
    let status_code = handle.response_code()?;
    debug!("GET {}, status={}", url, status_code);
    Ok(CurlReply { status_code, data })
}

/// Internal function that is responsible for consuming `CurlReply` (Status code and data) into
/// useful error statuses, log lines and other data we may require.
///
/// # Errors
/// * `CcError::Rejected` when CSR was rejected by server.
/// * `CcError::Network`  when failed to fetch from server.
fn inner_get_crt(url: &str, res: CurlReply) -> Result<CertState, CcError> {
    match res.status_code {
        200 => Ok(CertState::Downloaded(res.data)),
        202 | 304 => Ok(CertState::Pending),
        404 => Ok(CertState::NotFound),
        403 => {
            warn!(
                "Rejected CSR from server when fetching '{}':\n {:?}",
                url, res.data
            );
            Ok(CertState::Rejected)
        }
        _ => {
            error!(
                "Error from server when fetching '{}':\n {:?}",
                url, res.data
            );
            Err(CcError::Network)
        }
    }
}

/// Get crt _only_ attempts to fetch the certificate, and only attempts to do so once.
///
/// # Ok
/// * `CertState::NotFound`   Means that you need to POST this CSR first.
/// * `CertState::Downloaded<Vec<u8>>` Contains the fresh certificate.
/// * `CertState::Pending`    Means we need to wait for unknown time for the server to sign our CSR.
/// * `CertState::Rejected`   The server has rejected our CSR, and we may need to re-generate both our Key and CSR.
///
/// # Errors
/// * `CcError::Network` for most HTTP status-codes that we do not know what to do with.
/// * `CcError::LibCurl` for curl internal errors. (DNS, timeout, etc.).
#[allow(dead_code)]
pub fn get_crt(server: &str, ca_cert: &Path, csr_data: &[u8]) -> Result<CertState, CcError> {
    let hexname = hexsum::sha256hex(csr_data);
    let url = format!("https://{}/{}", server, hexname);
    info!("Fetching certificate from '{}'", server);
    let mut handle = curl_get_handle(server, ca_cert)?;
    let get_res = curl_get_crt(&mut handle, &url)?;
    inner_get_crt(&url, get_res)
}

/// Internal function that posts a CSR to the url.
/// Returns status code `CurlReply`.
///
/// # Errors
/// * Passes all `curl::Error` through.
fn curl_post_csr(
    handle: &mut Easy,
    url: &str,
    mut csr_data: &[u8],
) -> Result<CurlReply, curl::Error> {
    use std::io::Read;
    handle.url(url)?;
    handle.post(true)?;
    handle.post_field_size(csr_data.len() as u64)?;

    let mut data = Vec::new();
    // Start a scope here. Since the `transfer` is created inside this scope, and then transfer
    // gets the closure which posts the data, and after this block, `transfer` is no more.
    // For the compiler, that means that `csr_data` is no longer accessed outside this block, and
    // the lifetime is thus managed.
    {
        let mut transfer = handle.transfer();
        transfer.read_function(|to_server| {
            // "as_slice" means that we can use the Reader protocol on a vector
            // https://doc.rust-lang.org/std/io/trait.Read.html
            let len = csr_data.read(to_server).unwrap_or(0);
            Ok(len)
        })?;

        // See https://docs.rs/curl/0.4.33/curl/easy/struct.Easy.html#method.write_function
        transfer.write_function(|from_server| {
            data.extend_from_slice(from_server);
            Ok(from_server.len())
        })?;

        transfer.perform()?;
    }
    let status_code = handle.response_code()?;
    debug!("POST {}, status={}", url, status_code);
    Ok(CurlReply { status_code, data })
}

/// Internal function to handle replies from a curl POST CSR transaction.
/// It is responsible for decoding status codes and messages into useful Error and Result states.
///
/// # Errors
/// * `CcError::NetworkPost`  for error during Post, with reason.
/// * `CcError::Network`      for unknown Network Error.
fn inner_post_csr(url: &str, res: &CurlReply) -> Result<CertState, CcError> {
    // The server will return HTTP Bad Request in the following _known_ situations:
    // 1. POST of CSR to an URL that does not match the CSR.
    //    Ie, if the sha256 and the data do not match.
    // 2. Subject of CSR does not match Subject of the Server's CA
    //     (Posting a CSR to a different server)
    // 3. Posting the same CSR twice.
    // However, other than looking at the string output in the error message,
    // there is no way for us to know which of those errors we got.
    //
    // Other errors:
    // 1. Posting a too large file  => HTTP 413, RequestEntityTooLarge
    // 2. Posting without passing a Content-Length header, => HTTP 411, Length Required
    //
    match res.status_code {
        200 | 202 => Ok(CertState::Pending),
        400 | 411 | 413 => {
            error!("Error during POST of CSR to '{}': \n{:?}", url, res.data);
            // from_utf8_lossy converts bytes and replaces unknown data with "safe" utf8 code.
            // It is slow and may cause copies, but we aren't doing that very often.
            let msg = String::from_utf8_lossy(&res.data).to_string();
            Err(CcError::NetworkPost(msg))
        }
        _ => {
            error!("Unknown error POST of CSR to '{}': \n{:?}", url, res.data);
            Err(CcError::Network)
        }
    }
}

/// Assuming that a certificate file does not exist on the `server`, post `csr_data` to a name
/// calculated by the contents of `csr_data`.
///
/// # Errors
/// * `CcError::LibCurl` for various curl internal errors (DNS, timeout, typoed hostname, etc).
/// * `CcError::Network` for various status codes from the CA server.
#[allow(dead_code)]
pub fn post_csr(server: &str, ca_cert: &Path, csr_data: &[u8]) -> Result<CertState, CcError> {
    let hexname = hexsum::sha256hex(csr_data);
    let url = format!("https://{}/{}", server, hexname);

    let mut handle = curl_get_handle(server, ca_cert)?;

    info!("Posting CSR to '{}'", server);
    let post_res = curl_post_csr(&mut handle, &url, csr_data)?;
    inner_post_csr(&url, &post_res)
}

/// Calculate an exponential backoff.
fn calculate_backoff(count: usize) -> std::time::Duration {
    use std::cmp::{max, min};
    use std::convert::TryInto;
    // Note, this could be improved by adding a jitter to it
    // https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/

    const MAX: Duration = Duration::from_secs(23);
    const BASE: Duration = Duration::from_millis(870);
    const TWO: u32 = 2;

    // Note that 2^0 = 1
    let count = max(0, count);
    // If count overflows into a u32, attempt it's a big number.
    let attempt: u32 = count.try_into().unwrap_or(100);
    let duration: u32 = TWO.saturating_pow(attempt);

    let delay: Duration = BASE * duration;
    let bounded_delay = min(MAX, delay);
    // Add jitter, select a point at random, [+15%, -15%] of the bounded delay
    let mut generator = rand::thread_rng();
    let between_0_and_1: f64 = generator.gen();
    bounded_delay.mul_f64(1.0 + 0.3 * (between_0_and_1 - 0.5))
}

/// Tries to ensure we can get a certificate.
///
/// 1. A get attempt is made to the server, if succesful, early exit.
/// 2. If not found, POST it to the server.
/// 3. If POST was succesful, iterate forever.
/// 4  Attempt to download and return the certificate.
/// 5. If all attempts fail (no signed certificate exists) error out.
///
/// # Errors
/// * `CcError::LibCurl` for various curl internal errors (dns, timeout, typoed hostname, etc).
/// * `CcError::Network` for various status codes from the CA server.
pub fn post_and_get_crt(
    server: &str,
    ca_cert: &Path,
    csr_data: &[u8],
    timeout: Duration,
) -> Result<CertState, CcError> {
    use std::thread::sleep;

    let hexname = hexsum::sha256hex(csr_data);
    let url = format!("https://{}/{}", server, hexname);

    let mut handle = curl_get_handle(server, ca_cert)?;

    let mut attempt = 0;
    let mut total_time = Duration::new(0, 0);
    loop {
        attempt += 1;

        debug!(
            "attempt: {} total_time: {} ms timeout: {} ms",
            attempt,
            total_time.as_millis(),
            timeout.as_millis()
        );

        // TODO change to !certificate_timeout.is_zero() when Duration::is_zero() is available as stable
        // https://github.com/rust-lang/rust/issues/73544
        if timeout.as_secs() > 0 && total_time.as_secs() > timeout.as_secs() {
            error!(
                "CRT request failed due to timeout passed, total_time spent {} seconds",
                total_time.as_secs()
            );
            return Err(CcError::CrtTimeout {
                total_time: total_time.as_secs(),
            });
        }

        let get_res = curl_get_crt(&mut handle, &url)?;
        match inner_get_crt(&url, get_res) {
            // Pending, We sleep for a bit and try again
            Ok(CertState::Pending) => {
                let delay = calculate_backoff(attempt);
                total_time += delay;
                info!("Request pending. Sleeping for {:?}", delay);
                sleep(delay);
            }
            // Certificate not found? Attempt to upload it.
            Ok(CertState::NotFound) => {
                info!("CSR not found on server, posting to server '{}'", &server);
                let post_res = curl_post_csr(&mut handle, &url, csr_data)?;
                let _discard_post_status = inner_post_csr(&url, &post_res)?;
            }
            // all other Ok states ( Rejected, Downloaded, etc..  are passed out of this function
            Ok(c) => break Ok(c),
            Err(e) => break Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const BIG_DUR: Duration = Duration::from_secs(60);
    const SMALL_DUR: Duration = Duration::from_millis(500);

    #[must_use]
    pub fn convert_string_to_vec8(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    #[test]
    fn test_backoff_zero() {
        let zero = calculate_backoff(0);
        assert!(zero < BIG_DUR);
        assert!(zero > SMALL_DUR);
    }

    #[test]
    fn test_backoff_one() {
        let one = calculate_backoff(1);
        assert!(one < BIG_DUR);
        assert!(one > SMALL_DUR);
    }

    #[test]
    fn test_backoff_increasing() {
        const LIMIT_FOR_INCREMENT: Duration = Duration::from_secs(15);
        let mut previous = calculate_backoff(0);
        let mut count = 1;
        while previous < LIMIT_FOR_INCREMENT {
            let current = calculate_backoff(count);

            assert!(current >= previous);
            count += 1;
            previous = current;
        }
    }

    #[test]
    fn test_backoff_large_values() {
        let thousand = calculate_backoff(1000);
        assert!(thousand < BIG_DUR);
        assert!(thousand > SMALL_DUR);
    }

    #[test]
    fn test_backoff_bignum() {
        // number is larger than u32, make sure wrap logic works
        let bignum = calculate_backoff(8_589_934_592);
        assert!(bignum < BIG_DUR);
        assert!(bignum > SMALL_DUR);
    }

    fn make_reply(status_code: u32, msg: &str) -> CurlReply {
        let data = msg.as_bytes().to_vec();
        CurlReply { status_code, data }
    }

    #[test]
    fn test_post_csr_200_ok() {
        let reply = make_reply(200, "");

        let res = inner_post_csr("", &reply);
        assert_eq!(Some(CertState::Pending), res.ok());
    }
    #[test]
    fn test_post_csr_202_not_modified() {
        let reply = make_reply(202, "");

        let res = inner_post_csr("", &reply);
        assert_eq!(Some(CertState::Pending), res.ok());
    }

    #[test]
    fn test_post_csr_error_missing_header() {
        let reply = make_reply(411, "Length required");
        match inner_post_csr("", &reply) {
            Err(CcError::NetworkPost(_)) => (),
            _ => panic!("We should get a Post error"),
        }
    }

    #[test]
    fn test_post_csr_error_too_large() {
        let reply = make_reply(413, "Too large 100kb > 12kb");

        match inner_post_csr("", &reply) {
            Err(CcError::NetworkPost(_)) => (),
            _ => panic!("We should get a Post error"),
        }
    }

    #[test]
    fn test_post_csr_error() {
        let err_msg = r#"{"status":400,"title":"Bad Request","detail":"Bad subject: (('ST', '\u00d6sterg\u00f6tland'),) do not match (('O', 'ModioAB'),)"}"#;
        let reply = make_reply(400, err_msg);
        match inner_post_csr("", &reply) {
            Err(CcError::NetworkPost(_)) => (),
            _ => panic!("We should get a Post error"),
        }
    }

    #[test]
    fn test_post_csr_unknown() {
        let message = "Cannot connect to database";
        let reply = make_reply(500, message);
        let res = inner_post_csr("", &reply);
        assert_eq!(Some(CcError::Network), res.err());
    }

    #[test]
    fn test_get_crt_ok() {
        let reply = make_reply(200, "");
        let res = inner_get_crt("", reply);
        assert_eq!(
            Some(CertState::Downloaded(convert_string_to_vec8(""))),
            res.ok()
        );
    }

    #[test]
    fn test_get_crt_pending() {
        let reply = make_reply(202, "XXXXXXXXXXX");
        let res = inner_get_crt("", reply);
        // Should get an OK / Pending on 202
        assert_eq!(Some(CertState::Pending), res.ok());
    }
    #[test]
    fn test_get_crt_rejected() {
        let reply = make_reply(403, "Forbidden");
        let res = inner_get_crt("", reply);
        // Should get an OK / Rejected on status 403
        assert_eq!(Some(CertState::Rejected), res.ok());
    }

    #[test]
    fn test_get_crt_not_posted() {
        let reply = make_reply(404, "Not found");
        let res = inner_get_crt("", reply);
        // Should get an OK /  NotFound on 404
        assert_eq!(Some(CertState::NotFound), res.ok());
    }
    #[test]
    fn test_get_crt_error() {
        let reply = make_reply(500, "Cannot connect to database");
        let res = inner_get_crt("", reply);
        // We should get a misc error
        assert_eq!(Some(CcError::Network), res.err());
    }
}

/// Tests that run against "live" data. These tests may randomly fail due to network services being down.
#[cfg(test)]
mod integration {
    use super::{fetch_root_cert, get_crt, CcError, CertState, Path};

    #[test]
    fn get_cacert_from_log_ca() {
        // ca.log.modio.se runs on a publicly signed PKI
        let res = fetch_root_cert("ca.log.modio.se");
        res.expect("Failed to download cert from ca.log.modio.se");
    }

    #[test]
    fn get_cacert_from_ca_modio() {
        // ca.modio.se runs on a self-signed PKI
        let res = fetch_root_cert("ca.modio.se");
        if res.is_ok() {
            panic!("Should not succeed due to being signed by others");
        } else if res.err() == Some(CcError::CaNotFound) {
            panic!("Should not get 404 from this server.");
        } else {
            println!("Correct, should be a TLS connection error.");
        }
    }

    #[test]
    fn get_cacert_from_www_modio() {
        // www.modio.se does not run a caramel server.
        let res = fetch_root_cert("www.modio.se");
        if res.err() == Some(CcError::CaNotFound) {
            println!("Should 404 from a web server");
        } else {
            panic!("Wrong return from www.modio.se");
        }
    }

    #[test]
    fn get_crt_from_ca_modio() {
        // This is a well-known test-certificate CSR that is valid for 'ca.modio.se'
        // It is expected to be able to download this.
        let fffbeec0ffee_csr: &str = "-----BEGIN CERTIFICATE REQUEST-----
MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCU0UxFzAVBgNVBAgMDsOWc3RlcmfDtnRs
YW5kMRMwEQYDVQQHDApMaW5rw7ZwaW5nMREwDwYDVQQKDAhNb2RpbyBBQjEQMA4G
A1UECwwHQ2FyYW1lbDEVMBMGA1UEAwwMZmZmYmVlYzBmZmVlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx0XvZX2qZn0oijLw2YptgP2dgPOXiV74LWYT
4LLtQwTzgLE+3sHt9Hrk/nBtZtTTYqDGpKdOEEbnx/SV5E4QiGiAPR03LUKVprhD
v3/uCz7GnzJLjBT6H5JaV0xi7zMYOdSqkJfi2nG0cShqD7PkXym1WODDPfRjAZ1c
g1pjeGH0dfGuKe7bQlO2i9gsC/x1J7nWDdS/E8kffkDWamsWzb/a2iuHALp3IKnJ
xc+IxmhdTCGzAqTEcasYERpUSPjTZ5O0ky0rIqS/97pT8TZjJ4jFLd7OEXv6hXK+
2TOhZEGbmXLlOiXqRzVN+AoRPcBwLNE5MdVOxuoO+20jBMSgnQIDAQABoAAwDQYJ
KoZIhvcNAQELBQADggEBAC+KY6lE8+cLTfKj9260om7atPcS8qQiywOeWNzyhp9F
Ov7vWNCoh89vCiD4VWPRj7fPGiyB4oIY3M+cXUD3zW8Gi3IbwdnUoyrN9MzGALzQ
6zBLcxUIEt6TgQLbLNBCjqNEy4gV9qmn/XmN+J8r0orRt66S9rxYjxhIKLkuQ9xa
LixKAxaIJ58bLH0W3/+dBDTeugt2zR+bJrJXbf6n4A+wFqJnhn8uGH2dkRxhxGK8
L4CRL0Y1CrLO2Rl/ukqN9Fvdpy3RVrjQQ4jERVzc8n+QaKtrPcJsVX9wP0IYLqPO
aq69O+gq+AO+jX+8xQHnSIp6pxocIxaufeSaXCgVysM=
-----END CERTIFICATE REQUEST-----
";
        let res = get_crt(
            "ca.modio.se",
            Path::new("certs/ca.modio.se.cacert"),
            fffbeec0ffee_csr.as_bytes(),
        );
        match res {
            Ok(CertState::Downloaded(_)) => println!("Is a valid csr, should have valid crt"),
            _ => panic!("Failure for unknown reason"),
        }
    }
}
