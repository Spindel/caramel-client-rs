mod hexsum;

use curl::easy::Easy;
use log::{debug, error, info};
use std::fs::File;
use std::path::Path;

pub enum CertState {
    NotFound,
    Pending,
    Done,
}

/// Fetch the root certificate if we do not have it already.
/// Will fail violently if the file already exists
/// Will fail if the server is not valid against our default CA-store
///
pub fn fetch_root_cert(server: &String) -> Result<Vec<u8>, String> {
    // 1. Connect to server
    // 2. Verify that TLS checks are _enabled_
    // 3. Fail if not using _public_ (ie, LetsEncrypt or other public PKI infra) cert for this
    //    server.
    // 4. Download the cert, return it
    let url = format!("https://{}/root.crt", server);
    info!("Attempting to fetch CA cert from {}", url);

    // Certificates are usually around 2100-2300 bytes
    // A 4k allocation should be good for this
    let mut content = Vec::<u8>::with_capacity(4096);

    let mut handle = Easy::new();
    handle.url(&url).unwrap();
    handle.ssl_verify_host(true).unwrap();
    handle.ssl_verify_peer(true).unwrap();
    handle
        .ssl_min_max_version(
            curl::easy::SslVersion::Tlsv11,
            curl::easy::SslVersion::Tlsv13,
        )
        .unwrap();

    // Start a new block scope here, that allows it to access our buffer `content` exclusive or
    // not, and then we can once more use it after the block scope.
    // Lifetimes are fun, but this basically means that even if curl sends our buffers into a
    // thread or similar, the compiler can track it and know that once we're out of this block,
    // it's safe to access it again.
    // At least that's how I'm sort of currently understanding how this works.
    {
        let mut transfer = handle.transfer();
        transfer
            .write_function(|data| {
                content.extend_from_slice(data);
                Ok(data.len())
            })
            .unwrap();

        match transfer.perform() {
            Ok(_) => info!("Got a new CA certificate"),
            Err(e) => {
                error!("Error fetching certificate: {}", e);
                return Err("Unable to fetch cert".to_owned());
            }
        }
    }
    Ok(content)
}

/// Assuming that a certificate file does not exist on the server, post the file.
/// Internal use, handle is an already initialized and configured curl handle with the correct
/// logic for data
fn post_csr(handle: curl::easy::Easy, csr_filename: &String) -> Result<(), String> {
    use std::io::prelude::*;

    let path = Path::new(&csr_filename);
    let mut file = match File::open(&path) {
        Err(e) => panic!("Unable to read: {}", e),
        Ok(file) => file,
    };
    let mut data = String::new();

    match file.read_to_string(&mut data) {
        Err(e) => panic!("Humbug reading: {}", e),
        _ => debug!("File read"),
    };

    let hexname = hexsum::sha256hex(&data);
    let url = format!("https://foo/{}", hexname);
    info!("About to post to: {}", url);
    Err("humbug".to_owned())
}

/// 1. set up our default settings for curl connections
/// 2. Try to connect using the default PKI info of the  server
/// 2a. Return a handle if that works
/// 3. If it failed, add the ca_cert to the cert store, and try again
/// 3a. Return handle if that works
/// 4. failure
///
fn get_curl_handle(server: &String, ca_cert: &String) -> Result<curl::easy::Easy, String> {
    // First we start by getting https://{server}/
    // Then, if that succeeds, we are done and return the handle
    // If that _fails_ because fex. SSL certificate failure, we add the ca_cert to the SSL
    // connection path, and try again.
    // If that succeeds, we return success.
    // Otherwise, fail hard as we cannot continue
    //
    let url = format!("https://{}/root.crt", server);
    let mut handle = Easy::new();
    handle.ssl_verify_host(true).unwrap();
    handle.ssl_verify_peer(true).unwrap();
    handle
        .ssl_min_max_version(
            curl::easy::SslVersion::Tlsv11,
            curl::easy::SslVersion::Tlsv13,
        )
        .unwrap();
    handle.url(&url).unwrap();
    match handle.perform() {
        Ok(_) => {
            debug!("Got a handle on the first attempt.");
            return Ok(handle);
        }
        Err(e) => error!("Failed to connect with default TLS settings. \n{}", e),
    };

    // Force a re-connect on the next run
    handle.fresh_connect(true);
    let ca_path = Path::new(&ca_cert);
    handle.cainfo(ca_path);

    match handle.perform() {
        Ok(_) => {
            debug!("Got a handle on second attempt");
            return Ok(handle);
        }
        Err(e) => {
            error!("Failed to connect with {} as certificate. \n{}", ca_cert, e);
        }
    };
    Err("Unable to get a connection".to_owned())
}

/// Get crt wraps all the logic that we might need to perform to get a certificate
/// 1. Get the required connection information (tls, curl handle, etc)
/// 2. Calculate sha256sum of our csr to post to the server.
/// 3. Attempt to download a fresh certificate and save it locally
/// 4. If we fail, POST the certificate to the server and try again
/// 5. Depending on error codes, wait longer or not
///
pub fn get_crt(server: &String, ca_cert: &String, csr_filename: &String) -> Result<String, String> {
    // Try GET on the url:
    //     if 200:  return
    //     if 202: Do nothing, we are waiting for the server to sign
    //     if 304: Do nothing. We are waiting for the server
    //     if 404:  post csr to url and re-do
    //
    //     Other return codes? Treat as an error
    //
    let handle = get_curl_handle(&server, &ca_cert)?;
    post_csr(handle, &csr_filename).unwrap();
    Err("get_crt is not implemented yet".to_owned())
}
