use curl::easy::Easy;
use std::fs::File;
use std::io::{stdout, Write};
use std::path::Path;

/// Fetch the root certificate if we do not have it already.
/// Will fail violently if the file already exists
/// Will fail if the server is not valid against our default CA-store
///
pub fn fetch_root_cert(server: &String, filename: &String) -> Result<(), String> {
    // 1. Connect to server
    // 2. Verify that TLS checks are _enabled_
    // 3. Fail if not using _public_ (ie, LetsEncrypt or other public PKI infra) cert for this
    //    server.
    // 4. Download the cert, save to temp file
    // 5. atomically move temp cert to our filename
    use std::fs::OpenOptions;

    let url = format!("https://{}/root.crt", server);
    println!("Attempting to fetch CA cert from {}", url);

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
            Ok(_) => println!("Got a new CA certificate"),
            Err(e) => {
                println!("Error fetching certificate: {}", e);
                return Err("Unable to fetch cert".to_owned());
            }
        }
    }

    // Open the file for writing with "Create new" option, which causes a failure if this file
    // already exists.
    // We only perform this _after_ we have downloaded the certificate, to make sure we do not
    // leave an empty file around.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&filename)
        .unwrap();

    // Write the content to file and be done
    file.write_all(&content).unwrap();
    Ok(())
}

/// Get crt wraps all the logic that we might need to perform to get a certificate
/// 1. Get the required connection information (tls, curl handle, etc)
/// 2. Calculate sha256sum of our csr to post to the server.
/// 3. Attempt to download a fresh certificate and save it locally
/// 4. If we fail, POST the certificate to the server and try again
/// 5. Depending on error codes, wait longer or not
///
pub fn get_crt(_url: &String, _csrfile: &String) -> Result<String, String> {
    // Try GET on the url:
    //     if 200:  return
    //     if 202: Do nothing, we are waiting for the server to sign
    //     if 304: Do nothing. We are waiting for the server
    //     if 404:  post csr to url and re-do
    //
    //     Other return codes? Treat as an error
    //
    Err("get_crt is not implemented".to_owned())
}
