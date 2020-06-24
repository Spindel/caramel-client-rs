use curl::easy::Easy;
use std::fs::File;
use std::io::{stdout, Write};
use std::path::Path;

pub fn fetch_root_cert(url: String, _filename: &String) -> Result<(), String> {
    // 1. connect to server
    // 2. Verify that TLS checks are _enabled_
    // 3. Fail if not using _public_ (ie, LetsEncrypt or other public PKI infra) cert for this
    //    server.
    // 4. Download the cert, save to temp file
    // 5. atomically move temp cert to our filename
    println!("Attempting to fetch CA cert from {}", url);
    Err("fetch_root_cert is not implemented".to_owned())
}

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

pub fn ensure_ca_cert_available(
    server: &String,
    filename: &String,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(filename);

    if !path.exists() {
        let url = format!("https://{}/root.crt", server);
        println!("Attempting to fetch CA cert from {}", url);

        let mut handle = Easy::new();

        handle.url(&url).unwrap();
        handle
            .write_function(|data| {
                stdout().write_all(data).unwrap();
                Ok(data.len())
            })
            .unwrap();
        handle.perform().unwrap();

        let display = path.display();
        let mut file = match File::create(&path) {
            Err(why) => panic!("couldn't create {}: {}", display, why),
            Ok(file) => file,
        };
        let mut transfer2 = handle.transfer();
        transfer2
            .write_function(|data| {
                file.write_all(data).unwrap();
                Ok(data.len())
            })
            .unwrap();
        transfer2.perform().unwrap();
    }
    Ok(())
}
