pub fn fetch_root_cert(url: String, _filename: &String) -> Result<(), String> {
    // 1. connect to server
    // 2. Verify that TLS checks are _enabled_
    // 3. Fail if not using _public_ (ie, LetsEncrypt or other public PKI infra) cert for this
    //    server.
    // 4. Download the cert, save to temp file
    // 5. atomically move temp cert to our filename
    println!("Attempting to fetch CA cert from {}", url);
    Err("Not implemnted".to_owned())
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
    Err("Not implenented".to_owned())
}
