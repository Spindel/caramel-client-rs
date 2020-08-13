// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

use caramel_client::certs;
use caramel_client::network;
use log::{debug, error, info};
use std::path::Path;

//-----------------------------     Certificate crunch     ---------------------------------------------
struct CertificateRequest {
    server: String,
    client_id: String,
    key_file_name: String,
    csr_file_name: String,
    crt_temp_file_name: String,
    crt_file_name: String,
    ca_cert_file_name: String,
}

impl CertificateRequest {
    pub fn new(server: String, client_id: String) -> CertificateRequest {
        CertificateRequest {
            server: server.to_string(),
            client_id: client_id.to_string(),
            key_file_name: format!("{}{}", &client_id, ".key"),
            csr_file_name: format!("{}{}", &client_id, ".csr"),
            crt_temp_file_name: format!("{}{}", &client_id, ".temp"),
            crt_file_name: format!("{}{}", &client_id, ".crt"),
            ca_cert_file_name: format!("{}{}", &server, ".cacert"),
        }
    }

    pub fn ensure_cacert(&self) -> Result<(), String> {
        // should perform:
        // 1. Test for cacert
        // 2. Download root.crt and save to cacert if not.
        // 3. Verify cacert can be loaded
        use std::fs::OpenOptions;
        use std::io::prelude::*;
        let ca_path = Path::new(&self.ca_cert_file_name);

        if !ca_path.exists() {
            info!(
                "CA cert: '{}' does not exist, fetching.",
                self.ca_cert_file_name
            );
            let ca_data = network::fetch_root_cert(&self.server)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&ca_path)
                .unwrap();
            // Write the content to file and be done
            file.write_all(&ca_data).unwrap();
        }
        let ca_data = std::fs::read(&ca_path).unwrap();
        certs::verify_cacert(&ca_data)
    }

    pub fn ensure_key(&self) -> Result<(), String> {
        // should perform:
        // 1. If no private key exists, create a new one and save it.
        // 2. Verify existing key files can be loaded and have a proper size / validation
        use std::io::prelude::*;
        let key_path = Path::new(&self.key_file_name);

        if !key_path.exists() {
            let key_data = certs::create_private_key()?;
            let mut file = std::fs::File::create(&key_path).unwrap();
            file.write_all(&key_data).unwrap();
        }
        let data = std::fs::read(&key_path).unwrap();
        certs::verify_private_key(&data)
    }

    pub fn ensure_csr(&self) -> Result<(), String> {
        // should perform:
        // 1. If no CSR exist create a new one, building subject from "clientid" and "cacert"
        //    subjects
        // 2. Load the CSR and ensure that it's public key matches our private key
        use std::io::prelude::*;

        let ca_path = Path::new(&self.ca_cert_file_name);
        let csr_path = Path::new(&self.csr_file_name);
        let key_path = Path::new(&self.key_file_name);

        let ca_data = std::fs::read(&ca_path).unwrap();
        let key_data = std::fs::read(&key_path).unwrap();
        if !csr_path.exists() {
            let csrdata = certs::create_csr(&ca_data, &key_data, &self.client_id)?;
            let mut file = std::fs::File::create(&csr_path).unwrap();
            file.write_all(&csrdata).unwrap();
        }
        let csr_data = std::fs::read(&csr_path).unwrap();
        certs::verify_csr(&csr_data, &key_data, &self.client_id)?;
        Ok(())
    }

    pub fn ensure_crt(&self) -> Result<(), String> {
        // Should perform:
        // 1. sha256sum of the CSR file
        // 2. try to GET the crt from the server  https://ca/{sha256(csr)}
        // 2a. Default to trusting the public PKI
        // 2b. If TLS error, add the cacert to the list of verifying certs for this connection
        // 3. If we get 404, Post the CSR to the server
        // 4. If we get 202 or 304,  wait?
        // 5. If we get 200, save the cert to a temp place
        // 6. If we get a cert, verify that it's valid
        //      ( openssl verify, and make sure it matches our pub keypair)
        // 7. Replace existing cert with the new temp one.
        //    Only if the two differ, to avoid updating ctime/mtime on files unnecessarily.

        let ca_path = Path::new(&self.ca_cert_file_name);
        let crt_path = Path::new(&self.crt_file_name);
        let key_path = Path::new(&self.key_file_name);
        let ca_cert_data = std::fs::read(&ca_path).unwrap();
        let key_data = std::fs::read(&key_path).unwrap();

        if crt_path.exists() {
            let cert_data = std::fs::read(&crt_path).unwrap();
            let _valid =
                match certs::verify_cert(&cert_data, &ca_cert_data, &key_data, &self.client_id) {
                    Ok(_) => debug!("Valid cert"),
                    Err(e) => error!("Invalid / error parsing: {}", e),
                };
        }

        let temp_crt =
            network::get_crt(&self.server, &self.ca_cert_file_name, &self.csr_file_name)?;

        let _valid = match certs::verify_cert(
            &temp_crt.into_bytes(),
            &ca_cert_data,
            &key_data,
            &self.client_id,
        ) {
            Ok(_) => {
                debug!("Valid cert, should compare and move");
                debug!(
                    "moving {} to {}",
                    &self.crt_temp_file_name, &self.crt_file_name
                );
            }
            Err(e) => panic!("I don't know what to do with: {:?}", e),
        };
        Err("Not implemented, ensure_crt".to_string())
    }
}

fn certificate_request(
    server: String,
    client_id: String,
) -> Result<String, Box<dyn std::error::Error>> {
    info!("Server: {} client_id: {}", server, client_id);

    // Create request info
    let request_info = CertificateRequest::new(server, client_id);

    request_info.ensure_key()?;
    request_info.ensure_cacert()?;
    request_info.ensure_csr()?;
    request_info.ensure_crt()?;
    Ok("Received Certificate".into())
}

/// Parse the commandline, returning server and client_id
/// Alternatively, an error message in an Err
///
fn read_cmd_input() -> Result<(String, String), String> {
    let mut args: Vec<String> = std::env::args().collect();

    debug!("{:?}", args); // DEBUG PRINT

    let length = args.len();
    if length == 3 {
        let client_id = args.pop().unwrap();
        let server = args.pop().unwrap();
        Ok((server, client_id))
    } else {
        let program = args.first().unwrap();
        let err_msg = format!("Usage: {} <SERVER> <CLIENTID>", program);
        Err(err_msg)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::init_with_level(log::Level::Debug).unwrap();
    let (server, client_id) = read_cmd_input()?;
    let res = certificate_request(server, client_id);

    if res.is_err() {
        eprintln!("{}", res.unwrap_err().to_string());
        std::process::exit(1);
    } else {
        info!("Certificate Success");
        Ok(())
    }
}
