// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

use caramel_client::certs;
use caramel_client::network;
use caramel_client::CcError;
use log::{debug, info};
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;

//-----------------------------     Certificate crunch     ---------------------------------------------
struct CertificateRequest {
    server: String,
    client_id: String,
    key_file_name: String,
    csr_file_name: String,
    crt_file_name: String,
    ca_cert_file_name: String,
}

/// Implement `CertificateRequest` handling.
impl CertificateRequest {
    pub fn new(server: &str, client_id: &str) -> CertificateRequest {
        CertificateRequest {
            server: server.to_string(),
            client_id: client_id.to_string(),
            key_file_name: format!("{}{}", &client_id, ".key"),
            csr_file_name: format!("{}{}", &client_id, ".csr"),
            crt_file_name: format!("{}{}", &client_id, ".crt"),
            ca_cert_file_name: format!("{}{}", &server, ".cacert"),
        }
    }

    /// If no CA certificate exists, download it and save to disk.
    /// Will always verify the CA certificate according to some basic parsing rules.
    /// #Errors
    /// Will pass through `CcErrors`on CA certificate errors.
    pub fn ensure_cacert(&self) -> Result<(), CcError> {
        let ca_path = Path::new(&self.ca_cert_file_name);

        if !ca_path.exists() {
            info!(
                "CA certificate file: '{:?}' does not exist, fetching from '{}'",
                &ca_path, &self.server
            );

            let ca_data = network::fetch_root_cert(&self.server)?;

            // Open the file for writing with "Create new" option, which causes a failure if this file
            // already exists.
            // We only perform this _after_ we have downloaded the certificate, to make sure we do not
            // leave an empty file around.
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&ca_path)
                .unwrap();
            // Write the content to file and be done
            file.write_all(&ca_data).unwrap();
        }

        debug!("Verifying CA certificate file: '{:?}'", &ca_path);
        let ca_data = std::fs::read(&ca_path).unwrap();
        certs::verify_cacert(&ca_data)
    }

    /// Ensure that a local key exists in our key filename.
    /// 1. If no private key exists, create one and save to disk.
    /// 2. Verify existing key file can be loaded and passes our validation
    /// #Errors
    /// Will pass through `CcErrors`on private key errors.
    pub fn ensure_key(&self) -> Result<(), CcError> {
        let key_path = Path::new(&self.key_file_name);

        if !key_path.exists() {
            info!(
                "Private key file: '{:?}' does not exist, creating",
                &key_path
            );
            let key_data = certs::create_private_key()?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&key_path)
                .unwrap();

            file.write_all(&key_data).unwrap();
        }

        debug!("Verifying private key file: '{:?}'", &key_path);
        let data = std::fs::read(&key_path).unwrap();
        certs::verify_private_key(&data)
    }

    /// Ensure that a local CSR (Certificate Sign Request) exists in our csr filename.
    /// 1. If no CSR exists, will create a new one, basing the subject on clientid and CA
    ///    certificate.
    /// 2. Load the CSR from disk and ensure that our private key matches the CSR request public
    ///    key.
    /// #Errors
    /// Will pass through `CcErrors`on CSR errors.
    pub fn ensure_csr(&self) -> Result<(), CcError> {
        let ca_path = Path::new(&self.ca_cert_file_name);
        let csr_path = Path::new(&self.csr_file_name);
        let key_path = Path::new(&self.key_file_name);

        let key_data = std::fs::read(&key_path).unwrap();
        if !csr_path.exists() {
            info!(
                "CSR file: '{:?}' does not exist, creating CSR file",
                &csr_path
            );
            let ca_data = std::fs::read(&ca_path).unwrap();
            let csrdata = certs::create_csr(&ca_data, &key_data, &self.client_id)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&csr_path)
                .unwrap();
            file.write_all(&csrdata).unwrap();
        }

        debug!("Verifying CSR file: '{:?}'", &csr_path);
        let csr_data = std::fs::read(&csr_path).unwrap();
        certs::verify_csr(&csr_data, &key_data, &self.client_id)?;
        Ok(())
    }

    /// Attempt to ensure that we get a fresh certificate from the server
    /// 1. Attempt to download a certificate matching our CSR
    /// 2. Post the CSR to the server if needed
    /// 3. Loops a few times to let automatic server signing finish signing a CSR
    /// 4. Downloads a certificate if we have one
    /// 5. Validates that the downloaded certificate matches our CSR and our Private Key
    /// 6. Stores the result on disk.
    pub fn ensure_crt(&self) -> Result<(), String> {
        let ca_path = Path::new(&self.ca_cert_file_name);
        let crt_path = Path::new(&self.crt_file_name);
        let csr_path = Path::new(&self.csr_file_name);
        let key_path = Path::new(&self.key_file_name);

        let csr_data = std::fs::read(&csr_path).unwrap();

        info!("Sending CSR to server: '{}'", &self.server);
        let res = network::post_and_get_crt(&self.server, &ca_path, &csr_data);

        let temp_crt = match res {
            Ok(network::CertState::Downloaded(data)) => data,
            Ok(network::CertState::Pending) => panic!("Not implemented, pending signature"),
            Ok(network::CertState::Rejected) => panic!("Not implemented, delete rejected crt/key"),
            Ok(network::CertState::NotFound) => panic!(
                "Not found is not supposed to happen. Has CSR really been POST-ed and accepted?"
            ),
            Err(e) => panic!("Unknown error. cannot cope: {}", e),
        };

        info!("Verifying certificate received from '{}'", &self.server);
        let ca_cert_data = std::fs::read(&ca_path).unwrap();
        let key_data = std::fs::read(&key_path).unwrap();
        let valid = certs::verify_cert(&temp_crt, &ca_cert_data, &key_data, &self.client_id);
        if valid.is_err() {
            debug!(
                "Invalid certificate received from '{}'\n {:?}",
                &self.server, valid
            );
            let err_msg = format!("Invalid certificate received from '{}'", &self.server);
            return Err(err_msg);
        }

        debug!("Verify CRT file: '{:?}'", &crt_path);
        if crt_path.exists() {
            let cert_data = std::fs::read(&crt_path).unwrap();
            if cert_data == temp_crt {
                info!("CA certificate '{:?}' is unchanged", crt_path);
                return Ok(());
            }
        }
        // We explicitly open for over-write here as we either have a new file, or are writing a
        // new certificate to the file.
        debug!("Writing CRT file: '{:?}'", &crt_path);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&crt_path)
            .unwrap();
        // Write the content to file and be done
        file.write_all(&temp_crt).unwrap();
        Ok(())
    }
}

/// Create CSR
fn certificate_request(
    server: &str,
    client_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    info!(
        "Using caramel server: '{}' with client_id: '{}'",
        server, client_id
    );

    // Create request info
    let request_info = CertificateRequest::new(&server, &client_id);

    request_info.ensure_key()?;
    request_info.ensure_cacert()?;
    request_info.ensure_csr()?;
    request_info.ensure_crt()?;
    Ok("Received certificate".into())
}

/// Parse the commandline, returning `server` and `client_id`
/// Alternatively, an error message in an Err
///
fn read_cmd_input() -> Result<(String, String), String> {
    let mut args: Vec<String> = std::env::args().collect();

    debug!("{:?}", args);

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
    let res = certificate_request(&server, &client_id);

    if res.is_err() {
        eprintln!("{}", res.unwrap_err().to_string());
        std::process::exit(1);
    } else {
        info!("Certificate success");
        Ok(())
    }
}
