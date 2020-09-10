// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

//! Implementation of a Caramel client in Rust.
//!
//! See [Caramel Client project](https://gitlab.com/ModioAB/caramel-client-rs) on GitLab for more information.

#[macro_use]
extern crate clap;

use caramel_client::certs;
use caramel_client::network;
use caramel_client::CcError;
use clap::Arg;
use log::{debug, error, info};
use simple_logger::SimpleLogger;
use std::fs::{create_dir_all, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};

//-----------------------------     Certificate crunch     ---------------------------------------------
/// Struct for `CertificateRequest`.
struct CertificateRequest {
    server: String,
    client_id: String,
    tls_dir: PathBuf,
    key_file: PathBuf,
    csr_file: PathBuf,
    crt_file: PathBuf,
    ca_cert_file: PathBuf,
}

/// Implement `CertificateRequest` handling.
impl CertificateRequest {
    pub fn new(server: &str, client_id: &str, tls_dir: &str) -> CertificateRequest {
        CertificateRequest {
            server: server.to_string(),
            client_id: client_id.to_string(),
            tls_dir: Path::new(&tls_dir).to_path_buf(),
            key_file: Path::new(&tls_dir).join(&client_id).with_extension("key"),
            csr_file: Path::new(&tls_dir).join(&client_id).with_extension("csr"),
            crt_file: Path::new(&tls_dir).join(&client_id).with_extension("crt"),
            ca_cert_file: Path::new(&tls_dir)
                .join("certs")
                .join(&server)
                .with_extension("cacert"),
        }
    }

    /// If no CA certificate exists, download it and save to disk.
    ///
    /// Will always verify the CA certificate according to some basic parsing rules.
    ///
    /// # Errors
    /// * `CcErrors` on CA certificate errors.
    pub fn ensure_cacert(&self) -> Result<(), CcError> {
        let ca_path = self.ca_cert_file.as_path();

        if !ca_path.exists() {
            info!(
                "CA certificate file: {:?} does not exist, fetching from '{}'",
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

        debug!("Verifying CA certificate file: {:?}", &ca_path);
        let ca_data = std::fs::read(&ca_path).unwrap();
        certs::verify_cacert(&ca_data)
    }

    /// Ensure that a local TLS directory exists.
    ///
    /// 1. Check if the requested TLS path exist.
    /// 2. If the TLS path exists and is of type file return error.
    /// 3. Since no TLS directory exists, create one and save to disk.
    ///
    /// # Errors
    /// * `CcErrors::TlsDirectoryPointsToFile`          if TLS directory is a existing file.
    /// * `CcErrors::TlsDirectoryCreationFailure`       if TLS directory cannot be created.
    pub fn ensure_tls_dir(&self) -> Result<(), CcError> {
        let dir_path = self.tls_dir.as_path();

        if dir_path.exists() && !dir_path.is_dir() {
            error!(
                "Could not create TLS directory since TLS path: '{:?}' is a file",
                &self.tls_dir
            );
            return Err(CcError::TlsDirectoryPointsToFile);
        } else {
            info!("TLS directory: {:?} does not exist, creating", &dir_path);

            match create_dir_all(&dir_path) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to create TLS directory: {}", e);
                    return Err(CcError::TlsDirectoryCreationFailure);
                }
            }
        }

        // TODO create certs dir if not avaliable
        let certs_path = dir_path.join("certs");
        if !certs_path.exists() {
            match create_dir_all(&dir_path.join("certs")) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to create certs directory: {}", e);
                    return Err(CcError::TlsDirectoryCreationFailure); // TODO add error
                }
            }
        }
        Ok(())
    }

    /// Ensure that a local key exists in our key filename.
    ///
    /// 1. If no private key exists, create one and save to disk.
    /// 2. Verify existing key file can be loaded and passes our validation.
    ///
    /// # Errors
    /// * `CcErrors` on private key errors.
    pub fn ensure_key(&self) -> Result<(), CcError> {
        let key_path = self.key_file.as_path();

        if !key_path.exists() {
            info!("Private key file: {:?} does not exist, creating", &key_path);
            let key_data = certs::create_private_key()?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&key_path)
                .unwrap();

            file.write_all(&key_data).unwrap();
        }

        debug!("Verifying private key file: {:?}", &key_path);
        let data = std::fs::read(&key_path).unwrap();
        certs::verify_private_key(&data)
    }

    /// Ensure that a local CSR (Certificate Sign Request) exists in our csr filename.
    ///
    /// 1. If no CSR exists, will create a new one, basing the subject on clientid and CA
    ///    certificate.
    /// 2. Load the CSR from disk and ensure that our private key matches the CSR request public
    ///    key.
    ///
    /// # Errors
    /// * `CcErrors` on CSR errors.
    pub fn ensure_csr(&self) -> Result<(), CcError> {
        let ca_path = self.ca_cert_file.as_path();
        let csr_path = self.csr_file.as_path();
        let key_path = self.key_file.as_path();

        let key_data = std::fs::read(&key_path).unwrap();
        if !csr_path.exists() {
            info!(
                "CSR file: {:?} does not exist, creating CSR file",
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

        debug!("Verifying CSR file: {:?}", &csr_path);
        let csr_data = std::fs::read(&csr_path).unwrap();
        certs::verify_csr(&csr_data, &key_data, &self.client_id)?;
        Ok(())
    }

    /// Attempt to ensure that we get a fresh certificate from the server.
    ///
    /// 1. Attempt to download a certificate matching our CSR.
    /// 2. Post the CSR to the server if needed.
    /// 3. Loops a few times to let automatic server signing finish signing a CSR.
    /// 4. Downloads a certificate if we have one.
    /// 5. Validates that the downloaded certificate matches our CSR and our Private Key.
    /// 6. Stores the result on disk.
    ///
    /// # Errors
    /// * `String` on errors.
    pub fn ensure_crt(&self) -> Result<(), String> {
        let ca_path = self.ca_cert_file.as_path();
        let crt_path = self.crt_file.as_path();
        let csr_path = self.csr_file.as_path();
        let key_path = self.key_file.as_path();

        let csr_data = std::fs::read(&csr_path).unwrap();

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

        debug!("Verifying certificate received from '{}'", &self.server);
        let ca_cert_data = std::fs::read(&ca_path).unwrap();
        let key_data = std::fs::read(&key_path).unwrap();
        let valid = certs::verify_cert(&temp_crt, &ca_cert_data, &key_data, &self.client_id);
        if valid.is_err() {
            error!(
                "Invalid certificate received from '{}'\n {:?}",
                &self.server, valid
            );
            let err_msg = format!("Invalid certificate received from '{}'", &self.server);
            return Err(err_msg);
        }

        if crt_path.exists() {
            let cert_data = std::fs::read(&crt_path).unwrap();
            if cert_data == temp_crt {
                info!("CA certificate '{:?}' is unchanged", crt_path);
                return Ok(());
            }
        }
        // We explicitly open for over-write here as we either have a new file, or are writing a
        // new certificate to the file.
        info!("Writing certificate file: {:?}", &crt_path);
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

/// Send a Certificate Request to server.
///
/// # Errors
/// * `Error` if certificate request fails.
fn certificate_request(
    server: &str,
    client_id: &str,
    tls_dir: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    info!(
        "Using caramel server: '{}' with client_id: '{}'",
        server, client_id
    );
    debug!("Using tls_dir: '{}'", tls_dir);

    // Create request info
    let request_info = CertificateRequest::new(&server, &client_id, &tls_dir);

    request_info.ensure_tls_dir()?;
    request_info.ensure_key()?;
    request_info.ensure_cacert()?;
    request_info.ensure_csr()?;
    request_info.ensure_crt()?;
    Ok("Received certificate".into())
}

/// Parse the command line, returning a tuble with:
/// `server`, `client_id`, `log_level`, `tls_dir`
fn read_cmd_input() -> (String, String, log::LevelFilter, String) {
    let matches = clap::App::new(crate_description!())
        .author(crate_authors!())
        .version(crate_version!())
        .arg(
            Arg::with_name("SERVER")
                .help("Caramel server to use")
                .index(1)
                .required(true),
        )
        .arg(
            Arg::with_name("CLIENT_ID")
                .help("Client_id to use")
                .index(2)
                .required(true),
        )
        .arg(
            Arg::with_name("tls_dir")
                .help("Directory for saving retrieved TLS files")
                .short("d")
                .long("dir")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbosity")
                .help("Level of verbosity for debug traces")
                .short("v")
                .multiple(true),
        )
        .get_matches();

    debug!("matches: {:?}", matches);

    let server = matches.value_of("SERVER").unwrap().to_string();
    debug!("Using SERVER: {:?}", server);

    let client_id = matches.value_of("CLIENT_ID").unwrap().to_string();
    debug!("Using CLIENT_ID: {:?}", client_id);

    let tls_dir = matches.value_of("tls_dir").unwrap_or(".").to_string();
    debug!("Using tls_dir: {:?}", tls_dir);

    // Vary the output based on how many times the user used the "verbose" flag
    // (i.e. 'myprog -v -v -v' or 'myprog -vvv' vs 'myprog -v'
    let log_level: log::LevelFilter;
    match matches.occurrences_of("verbosity") {
        0 => {
            //debug!("Info and Error level");
            //log_level = log::LevelFilter::Error
            log_level = log::LevelFilter::Debug; // TODO Use Error as above
        }
        1 => {
            debug!("Debug level");
            log_level = log::LevelFilter::Debug
        }
        _ => {
            debug!("Trace level");
            log_level = log::LevelFilter::Trace
        }
    }

    (server, client_id, log_level, tls_dir)
}

/// `main` function of the caramel-client-rs.
///
/// # Errors
/// * `Error` if CA Certificate request fails.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (server, client_id, log_level, tls_dir) = read_cmd_input();

    SimpleLogger::new().with_level(log_level).init().unwrap();
    debug!(
        "server: {} client_id={}, log_level={:?}, tls_dir={}",
        server, client_id, log_level, tls_dir
    );

    let res = certificate_request(&server, &client_id, &tls_dir);

    if res.is_err() {
        eprintln!("{}", res.unwrap_err().to_string());
        std::process::exit(1);
    } else {
        info!("Certificate success");
        Ok(())
    }
}
