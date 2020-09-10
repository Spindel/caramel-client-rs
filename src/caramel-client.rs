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
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::time::Duration;

//-----------------------------     Certificate crunch     ---------------------------------------------
/// Struct for `CertificateRequest`.
struct CertificateRequest {
    server: String,
    client_id: String,
    key_file_name: String,
    csr_file_name: String,
    crt_file_name: String,
    ca_cert_file_name: String,
    certificate_timeout: Duration,
}

/// Implement `CertificateRequest` handling.
impl CertificateRequest {
    pub fn new(server: &str, client_id: &str, certificate_timeout: Duration) -> CertificateRequest {
        CertificateRequest {
            server: server.to_string(),
            client_id: client_id.to_string(),
            key_file_name: format!("{}{}", &client_id, ".key"),
            csr_file_name: format!("{}{}", &client_id, ".csr"),
            crt_file_name: format!("{}{}", &client_id, ".crt"),
            ca_cert_file_name: format!("{}{}", &server, ".cacert"),
            certificate_timeout,
        }
    }

    /// If no CA certificate exists, download it and save to disk.
    ///
    /// Will always verify the CA certificate according to some basic parsing rules.
    ///
    /// # Errors
    /// * `CcErrors` on CA certificate errors.
    pub fn ensure_cacert(&self) -> Result<(), CcError> {
        let ca_path = Path::new(&self.ca_cert_file_name);

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

    /// Ensure that a local key exists in our key filename.
    ///
    /// 1. If no private key exists, create one and save to disk.
    /// 2. Verify existing key file can be loaded and passes our validation.
    ///
    /// # Errors
    /// * `CcErrors` on private key errors.
    pub fn ensure_key(&self) -> Result<(), CcError> {
        let key_path = Path::new(&self.key_file_name);

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
        let ca_path = Path::new(&self.ca_cert_file_name);
        let csr_path = Path::new(&self.csr_file_name);
        let key_path = Path::new(&self.key_file_name);

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
        let ca_path = Path::new(&self.ca_cert_file_name);
        let crt_path = Path::new(&self.crt_file_name);
        let csr_path = Path::new(&self.csr_file_name);
        let key_path = Path::new(&self.key_file_name);

        let csr_data = std::fs::read(&csr_path).unwrap();

        let res =
            network::post_and_get_crt(&self.server, &ca_path, &csr_data, self.certificate_timeout);
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
    certificate_timeout: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    info!(
        "Using caramel server: '{}' with client_id: '{}'",
        server, client_id
    );

    // Create request info
    let request_info = CertificateRequest::new(&server, &client_id, certificate_timeout);

    request_info.ensure_key()?;
    request_info.ensure_cacert()?;
    request_info.ensure_csr()?;
    request_info.ensure_crt()?;
    Ok("Received certificate".into())
}

/// Implementation of parsing of the command line using clap
#[derive(Debug, PartialEq)]
struct CmdArgs {
    server: String,
    client_id: String,
    log_level: log::LevelFilter,
    certificate_timeout: std::time::Duration,
}

impl CmdArgs {
    fn new() -> Self {
        Self::new_from(std::env::args_os()).unwrap_or_else(|e| e.exit())
    }

    fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let app = clap::App::new(crate_description!())
            .author(crate_authors!())
            .version(crate_version!())
            .arg(
                Arg::with_name("SERVER")
                    .help("Caramel SERVER to use")
                    .index(1)
                    .required(true),
            )
            .arg(
                Arg::with_name("CLIENT_ID")
                    .help("Caramel CLIENT_ID to use")
                    .index(2)
                    .required(true),
            )
            .arg(
                Arg::with_name("verbosity")
                    .help("Level of verbosity for debug traces")
                    .short("v")
                    .multiple(true),
            )
            .arg(
                Arg::with_name("timeout")
                    .help("Timeout in seconds for waiting for certificate to be signed. Missing of 0 value means forever.")
                    .short("t")
                    .long("timeout")
                    .takes_value(true)
                    .default_value("0")
            );

        let matches = app.get_matches_from_safe(args)?;

        let server = matches.value_of("SERVER").unwrap().to_string();

        let client_id = matches.value_of("CLIENT_ID").unwrap().to_string();

        // Vary the output based on how many times the user used the "verbose" flag
        // (i.e. 'myprog -v -v -v' or 'myprog -vvv' vs 'myprog -v'
        let log_level: log::LevelFilter;
        match matches.occurrences_of("verbosity") {
            0 => {
                debug!("Info and Error level");
                log_level = log::LevelFilter::Error
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

        let certificate_timeout = Duration::from_secs(value_t!(matches, "timeout", u64).unwrap());

        Ok(CmdArgs {
            server,
            client_id,
            log_level,
            certificate_timeout,
        })
    }
}

/// `main` function of the caramel-client-rs.
///
/// # Errors
/// * `Error` if CA Certificate request fails.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cmd_args = CmdArgs::new();

    SimpleLogger::new()
        .with_level(cmd_args.log_level)
        .init()
        .unwrap();
    debug!("cmd_args: {:?}", cmd_args);

    let res = certificate_request(
        &cmd_args.server,
        &cmd_args.client_id,
        cmd_args.certificate_timeout,
    );

    if res.is_err() {
        eprintln!("{}", res.unwrap_err().to_string());
        std::process::exit(1);
    } else {
        info!("Certificate success");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn parse_args(args: &[&str]) -> CmdArgs {
        println!("args {:?}", args);
        let mut vec = Vec::with_capacity(10);
        vec.extend_from_slice(&["execname"]);
        vec.extend_from_slice(&args);
        println!("vec {:?}", vec);
        CmdArgs::new_from(vec.iter()).unwrap()
    }

    fn parse_optional(args_optional: &[&str]) -> CmdArgs {
        println!("args_optional {:?}", args_optional);
        let mut vec = Vec::with_capacity(10);
        vec.extend_from_slice(&["execname", "server_1", "client_id_1"]);
        vec.extend_from_slice(&args_optional);
        println!("vec {:?}", vec);
        CmdArgs::new_from(vec.iter()).unwrap()
    }

    #[test]
    fn test_command_parser_given_no_arguments_returns_too_few_arguments_error() {
        CmdArgs::new_from(["execname"].iter()).unwrap_err();
    }

    #[test]
    fn test_command_parser_given_mandatory_arguments_server_and_client_id() {
        let parse_result = parse_args(&["server_1", "client_id_1"]);
        assert_eq!(parse_result.server, "server_1");
        assert_eq!(parse_result.client_id, "client_id_1");
    }

    #[test]
    fn test_command_parser_given_no_client_id_returning_too_few_arguments_error() {
        CmdArgs::new_from(["execname", "server_1"].iter()).unwrap_err();
    }

    #[test]
    fn test_command_parser_verbosity_default() {
        let parse_result = parse_args(&["server_1", "client_id_1"]);
        assert_eq!(parse_result.log_level, log::LevelFilter::Error);
    }

    #[test]
    fn test_command_parser_verbosity_single_v() {
        let parse_result = parse_optional(&["-v"]);
        assert_eq!(parse_result.log_level, log::LevelFilter::Debug);
    }

    #[test]
    fn test_command_parser_verbosity_double_vv() {
        let parse_result = parse_optional(&["-vv"]);
        assert_eq!(parse_result.log_level, log::LevelFilter::Trace);
    }

    #[test]
    fn test_command_parser_verbosity_double_vvv() {
        let parse_result = parse_optional(&["-vvv"]);
        assert_eq!(parse_result.log_level, log::LevelFilter::Trace);
    }
}
