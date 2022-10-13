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
use std::fs::{create_dir_all, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

//-----------------------------     Certificate crunch     ---------------------------------------------
/// Struct for `CertificateRequest`.
struct CertificateRequest {
    server: String,
    client_id: String,
    key_file: PathBuf,
    csr_file: PathBuf,
    crt_file: PathBuf,
    ca_cert_file: PathBuf,
    timeout: Duration,
}

/// Implement `CertificateRequest` handling.
impl CertificateRequest {
    pub fn new(
        server: &str,
        client_id: &str,
        paths: CertPaths,
        timeout: Duration,
    ) -> CertificateRequest {
        Self {
            server: server.to_string(),
            client_id: client_id.to_string(),
            key_file: paths.key_path,
            csr_file: paths.csr_path,
            crt_file: paths.crt_path,
            ca_cert_file: paths.ca_cert_path,
            timeout,
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

    /// Drop the "file part from the path `file`, and ensure that the section leading up to the
    /// file exists.
    ///
    /// Similar to unix `mkdir -p "$(dirname $file)"`
    fn ensure_file_dir(file: &Path) -> Result<(), CcError> {
        match file.parent() {
            None => {
                error!("No parent exists for file: {}", file.display());
                Err(CcError::TlsDirectoryNotDirectory)
            }
            Some(parent) => match create_dir_all(parent) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("Failed to create directory: '{}',  {}", parent.display(), e);
                    Err(CcError::TlsDirectoryCreationFailure)
                }
            },
        }
    }

    /// Ensure that a local TLS directory exists.
    ///
    /// 1. Check if the requested TLS path exist.
    /// 2. If the TLS path exists and is not a directory, return error.
    /// 3. Since no TLS directory exists, create one and save to disk.
    ///
    /// # Errors
    /// * `CcErrors::TlsDirectoryPointsToFile`          if TLS directory is not a director.
    /// * `CcErrors::TlsDirectoryCreationFailure`       if TLS directory cannot be created.
    pub fn ensure_tls_dir(&self) -> Result<(), CcError> {
        Self::ensure_file_dir(&self.ca_cert_file)?;
        Self::ensure_file_dir(&self.key_file)?;
        Self::ensure_file_dir(&self.csr_file)?;
        Self::ensure_file_dir(&self.crt_file)?;
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
    pub fn ensure_crt(&self) -> Result<(), CcError> {
        let ca_path = self.ca_cert_file.as_path();
        let crt_path = self.crt_file.as_path();
        let csr_path = self.csr_file.as_path();
        let key_path = self.key_file.as_path();

        let csr_data = std::fs::read(&csr_path).unwrap();

        let res = network::post_and_get_crt(&self.server, ca_path, &csr_data, self.timeout)?;
        let temp_crt = match res {
            network::CertState::Downloaded(data) => data,
            network::CertState::Pending => return Err(CcError::CsrPending),
            network::CertState::Rejected => {
                return Err(CcError::CsrRejected(self.csr_file.display().to_string()))
            }
            network::CertState::NotFound => return Err(CcError::NotFound),
        };

        debug!("Verifying certificate received from '{}'", &self.server);
        let ca_cert_data = std::fs::read(&ca_path).unwrap();
        let key_data = std::fs::read(&key_path).unwrap();

        certs::verify_cert(&temp_crt, &ca_cert_data, &key_data, &self.client_id)?;

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

#[derive(Debug, PartialEq)]
struct CertPaths {
    ca_cert_path: PathBuf,
    key_path: PathBuf,
    csr_path: PathBuf,
    crt_path: PathBuf,
}

/// Take some optional configuration and turn it to non-optional paths
///
/// Uses:  `server`, `client_id`  to generate default paths
/// Optionals:  Passed in as Option, will either be consumed or created.
///
/// Failure:  Does not fail.
impl CertPaths {
    fn resolve(
        server: &str,
        client_id: &str,
        tls_dir: Option<String>,
        key_path: Option<String>,
        csr_path: Option<String>,
        crt_path: Option<String>,
        ca_cert_path: Option<String>,
    ) -> CertPaths {
        let cwd = match tls_dir {
            Some(s) => PathBuf::from(s),
            None => PathBuf::from("."),
        };
        // "server" and "client" will contain "."
        // Rust lacks an "add_extension" method for Path and PathBuf, and only has "with_extension"
        // or "set_extension".
        // Therefore, we append a ".tmp" to our temporary files, and then let the standard library
        // adjust the paths.
        let server_tmp = format!("{}.tmp", server);
        let client_tmp = format!("{}.tmp", client_id);
        debug!("Using root dir: {}", cwd.display());

        let key_path = match key_path {
            Some(s) => PathBuf::from(s),
            None => cwd.join(&client_tmp).with_extension("key"),
        };
        info!("Using key path: {}", key_path.display());

        let csr_path = match csr_path {
            Some(s) => PathBuf::from(s),
            None => cwd.join(&client_tmp).with_extension("csr"),
        };
        info!("Using csr path: {}", csr_path.display());

        let crt_path = match crt_path {
            Some(s) => PathBuf::from(s),
            None => cwd.join(&client_tmp).with_extension("crt"),
        };
        info!("Using Certificate path: {}", crt_path.display());

        let ca_cert_path = match ca_cert_path {
            Some(s) => PathBuf::from(s),
            None => cwd.join("certs").join(&server_tmp).with_extension("cacert"),
        };
        info!("Using CA Certificate path: {}", ca_cert_path.display());
        Self {
            ca_cert_path,
            key_path,
            csr_path,
            crt_path,
        }
    }
}

/// Send a Certificate Request to server.
///
/// # Errors
/// * `Error` if certificate request fails.
fn certificate_request(
    server: &str,
    client_id: &str,
    paths: CertPaths,
    timeout: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    info!(
        "Using caramel server: '{}' with client_id: '{}'",
        server, client_id
    );

    // Create request info
    let request_info = CertificateRequest::new(server, client_id, paths, timeout);

    request_info.ensure_tls_dir()?;
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
    timeout: std::time::Duration,
    tls_dir: Option<String>,
    cacert_path: Option<String>,
    cert_path: Option<String>,
    key_path: Option<String>,
    csr_path: Option<String>,
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
            ).arg(
                Arg::with_name("tls_dir")
                    .help("Directory for saving retrieved TLS files")
                    .short("d")
                    .long("dir")
                    .takes_value(true),
            ).arg(
                Arg::with_name("key_path")
                    .help("Full path of Private Key file")
                    .long("key-path")
                    .takes_value(true),
            ).arg(
                Arg::with_name("csr_path")
                    .help("Full path of CSR file")
                    .long("csr-path")
                    .takes_value(true),
            ).arg(
                Arg::with_name("cert_path")
                    .help("Full path of Certificate")
                    .long("cert-path")
                    .takes_value(true),
            ).arg(
                Arg::with_name("cacert_path")
                    .help("Full path of CA Certificate")
                    .long("cacert-path")
                    .takes_value(true),
            );

        let matches = app.get_matches_from_safe(args)?;

        let server = matches.value_of("SERVER").unwrap().to_string();

        let client_id = matches.value_of("CLIENT_ID").unwrap().to_string();

        // Vary the output based on how many times the user used the "verbose" flag
        // (i.e. 'myprog -v -v -v' or 'myprog -vvv' vs 'myprog -v'

        let log_level = match matches.occurrences_of("verbosity") {
            0 => {
                debug!("Info and Error level");
                log::LevelFilter::Error
            }
            1 => {
                debug!("Debug level");
                log::LevelFilter::Debug
            }
            _ => {
                debug!("Trace level");
                log::LevelFilter::Trace
            }
        };

        let timeout = Duration::from_secs(value_t!(matches, "timeout", u64).unwrap());

        // clap has references to argv, and we want the result to be owned strings.
        let tls_dir = matches.value_of("tls_dir").map(str::to_string);
        let key_path = matches.value_of("key_path").map(str::to_string);
        let csr_path = matches.value_of("csr_path").map(str::to_string);
        let cert_path = matches.value_of("cert_path").map(str::to_string);
        let cacert_path = matches.value_of("cacert_path").map(str::to_string);
        Ok(CmdArgs {
            server,
            client_id,
            log_level,
            timeout,
            tls_dir,
            cacert_path,
            cert_path,
            key_path,
            csr_path,
        })
    }
}

/// `main` function of the caramel-client-rs.
///
/// # Errors
/// * `Error` if CA Certificate request fails.
fn main() {
    let cmd_args = CmdArgs::new();

    SimpleLogger::new()
        .with_level(cmd_args.log_level)
        .init()
        .unwrap();
    debug!("cmd_args: {:?}", cmd_args);

    let paths = CertPaths::resolve(
        &cmd_args.server,
        &cmd_args.client_id,
        cmd_args.tls_dir,
        cmd_args.key_path,
        cmd_args.csr_path,
        cmd_args.cert_path,
        cmd_args.cacert_path,
    );

    let res = certificate_request(
        &cmd_args.server,
        &cmd_args.client_id,
        paths,
        cmd_args.timeout,
    );

    if res.is_err() {
        eprintln!("{}", res.unwrap_err());
        std::process::exit(1);
    } else {
        info!("Certificate success");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn parse_args(args: &[&str]) -> CmdArgs {
        println!("args {:?}", args);
        let mut vec = Vec::with_capacity(10);
        vec.extend_from_slice(&["execname"]);
        vec.extend_from_slice(args);
        println!("vec {:?}", vec);
        CmdArgs::new_from(vec.iter()).unwrap()
    }

    fn parse_optional(args_optional: &[&str]) -> CmdArgs {
        println!("args_optional {:?}", args_optional);
        let mut vec = Vec::with_capacity(10);
        vec.extend_from_slice(&["execname", "server_1", "client_id_1"]);
        vec.extend_from_slice(args_optional);
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

    #[test]
    fn test_path_resolve_all_none() {
        let client = "test.example";
        let server = "ca.example.com";
        let paths = CertPaths::resolve(server, client, None, None, None, None, None);
        assert_eq!(paths.key_path, Path::new("./test.example.key"));
        assert_eq!(paths.csr_path, Path::new("./test.example.csr"));
        assert_eq!(paths.crt_path, Path::new("./test.example.crt"));
        assert_eq!(
            paths.ca_cert_path,
            Path::new("./certs/ca.example.com.cacert")
        );
    }

    #[test]
    fn test_path_resolve_with_dir() {
        let client = "test.example";
        let server = "ca.example.com";
        let paths = CertPaths::resolve(
            server,
            client,
            Some("/secret/data".into()),
            None,
            None,
            None,
            None,
        );
        assert_eq!(paths.key_path, Path::new("/secret/data/test.example.key"));
        assert_eq!(paths.csr_path, Path::new("/secret/data/test.example.csr"));
        assert_eq!(paths.crt_path, Path::new("/secret/data/test.example.crt"));
        assert_eq!(
            paths.ca_cert_path,
            Path::new("/secret/data/certs/ca.example.com.cacert")
        );
    }

    #[test]
    fn test_path_resolve_with_prefix() {
        let client = "test.example";
        let server = "ca.example.com";
        let paths = CertPaths::resolve(
            server,
            client,
            Some("/secret/data".into()),
            Some("/d/tls.key".into()),
            Some("/d/tls.csr".into()),
            Some("/d/tls.crt".into()),
            Some("/d/ca.crt".into()),
        );
        assert_eq!(paths.key_path, Path::new("/d/tls.key"));
        assert_eq!(paths.csr_path, Path::new("/d/tls.csr"));
        assert_eq!(paths.crt_path, Path::new("/d/tls.crt"));
        assert_eq!(paths.ca_cert_path, Path::new("/d/ca.crt"));
    }
}
