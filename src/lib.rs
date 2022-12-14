// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

//! A crate named caramel-client. The crate provides library API used to implement a Caramel Client in Rust.
//!
//! See [Caramel Client project](https://gitlab.com/ModioAB/caramel-client-rs) on GitLab for more information.

pub mod certs;
pub mod network;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
/// Enum `CcError` used for library error replies.
pub enum CcError {
    // certs.rs errors
    #[error("Unable to parse private key")]
    PrivateKeyParseFailure,

    #[error(
        "Private key is too short, {actual:} bits < {} bits threshold",
        certs::MIN_RSA_BITS
    )]
    PrivateKeyTooShort { actual: u32 },

    #[error("Could not create TLS directory since provided dir path is not a directory")]
    TlsDirectoryNotDirectory,

    #[error("Could not create provided TLS directory path")]
    TlsDirectoryCreationFailure,

    #[error("Could not create private RSA key")]
    PrivateKeyCreationFailure,

    #[error("CA certificate not self-signed")]
    CaCertNotSelfSigned,

    #[error("Unable to parse CA certificate")]
    CaCertParseFailure,

    #[error("Certificate does not match private key")]
    CertKeyMismatch,

    #[error("Certificate signature is not valid")]
    CertSignatureInvalid,

    #[error("Certificate CommonName does not match client id")]
    CertCommonNameMismatch,

    #[error("Unable to validate certificate")]
    CertValidationFailure,

    #[error("Error while building new CSR (Certificate Signing Request) Subject")]
    CsrBuildSubjectFailure,

    #[error("Error while building new CSR (Certificate Signing Request)")]
    CsrBuildFailure,

    #[error("CSR (Certificate Signing Request) not signed by our private key")]
    CsrSignedWithWrongKey,

    #[error("CSR (Certificate Signing Request) CommonName does not match client id")]
    CsrCommonNameMismatch,

    #[error("Unable to validate CSR (Certificate Signing Request)")]
    CsrValidationFailure,

    #[error("Unable to receive CRT within timeout, time spent {total_time:} seconds")]
    CrtTimeout { total_time: u64 },

    #[error("Server rejected CSR (Certificate Signing Request). Delete {0} and .key")]
    CsrRejected(String),

    #[error("Waiting for server to sign the certificate")]
    CsrPending,

    // network.rs errors
    #[error("Unable to download certificate")]
    DownloadCertificateFailure,

    #[error("Error from Libcurl during network operations")]
    LibCurl,

    #[error("Unknown error happened in transfer")]
    Network,

    #[error("Server rejected our POST with reason: `{0}`")]
    NetworkPost(String),

    #[error("The certificate was not found")]
    NotFound,

    #[error("The CA certificate was not found")]
    CaNotFound,
}
