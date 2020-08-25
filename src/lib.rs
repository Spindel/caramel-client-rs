// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB


//! A crate for implementing a Caramel Client library API in Rust.
//!
//! See [Caramel Client project](https://gitlab.com/ModioAB/caramel-client-rs) on GitLab for more information.


pub mod certs;
pub mod network;

#[derive(thiserror::Error, Debug, PartialEq)]
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

    #[error("Could not create private RSA key")]
    PrivateKeyCreationFailure,

    #[error("CA certificate not self-signed")]
    CaCertNotSelfSigned,

    #[error("Unable to parse CA cert")]
    CaCertParseFailure,

    #[error("Certificate does not match private key")]
    CertKeyMismatch,

    #[error("Certificate signature is not valid")]
    CertSignatureInvalid,

    #[error("Certificate CommonName does not match client id")]
    CertCommonNameMismatch,

    #[error("Unable to validate certificate")]
    CertValidationFailure,

    #[error("Error while building new CSR Subject")]
    CsrBuildSubjectFailure,

    #[error("Error while building new Certificate Sign Request")]
    CsrBuildFailure,

    #[error("CSR (certificat signing request) not signed by our private key CSR")]
    CsrSignedWithWrongKey,

    #[error("CSR (certificat signing request) CommonName does not match client id")]
    CsrCommonNameMismatch,

    #[error("Unable to validate CSR (certificat signing request)")]
    CsrValidationFailure,

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

    // Cludge to make other parts of the code return CcError instead of String.
    #[error("***ERROR*** WrappedString is no good!!!: {0}")]
    WrappedString(String),
}
