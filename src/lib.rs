// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

pub mod certs;
pub mod network;

#[derive(thiserror::Error, Debug, PartialEq)]
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

    #[error("Error while building new CSR Subject")]
    CsrBuildSubjectFailure,

    #[error("Error while building new Certificate Sign Request")]
    CsrBuildFailure,

    #[error("CSR (certificat signing request) not signed by our private key CSR")]
    CsrSignedWithWrongKey,

    #[error("Unable to validate CSR (certificat signing request)")]
    CsrValidationFailure,

    // network.rs errors
    #[error("Unable to download certificate")]
    DownloadCertificateFailure,

    #[error("Error from Libcurl during network operations")]
    LibCurl,

    #[error("Unknown error happened in transfer")]
    Network,

    #[error("The certificate was not found.")]
    NotFound,

    #[error("The CA certificate was not found.")]
    CaNotFound,

    // Cludge to make other parts of the code return CcError instead of String
    #[error("***ERROR*** WrappedString is no good!!!: {0}")]
    WrappedString(String),
}
