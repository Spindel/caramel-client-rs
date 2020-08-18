// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

pub mod certs;
pub mod network;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CaramelClientLibError {
    // certs.rs errors
    #[error("Unable to parse private key")]
    PrivateKeyParseError,

    #[error(
        "Private key is too short, {actual:} bits < {} bits threshold",
        certs::MIN_RSA_BITS
    )]
    PrivateKeyTooShort { actual: u32 },

    #[error("Could not create private RSA key")]
    PrivateKeyCreationError,

    #[error("CA certificate not self-signed")]
    CaCertNotSelfSignedError,

    #[error("Unable to parse CA cert")]
    CaCertParseFailure,

    // network.rs errors
    #[error("Unable to download certificate")]
    DownloadCertificateFailed,

    #[error("Unknown caramel client library error")]
    UnknownCaramelClientError,

    #[error("Error from Libcurl during network operations")]
    LibCurl,

    #[error("Unknown error happened in transfer")]
    Network,

    #[error("The certificate was not found.")]
    NotFound,

    #[error("The CA certificate was not found.")]
    CaNotFound,
}
