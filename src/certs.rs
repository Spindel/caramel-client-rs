// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2020 Modio AB

use crate::CcError;
use log::{debug, error, info};
use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509;
use openssl::x509::{X509Name, X509NameRef, X509Req, X509};

pub mod blobs;

// Encoded in upstream definitions
const MAX_CN_LENGTH: usize = 64;

/// Desired RSA key length
const DESIRED_RSA_BITS: u32 = 2048;
/// Minimum RSA key length accepted
pub const MIN_RSA_BITS: u32 = 2048;

enum VerifyCertResult {
    Ok,
    CertKeyMismatch,
    CertSignatureInvalid,
    CertCommonNameMismatch,
}

/// Use openssl to verify CA certificate.
/// # Errors
/// Will return openssl `ErrorStack` if certificate cannot be loaded or is malformed.
fn openssl_verify_cacert(ca_cert_data: &[u8]) -> Result<bool, ErrorStack> {
    let ca_cert = X509::from_pem(&ca_cert_data)?;
    info!("Try to verify CA certificate: {:?}", ca_cert);
    let pkey = ca_cert.public_key()?;
    let res = ca_cert.verify(&pkey)?;
    Ok(res)
}

/// Load and verify that the CA certificate is okay.
/// # Errors
/// Will return `CcError::CaCertNotSelfSigned` CA cerificate cannot be verified.
/// Will return `CcError::CaCertParseFailure` if passed invalid data that cannot be parsed as
/// a CA certificate by openssl.
pub fn verify_cacert(ca_cert_data: &[u8]) -> Result<(), CcError> {
    /*
       openssl  verify  -CAfile  filename, filename
    */
    match openssl_verify_cacert(ca_cert_data) {
        Ok(true) => Ok(()),
        Ok(false) => Err(CcError::CaCertNotSelfSigned),
        Err(e) => {
            error!("openssl_verify_cacert failed, underlying error: {:?}", e);
            Err(CcError::CaCertParseFailure)
        }
    }
}

/// Load and verify that the private key is okay. not too short, can be parsed, etc.
/// should probably take a path or similar rather than a string.
/// # Errors
/// Will return `CcError::PrivateKeyParseFailure` if passed invalid data that cannot be parsed as
/// a private key.
/// Will return `CcError::PrivateKeyTooShort` if the private key is to short.
pub fn verify_private_key(private_key_data: &[u8]) -> Result<(), CcError> {
    // Matching of
    /*
        openssl pkey -noout -in $filename
    */
    let pkey = match PKey::private_key_from_pem(&private_key_data) {
        Ok(c) => c,
        Err(_e) => return Err(CcError::PrivateKeyParseFailure),
    };
    if pkey.bits() < MIN_RSA_BITS {
        return Err(CcError::PrivateKeyTooShort {
            actual: pkey.bits(),
        });
    }
    Ok(())
}

fn openssl_create_private_key(size: u32) -> Result<Vec<u8>, ErrorStack> {
    let rsa = Rsa::generate(size)?;
    let pkey = PKey::from_rsa(rsa)?;
    let pem = pkey.private_key_to_pem_pkcs8()?;
    Ok(pem)
}

/// Create a new private key and return it.
/// # Errors
/// Will return `CcError::PrivateKeyCreationFailure` if a private RSA key cannot be created.
pub fn create_private_key() -> Result<Vec<u8>, CcError> {
    match openssl_create_private_key(DESIRED_RSA_BITS) {
        Ok(c) => Ok(c),
        Err(e) => {
            error!("Error creating {} bits RSA key: {}", DESIRED_RSA_BITS, e);
            Err(CcError::PrivateKeyCreationFailure)
        }
    }
}

/// Old caramel, before Open Source release, did not specify the order of the fields as strictly as today.
/// Due to the root crt not being rotated on the embedded firmwares of devices, the new clients should pass it in a work-around order for this very specific certificate.
/// This is a backwards compatibility hack around names and naming structures so it is set to only match on this specific case.
fn workaround_subject() -> (X509Name, X509Name) {
    use openssl::nid::Nid;

    let mut before = X509Name::builder().unwrap();
    before.append_entry_by_nid(Nid::COUNTRYNAME, "SE").unwrap();
    before
        .append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "Caramel")
        .unwrap();
    before
        .append_entry_by_nid(Nid::LOCALITYNAME, "Link\u{f6}ping")
        .unwrap();
    before
        .append_entry_by_nid(Nid::ORGANIZATIONNAME, "Modio AB")
        .unwrap();
    before
        .append_entry_by_nid(Nid::STATEORPROVINCENAME, "\u{d6}sterg\u{f6}tland")
        .unwrap();
    before
        .append_entry_by_nid(Nid::COMMONNAME, "Caramel Signing Certificate")
        .unwrap();

    let subj_before = before.build();

    let mut after = X509Name::builder().unwrap();
    after.append_entry_by_nid(Nid::COUNTRYNAME, "SE").unwrap();
    after
        .append_entry_by_nid(Nid::STATEORPROVINCENAME, "\u{d6}sterg\u{f6}tland")
        .unwrap();
    after
        .append_entry_by_nid(Nid::LOCALITYNAME, "Link\u{f6}ping")
        .unwrap();
    after
        .append_entry_by_nid(Nid::ORGANIZATIONNAME, "Modio AB")
        .unwrap();
    after
        .append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "Caramel")
        .unwrap();
    after
        .append_entry_by_nid(Nid::COMMONNAME, "Caramel Signing Certificate")
        .unwrap();
    let subj_after = after.build();

    (subj_before, subj_after)
}

/// Convert the PEM data in `ca_data` into a certificate, and clone it's subject out.
/// ^ `ca_data` is CA certificate.
fn clone_subject(ca_data: &[u8]) -> Result<X509Name, ErrorStack> {
    let ca_cert = X509::from_pem(&ca_data)?;
    let mut ca_subject = X509Name::builder()?;
    // From a cert we cannot get an _owned_ copy of the subject without loading if from a PEM file
    // on disk.
    // This iterates over the subject and copies it element-by-element instead, in order to make
    // sure that we are the sole owner of all the subjects
    for entry in ca_cert.subject_name().entries() {
        let entry_nid = entry.object().nid();
        let entry_text = entry.data().as_utf8()?;
        ca_subject.append_entry_by_nid(entry_nid, &entry_text)?;
    }
    Ok(ca_subject.build())
}

/// Parse the cert-data from a file, returning an owned copy of a CA subject.
/// This handles the data-replacement of our "known bad" compatibility subject as well.
/// #Errors
/// Will return openssl `ErrorStack` the data-replacemen the in the X509 object fails.
fn get_ca_subject(ca_data: &[u8]) -> Result<X509Name, ErrorStack> {
    let subject = clone_subject(ca_data)?;
    let (before, after) = workaround_subject();

    // This should technically compare the two item-by-item
    // However, string-wise comparision seems to also work about as well.
    // btw. as_ref is needed as we can only print _references_ to an object, not the actual object.
    let real_subj = format!("{:?}", subject.as_ref());
    let should_replace = format!("{:?}", before.as_ref());
    if real_subj == should_replace {
        debug!(
            "Backwards compatibility hack in place. Replacing subjects.
Original: '{:?}'
Replaced: '{:?}'",
            subject.as_ref(),
            after.as_ref()
        );
        Ok(after)
    } else {
        Ok(subject)
    }
}

/// Make a new subject from the CA subject
///
/// ex.  Converts  from
///    `subject=C = SE, O = ModioAB, OU = Sommar, CN = Caramel Signing Certificate`
/// to
///    `subject=C = SE, O = ModioAB, OU = Sommar, CN = be172c92-d002-4f8d-a702-32683f57d3f9`
/// It passes through all data-points _except_ COMMONNAME, which is set to `client_id`
///
/// This code works with OpenSSL datatypes and errors
/// # Errors
/// Will return openssl `ErrorStack` if openssl fails.
fn make_inner_subject(ca_subject: &X509NameRef, client_id: &str) -> Result<X509Name, ErrorStack> {
    use openssl::nid::Nid;

    let mut subject = X509Name::builder()?;
    let all_entries = ca_subject.entries();
    for entry in all_entries {
        let entry_nid = entry.object().nid();
        let entry_text = entry.data().as_utf8()?;

        if entry_nid == Nid::COMMONNAME {
            debug!("Changing {:?}=={} => {}", entry_nid, &entry_text, client_id);
            subject.append_entry_by_nid(Nid::COMMONNAME, client_id)?;
        } else {
            debug!("Passing through {:?}=={}", &entry_nid, &entry_text);
            subject.append_entry_by_nid(entry_nid, &entry_text)?;
        }
    }
    let our_subject = subject.build();
    Ok(our_subject)
}

/// Create a subject from a `ca_cert_data` + our expected `client_id`
/// The general case rule is to take the CA cert and _only_ replace the common name.
/// This means that all the other fields in the CA subject should match exactly.
///
/// there is also a special case that is handled when reading out the CA certificate.
/// # Errors
/// Will return openssl `ErrorStack` if openssl fails.
fn openssl_make_subject(ca_cert_data: &[u8], client_id: &str) -> Result<X509Name, ErrorStack> {
    //  This is the old Python code
    // Caramel has the extra requirement that SUBJECT should come in the same order as it was in the
    // PKI root SUBJECT, only differing in the CN= part (CommonName)
    //
    // With the one hard-coded bug-case below:
    //
    /*
        output = call("openssl x509  -subject -noout -in filename")

        state = decode_openssl_utf8(output).strip()
        # The below ugly thing is for OpenSSL 1.1, as it is no longer outputting a
        # format useful as -subject when you parse the subject
        # FIXME: EX-TER-MI-NATE
        state = state.replace("C = ", "/C=")
        state = state.replace(", OU = ", "/OU=")
        state = state.replace(", L = ", "/L=")
        state = state.replace(", O = ", "/O=")
        state = state.replace(", ST = ", "/ST=")
        state = state.replace(", CN = ", "/CN=")
        state = state.strip()
        _, value = state.split('subject=', 1)
        value = value.strip()
        prefix, original_cn = value.split('/CN=')
        if prefix == '/C=SE/OU=Caramel/L=Linköping/O=Modio AB/ST=Östergötland':
            prefix = '/C=SE/ST=Östergötland/L=Linköping/O=Modio AB/OU=Caramel'
        return '/CN={cn}/{prefix}'.format(prefix=prefix, cn=self.client_id)
    */
    let subj = get_ca_subject(&ca_cert_data)?;
    debug!("Got ca subject   {:?}", subj.as_ref());
    let new_subject = make_inner_subject(&subj, client_id)?;
    debug!("Created new subject '{:?}'", new_subject.as_ref());
    Ok(new_subject)
}

/// See if COMMONNAME of the subject matches an expected `client_id`
/// # Errors
/// Will return openssl `ErrorStack` if openssl fails.
fn check_commoname_match(subject: &x509::X509NameRef, client_id: &str) -> Result<bool, ErrorStack> {
    use openssl::nid::Nid;
    let entry = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    let raw_name = entry.data().as_utf8()?;
    let name = raw_name.to_string();
    if client_id != name {
        return Ok(false);
    }
    // MAX_CN_LENGTH is from the caramel server codebase as of 2020-07
    if name.len() > MAX_CN_LENGTH {
        return Ok(false);
    }
    Ok(true)
}

enum VerifyCsrResult {
    Ok,
    CsrDoesNotMatchPrivateKey,
    CommonNameMismatch,
}

fn openssl_verify_csr(
    csr_data: &[u8],
    private_key_data: &[u8],
    client_id: &str,
) -> Result<VerifyCsrResult, ErrorStack> {
    let pkey = PKey::private_key_from_pem(&private_key_data)?;
    let csr = X509Req::from_pem(&csr_data)?;
    let verified = csr.verify(&pkey)?;
    if !verified {
        return Ok(VerifyCsrResult::CsrDoesNotMatchPrivateKey);
    }

    let subject = csr.subject_name();
    let matching_name = check_commoname_match(subject, client_id)?;
    if !matching_name {
        return Ok(VerifyCsrResult::CommonNameMismatch);
    }

    Ok(VerifyCsrResult::Ok)
}

/// Verify that the Certificate Sign Request is valid according to our rules.
///    The Client ID must match our expected client-id.
///    The private key must match the Requests public key.
///
/// Left undone: Verify that the CSR checks out against the server
/// # Errors
///
/// Will return `CcError::CsrSignedWithWrongKey` if CSR cannot be validated.
/// Will return `CcError::CsrValidationFailure` if CSR cannot be parsed.
/// Will return `CcError::CsrCommonNameMismatch` if CommonName in CSR does not match client_id.
pub fn verify_csr(
    csr_data: &[u8],
    private_key_data: &[u8],
    client_id: &str,
) -> Result<(), CcError> {
    /*
            openssl req -noout -verify -in csrfile -key keyfile
    */

    let valid = openssl_verify_csr(csr_data, private_key_data, client_id);
    match valid {
        Ok(VerifyCsrResult::Ok) => Ok(()),
        Ok(VerifyCsrResult::CsrDoesNotMatchPrivateKey) => Err(CcError::CsrSignedWithWrongKey),
        Ok(VerifyCsrResult::CommonNameMismatch) => Err(CcError::CsrCommonNameMismatch),
        Err(e) => {
            error!("Error parsing CSR: {}", e);
            Err(CcError::CsrValidationFailure)
        }
    }
}

// Use openssl to verify the CA certificate.
/// # Errors
/// Will return openssl `ErrorStack` if either input is invalid.
fn openssl_verify_cert(
    cert_data: &[u8],
    ca_cert_data: &[u8],
    private_key_data: &[u8],
    client_id: &str,
) -> Result<VerifyCertResult, ErrorStack> {
    let private_key = PKey::private_key_from_pem(&private_key_data)?;
    let ca_cert = X509::from_pem(&ca_cert_data)?;
    let cert = X509::from_pem(&cert_data)?;

    let cert_pubkey = cert.public_key()?;
    let ok_key = private_key.public_eq(&cert_pubkey);
    if !ok_key {
        return Ok(VerifyCertResult::CertKeyMismatch);
    }

    let ca_pubkey = ca_cert.public_key()?;
    let ok_signature = cert.verify(&ca_pubkey)?;
    if !ok_signature {
        return Ok(VerifyCertResult::CertSignatureInvalid);
    }

    let subject = cert.subject_name();
    let ok_name = check_commoname_match(subject, client_id)?;
    if !ok_name {
        return Ok(VerifyCertResult::CertCommonNameMismatch);
    }
    Ok(VerifyCertResult::Ok)
}

/// Verify that the CA certificate we downloaded matches what we want checks:
///     Private key corresponds to public key in the cert
///     subject/ Common name in cert matches our client id
///     Cert signature was signed by our expected CA cert
/// # Errors
/// Will return `CcError` if CA certificate does not match or cannot be valided.
pub fn verify_cert(
    cert_data: &[u8],
    ca_cert_data: &[u8],
    private_key_data: &[u8],
    client_id: &str,
) -> Result<(), CcError> {
    /*
     * openssl verify -CAfile ca_cert_file_name, temp_cert_file_name
     */
    match openssl_verify_cert(cert_data, ca_cert_data, private_key_data, client_id) {
        Ok(VerifyCertResult::Ok) => Ok(()),
        Ok(VerifyCertResult::CertKeyMismatch) => Err(CcError::CertKeyMismatch),
        Ok(VerifyCertResult::CertSignatureInvalid) => Err(CcError::CertSignatureInvalid),
        Ok(VerifyCertResult::CertCommonNameMismatch) => Err(CcError::CertCommonNameMismatch),
        Err(e) => {
            error!("Error verifying CA certificate: {}", e);
            Err(CcError::CertValidationFailure)
        }
    }
}

/// Create a new CSR request from the OpenSSL Private key and Subject, returning the data as a PEM
/// Create a new CSR request from the OpenSSL Private key and Subject,
/// returning the data as a PEM object vector.
/// This function works on and with OpenSSL data-types.
/// # Errors
/// Will return openssl `ErrorStack` if either input is invalid.
fn openssl_create_csr(private_key_data: &[u8], subject: &X509Name) -> Result<Vec<u8>, ErrorStack> {
    use openssl::hash::MessageDigest;
    use openssl::x509::X509ReqBuilder;

    let private_key = PKey::private_key_from_pem(private_key_data)?;

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&private_key)?;
    req_builder.set_subject_name(&subject)?;
    req_builder.sign(&private_key, MessageDigest::sha256())?;
    let req = req_builder.build();
    let pem = req.to_pem()?;
    Ok(pem)
}

/// Make a CSR. Indata is so generic, but I don't know the openssl/rust datatypes well enough placeholder.
/// # Errors
/// Will return `CcError::CsrBuildSubjectFailure` if a openssl object cannot be created.
/// Will return `CcError::CsrBuildFailure` if CSR cannot be created.
pub fn create_csr(
    ca_cert_data: &[u8],
    private_key_data: &[u8],
    client_id: &str,
) -> Result<Vec<u8>, CcError> {
    /*
    config:
        [ req ]
        default_bits        = 2048
        default_md      = sha256
        default_keyfile     = privkey.pem
        distinguished_name  = req_distinguished_name
        attributes      = req_attributes
        x509_extensions = v3_req    # The extentions to add to the self signed cert
        string_mask = utf8only

        [ v3_req ]
        basicConstraints = CA:FALSE
        keyUsage = nonRepudiation, digitalSignature, keyEncipherment

        [ req_distinguished_name ]
        countryName         = Country Name (2 letter code)
        countryName_default     = AU
        countryName_min         = 2
        countryName_max         = 2
        stateOrProvinceName     = State or Province Name (full name)
        stateOrProvinceName_default = Some-State
        localityName            = Locality Name (eg, city)
        0.organizationName      = Organization Name (eg, company)
        0.organizationName_default  = Internet Widgits Pty Ltd
        organizationalUnitName      = Organizational Unit Name (eg, section)
        commonName          = Common Name (e.g. server FQDN or YOUR name)
        commonName_max          = 64
        emailAddress            = Email Address
        emailAddress_max        = 64

        [ req_attributes ]
        challengePassword       = A challenge password
        challengePassword_min       = 4
        challengePassword_max       = 20
        unstructuredName        = An optional company name
    */

    // base requirements, distilled
    // constraints = CA:FALSE
    // keyUsage =     nonRepudiation, digitalSignature, keyEncipherment
    // CommonName max == 64
    // CN min = 2
    // CN max = 2
    // md = sha256
    //
    //
    /*
     *
     *   cnf.name is a file that contains the config from above
     *   subject is the result of the above "make_subject" function
         openssl req  -config cnf.name -sha256 -utf8 -new -key key_file_name -out csr_file_name -subj subject
    */

    let subject = match openssl_make_subject(ca_cert_data, &client_id) {
        Ok(c) => c,
        Err(e) => {
            error!("OpenSSL Error building request: {}", e);
            return Err(CcError::CsrBuildSubjectFailure);
        }
    };
    let pemdata = match openssl_create_csr(private_key_data, &subject) {
        Ok(c) => c,
        Err(e) => {
            error!("OpenSSL Error building request: {}", e);
            return Err(CcError::CsrBuildFailure);
        }
    };
    Ok(pemdata)
}

// To enable logging for one testcase, change "#[test]" -> "#[test_env_log::test]",
// when execute `cargo test -- --nocapture` or `cargo test --workspace --verbose -- --nocapture`
#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::blobs::testdata::{
        convert_string_to_vec8, OTHER_CLIENT_ID1, RANDOM_DATA_KEY_DATA1, TOO_SMALL_KEY_DATA1,
        VALID_CACERT_DATA1, VALID_CLIENT_ID1, VALID_CRT_DATA1, VALID_CSR_DATA1, VALID_KEY_DATA1,
        VALID_KEY_DATA2, WORKAROUND_CACERT, WORKAROUND_CSR_DATA1,
    };

    #[test]
    fn test_fail_on_key_with_to_few_bits() {
        let key_with_too_few_bits = convert_string_to_vec8(TOO_SMALL_KEY_DATA1);
        let golden_short_key_error = CcError::PrivateKeyTooShort { actual: 1024 };
        let result = verify_private_key(&key_with_too_few_bits);
        assert!(result.is_err());
        assert_eq!(Some(golden_short_key_error), result.err());
    }

    #[test]
    fn test_fail_on_key_with_random_data() {
        let key_with_random_data = convert_string_to_vec8(RANDOM_DATA_KEY_DATA1);
        let result = verify_private_key(&key_with_random_data);
        assert!(result.is_err());
        assert_eq!(Some(CcError::PrivateKeyParseFailure), result.err());
    }

    #[test_env_log::test]
    fn test_accept_valid_cacert() {
        let valid_cacert = convert_string_to_vec8(VALID_CACERT_DATA1);
        let result = verify_cacert(&valid_cacert);
        assert!(result.is_ok());
    }

    #[test]
    fn test_accept_valid_workaround_cacert() {
        let valid_cacert = convert_string_to_vec8(WORKAROUND_CACERT);
        let result = verify_cacert(&valid_cacert);
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fail_on_signed_crtificate() {
        let signed_cert = convert_string_to_vec8(VALID_CRT_DATA1);
        let result = verify_cacert(&signed_cert);
        assert!(result.is_err());
        assert_eq!(Some(CcError::CaCertNotSelfSigned), result.err());
    }

    #[test]
    fn test_fail_on_random_data_as_certificate() {
        let random_data = convert_string_to_vec8(RANDOM_DATA_KEY_DATA1);
        let result = verify_cacert(&random_data);
        assert!(result.is_err());
        assert_eq!(Some(CcError::CaCertParseFailure), result.err());
    }

    #[test]
    fn test_verify_csr_happy() {
        let client_id = "06bc4ab2-dbaf-11ea-9abc-00155dcdee8d";
        let key = convert_string_to_vec8(VALID_KEY_DATA1);
        let csr = convert_string_to_vec8(VALID_CSR_DATA1);

        let result = verify_csr(&csr, &key, &client_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_csr_failure() {
        let client_id = "06bc4ab2-dbaf-11ea-9abc-00155dcdee8d";
        let csr = convert_string_to_vec8(VALID_CSR_DATA1);
        let key = create_private_key().unwrap();
        let result = verify_csr(&csr, &key, &client_id);

        match result {
            Err(e) => assert_eq!(CcError::CsrSignedWithWrongKey, e),
            Ok(_) => panic!("Should not be ok with different key"),
        }
    }

    #[test]
    fn test_verify_csr_failure_when_clientid_differs() {
        let key = convert_string_to_vec8(VALID_KEY_DATA1);
        let csr = convert_string_to_vec8(VALID_CSR_DATA1);
        let result = verify_csr(&csr, &key, &OTHER_CLIENT_ID1);
        match result {
            Err(e) => assert_eq!(CcError::CsrCommonNameMismatch, e),
            Ok(_) => panic!("Should not be ok with client id mismatch"),
        }
    }

    /// Normal functionality, subject passed through and CSR generated
    #[test]
    fn test_making_csr_no_override() {
        let valid_key = convert_string_to_vec8(VALID_KEY_DATA1);
        let ca_sommar_modio_se = convert_string_to_vec8(VALID_CACERT_DATA1);
        let expected = convert_string_to_vec8(VALID_CSR_DATA1);

        let result = create_csr(
            &ca_sommar_modio_se,
            &valid_key,
            "06bc4ab2-dbaf-11ea-9abc-00155dcdee8d",
        );
        assert!(result.is_ok());
        let csr = result.unwrap();
        assert_eq!(csr, expected);
    }

    #[test]
    /// Override functionality, should fail
    fn test_making_csr_with_override() {
        let valid_key = convert_string_to_vec8(VALID_KEY_DATA1);
        let ca_modio_se = convert_string_to_vec8(WORKAROUND_CACERT);

        let result = create_csr(
            &ca_modio_se,
            &valid_key,
            "06bc4ab2-dbaf-11ea-9abc-00155dcdee8d",
        );
        assert!(result.is_ok());
        let csr = result.unwrap();
        let csr_text = std::str::from_utf8(&csr).unwrap();
        assert_eq!(csr_text, WORKAROUND_CSR_DATA1);
    }

    #[test]
    fn test_verify_cert_fails_on_mismatch_key() {
        let cert = convert_string_to_vec8(VALID_CRT_DATA1);
        let ca_cert = convert_string_to_vec8(VALID_CACERT_DATA1);
        let other_key = convert_string_to_vec8(VALID_KEY_DATA2);

        let result = verify_cert(&cert, &ca_cert, &other_key, &VALID_CLIENT_ID1);
        match result {
            Err(e) => assert_eq!(CcError::CertKeyMismatch, e),
            Ok(_) => panic!("Should not be ok with key mismatch"),
        }
    }

    #[test]
    fn test_verify_cert_fails_on_mismatch_client_id() {
        let cert = convert_string_to_vec8(VALID_CRT_DATA1);
        let ca_cert = convert_string_to_vec8(VALID_CACERT_DATA1);
        let key = convert_string_to_vec8(VALID_KEY_DATA1);

        let result = verify_cert(&cert, &ca_cert, &key, &OTHER_CLIENT_ID1);
        match result {
            Err(e) => assert_eq!(CcError::CertCommonNameMismatch, e),
            Ok(_) => panic!("Should not be ok with client id mismatch"),
        }
    }

    #[test]
    fn test_verify_cert_fails_on_mismatch_signing_cert() {
        let cert = convert_string_to_vec8(VALID_CRT_DATA1);
        let other_ca_cert = convert_string_to_vec8(WORKAROUND_CACERT);
        let key = convert_string_to_vec8(VALID_KEY_DATA1);

        let result = verify_cert(&cert, &other_ca_cert, &key, &VALID_CLIENT_ID1);
        match result {
            Err(e) => assert_eq!(CcError::CertSignatureInvalid, e),
            Ok(_) => panic!("Should not be ok with key mismatch"),
        }
    }
}
