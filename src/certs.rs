use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509;
use openssl::x509::{X509Name, X509Req, X509};

// Encoded in upstream definitions
const MAX_CN_LENGTH: usize = 64;

const DESIRED_RSA_BITS: u32 = 2048;
const MIN_RSA_BITS: u32 = 2048;

/// Load and verify that the CACert is okay.
pub fn verify_cacert(filename: &String) -> Result<(), String> {
    /*
       openssl  verify  -CAfile  filename, filename
    */
    let cacert = load_cert(filename)?;

    fn check_cacert(cacert: X509) -> Result<bool, ErrorStack> {
        println!("Got CA cert: {:?}", cacert);
        let pkey = cacert.public_key()?;
        let res = cacert.verify(&pkey)?;
        Ok(res)
    }

    let valid = check_cacert(cacert);
    println!("Validating CA cert in file '{}'", filename);
    match valid {
        Ok(true) => Ok(()),
        Ok(false) => Err("CA cert not self-signed.".to_owned()),
        Err(e) => {
            println!("Error parsing CA cert: {}", e);
            return Err("Unable to parse CA cert".to_owned());
        }
    }
}

/// Load a file into a private key-pair object
fn load_private_key(filename: &String) -> Result<PKey<Private>, String> {
    let contents = match std::fs::read(filename) {
        Ok(c) => c,
        _ => return Err("Unable to read private key from file".to_owned()),
    };

    let pkey = PKey::private_key_from_pem(&contents);
    match pkey {
        Ok(c) => Ok(c),
        Err(e) => {
            println!("Error parsing private key: {}", e);
            return Err("Unable to parse private key".to_owned());
        }
    }
}

/// Load a file into a CSR object.
fn load_csr_file(filename: &String) -> Result<X509Req, String> {
    let contents = match std::fs::read(filename) {
        Ok(c) => c,
        _ => return Err("Unable to read CSR  from file".to_owned()),
    };

    let csr = X509Req::from_pem(&contents);

    match csr {
        Ok(c) => Ok(c),
        Err(e) => {
            println!("Error parsing CSR file from disk: {}", e);
            Err("Unable to parse csr file".to_owned())
        }
    }
}

/// Load a file into a X509 Certificate object
fn load_cert(filename: &String) -> Result<X509, String> {
    let contents = match std::fs::read(filename) {
        Ok(c) => c,
        _ => return Err("Unable to read cacert from file when verifying cacert".to_owned()),
    };

    let cert = X509::from_pem(&contents);
    match cert {
        Ok(c) => Ok(c),
        Err(e) => {
            println!("Error from openssl when loading certificate: {}", e);
            Err("Error loading key".to_owned())
        }
    }
}

/// Load and verify that the private key is okay. not too short, can be parsed, etc.
/// should probably take a path or similar rather than a string.
pub fn verify_private_key(filename: &String) -> Result<(), String> {
    // Matching of
    /*
        openssl pkey -noout -in $filename
    */

    let pkey = load_private_key(filename)?;
    if pkey.bits() < MIN_RSA_BITS {
        return Err("Private key is too short".to_owned());
    }
    Ok(())
}

/// Create a new private key and save it to filename
/// Should this take a path rather than a string?
pub fn create_private_key(filename: &String) -> Result<(), String> {
    use std::io::prelude::*;

    fn make_private_pem() -> Result<Vec<u8>, ErrorStack> {
        let rsa = Rsa::generate(DESIRED_RSA_BITS)?;
        let pkey = PKey::from_rsa(rsa)?;
        let pem = pkey.private_key_to_pem_pkcs8()?;
        return Ok(pem);
    }

    let pemdata = match make_private_pem() {
        Ok(c) => c,
        Err(e) => {
            println!("Error creating {} bits RSA key: {}", DESIRED_RSA_BITS, e);
            return Err("Could not create private RSA key".to_owned());
        }
    };
    let mut file = std::fs::File::create(filename).unwrap();

    file.write_all(&pemdata).unwrap();
    println!(
        "Wrote a new {} bit RSA key to file '{}'",
        DESIRED_RSA_BITS, filename
    );
    Ok(())
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
        .append_entry_by_nid(Nid::LOCALITYNAME, "Linköping")
        .unwrap();
    before
        .append_entry_by_nid(Nid::ORGANIZATIONNAME, "Modio AB")
        .unwrap();
    before
        .append_entry_by_nid(Nid::STATEORPROVINCENAME, "Östergötland")
        .unwrap();
    before
        .append_entry_by_nid(Nid::COMMONNAME, "Caramel Signing Certificate")
        .unwrap();

    let subj_before = before.build();

    let mut after = X509Name::builder().unwrap();
    after.append_entry_by_nid(Nid::COUNTRYNAME, "SE").unwrap();
    after
        .append_entry_by_nid(Nid::STATEORPROVINCENAME, "Östergötland")
        .unwrap();
    after
        .append_entry_by_nid(Nid::LOCALITYNAME, "Linköping")
        .unwrap();
    after
        .append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "Caramel")
        .unwrap();
    after
        .append_entry_by_nid(Nid::ORGANIZATIONNAME, "Modio AB")
        .unwrap();
    after
        .append_entry_by_nid(Nid::COMMONNAME, "Caramel Signing Certificate")
        .unwrap();
    let subj_after = after.build();

    return (subj_before, subj_after);
}

/// Parse the cert-data from a file, returning an owned copy of a CA subject.
/// This handles the data-replacement of our "known bad" compatibility subject as well.
fn get_ca_subject(filename: &String) -> Result<X509Name, ErrorStack> {
    let mut names = X509Name::load_client_ca_file(&filename)?;
    assert!(names.len() == 1, "More than 1 name present in the CA cert");

    let subject = names.pop().unwrap();
    let (before, after) = workaround_subject();

    // This should technically compare the two item-by-item
    // However, string-wise comparision seems to also work about as well.
    // btw. as_ref is needed as we can only print _references_ to an object, not the actual object.
    let real_subj = format!("{:?}", subject.as_ref());
    let should_replace = format!("{:?}", before.as_ref());
    match real_subj == should_replace {
        true => {
            println!(
                "Backwards compat hack in place. Replacing subjects.
Original: '{}'
Replaced: '{:?}'",
                real_subj,
                after.as_ref()
            );
            Ok(after)
        }
        false => Ok(subject),
    }
}

/// Make a new subject from the CA subject
///
/// ex.  Converts  from
///    `subject=C = SE, O = ModioAB, OU = Sommar, CN = Caramel Signing Certificate`
/// to
///    `subject=C = SE, O = ModioAB, OU = Sommar, CN = be172c92-d002-4f8d-a702-32683f57d3f9` 
/// It passes through all data-points _except_ CommonName, which gets set to `client_id`
/// This code works with OpenSSL datatypes and errors
fn make_inner_subject(ca_subject: X509Name, clientid: &String) -> Result<X509Name, ErrorStack> {
    use openssl::nid::Nid;

    let mut subject = X509Name::builder()?;
    let all_entries = ca_subject.entries();
    for entry in all_entries {
        let entry_nid = entry.object().nid();
        let entry_text = entry.data().as_utf8()?;

        if entry_nid == Nid::COMMONNAME {
            println!("Changing {:?}=={} => {}", entry_nid, &entry_text, clientid);
            subject.append_entry_by_nid(Nid::COMMONNAME, clientid)?;
        } else {
            println!("Passing through {:?}=={}", &entry_nid, &entry_text);
            subject.append_entry_by_nid(entry_nid, &entry_text)?;
        }
    }
    let our_subject = subject.build();
    Ok(our_subject)
}

/// Create a subject from a CAcert + our expected clientid
/// The general case rule is to take the CA cert and _only_ replace the common name.
/// This means that all the other fields in the CA subject should match exactly.
///
/// there is also a special case that is handled when reading out the CA certificate.
fn make_subject(cacert_filename: &String, clientid: &String) -> Result<X509Name, String> {
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
    let subj = match get_ca_subject(&cacert_filename) {
        Ok(c) => c,
        Err(e) => {
            println!("Error parsing CA cert: {}", e);
            return Err("Could not get subject from ca cert".to_owned());
        }
    };
    println!("Got ca subject   {:?}", subj.as_ref());
    let new_subject = match make_inner_subject(subj, clientid) {
        Ok(c) => c,
        Err(e) => {
            println!("Error building new subject: {}", e);
            return Err("Could not create new subject from ca_cert".to_owned());
        }
    };
    println!("Created new subject '{:?}'", new_subject.as_ref());
    Ok(new_subject)
}

/// See if commonname of the subject matches an expected clientid
///
fn check_commoname_match(
    subject: &x509::X509NameRef,
    clientid: &String,
) -> Result<bool, ErrorStack> {
    use openssl::nid::Nid;
    let entry = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    let raw_name = entry.data().as_utf8()?;
    let name = raw_name.to_string();
    if clientid != &name {
        return Ok(false);
    }
    // Other validation here.
    if name.len() > MAX_CN_LENGTH {
        return Ok(false);
    }
    Ok(true)
}

/// Verify that the Certificate Sign Request is valid according to our rules
/// The Client ID must match our expected client-id
/// The private key must match the Requests public ke
///
/// Left undone: Verfiy that the CSR checks out against the server

pub fn verify_csr(
    csr_filename: &String,
    private_key_filename: &String,
    clientid: &String,
) -> Result<(), String> {
    /*
            openssl req -noout -verify -in csrfile -key keyfile
    */

    let pkey = load_private_key(private_key_filename)?;
    let csr = load_csr_file(csr_filename)?;

    fn check_csrdata(
        csr: X509Req,
        pkey: PKey<Private>,
        clientid: &String,
    ) -> Result<bool, ErrorStack> {
        let verified = csr.verify(&pkey)?;
        let subject = csr.subject_name();
        let matching_name = check_commoname_match(subject, clientid)?;

        Ok(verified && matching_name)
    }

    let valid = check_csrdata(csr, pkey, clientid);
    match valid {
        Ok(true) => Ok(()),
        Ok(false) => Err("CSR not signed by our private key".to_owned()),
        Err(e) => {
            println!("Error parsing CSR: {}", e);
            return Err("Unable to validate CSR".to_owned());
        }
    }
}

/// Verify that the cert we downloaded matches what we want
/// checks:
///     Private key corresponds to public key in the cert
///     subject/ Common name in cert matches our client id
///     Cert signature was signed by our expected CA cert
pub fn verify_cert(
    cert_file_name: &String,
    ca_cert_file_name: &String,
    private_key_file: &String,
    clientid: &String,
) -> Result<(), String> {
    /*
     * openssl verify -CAfile ca_cert_file_name, temp_cert_file_name
     */
    let pkey = load_private_key(private_key_file)?;
    let ca_cert = load_cert(ca_cert_file_name)?;
    let cert = load_cert(cert_file_name)?;

    fn check_cert_matching(
        ca_cert: X509,
        cert: X509,
        private_key: PKey<Private>,
        clientid: &String,
    ) -> Result<bool, ErrorStack> {
        let subject = cert.subject_name();
        let ca_pubkey = ca_cert.public_key()?;
        let ok_name = check_commoname_match(subject, clientid)?;
        let ok_signature = cert.verify(&ca_pubkey)?;
        let cert_pubkey = cert.public_key()?;
        let ok_key = private_key.public_eq(&cert_pubkey);
        Ok(ok_name && ok_signature && ok_key)
    }

    let valid = check_cert_matching(ca_cert, cert, pkey, clientid);
    match valid {
        Ok(true) => Ok(()),
        Ok(false) => Err("Certificates load but do not match".to_owned()),
        Err(e) => {
            println!("Error verifying certificate: {}", e);
            Err("Unable to validate certificate".to_owned())
        }
    }
}

/// Create a new CSR request from the OpenSSL Private key and Subject, returning the data as a PEM
/// object vector.
/// This function works on and with OpenSSL data-types.
fn make_new_request(private_key: PKey<Private>, subject: X509Name) -> Result<Vec<u8>, ErrorStack> {
    use openssl::hash::MessageDigest;
    use openssl::x509::X509ReqBuilder;

    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&private_key)?;
    req_builder.set_subject_name(&subject)?;
    req_builder.sign(&private_key, MessageDigest::sha256())?;
    let req = req_builder.build();
    let pem = req.to_pem()?;
    Ok(pem)
}

/// Make a CSR. Indata is so generic, but I don't know the openssl/rust datatypes well enough
/// placeholder
pub fn create_csr_request(
    csr_filename: &String,
    cacert_filename: &String,
    clientid: &String,
    private_key_filename: &String,
) -> Result<(), String> {
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
    use std::io::prelude::*;

    let subject = make_subject(&cacert_filename, &clientid)?;
    let pkey = load_private_key(private_key_filename)?;

    let pemdata = match make_new_request(pkey, subject) {
        Ok(c) => c,
        Err(e) => {
            println!("OpenSSL Error building request: {}", e);
            return Err("Error while building new Certificate Sign Request".to_owned());
        }
    };
    let mut file = std::fs::File::create(csr_filename).unwrap();
    file.write_all(&pemdata).unwrap();
    Ok(())
}
