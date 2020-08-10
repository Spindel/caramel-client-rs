use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

const DESIRED_RSA_BITS: u32 = 2048;
const MIN_RSA_BITS: u32 = 2048;

/// Load and verify that the CACert is okay.
pub fn verify_cacert(filename: &String) -> Result<(), String> {
    /*
       openssl  verify  -CAfile  filename, filename
    */
    use openssl::x509;
    let contents = match std::fs::read(filename) {
        Ok(c) => c,
        _ => return Err("Unable to read CA cert from file when verifying cacert".to_owned()),
    };

    fn check_cacert(data: &Vec<u8>) -> Result<bool, ErrorStack> {
        let cacert = x509::X509::from_pem(&data)?;
        println!("Got CA cert: {:?}", cacert);
        let pkey = cacert.public_key()?;
        let res = cacert.verify(&pkey)?;
        Ok(res)
    }

    let valid = check_cacert(&contents);
    println!("Validating cacert in file '{}'", filename);
    match valid {
        Ok(true) => Ok(()),
        Ok(false) => Err("CA cert not self-signed.".to_owned()),
        Err(e) => {
            println!("Error parsing CA cert: {}", e);
            return Err("Unable to parse CA cert".to_owned());
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

    let contents = match std::fs::read(filename) {
        Ok(c) => c,
        _ => return Err("Unable to read private key from file".to_owned()),
    };

    let pkey = match PKey::private_key_from_pem(&contents) {
        Ok(c) => c,
        Err(e) => {
            println!("Error parsing private key: {}", e);
            return Err("Unable to parse private key".to_owned());
        }
    };
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
fn workaround_subject() -> (openssl::x509::X509Name, openssl::x509::X509Name) {
    use openssl::nid::Nid;
    use openssl::x509::{X509Name, X509};

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
fn get_ca_subject(filename: &String) -> Result<openssl::x509::X509Name, ErrorStack> {
    use openssl::x509;
    let mut names = x509::X509Name::load_client_ca_file(&filename)?;
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
fn make_inner_subject(
    ca_subject: openssl::x509::X509Name,
    clientid: &String,
) -> Result<openssl::x509::X509Name, ErrorStack> {
    use openssl::nid::Nid;
    use openssl::x509::{X509Name, X509};

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
/// placeholder
fn make_subject(
    cacert_filename: &String,
    clientid: &String,
) -> Result<openssl::x509::X509Name, String> {
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

pub fn verify_csr(_csrfile: &String, _keyfile: &String) -> Result<String, String> {
    /*
            openssl req -noout -verify -in csrfile -key keyfile
    */
    Err("verify_csr is not implemented".to_owned())
}

/// Verify that the cert we downloaded matches what we want
/// placeholder
pub fn verfiy_cert(_temp_cert: &String, _ca_cert_file_name: &String) -> Result<String, String> {
    // Missing: Check that it's for the same ClientId that we requested
    // Missing: Check that the pubkey in the cert matches our private keyfile
    /*
     * openssl verify -CAfile ca_cert_file_name, temp_cert_file_name
     */
    Err("verify_cert is not implemented".to_owned())
}

/// Make a CSR. Indata is so generic, but I don't know the openssl/rust datatypes well enough
/// placeholder
pub fn make_csr_request(cacert_filename: &String, clientid: &String) -> Result<String, String> {
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
    let _subject = make_subject(&cacert_filename, &clientid)?;
    Err("make_csr_request is not implemented".to_owned())
}
