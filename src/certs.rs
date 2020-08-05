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

println!("Validating private key in file '{}'", filename);
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
    let subj_after = after.build();
    return (subj_before, subj_after);
}

/// Create a subject from a CAcert + our expected clientid
/// placeholder
fn make_subject(cacert_filename: &String, _clientid: &String) -> Result<String, String> {
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
    use openssl::x509;
    println!("About to read CA cert from file {}", cacert_filename);
    let contents = match std::fs::read(cacert_filename) {
        Ok(c) => c,
        _ => return Err("Unable to read cacert from file when getting subject".to_owned()),
    };

    let (before, after) = workaround_subject();

    fn get_subject(data: &Vec<u8>) -> Result<String, ErrorStack> {
        let cacert = x509::X509::from_pem(&data)?;
        println!("Got cacert: {:?}", cacert);
        let subject_name = cacert.subject_name();
        let issuer_name = cacert.issuer_name();
        println!("Subject: {:?}", subject_name);
        println!("Issuer: {:?}", issuer_name);
        Ok("abc".to_owned())
    }

    let subj = match get_subject(&contents) {
        Ok(c) => c,
        Err(e) => {
            println!("Error parsing CA cert: {}", e);
            return Err("Could not get subject from ca cert".to_owned());
        }
    };

    Err("make_subject is not implemented".to_owned())
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
    make_subject(&cacert_filename, &clientid)?;
    Err("make_csr_request is not implemented".to_owned())
}
