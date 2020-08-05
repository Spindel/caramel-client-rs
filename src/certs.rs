use openssl::pkey::PKey;
use openssl::rsa::Rsa;

/// Load and verify that the CACert is okay.
pub fn verify_cacert(_filename: &String) -> Result<(), String> {
    /*
       openssl  verify  -CAfile  filename, filename
    */
    Err("verify_cacert is not implemented.".to_owned())
}

/// Load and verify that the private key is okay. not too short, can be parsed, etc.
/// should probably take a path or similar rather than a string.
/// placeholder
pub fn verify_private_key(_filename: &String) -> Result<(), String> {
    // Matching of
    /*
        openssl pkey -noout -in $filename
    */
    Err("verify_key is not implemented".to_owned())
}

/// Create a new private key and save it to filename
/// Should definitely take a path...
/// placeholder
pub fn create_private_key(_filename: &String) -> Result<(), String> {
    /*
        openssl genrsa -out  $filename 2048
    */
    let rsa = Rsa::generate(2048).unwrap();
    let _pkey = PKey::from_rsa(rsa).unwrap();
    Err("create_private_key is not implemented".to_owned())
}

/// Create a subject from a CAcert + our expected clientid
/// placeholder
fn make_subject(_cacert_filename: &String, _clientid: &String) -> Result<String, String> {
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
    Err("make_subject is not implemented".to_owned())
}

pub fn verify_csr(_csrfile: &String, _keyfile: &String) -> Result<String, String> {
    /*
            openssl req -noout -verify -in csrfile -key keyfile
    */
    Err("verify_csr is implemented".to_owned())
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
pub fn make_csr_request(_indata: &String, _clientid: &String) -> Result<String, String> {
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
    make_subject(&"place_holder".to_owned(), &"place_holder".to_owned())?;
    Err("make_csr_request is not implemented".to_owned())
}
