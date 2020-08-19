// sketch / pseubdo code

enum CsrReply {
    Downloaded,
    Pending,
    Rejected,
    // more?
}

// Not a strict partial order since we might have differenet branches
// but generally, futher down i later in time
enum CcEvent {
    StartCaCertDownload,
    CaCertAvailable,
    PrivateKeyAvailable,
    //
    CsrCreated,
    CsrAvailible,
    SendingCsrToServer,
    CrtReply(CsrReply),
    CertificateAvailible,
}

// Implemented in file CaramelClientLogic
// too used to object orientation?
trait CaramelClientLogic {
    fn create() -> CcContext;
    // inputs
    fn inject_user(context: CcContext, user: CaramelClientUser);
    fn inject_ca_cert(context: CcContext, cacert: &[u8]);
    fn inject_private_key(context: CcContext, key: &[u8]);
    fn inject_csr(context: CcContext, csr: &[u8]);

    fn restart_from(context: CcContext, state: CcEvent);

    // different run modes follow

    /// Run until the next event/callback
    fn run_single_step(context: CcContext);
    fn run_untill_retry(context: CcContext);
    fn run_forever(context: CcContext);
}

// Implemented by user, simple example found in file_based_client.rs
trait CaramelClientUser {
    // outputs
    fn event(&self, event: CcEvent);

    // One idea might to throw out all these functions and add more enums to event, and give them arguments.

    fn ca_cert_downloaded(&self, cacert: &[u8]);
    fn private_key_created(&self, key: &[u8]);
    fn csr_created(&self, csr: &[u8]);
    fn csr_reply(&self, reply: CsrReply);
    fn cert_downloaded(&self, cert: &[u8]);
}

// Perhaps most users are not in the habit of simulating 200 users (clients) run within the same program, and hence
// have little need for receiving a context (this pointer) when an event is tiggered.

#[allow(dead_code)]
struct FileBasedClientImpl {
    dir: &str,
    stem: &str,
}

impl CaramelClientUser for FileBasedClientImpl {
    pub fn new(dir: &str, filename_stem: &str) -> CaramelClientUser {
        CaramelClientUser {
            dir: dir,
            stem: filename_stem,
        }
    }
    fn write_to_file(&self, suffix: &str, data: &[u8]) {
        let filename = format("{}/{}.{}", self.dir, self.stem, suffix);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&filename)
            .unwrap();
        // Write the content to file and be done
        file.write_all(&data).unwrap();
    }

    fn event(&self, event: CcEvent) {
        println!("{:?}", event);
    }

    // Borde den här lagras under det CN som den innehåller?
    fn ca_cert_downloaded(&self, cacert: &[u8]) {
        write_to_file("cacert", cacert);
    }

    fn private_key_created(&self, key: &[u8]) {
        write_to_file("key", key);
    }

    fn csr_created(&self, csr: &[u8]) {
        write_to_file("key", key);
    }

    fn csr_reply(&self, reply: CsrReply) {
        println!("CSR reply {:?}", reply);
    }

    fn cert_downloaded(&self, cert: &[u8]) {
        write_to_file("crt", key);
    }
}
