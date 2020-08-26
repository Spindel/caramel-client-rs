#![no_main]
use libfuzzer_sys::fuzz_target;
use caramel_client::certs::verify_cacert;

fuzz_target!(|data: &[u8]| {
    let _ = verify_cacert(&data);
});
