# Fuzzing, how to

To use the fuzzing targets you need to first install the cargo plugin:

    # cargo install cargo-fuzz

Documentation:  

- https://rust-fuzz.github.io/book/cargo-fuzz/guide.html
- https://github.com/rust-fuzz/cargo-fuzz

# Running fuzz jobs

Fuzz jobs (today) only work in nightly mode of rust.

List all jobs:

    # cargo +nightly fuzz list

    create_csr
    private_key
    verify_cacert
    verify_cert
    verify_cert_2



At 2020-08-27, running the fuzz targets required a nightly toolchain to be
installed, if you haven't already installed a nightly toolchain,

    # rustup toolchain install nightly

Run jobs:

    # cargo +nightly fuzz run verify_cacert

Usually you want to run more than a single thread, so perhaps:

    # cargo +nightly fuzz run -j4 verify_cacert


# Take a peek inside a fuzz job:

    # cat fuzz/fuzz_targets/verify_cacert.rs 

    #![no_main]
    use libfuzzer_sys::fuzz_target;
    use caramel_client::certs::verify_cacert;

    fuzz_target!(|data: &[u8]| {
        let _ = verify_cacert(&data);
    });

Simple, no? Corpus data lives in `fuzz/corpus/verify_cacert/`,  you should
usually place a couple of "good" working examples there, and perhaps some
"good" bad examples too.


# Coverage?

Well, crypto stuff is going to be hard for the fuzzer to generate (public key
data, etc.) so that might not be a good choice. 

On the other hand, the outputs of non-crypto file parsing & validation is a
pretty good thing to run fuzzers on.
