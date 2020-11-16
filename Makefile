IMAGE_REPO = registry.gitlab.com/modioab/caramel-client-rs/client
IMAGE_DOCKERFILE = Dockerfile

IMAGE_FILES += empty/.keep
IMAGE_FILES += ssl.tar
IMAGE_FILES += target/x86_64-unknown-linux-musl/release/caramel-client-rs

CLEANUP_FILES += ssl.tar
CLEANUP_FILES += empty/.keep
CLEANUP_FILES += empty

ssl.tar:
	tar -cf ssl.tar /etc/ssl/ /etc/pki/tls/certs/ /etc/pki/ca-trust/

empty:
	mkdir -p $@

empty/.keep: empty
	touch $@

include build.mk
