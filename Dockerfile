FROM rust

ENV LANG  C.utf8
ENV LANGUAGE C.utf8
ENV LC_ALL C.utf8

WORKDIR '/data'
# First try call init to make a trivial program, add our Cargo.toml to download all dependencies
# to create a cache of everything we need before adding our actual sourcecode
RUN USER=rust cargo init --name caramel-client-rs && \
    mv src/main.rs src/caramel-client.rs
COPY Cargo.toml .
RUN cargo update && \
    cargo generate-lockfile && \
    cargo fetch && \
    cargo build && \
    cargo install --path .

# Now copy everything (source code) and build the application
COPY . .
RUN cargo build && cargo install --path .
RUN cargo run -- --help ||:

CMD ["cargo run"]

# Build container with:             docker build -t caramel-client-rs .

# For development map code and run with bash:
# docker run -it -v `pwd`/.:/data caramel-client-rs bash
# In the container to run code: cargo run
