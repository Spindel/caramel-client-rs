FROM rust

ENV LANG  C.utf8
ENV LANGUAGE C.utf8
ENV LC_ALL C.utf8

WORKDIR '/data'
COPY . .

RUN cargo install --path .

CMD ["cargo run"]

# Build container with:             docker build -t caramel-client-rs .

# For development map code and run with bash:
# docker run -it -v `pwd`/.:/data caramel-client-rs bash
# In the container to run code: cargo run