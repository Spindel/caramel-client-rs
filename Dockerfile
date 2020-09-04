# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2020 Modio AB

FROM rust:buster AS build

RUN apt-get update \
    && apt-get install -y musl-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && /usr/sbin/update-ca-certificates

WORKDIR /data
COPY . /data

RUN mkdir /empty/ \
    && rustup target add x86_64-unknown-linux-musl  \
    && cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

ARG URL=unknown
ARG COMMIT=unknown
ARG BRANCH=unknown
ARG HOST=unknown
ARG DATE=unknown
LABEL "se.modio.ci.url"=$URL  "se.modio.ci.branch"=$BRANCH  "se.modio.ci.commit"=$COMMIT  "se.modio.ci.host"=$HOST  "se.modio.ci.date"=$DATE

COPY --from=build /etc/ssl/ /etc/ssl/
# We can't create a directory inside the scratch container, so we copy one
COPY --from=build /empty/ /data/
COPY --from=build /data/target/x86_64-unknown-linux-musl/release/caramel-client-rs /usr/bin/caramel-client-rs

WORKDIR /data
ENTRYPOINT ["/usr/bin/caramel-client-rs"]
