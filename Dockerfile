# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2020 Modio AB
FROM rust:buster AS build

# To make sure we build & link against the same libraries, we install openssl and curl headers.
RUN apt-get update \
    && apt-get install -y libcurl4-openssl-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data
COPY . /data
RUN cargo build --release

FROM debian:buster

ARG URL=unknown
ARG COMMIT=unknown
ARG BRANCH=unknown
ARG HOST=unknown
ARG DATE=unknown
LABEL "se.modio.ci.url"=$URL  "se.modio.ci.branch"=$BRANCH  "se.modio.ci.commit"=$COMMIT  "se.modio.ci.host"=$HOST  "se.modio.ci.date"=$DATE

# To run, we currently need:
#    ca-certificates ( public PKI root)
#    libssl (openssl)
#    libcurl (curl)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcurl4 libssl1.1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /data/target/release/caramel-client-rs /usr/bin/caramel-client-rs

WORKDIR /data
ENTRYPOINT ["/usr/bin/caramel-client-rs"]
