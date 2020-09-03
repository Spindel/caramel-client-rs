# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2020 Modio AB

FROM scratch

ARG URL=unknown
ARG COMMIT=unknown
ARG BRANCH=unknown
ARG HOST=unknown
ARG DATE=unknown
LABEL "se.modio.ci.url"=$URL  "se.modio.ci.branch"=$BRANCH  "se.modio.ci.commit"=$COMMIT  "se.modio.ci.host"=$HOST  "se.modio.ci.date"=$DATE

ADD ssl.tar /

COPY empty /data/
COPY target/x86_64-unknown-linux-musl/release/caramel-client-rs /usr/bin/caramel-client-rs

WORKDIR /data
ENTRYPOINT ["/usr/bin/caramel-client-rs"]
