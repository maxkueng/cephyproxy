#!/usr/bin/env bash

docker run --rm -p 8080:8080 \
  -v $(pwd)/cephyproxy.toml:/config.toml \
  cephyproxy
