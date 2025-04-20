#!/usr/bin/env bash

docker run --rm -p 8089:8089 \
  -v $(pwd)/cephyproxy.toml:/config.toml \
  cephyproxy
