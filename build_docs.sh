#!/usr/bin/env bash

mkdir -p ./docs
INSTALL="export DEBIAN_FRONTEND=noninteractive && apt install -y python3-sphinx python3-eventlet"
SPHINX_API="sphinx-apidoc -lFP -o /build /chewie"
HTML_BUILD="env PYTHONPATH=/ sphinx-build -b html /build /docs"
CHOWN="chown -R $(id -u):$(id -g) /docs"

docker build --tag chewie_build_docs -f Dockerfile.chewie .
docker run --rm -v $(pwd)/chewie:/chewie:ro -v $(pwd)/docs:/docs -it \
        chewie_build_docs \
        /bin/bash -c "$INSTALL && $SPHINX_API && $HTML_BUILD && $CHOWN"
