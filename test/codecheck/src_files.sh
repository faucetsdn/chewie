#!/bin/bash

set -e  # quit on error

echo "src_files"

if [ -z "$CHEWIE_ROOT" ]; then
    CDIR=`dirname $0`
    CHEWIE_ROOT=$(realpath ${CDIR}"/../..")
fi

for i in chewie test ; do find $CHEWIE_ROOT/$i/ -type f -name [a-z]*.py ; done
