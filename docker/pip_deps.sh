#!/bin/bash

set -e

CHEWIE_ROOT=`dirname $0`/..
CHEWIE_ROOT=`readlink -f $CHEWIE_ROOT`
PIPARGS="install -q --upgrade $*"

for r in test-requirements.txt requirements.txt ; do
  pip3 $PIPARGS -r ${CHEWIE_ROOT}/$r
done
