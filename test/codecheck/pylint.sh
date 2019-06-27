#!/bin/bash

set -e  # quit on error

echo "pylint"
CDIR=`dirname $0`
if [ -z "$CHEWIE_ROOT" ]; then
    CHEWIE_ROOT=$(realpath ${CDIR}"/../..")
fi

SRCFILES="$CHEWIE_ROOT/test/codecheck/src_files.sh"
$SRCFILES
$SRCFILES | xargs -n 1 -P 8 ${CDIR}/min_pylint.sh || exit 1
exit 0