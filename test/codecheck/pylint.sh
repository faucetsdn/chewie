#!/bin/bash

CHEWIEHOME=`dirname $0`"/../.."
SRCFILES="$CHEWIEHOME/test/codecheck/src_files.sh"
$SRCFILES | xargs -n 1 -P 8 ./min_pylint.sh || exit 1
exit 0