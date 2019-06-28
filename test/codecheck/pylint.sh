#!/bin/bash

CHEWIEHOME=`dirname $0`"/../.."
echo $CHEWIEHOME

SRCFILES="$CHEWIEHOME/test/codecheck/src_files.sh"
echo $SRCFILES

$SRCFILES | xargs -n 1 -P 8 $CHEWIEHOME/test/codecheck/min_pylint.sh || exit 1
exit 0