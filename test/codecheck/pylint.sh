#!/bin/bash
CURR_DIR=`dirname $0`
CHEWIEHOME=$CURR_DIR"/../.."
SRCFILES="$CHEWIEHOME/test/codecheck/src_files.sh"
$SRCFILES | xargs -n 1 -P 8 $CURR_DIR/min_pylint.sh || exit 1
exit 0