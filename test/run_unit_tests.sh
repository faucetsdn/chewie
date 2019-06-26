#!/bin/bash
set -e

MIN_CODE_COVERAGE=92
SCRIPTPATH=$(readlink -f "$0")
TESTDIR=`dirname ${SCRIPTPATH}`

# replace with chewie_ROOT
BASEDIR=`readlink -f ${TESTDIR}/..`

TESTCMD="PYTHONPATH=$BASEDIR coverage run --parallel-mode --source $BASEDIR/chewie"
SRCFILES="find $TESTDIR/unit/test_*py -type f"

coverage erase
${SRCFILES} | xargs realpath | shuf | parallel --delay 1 --bar --halt now,fail=1 -j 2 ${TESTCMD}
coverage combine
coverage report -m --fail-under=${MIN_CODE_COVERAGE}
