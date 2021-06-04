#!/bin/bash

set -euo pipefail

SCRIPTPATH=$(readlink -f "$0")
TESTDIR=$(dirname "${SCRIPTPATH}")

srcfiles="${TESTDIR}/src_files.sh $*"
${srcfiles} | xargs -n 1 -P 8 "${TESTDIR}/min_pylint.sh"
