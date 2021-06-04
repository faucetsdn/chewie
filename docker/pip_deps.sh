#!/bin/bash

set -euo pipefail

SCRIPTPATH=$(readlink -f "$0")
SCRIPTDIR=$(dirname "${SCRIPTPATH}")
BASEDIR=$(readlink -f "${SCRIPTDIR}/..")

reqs="test-requirements.txt requirements.txt"
pip_args=""

pip3="pip3 install -q --upgrade ${pip_args}"

"${BASEDIR}/docker/retrycmd.sh" "${pip3} wheel"

for req in ${reqs}; do
  "${BASEDIR}/docker/retrycmd.sh" "${pip3} -r ${BASEDIR}/${req}"
done
