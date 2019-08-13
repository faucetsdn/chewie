#!/bin/bash
FILE_NAME=$(readlink -f "$0")
set -e  # quit on error

CHEWIE_ROOT=$(dirname "$FILE_NAME")

PIP_INSTALL=0
UNIT_TEST=0
CODE_CHECK=0
INTEGRATION=0

# allow user to skip parts of docker test
while getopts "nuzi" o $CHEWIE_TESTS; do
  case "${o}" in
        n)
            CODE_CHECK=1
            ;;
        u)
            UNIT_TEST=1
            ;;
        i)
            INTEGRATION=1
            ;;
        z)
            PIP_INSTALL=1
            ;;
        *)
            echo "Provided unsupported option. Exiting with code 1"
            exit 1
            ;;
    esac
done

# ============================= PIP Install =============================
if [ "$PIP_INSTALL" == 1 ] ; then
    echo "=============== Installing Pypi Dependencies ================="
    pip3 install --upgrade --cache-dir=/var/tmp/pip-cache \
        -r ${CHEWIE_ROOT}/test-requirements.txt -r ${CHEWIE_ROOT}/requirements.txt
fi

# ============================= Unit Tests =============================
if [ "$UNIT_TEST" == 1 ] ; then
    echo "=============== Running Unit Tests ================="
    time env PYTHONPATH=${CHEWIE_ROOT} pytest -v --cov=chewie \
        ${CHEWIE_ROOT}/test/unit/test_*.py
fi

# ============================= Code Checks =============================
if [ "$CODE_CHECK" == 1 ] ; then

    echo "=============== Running PyType ===================="
    time PYTHONPATH=${CHEWIE_ROOT} pytype --config ${CHEWIE_ROOT}/setup.cfg \
        ${CHEWIE_ROOT}/chewie/*py

    echo "=============== Running Pylint ===================="
    time ${CHEWIE_ROOT}/test/codecheck/pylint.sh
fi

# ============================= Integration Tests =============================
if [ "$INTEGRATION" == 1 ] ; then
    echo "=============== Running Integration Tests ===================="
    time docker run -it --rm --privileged --cap-add NET_ADMIN -e CHEWIE_ROOT="/chewie-src/" \
        -e PIP_INSTALL=1 -v ${CHEWIE_ROOT}:/chewie-src:ro -v /var/tmp/pip-cache:/var/tmp/pip-cache \
        faucet/test-base bash /chewie-src/docker/run_integration_tests.sh
fi
