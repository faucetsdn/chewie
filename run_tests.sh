#!/bin/bash
FILE_NAME=$(readlink -f "$0")
export CHEWIE_ROOT=$(dirname "$FILE_NAME")
set -e  # quit on error

LOG_DIR=/tmp/

UNIT_TEST=1
CODE_CHECK=1
INTEGRATION=1
#MIN_CODE_COVERAGE=85
MIN_LINT_RATING=8.0

# allow user to skip parts of docker test
while getopts "inu" o $CHEWIE_TESTS; do
  case "${o}" in
        i)
            # run only integration tests
            echo "Running Integration Tests."
            UNIT_TEST=0
            CODE_CHECK=0
            ;;
        n)
            # skip code check
            echo "Skipping Code Checks."
            CODE_CHECK=0
            ;;
        u)
            # skip unit tests
            echo "Skipping Unit Tests."
            UNIT_TEST=0
            ;;
        *)
            echo "Provided unsupported option. Exiting with code 1"
            exit 1
            ;;
    esac
done

if [ -z "${TRAVIS_PYTHON_VERSION}" ]; then
    PYTYPE_TARGET_VERSION=3.6
else
    PYTYPE_TARGET_VERSION=$TRAVIS_PYTHON_VERSION
fi

echo "=============== Installing Pypi Dependencies ================="
pip3 install --upgrade -q -r ${CHEWIE_ROOT}/test-requirements.txt -r ${CHEWIE_ROOT}/requirements.txt

# ============================= Unit Tests =============================
if [ "$UNIT_TEST" == 1 ] ; then
    echo "=============== Running Unit Tests ================="
    time PYTHONPATH=${CHEWIE_ROOT} pytest -v --cov=chewie --cov-report term \
        --cov-report=xml:${LOG_DIR}coverage.xml ${CHEWIE_ROOT}/test/test_*.py
fi

# ============================= Code Checks =============================
if [ "$CODE_CHECK" == 1 ] ; then

    if [ "${PYTYPE}" != "false" ] ; then
        echo "=============== Running PyType ===================="
        time pytype -V$PYTYPE_TARGET_VERSION ${CHEWIE_ROOT}/chewie/*py
    fi
    
    echo "=============== Running Pylint ===================="
    time ${CHEWIE_ROOT}/test/codecheck/pylint.sh
fi

# ============================= Integration Tests =============================
if [ "$INTEGRATION" == 1 ] ; then
    echo "=============== Running Integration Tests ===================="
    time PYTHONPATH=${CHEWIE_ROOT} pytest -v ${CHEWIE_ROOT}/test/integration/test_*.py
fi