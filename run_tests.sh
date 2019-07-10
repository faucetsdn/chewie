#!/bin/bash
FILE_NAME=$(readlink -f "$0")
set -e  # quit on error

CHEWIE_ROOT=$(dirname "$FILE_NAME")

PIP_INSTALL=1
UNIT_TEST=1
CODE_CHECK=1

# allow user to skip parts of docker test
while getopts "nuz" o $CHEWIE_TESTS; do
  case "${o}" in
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
        z)
            # skip pip install
            echo "Skipping PIP Install."
            PIP_INSTALL=0
            ;;
        *)
            echo "Provided unsupported option. Exiting with code 1"
            exit 1
            ;;
    esac
done

if [ -z "${TRAVIS_PYTHON_VERSION}" ]; then
    PYTYPE_TARGET_VERSION=3.7
else
    PYTYPE_TARGET_VERSION=$TRAVIS_PYTHON_VERSION
fi


# ============================= Unit Tests =============================
if [ "$PIP_INSTALL" == 1 ] ; then
    echo "=============== Installing Pypi Dependencies ================="
    pip3 install --upgrade -r ${CHEWIE_ROOT}/test-requirements.txt -r ${CHEWIE_ROOT}/requirements.txt
fi

# ============================= Unit Tests =============================
if [ "$UNIT_TEST" == 1 ] ; then
    echo "=============== Running Unit Tests ================="
    time env PYTHONPATH=${CHEWIE_ROOT} pytest -v --cov=chewie --cov-report term \
        --cov-report=xml:coverage.xml ${CHEWIE_ROOT}/test/unit/test_*.py
fi

# ============================= Code Checks =============================
if [ "$CODE_CHECK" == 1 ] ; then

    if [ "${PYTYPE}" != "false" ] ; then
        echo "=============== Running PyType ===================="
        time PYTHONPATH=${CHEWIE_ROOT} pytype -V$PYTYPE_TARGET_VERSION ${CHEWIE_ROOT}/chewie/*py
    fi

    echo "=============== Running Pylint ===================="
    time ${CHEWIE_ROOT}/test/codecheck/pylint.sh
fi