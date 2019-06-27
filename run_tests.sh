#!/bin/bash
set -e  # quit on error

bash --version


FILE_NAME=$(readlink -f "$0")
export CHEWIE_ROOT=$(dirname "$FILE_NAME")
export MIN_LINT_RATING=8.0
export MIN_CODE_COVERAGE=40

UNIT_TEST=1
CODE_CHECK=1

# allow user to skip parts of the tests
while getopts "nu" o $CHEWIE_TESTS; do
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

echo "=============== Installing Pip Dependencies ================="
pip3 install --upgrade -q -r ${CHEWIE_ROOT}/test-requirements.txt -r ${CHEWIE_ROOT}/requirements.txt

# ============================= Unit Tests =============================
if [ "$UNIT_TEST" == 1 ] ; then
    echo "=============== Running Unit Tests ================="
    time env PYTHONPATH=${CHEWIE_ROOT}/ pytest -v --cov=chewie --cov-report term \
        --cov-report=xml:coverage.xml ${CHEWIE_ROOT}/test/test_*.py
fi

# ============================= Code Checks =============================
if [ "$CODE_CHECK" == 1 ] ; then

    if [ "${PYTYPE}" != "false" ] ; then
        echo "=============== Running PyType ===================="
        pytype -V$PYTYPE_TARGET_VERSION ${CHEWIE_ROOT}/chewie/*py
    fi
    
    echo "=============== Running Pylint ===================="
    bash ${CHEWIE_ROOT}/test/codecheck/pylint.sh
fi
