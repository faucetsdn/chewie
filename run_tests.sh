#!/bin/sh
# TODO: must be run from chewie root
pip3 install .
if [ -z "${TRAVIS_PYTHON_VERSION}" ]; then
    PYTYPE_TARGET_VERSION=3.6
else
    PYTYPE_TARGET_VERSION=$TRAVIS_PYTHON_VERSION
fi

echo "=============== Running UnitTests ================="

PYTHONPATH=./ pytest --cov=chewie --cov-report term --cov-report=xml:coverage.xml test/test_*.py || exit 1

echo "=============== Running PyType ===================="
pytype -V$PYTYPE_TARGET_VERSION chewie/*py || exit 1

cd test/codecheck
echo "=============== Running Pylint ===================="
./pylint.sh || exit 1

exit 0
