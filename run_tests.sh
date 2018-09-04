#!/bin/sh
# TODO: must be run from chewie root
# TODO: add pylint
pip install .
if [ -z "${TRAVIS_PYTHON_VERSION}" ]; then
    PYTYPE_TARGET_VERSION=3.6
else
    PYTYPE_TARGET_VERSION=$TRAVIS_PYTHON_VERSION
fi

PYTHONPATH=./ pytest --cov=chewie --cov-report term --cov-report=xml:coverage.xml test/test_*.py && pytype -V$PYTYPE_TARGET_VERSION chewie/*py
