#!/bin/sh
# TODO: must be run from chewie root
# TODO: add pylint
PYTHONPATH=./ pytest --cov=chewie --cov-report term --cov-report=xml:coverage.xml test/test_*.py && pytype -V$TRAVIS_PYTHON_VERSION chewie/*py
