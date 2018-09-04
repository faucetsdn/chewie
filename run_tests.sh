#!/bin/sh

# TODO: must be run from chewie root
# TODO: add pylint
PYTHONPATH=./ pytest --cov=chewie --cov-report=xml:coverage.xml test/
# TODO: add pytype
# && pytype -V3.5 -d import-error chewie/*py
