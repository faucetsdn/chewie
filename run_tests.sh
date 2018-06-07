#!/bin/bash

cd /chewie-src/
python3 -m pytest --cov=chewie/ --cov-report term --cov-report=xml:coverage.xml test/
