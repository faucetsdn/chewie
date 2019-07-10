#!/bin/bash

if [ "$PIP_INSTALL" == 1 ] ; then
    echo "=============== Installing Pypi Dependencies ================="
    pip3 install  --cache-dir --upgrade \
    -r ${CHEWIE_ROOT}/test-requirements.txt -r ${CHEWIE_ROOT}/requirements.txt
fi


if [ -z "$CHEWIE_ROOT" ] ; then
    CHEWIE_ROOT=$(pwd)/..
fi


PYTHONPATH=${CHEWIE_ROOT} pytest -v ${CHEWIE_ROOT}/test/integration/test_*.py