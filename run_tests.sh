#!/bin/sh
# TODO: must be run from chewie root
pip3 install .
if [ -z "${TRAVIS_PYTHON_VERSION}" ]; then
    PYTYPE_TARGET_VERSION=3.6
else
    PYTYPE_TARGET_VERSION=$TRAVIS_PYTHON_VERSION
fi

echo "=============== Running UnitTests ================="

PYTHONPATH=./ pytest -v --cov=chewie --cov-report term --cov-report=xml:coverage.xml test/test_*.py || exit 1

if [ "${PYTYPE}" != "false" ] ; then
echo "=============== Running PyType ===================="
pytype -V$PYTYPE_TARGET_VERSION chewie/*py || exit 1
fi

START_DIR=$(pwd)
cd test/codecheck
echo "=============== Running Pylint ===================="
./pylint.sh || exit 1
cd $START_DIR

echo "=============== Running Blackbox ===================="
# TODO Change when faucet takes docker image
docker run --rm --cap-add NET_ADMIN -it \
       	-v $(pwd)/etc/wpasupplicant/cert/:/tmp/cert/:ro \
       	-v $(pwd)/:/chewie-src/:ro \
        -v $(pwd)/etc/freeradius/clients.conf:/etc/freeradius/clients.conf:ro \
        -v $(pwd)/etc/freeradius/users:/etc/freeradius/users:ro \
        -v $(pwd)/etc/freeradius/certs:/etc/freeradius/certs michaelwasher/chewie_blackbox \
	/chewie-src/docker/run_integration.sh || exit 1

