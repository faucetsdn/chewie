#!/bin/bash
set -e  # quit on error

# See https://docs.travis-ci.com/user/environment-variables/#convenience-variables
echo TRAVIS_BRANCH: $TRAVIS_BRANCH
echo TRAVIS_COMMIT: $TRAVIS_COMMIT

if [ $TRAVIS_SHARD == "unittest" ]; then
  env CHEWIE_TESTS="-i -n" ./run_tests.sh

  if [ $CODE_COV == "true" ]; then
    codecov || true
  fi

  if [ $CODE_CHECK == "true" ]; then
    env CHEWIE_TESTS="-z -i -u" ./run_tests.sh
  fi

  exit 0
fi

if [ $TRAVIS_SHARD == "integration" ]; then
  env CHEWIE_TESTS="-n -z -u" ./run_tests.sh
fi