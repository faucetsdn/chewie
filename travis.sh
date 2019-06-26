#!/bin/bash

docker run -it --rm --privileged --cap-add NET_ADMIN -v $(pwd):/chewie-src:ro \
    faucet/test-base /chewie-src/run_tests.sh