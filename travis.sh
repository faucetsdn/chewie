#!/bin/bash

# TODO : Set to readonly after run_script refactor and output logs to separate folder.
docker run -it --rm --privileged --cap-add NET_ADMIN -v $(pwd):/chewie-src \
    faucet/test-base bash -c "cd /chewie-src && ./run_tests.sh"