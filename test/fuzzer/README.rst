Fuzzing
=======

Running
-------
There are two fuzzers, one for fuzzing the EAP parser, and another for fuzzing the RADIUS parser.
Both parsers use the same dockerfile 'Dockerfile.fuzz', to select which parser to fuzz against set
the environment variable 'PARSER' to 'eap' or 'radius' when running the docker container.

.. code:: console

  sudo docker build -t chewie/packet-fuzzer -f Dockerfile.fuzz .

  PARSER_TYPE=eap  # 'eap' or 'radius'
  sudo docker run --name chewie-fuzzer-$PARSER_TYPE -v /var/log/afl-$PARSER_TYPE/:/var/log/afl -v /var/log/chewie-$PARSER_TYPE/:/var/log/chewie -e PARSER=$PARSER_TYPE chewie/packet-fuzzer

