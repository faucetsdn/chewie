Development
===========

Building the Docker Image
-------------------------

For a developer to build and run the Chewie inside a Docker it is easy
to pass through the live source-code to the Docker container, allowing
for the developer to restart Chewie and code changes to be active on
application restart.

To get started working with ``Chewie``, the main image needs to be built
before a developer can run it.

``docker build -t chewie_image -f docker/Dockerfile.chewie .``

To start the docker image inside a container, mounting the ``Chewie``
source code to ``/chewie/`` the instruction below is provided:

``docker run -it -v $(pwd)/:/chewie/:ro chewie_image /bin/bash``

To run Chewie once in the Docker environment: ``python3 /chewie/run.py``

Testing
=======

Running unit-tests in Docker
-----------------------------

To build and run the Chewie test-suite inside a Docker:

``docker build -t chewie_test_image -f docker/Dockerfile.test .``
``docker run -t chewie_test_image``

Questions / Bugs


If there are any questions or bugs found please report them to the Chewie project via the issue link.
This can be found at https://github.com/faucetsdn/chewie/issues