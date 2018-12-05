# Chewie

[![Build Status](https://travis-ci.com/faucetsdn/chewie.svg?branch=master)](https://travis-ci.com/faucetsdn/chewie)
[![Maintainability](https://api.codeclimate.com/v1/badges/66b6e93ba93b6ac56d17/maintainability)](https://codeclimate.com/github/faucetsdn/chewie/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/66b6e93ba93b6ac56d17/test_coverage)](https://codeclimate.com/github/faucetsdn/chewie/test_coverage)

## Chewie - EAPOL / 802.1x
Chewie is an EAPOL/802.1x implementation in Python.
It is designed to work on it's own but primarily as a module for [The Faucet Project](https://github.com/faucetsdn/faucet)
which is an open-source SDN controller implementation in Python.

### Supported Features:
* PEAP
* MD5-SUM   
* TLS
* TTLS

 
## Configuration
Setting up credentials with Chewie can be set on the Radius server, if using the default configuration this can be found
in the `etc/freeradius/users` file.

The default credentials for the username and password are `user` and `microphone` respectively.
Example authentication certificates for TLS / TTLS / PEAP have been provided in the `etc` folder. 

NOTE: These are self-signed certificates


## Getting Started:

Getting started with Chewie is as easy as starting a docker-compose network. This has been described below.
If you would like to learn about the requirements for running Chewie, all of the dependencies for Chewie have been 
defined in the `Dockerfile.chewie` file, with the `pip` dependencies defined in the `requirements.txt` and 
`test-requirements.txt` files respectively.

### Docker / Docker-Compose:

#### Setup

If needed, installation instructions for [Docker](https://store.docker.com/) and [Docker-Compose](https://docs.docker.com/compose/) can be
found on the official Docker website or by following the links provided.

#### Starting a Docker-Compose

##### To run Chewie in the Docker-Compose Environment:

`docker-compose up --build`

##### To Stop and Clean Up the Docker Environment

`docker-compose down`

## Development 

## Building the Docker Image

For a developer to build and run the Chewie inside a Docker it is easy to pass through the live source-code to the Docker 
container, allowing for the developer to restart Chewie and code changes to be active on application restart.

To get started working with `Chewie`, the main image needs to be built before a developer can run it.

`docker build -t chewie_image -f docker/Dockerfile.chewie .`

To start the docker image inside a container, mounting the `Chewie` source code to `/chewie/` the instruction below is provided:

`docker run -it -v $(pwd)/:/chewie/:ro chewie_image /bin/bash`

To run Chewie once in the Docker environment:
`python3 /chewie/run.py`

#### Testing

##### Running unit-tests in Docker 

To build and run the Chewie test-suite inside a Docker:

```
docker build -t chewie_test_image -f docker/Dockerfile.test .
docker run -t chewie_test_image
```


#### Questions / Bugs

If there are any questions or bugs found please report them to the Chewie project via the issue link.
This can be found at 
[https://github.com/faucetsdn/chewie/issues](https://github.com/faucetsdn/chewie/issues)


