# Chewie

[![Build Status](https://github.com/faucetsdn/chewie/workflows/Unit%20tests/badge.svg?branch=main)](https://github.com/faucetsdn/chewie/actions?query=workflow%3A%22Unit+tests%22)
[![Test Coverage](https://codecov.io/gh/faucetsdn/chewie/branch/main/graph/badge.svg)](https://codecov.io/gh/faucetsdn/chewie)

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

#### Questions / Bugs

If there are any questions or bugs found please report them to the Chewie project via the issue link.
This can be found at
[https://github.com/faucetsdn/chewie/issues](https://github.com/faucetsdn/chewie/issues)
