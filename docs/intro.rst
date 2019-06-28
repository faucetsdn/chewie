Introduction
============

What is Chewie?
-----------------------------

Chewie is an EAPOL/802.1x implementation in Python.
It is designed to work on it's own but primarily as a module for `The Faucet Project`_
which is an open-source SDN controller implementation in Python.


Supported Features:
~~~~~~~~~~~~~~~~~~~

-  PEAP
-  MD5-SUM
-  TLS
-  TTLS

Configuration
-------------

Setting up credentials with Chewie can be set on the Radius server, if
using the default configuration this can be found in the
``etc/freeradius/users`` file.

The default credentials for the username and password are ``user`` and
``microphone`` respectively. Example authentication certificates for TLS
/ TTLS / PEAP have been provided in the ``etc`` folder.

NOTE: These are self-signed certificates

Getting Started:
----------------

Getting started with Chewie is as easy as starting a docker-compose
network. This has been described below. If you would like to learn about
the requirements for running Chewie, all of the dependencies for Chewie
have been defined in the ``Dockerfile.chewie`` file, with the ``pip``
dependencies defined in the ``requirements.txt`` and
``test-requirements.txt`` files respectively.

Docker / Docker-Compose:
~~~~~~~~~~~~~~~~~~~~~~~~

Setup
^^^^^

If needed, installation instructions for `Docker`_ and `Docker-Compose`_
can be found on the official Docker website or by following the links
provided.

Starting a Docker-Compose
^^^^^^^^^^^^^^^^^^^^^^^^^

To run Chewie in the Docker-Compose Environment:
''''''''''''''''''''''''''''''''''''''''''''''''

``docker-compose up --build``

To Stop and Clean Up the Docker Environment
'''''''''''''''''''''''''''''''''''''''''''

``docker-compose down``

.. _The Faucet Project: https://github.com/faucetsdn/faucet
.. _Docker: https://store.docker.com/
.. _Docker-Compose: https://docs.docker.com/compose/
