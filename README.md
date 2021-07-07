OpenCraft Certificate Manager
=============================

This repository contains a certificate manager based on Certbot, using the Consul key-value store to retrieve its configuration and store the requested certificates.  It is intended to be used together with Ocim [1], the OpenCraft Open edX Instance Manager.

[1]: https://github.com/open-craft/opencraft

Running the unit tests
----------------------

There are two options to run the unit tests:

### Devstack way:

To run the unit tests in a devstack (containers), you need to start the devstack:

    make start

and run the tests:

    make test

### Locally way:

To run the unit tests locally, first make sure you have pipenv installed.  One way to install it is

    pip install --user pipenv

You can then install the pinned development requirements using

    pipenv install --dev --ignore-pipfile

and run the tests with

    pipenv run pytest
