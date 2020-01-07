OpenCraft Certificate Manager
=============================

This repository contains a certificate manager based on Certbot, using the Consul key-value store to retrieve its configuration and store the requested certificates.  It is intended to be used together with Ocim [1], the OpenCraft Open edX Instance Manager.

[1]: https://github.com/open-craft/opencraft

Running the unit tests
----------------------

To run the unit tests locally, first make sure you have pipenv installed.  One way to install it is

    pip install --user pipenv

You can then install the development requirements using

    pipenv install --dev

and run the tests with

    pipenv run pytest

How to reprovision certificates
-------------------------------

If a certificate wasn't automatically renewed for some reason, you can trigger a renewal in this way:

1. Log in to the `cert-manager` server as root and run `cerbot delete`, then select the number of the certificate you want to delete.

2. From the consul web interface, navigate to `ocim/certs` and delete the entry corresponding to the old certificate.

3. From the consul web interface, navigate to `ocim/instances` and find the instance number that you're editing. You can find the instance ID in Ocim (`OpenEdXInstance` admin). Edit the instance data by adding some harmless whitespace and click save. This will trigger the renewal.

4. You can watch `journalctl -f -u cert-manager.service` in cert-manager to verify that cert-manager requested the new certificate. You should see a message like _Successfully obtained a new certificate for these domains:_

5. After some seconds (around 15) the site will be working with the new certificate. You may need to empty the SSL cache from your browser
