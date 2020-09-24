#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deploy a certificate to the storage backend (currently Consul).

This command is meant to be run as a Certbot deploy hook.
"""

import argparse
import logging
import os
import pathlib
import sys

from cert_manager.certbot import CertbotClient
from cert_manager.backends import ConsulCertificateStorage
from cert_manager.utils import configure_logger

logger = logging.getLogger()


def parse_command_line(args):
    """Parse the command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-level", default="info")
    parser.add_argument("--consul-certs-prefix", default="certs")
    parser.add_argument("--certbot-path", default="/snap/bin/certbot")
    return parser.parse_args(args)


def main(args):
    """Parse command line, deploy certificate to Consul."""
    config = parse_command_line(args)
    configure_logger(logger, config.log_level.upper())

    certbot_client = CertbotClient(certbot_path=config.certbot_path)
    live_dir = pathlib.Path(os.environ["RENEWED_LINEAGE"])
    pem_data = certbot_client.get_cert_data_from_live_dir(live_dir)

    cert_storage = ConsulCertificateStorage(config.consul_certs_prefix)
    main_domain = os.environ["RENEWED_DOMAINS"].split()[0]
    cert_storage.deploy_cert(main_domain, pem_data)


if __name__ == "__main__":
    main(sys.argv[1:])
