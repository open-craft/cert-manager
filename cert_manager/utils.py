"""Utility functions for the certificate manager."""

import logging.handlers
import smtplib

import OpenSSL.crypto


def extract_x509_dns_names(pem_data):
    """Extract the DNS names from the given PEM certificate."""
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_data)
    for i in range(x509.get_extension_count()):
        ext = x509.get_extension(i)
        if ext.get_short_name() == b"subjectAltName":
            dns_names = []
            for component in ext._subjectAltNameString().split(", "):
                name_type, name = component.split(":", 1)
                if name_type == "DNS":
                    dns_names.append(name.lower())
            return dns_names
    for label, value in x509.get_subject().get_components():
        if label == b"CN":
            return [value.decode("utf8").lower()]
    raise ValueError("the certificate does not contain a valid Common Name, "
                     "nor valid Subject Alternative Names")


def configure_logger(logger_, log_level):
    """Configure the logger to log to the syslog with the given log level."""
    logger_.setLevel(log_level)
    handler = logging.handlers.SysLogHandler(address='/dev/log')
    handler.setFormatter(logging.Formatter("%(filename)s: %(message)s"))
    logger_.addHandler(handler)
    stderr_handler = logging.StreamHandler()
    stderr_handler.setLevel(logging.ERROR)
    logger_.addHandler(stderr_handler)


def send_email(from_address, to_addresses, message, mail_server='localhost'):
    """Send email using locally setup mailserver"""
    smtp = smtplib.SMTP(mail_server)
    smtp.sendmail(from_address, to_addresses, message)
