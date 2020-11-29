"""The main certificate manager class."""

from datetime import datetime
import logging
import os
import pwd
import socket
import subprocess
import tldextract

from .utils import extract_x509_dns_names, send_email
from .backends import StorageError


logger = logging.getLogger(__name__)


class CertificateManager:
    """Main class of the certificate manager.

    This class coordinates retrieving information from the storage backend and Certbot, deciding
    which certificates need to be requested and which ones removes, and actuating the required
    actions.
    """
    def __init__(self, certbot, domain_config, cert_storage, additional_domains,
                 dns_delay=0, extract_x509_dns_names_func=extract_x509_dns_names, failure_alert_email=None):
        """Initialize a CertificateManager instance."""
        self.certbot = certbot
        self.domain_config = domain_config
        self.cert_storage = cert_storage
        self.dns_delay = dns_delay
        self.additional_domains = additional_domains
        self.extract_x509_dns_names = extract_x509_dns_names_func
        self.failure_alert_email = failure_alert_email

    def remove_cert(self, main_domain):
        """Remove a certificate from both Certbot and the backend storage."""
        try:
            self.certbot.remove_cert(main_domain)
            logger.info(
                "Successfully deleted the certificate for %s from Certbot.", main_domain
            )
        except subprocess.CalledProcessError as exc:
            message = "Failed to delete the certificate for %s from Certbot:\n%s"
            logger.error(
                message,
                main_domain,
                exc.stderr,
            )
            self.send_failure_alert_email(message % (main_domain, ''), exc)
        try:
            self.cert_storage.remove_cert(main_domain)
            logger.info(
                "Successfully deleted the certificate for %s from the storage backend.", main_domain
            )
        except StorageError as exc:
            message = "Failed to delete the certificate for %s from the storage backend."
            logger.error(message, main_domain)
            self.send_failure_alert_email(message % (main_domain, ), exc)

    def request_cert(self, domains):
        """Request a new certificate using the Certbot client."""
        try:
            self.certbot.request_cert(domains)
            logger.info(
                "Successfully obtained a new certificate for these domains:\n    %s",
                "\n    ".join(domains),
            )
        except subprocess.CalledProcessError as exc:
            error_domains = "\n    ".join(domains)
            message = (
                "Failed to obtain a new certificate for these domains:\n    %s\n%s"
            )
            logger.error(
                message,
                error_domains,
                exc.stderr,
            )
            self.send_failure_alert_email(message % (error_domains, ''), exc)
        except Exception as exc:  # pylint: disable=broad-except
            message = (
                "An exception occurred when trying to obtain a new certificate for these "
                "domains:\n    %s"
                "\n    ".join(domains)
            )
            logger.exception(message)
            self.send_failure_alert_email(message, exc)

    def send_failure_alert_email(self, message, exception):
        """
        If a failure alert email address is provided, send a failure alert email with the given message
        and exception
        """
        if self.failure_alert_email:
            from_address = '{}@{}'.format(pwd.getpwuid(os.getuid())[0], socket.gethostname())
            exception_msg = exception.stderr.decode('utf-8') if hasattr(exception, 'stderr') else str(exception)
            email_message = (
                'From: {}\n'
                'To: {}\n'
                'Subject: Alert: {}\n\n'
                'Below is the exception:\n{}'
            ).format(from_address, self.failure_alert_email, message.replace('\n', ''), exception_msg)
            send_email(from_address, self.failure_alert_email, email_message)

    def get_current_domains(self):
        """Return the domain names of all certificates in the storage backend.

        The return value is a dictionary mapping each certificate name to the set of all domain
        names the certificate covers.
        """
        current_certs = self.cert_storage.get_all_certs()
        current_domains = {}
        for main_domain, pem_data in current_certs.items():
            try:
                current_domains[main_domain] = set(self.extract_x509_dns_names(pem_data))
            except ValueError:
                logger.error("Unable to determine domain names for certificate %s.", main_domain)
        return current_domains

    def request_missing(self, configured_domains, current_domains):
        """Request new certificates where needed."""
        for main_domain, domain_group in configured_domains.items():
            # Check if at least some of the domains are not covered by the current certificate
            domains = domain_group['domains']
            if set(domains) - current_domains.get(main_domain, set()):
                # Request new certificates, but only if DNS records for the domain have already
                # been set, *and* they have been set more than a preconfigured number of seconds ago
                # to allow the changes to propagate.
                timestamp = datetime.utcnow().timestamp()
                dns_updated = domain_group['dns_records_updated']
                if dns_updated is not None and timestamp - dns_updated > self.dns_delay:
                    internal_domains = []
                    external_domains = []
                    for each_domain in domains:
                        domain_elem = tldextract.extract(each_domain)
                        # Separate internal domains and external domains
                        if domain_elem.domain == 'opencraft':
                            internal_domains.append(each_domain)
                        else:
                            external_domains.append(each_domain)
                    # request separate certs for each of the domains
                    if internal_domains:
                        self.request_cert(internal_domains)
                    if external_domains:
                        self.request_cert(external_domains)

    def remove_unneeded(self, configured_domains, current_domains):
        """Remove unneeded certificates from the backend storage."""
        all_domains = set()
        for main_domain, domain_group in configured_domains.items():
            if domain_group['dns_records_updated'] is not None:
                all_domains.update(domain_group['domains'])
        for main_domain, dns_names in current_domains.items():
            if dns_names.isdisjoint(all_domains):
                # The certificate isn't needed for any of the currently active domains
                self.remove_cert(main_domain)

    def run(self):
        """Run the certificate manager and update all certificates."""
        configured_domains = self.domain_config.get_domain_groups()
        if self.additional_domains is not None:
            for domain in self.additional_domains:
                configured_domains[domain] = {
                    'domains': [domain],
                    # Assume DNS entries for additional have been set up a long time ago:
                    'dns_records_updated': 0,
                }
        current_domains = self.get_current_domains()
        self.request_missing(configured_domains, current_domains)
        self.remove_unneeded(configured_domains, current_domains)
