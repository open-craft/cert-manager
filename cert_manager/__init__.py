"""The main certificate manager class."""

from datetime import datetime
import logging
import subprocess

from .utils import extract_x509_dns_names
from .backends import StorageError


logger = logging.getLogger(__name__)


class CertificateManager:
    """Main class of the certificate manager.

    This class coordinates retrieving information from the storage backend and Certbot, deciding
    which certificates need to be requested and which ones removes, and actuating the required
    actions.
    """
    def __init__(self, certbot, domain_config, cert_storage, additional_domains,
                 dns_delay=0, extract_x509_dns_names_func=extract_x509_dns_names):
        """Initialize a CertificateManager instance."""
        self.certbot = certbot
        self.domain_config = domain_config
        self.cert_storage = cert_storage
        self.dns_delay = dns_delay
        self.additional_domains = additional_domains
        self.extract_x509_dns_names = extract_x509_dns_names_func

    def remove_cert(self, main_domain):
        """Remove a certificate from both Certbot and the backend storage."""
        try:
            self.certbot.remove_cert(main_domain)
            logger.info(
                "Successfully deleted the certificate for %s from Certbot.", main_domain
            )
        except subprocess.CalledProcessError as exc:
            logger.error(
                "Failed to delete the certificate for %s from Certbot:\n%s",
                main_domain,
                exc.stderr,
            )
        try:
            self.cert_storage.remove_cert(main_domain)
            logger.info(
                "Successfully deleted the certificate for %s from the storage backend.", main_domain
            )
        except StorageError:
            logger.error(
                "Failed to delete the certificate for %s from the storage backend.", main_domain
            )

    def request_cert(self, domains):
        """Request a new certificate using the Certbot client."""
        try:
            self.certbot.request_cert(domains)
            logger.info(
                "Successfully obtained a new certificate for these domains:\n    %s",
                "\n    ".join(domains),
            )
        except subprocess.CalledProcessError as exc:
            logger.error(
                "Failed to obtain a new certificate for these domains:\n    %s\n%s",
                "\n    ".join(domains),
                exc.stderr,
            )
        except Exception:  # pylint: disable=broad-except
            logger.exception(
                "An exception occurred when trying to obtain a new certificate for these "
                "domains:\n    %s",
                "\n    ".join(domains),
            )

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
                    self.request_cert(domains)

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
