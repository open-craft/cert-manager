"""Storage and configuration backends for the certificate manager."""

import json
import logging
import re

import consul


logger = logging.getLogger()


class DomainConfiguration:
    """An abstract provider of the certificate configuration."""

    def get_domain_groups(self):
        """Return all currently configured domain groups.

        Domain groups are lists of domain names that correspond to a single certificate.  The
        certificate manager will ensure that there is a certificate for each configured domain
        group.

        This function returns a dictionary mapping the main domain name to a list of domains.
        """
        raise NotImplementedError


class CertificateStorage:
    """An abstract storage backend for certificate data."""

    def get_cert_data(self, main_domain):
        """Return the stored PEM data for the certificate idenitified by `main_domain`.

        The data is returned as a `bytes` object.  If the storage backend does not contain any data
        for the given key, `None` is returned instead.
        """
        raise NotImplementedError

    def get_all_certs(self):
        """Return a dictionary of all stored certificates.

        The dictionary maps the main domain names to the PEM data of each certificate.
        """
        raise NotImplementedError

    def deploy_cert(self, main_domain, pem_data):
        """Deploy the given PEM certificate to the storage backend."""
        raise NotImplementedError

    def remove_cert(self, main_domain):
        """Delete the certificate identified by `main_domain` from the storage backend.

        If there is no certificate for the given key, this function does nothing.
        """
        raise NotImplementedError


class StorageError(Exception):
    """An error with a storage backend.

    This class is used to signal backend storage errors to the certificate manager.
    """

### Consul-based backend implementations ###

class ConsulDomainConfiguration(DomainConfiguration):
    """Retrieve the domain configuration from Consul.

    The data is assumed to be in the format stored by the Ocim Open edX instance manager.
    """

    def __init__(self, prefix):
        """Initialize the backend with the given Consul prefix."""
        self.prefix = prefix


    def get_domain_groups(self):
        """Return all currently configured domain groups.

        Domain groups are lists of domain names that correspond to a single certificate.  The
        certificate manager will ensure that there is a certificate for each configured domain
        group.

        This function returns a dictionary mapping the main domain name to a list of domains.
        """
        consul_client = consul.Consul()
        dummy, all_keys = consul_client.kv.get(self.prefix, recurse=True, keys=True)
        domain_groups = {}
        domains_re = re.compile(r"{}/(\d+)/domains$".format(self.prefix))
        for key in all_keys:
            # all_keys includes all kinds of settings.  We need to filter out the "domains" setting
            # for each instance.
            match = domains_re.match(key)
            if match:
                dummy, data = consul_client.kv.get(key)
                try:
                    instance_domains = json.loads(data["Value"].decode())
                    instance_domains = [domain.lower() for domain in instance_domains]
                    main_domain = instance_domains[0]
                    domain_groups[main_domain] = instance_domains
                except (json.JSONDecodeError, TypeError, IndexError):
                    logger.error(
                        "Consul domains configuration for instance %s invalid.", match.group(1)
                    )
        return domain_groups


class ConsulCertificateStorage(CertificateStorage):
    """Consul-based certificate storage backend."""

    def __init__(self, prefix):
        """Initialize the backend with the given Consul prefix."""
        self.prefix = prefix

    def get_key(self, main_domain):
        """Return the Consul key storing the certificate for the given domain."""
        return "{prefix}/{name}.pem".format(prefix=self.prefix, name=main_domain)

    def get_cert_data(self, main_domain):
        """Return the stored PEM data for the certificate idenitified by `main_domain`.

        The data is returned as a `bytes` object.  If the storage backend does not contain any data
        for the given key, `None` is returned instead.
        """
        consul_client = consul.Consul()
        dummy, data = consul_client.kv.get(self.get_key(main_domain))
        return data

    def get_all_certs(self):
        """Return a dictionary of all stored certificates.

        The dictionary maps the main domain names to the PEM data of each certificate.
        """
        consul_client = consul.Consul()
        dummy, values = consul_client.kv.get(self.prefix, recurse=True)
        certs = {}
        if values is None:
            return certs
        pem_re = re.compile(r"{}/([^/]+).pem$".format(self.prefix))
        for data in values:
            match = pem_re.match(data["Key"])
            if match:
                certs[match.group(1)] = data["Value"]
        return certs

    def deploy_cert(self, main_domain, pem_data):
        """Deploy the given PEM certificate to the storage backend."""
        consul_client = consul.Consul()
        success = consul_client.kv.put(self.get_key(main_domain), pem_data)
        if not success:
            raise StorageError("Could not store the certificate to Consul.")

    def remove_cert(self, main_domain):
        """Delete the certificate identified by `main_domain` from the storage backend.

        If there is no certificate for the given key, this function does nothing.
        """
        consul_client = consul.Consul()
        success = consul_client.kv.delete(self.get_key(main_domain))
        if not success:
            raise StorageError("Could not store the certificate to Consul.")
