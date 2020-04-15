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

        This function returns a dictionary mapping the main domain name to a dict item of the form
        {'domains': ['list', 'of', 'domains'], dns_records_updated: 1586841904}
        where the 'domains' entry holds a list of domains in the group and the 'dns_records_updated'
        is a unix timestamp of the time the DNS entries for the domain group were last updated,
        or None if DNS records for the domain group don't  exist.
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

    def __init__(self, prefix, consul_client=None):
        """Initialize the backend with the given Consul prefix."""
        self.prefix = prefix
        self.consul_client = consul_client or consul.Consul()

    def get_domain_groups(self):
        """Return all currently configured domain groups.

        Domain groups are lists of domain names that correspond to a single certificate.  The
        certificate manager will ensure that there is a certificate for each configured domain
        group.

        This function returns a dictionary mapping the main domain name to a dict item of the form
        {'domains': ['list', 'of', 'domains'], dns_records_updated: 1586841904}
        where the 'domains' entry holds a list of domains in the group and the 'dns_records_updated'
        is a unix timestamp of the time the DNS entries for the domain group were last updated,
        or None if DNS records for the domain group don't  exist.
        """
        dummy, all_keys = self.consul_client.kv.get(self.prefix, recurse=True, keys=True)
        domain_groups = {}
        if all_keys is None:
            return domain_groups
        config_re = re.compile(r"{}/(\d+)$".format(self.prefix))
        for key in all_keys:
            match = config_re.match(key)
            if match:
                dummy, data = self.consul_client.kv.get(key)
                try:
                    config = json.loads(data["Value"].decode('utf-8'))
                    instance_domains = [domain.lower() for domain in config['domains']]
                    main_domain = config['domain']
                    domain_groups[main_domain] = {
                        'domains': instance_domains,
                        'dns_records_updated': config['dns_records_updated'],
                    }
                except (TypeError, KeyError):
                    logger.error(
                        "Consul domains configuration for instance %s invalid.", match.group(1)
                    )

        return domain_groups


class ConsulCertificateStorage(CertificateStorage):
    """Consul-based certificate storage backend."""

    def __init__(self, prefix, consul_client=None):
        """Initialize the backend with the given Consul prefix."""
        self.prefix = prefix
        self.consul_client = consul_client or consul.Consul()

    def get_key(self, main_domain):
        """Return the Consul key storing the certificate for the given domain."""
        return "{prefix}/{name}.pem".format(prefix=self.prefix, name=main_domain)

    def get_cert_data(self, main_domain):
        """Return the stored PEM data for the certificate idenitified by `main_domain`.

        The data is returned as a `bytes` object.  If the storage backend does not contain any data
        for the given key, `None` is returned instead.
        """
        dummy, data = self.consul_client.kv.get(self.get_key(main_domain))
        return data

    def get_all_certs(self):
        """Return a dictionary of all stored certificates.

        The dictionary maps the main domain names to the PEM data of each certificate.
        """
        dummy, values = self.consul_client.kv.get(self.prefix, recurse=True)
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
        success = self.consul_client.kv.put(self.get_key(main_domain), pem_data)
        if not success:
            raise StorageError("Could not store the certificate to Consul.")

    def remove_cert(self, main_domain):
        """Delete the certificate identified by `main_domain` from the storage backend.

        If there is no certificate for the given key, this function does nothing.
        """
        success = self.consul_client.kv.delete(self.get_key(main_domain))
        if not success:
            raise StorageError("Could not store the certificate to Consul.")
