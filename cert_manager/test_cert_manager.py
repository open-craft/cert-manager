"""Test the CertificateManager class."""

import json

from . import CertificateManager


class FakeDomainConfiguration:
    """Fake implementation of the DomainConfiguration backend."""

    def __init__(self, domain_groups=None):
        """Initialize a domain configuration instance."""
        self.domain_groups = domain_groups or {}

    def get_domain_groups(self):
        """Return all currently configured domain groups.

        Domain groups are lists of domain names that correspond to a single certificate.  The
        certificate manager will ensure that there is a certificate for each configured domain
        group.

        This function returns a dictionary mapping the main domain name to a list of domains.
        """
        return self.domain_groups.copy()


class FakeCertificateStorage:
    """Fake implementation of the CertificateStorage backend."""

    def __init__(self, certs=None):
        """Initialize a certificate storage instance."""
        self.certs = certs or {}

    def get_cert_data(self, main_domain):
        """Return the stored PEM data for the certificate idenitified by `main_domain`.

        The data is returned as a `bytes` object.  If the storage backend does not contain any data
        for the given key, `None` is returned instead.
        """
        return self.certs[main_domain]

    def get_all_certs(self):
        """Return a dictionary of all stored certificates.

        The dictionary maps the main domain names to the PEM data of each certificate.
        """
        return self.certs.copy()

    def deploy_cert(self, main_domain, pem_data):
        """Deploy the given PEM certificate to the storage backend."""
        self.certs[main_domain] = pem_data

    def remove_cert(self, main_domain):
        """Delete the certificate identified by `main_domain` from the storage backend.

        If there is no certificate for the given key, this function does nothing.
        """
        del self.certs[main_domain]


class FakeCertbotClient:
    """A fake implementation of CertbotClient that keeps track of requests and removals."""

    def __init__(self, cert_storage):
        """Initialize the fake Certbot client."""
        self.cert_storage = cert_storage
        self.reset()

    def reset(self):
        """Reset the records of requests and removals."""
        self.requests = {}
        self.removals = []

    def request_cert(self, domains):
        """Request a new SSL certificate from Let's Encrypt."""
        # In the real client, requesting a certificate also deploys it via the deploy hook.
        self.cert_storage.deploy_cert(domains[0], json.dumps(domains))
        self.requests[domains[0]] = domains

    def remove_cert(self, main_domain):
        """Remove a certificate from Certbot and the backend storage."""
        self.removals.append(main_domain)


def fake_extract_x509_dns_names(pem_data):
    """Fake implementation to extract domains from fake cert data.

    We use a JSON-encoded list of domains as fake PEM data.
    """
    return json.loads(pem_data)


class TestCertificateManager:
    """Tests for the CertificateManager class."""

    def test_run(self):
        """Test the logic of requesting and removing certificates."""
        domain_config = FakeDomainConfiguration()
        cert_storage = FakeCertificateStorage()
        certbot = FakeCertbotClient(cert_storage)
        additional_domains = ["haproxy-1.example.com", "haproxy-2.example.com"]
        cert_manager = CertificateManager(
            certbot,
            domain_config,
            cert_storage,
            additional_domains,
            fake_extract_x509_dns_names,
        )

        cert_manager.run()
        assert certbot.requests == {d: [d] for d in additional_domains}
        assert certbot.removals == []
        certbot.reset()

        domain_config.domain_groups["domain.com"] = ["domain.com", "www.domain.com"]
        domain_config.domain_groups["other-domain.com"] = ["other-domain.com"]
        cert_manager.run()
        assert certbot.requests == domain_config.domain_groups
        assert certbot.removals == []
        certbot.reset()

        del domain_config.domain_groups["domain.com"]
        domain_config.domain_groups["opencraft.com"] = ["opencraft.com"]
        cert_manager.run()
        assert certbot.requests == {"opencraft.com": ["opencraft.com"]}
        assert certbot.removals == ["domain.com"]
