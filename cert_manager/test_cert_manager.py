"""Test the CertificateManager class."""

from datetime import datetime, timedelta
import json
import subprocess
from unittest.mock import patch

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
        dns_delay = timedelta(minutes=5).total_seconds()
        cert_manager = CertificateManager(
            certbot,
            domain_config,
            cert_storage,
            additional_domains,
            dns_delay,
            fake_extract_x509_dns_names,
        )

        cert_manager.run()
        assert certbot.requests == {d: [d] for d in additional_domains}
        assert certbot.removals == []
        certbot.reset()

        domain_config.domain_groups["domain.com"] = {
            "domains": ["domain.com", "www.domain.com"],
            "dns_records_updated": (datetime.utcnow() - timedelta(days=1)).timestamp(),
        }
        domain_config.domain_groups["other-domain.com"] = {
            "domains": ["other-domain.com"],
            "dns_records_updated": (datetime.utcnow() - timedelta(hours=1)).timestamp(),
        }
        cert_manager.run()
        assert certbot.requests == {
            "domain.com": ["domain.com", "www.domain.com"],
            "other-domain.com": ["other-domain.com"],
        }
        assert certbot.removals == []
        certbot.reset()

        # Remove domain.com and add opencraft.com to domain config.
        del domain_config.domain_groups["domain.com"]
        domain_config.domain_groups["opencraft.com"] = {
            "domains": ["opencraft.com"],
            "dns_records_updated": (datetime.utcnow() - timedelta(minutes=6)).timestamp(),
        }
        cert_manager.run()
        assert certbot.requests == {"opencraft.com": ["opencraft.com"]}
        assert certbot.removals == ["domain.com"]
        certbot.reset()

        # Add some extra domains to the opencraft.com cert.
        domain_config.domain_groups["opencraft.com"]["domains"].extend(["www.opencraft.com", "ocim.com"])
        cert_manager.run()
        assert certbot.requests == {"opencraft.com": ["opencraft.com", "www.opencraft.com", "ocim.com"]}
        assert certbot.removals == []
        certbot.reset()

        # Replace the main domain of the opencraft.com cert, but keep the same list of domains.
        del domain_config.domain_groups["opencraft.com"]
        domain_config.domain_groups["ocim.com"] = {
            "domains": ["ocim.com", "opencraft.com", "www.opencraft.com"],
            "dns_records_updated": (datetime.utcnow() - timedelta(minutes=6)).timestamp(),
        }
        cert_manager.run()
        assert certbot.requests == {"ocim.com": ["ocim.com", "opencraft.com", "www.opencraft.com"]}
        assert certbot.removals == ["opencraft.com"]
        certbot.reset()

        # Certificate for new domain should not be requested if DNS records haven't been set yet.
        domain_config.domain_groups["new-domain.com"] = {
            "domains": ["new-domain.com"],
            "dns_records_updated": None,
        }
        cert_manager.run()
        assert certbot.requests == {}
        assert certbot.removals == []
        certbot.reset()

        # Certificate for new domain should not be requested if DNS records have been set
        # less than dns_delay seconds ago.
        four_minutes_ago = (datetime.utcnow() - timedelta(minutes=4)).timestamp()
        domain_config.domain_groups["new-domain.com"]["dns_records_updated"] = four_minutes_ago
        cert_manager.run()
        assert certbot.requests == {}
        assert certbot.removals == []
        certbot.reset()

        # Certificate for new domain should be requested if DNS records were set more than
        # dns_delay seconds ago.
        more_than_five_minutes_ago = (datetime.utcnow() - timedelta(minutes=5.01)).timestamp()
        domain_config.domain_groups["new-domain.com"]["dns_records_updated"] = more_than_five_minutes_ago
        cert_manager.run()
        assert certbot.requests == {"new-domain.com": ["new-domain.com"]}
        assert certbot.removals == []
        certbot.reset()

        # Certificate should be removed if DNS records were unset.
        domain_config.domain_groups["new-domain.com"]["dns_records_updated"] = None
        cert_manager.run()
        assert certbot.requests == {}
        assert certbot.removals == ["new-domain.com"]
        certbot.reset()

    @patch('cert_manager.send_email')
    def test_failure_alert_email(self, mock_send_email):
        domain_config = FakeDomainConfiguration()
        cert_storage = FakeCertificateStorage()
        certbot = FakeCertbotClient(cert_storage)
        dns_delay = timedelta(minutes=5).total_seconds()
        domain_config.domain_groups["domain.com"] = {
            "domains": ["domain.com", "www.domain.com"],
            "dns_records_updated": (datetime.utcnow() - timedelta(days=1)).timestamp(),
        }

        cert_manager = CertificateManager(
            certbot,
            domain_config,
            cert_storage,
            [],
            dns_delay,
            fake_extract_x509_dns_names,
            'nobody@example.com'
        )
        with patch(__name__ + '.FakeCertbotClient.request_cert') as mock_request_cert:
            mock_request_cert.side_effect = subprocess.CalledProcessError(
                stderr=b'Request failure', returncode=128, cmd=''
            )
            cert_manager.run()
            assert mock_send_email.call_count == 1
            assert 'Request failure' in mock_send_email.call_args[0][2]
            certbot.reset()

        cert_manager.run()
        certbot.reset()

        del domain_config.domain_groups["domain.com"]
        with patch(__name__ + '.FakeCertbotClient.remove_cert') as mock_remove_cert:
            mock_remove_cert.side_effect = subprocess.CalledProcessError(
                stderr=b'Remove failure', returncode=128, cmd=''
            )
            cert_manager.run()
            assert mock_send_email.call_count == 2
            assert 'Remove failure' in mock_send_email.call_args[0][2]
            certbot.reset()
