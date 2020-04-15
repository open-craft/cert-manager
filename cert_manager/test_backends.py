"""Tests for the backends module."""

import json
import pytest

import consul

from .backends import ConsulCertificateStorage, ConsulDomainConfiguration

# Use of Pytest fixtures results in warnings for redefined names from the outer scope.
# pylint: disable=redefined-outer-name


CONSUL_PREFIX = "test-cert-manager"


@pytest.fixture
def consul_client():
    """Fixture to clean out test data from Consul before and after use."""
    client = consul.Consul()
    client.kv.delete(CONSUL_PREFIX, recurse=True)
    yield client
    client.kv.delete(CONSUL_PREFIX, recurse=True)


class TestConsulDomainConfiguration:
    """Tests for ConsulDomainConfiguration."""

    prefix = CONSUL_PREFIX + "/instances"

    def add_config_data(self, consul_client, domain_groups, prefix):
        """Adds a dummy config data in K/V form."""

        for instance_id, main_domain in enumerate(domain_groups, 1):
            config = {
                'domain_slug': 'instance-{}'.format(instance_id),
                'domain': main_domain,
                'name': 'Instance {}'.format(instance_id),
                'domains': domain_groups[main_domain]['domains'],
                'dns_records_updated': domain_groups[main_domain]['dns_records_updated'],
                'health_checks_enabled': 'false',
                'basic_auth': 'dXNlcjpwYXNzd29yZAo=',
                'active_app_servers': [],
            }
            consul_client.kv.put('{}/{}'.format(prefix, instance_id), json.dumps(config).encode('utf-8'))

    def test_get_domain_groups(self, consul_client):
        """
        Test for get_domain_groups() when configuration is stored in a single K/V value.
        """
        expected_domain_groups = {
            "example.com": {
                "domains": ["lms.example.com", "studio.example.com"],
                "dns_records_updated": 123456789,
            },
            "opencraft.com": {
                "domains": ["opencraft.com"],
                "dns_records_updated": 123123123,
            },
            "opencraft.hosting": {
                "domains": ["lms.opencraft.hosting", "studio.opencraft.hosting", "courses.example.com"],
                "dns_records_updated": 123333333
            },
        }
        self.add_config_data(consul_client, expected_domain_groups, self.prefix)
        domain_config = ConsulDomainConfiguration(self.prefix, consul_client)
        domain_groups = domain_config.get_domain_groups()
        assert domain_groups == expected_domain_groups

    def test_get_domain_groups_no_data(self, consul_client):
        """Test for get_domain_groups() in case no data is in Consul yet."""
        domain_config = ConsulDomainConfiguration(self.prefix, consul_client)
        domain_groups = domain_config.get_domain_groups()
        assert domain_groups == {}



class TestConsulCertificateStorage:
    """Tests for ConsulCertificateStorage."""

    def test_invariants(self, consul_client):
        """Test consistency of deploying and removing certs to Consul"""
        prefix = CONSUL_PREFIX + "/certs"
        storage = ConsulCertificateStorage(prefix, consul_client)
        assert storage.get_all_certs() == {}
        storage.deploy_cert("domain.com", b"cert for domain.com")
        assert storage.get_all_certs() == {"domain.com": b"cert for domain.com"}
        storage.deploy_cert("other-domain.com", b"cert for other-domain.com")
        assert storage.get_all_certs() == {
            "domain.com": b"cert for domain.com",
            "other-domain.com": b"cert for other-domain.com",
        }
        storage.remove_cert("domain.com")
        assert storage.get_all_certs() == {"other-domain.com": b"cert for other-domain.com"}
        storage.remove_cert("other-domain.com")
        assert storage.get_all_certs() == {}
