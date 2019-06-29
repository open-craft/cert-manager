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

    def add_config_data(self, consul_client, domains, prefix):
        """Adds a dummy config data in K/V form."""

        for instance_id, domains in enumerate(domains, 1):
            config = {
                'domain_slug': 'instance-{}'.format(instance_id),
                'domain': domains[0],
                'name': 'Instance {}'.format(instance_id),
                'domains': domains,
                'health_checks_enabled': 'false',
                'basic_auth': 'dXNlcjpwYXNzd29yZAo=',
                'active_app_servers': [],
            }
            consul_client.kv.put('{}/{}'.format(prefix, instance_id), json.dumps(config).encode('utf-8'))

    def add_instance_to_consul(self, consul_client, prefix, instance_id, domains):
        """Add fake instance data to Consul."""
        for key, value in [
                ("active_appservers", "[]"),
                ("basic_auth", "dXNlcjpwYXNzd29yZAo="),
                ("domains", json.dumps(domains)),
                ("health_checks_enabled", "false"),
                ("name", "Instance"),
                ("version", "1"),
            ]:
            consul_client.kv.put("{}/{}/{}".format(prefix, instance_id, key), value)

    def get_domain_groups(self, consul_client, domain_groups):
        """Helper to add the domain groups to Consul and retrieve them again."""
        prefix = CONSUL_PREFIX + "/instances"
        for instance_id, domains in enumerate(domain_groups, 1):
            self.add_instance_to_consul(consul_client, prefix, instance_id, domains)
        domain_config = ConsulDomainConfiguration(prefix, consul_client)
        return domain_config.get_domain_groups()

    def test_get_domain_groups(self, consul_client):
        """Test for get_domain_groups()."""
        expected_domain_groups = [
            ["lms.example.com", "studio.example.com"],
            ["opencraft.com"],
            ["lms.opencraft.hosting", "studio.opencraft.hosting", "courses.example.com"],
        ]
        domain_groups = self.get_domain_groups(consul_client, expected_domain_groups)
        assert domain_groups == {domains[0]: domains for domains in expected_domain_groups}

    def test_get_domain_groups_no_data(self, consul_client):
        """Test for get_domain_groups() in case no data is in Consul yet."""
        domain_groups = self.get_domain_groups(consul_client, [])
        assert domain_groups == {}

    def test_get_domain_groups_from_kv(self, consul_client):
        """
        Test for get_domain_groups() when configuration is stored in a single K/V value.
        """
        prefix = CONSUL_PREFIX + "/instances"
        expected_domain_groups = [
            ["lms.example.com", "studio.example.com"],
            ["opencraft.com"],
            ["lms.opencraft.hosting", "studio.opencraft.hosting", "courses.example.com"],
        ]
        self.add_config_data(consul_client, expected_domain_groups, prefix)
        domain_config = ConsulDomainConfiguration(prefix, consul_client)
        domain_groups = domain_config.get_domain_groups()
        assert domain_groups == {domains[0]: domains for domains in expected_domain_groups}


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
