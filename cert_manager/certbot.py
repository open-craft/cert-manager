"""A client interacting with Certbot."""

import pathlib
import subprocess


class CertbotClient:
    """A client to interact with Certbot."""

    def __init__(self, certbot_path=None, contact_email=None, webroot_path=None,
                 deploy_hook=None, letsencrypt_use_staging=None):
        """Initialize the Certbot client."""
        self.certbot_path = certbot_path
        self.contact_email = contact_email
        self.webroot_path = webroot_path
        self.deploy_hook = deploy_hook
        self.letsencrypt_use_staging = letsencrypt_use_staging

    def request_cert(self, domains):
        """Request a new SSL certificate from Let's Encrypt."""
        command = [
            self.certbot_path, "certonly",
            "--email", self.contact_email,
            "--webroot",
            "--webroot-path", self.webroot_path,
            "--non-interactive",
            "--agree-tos",
            "--keep",
            "--allow-subset-of-names",
            "--deploy-hook", self.deploy_hook,
            "--cert-name", domains[0],
        ]
        if self.letsencrypt_use_staging:
            command.append("--staging")
        for domain in domains:
            command += ["--domain", domain]
        result = subprocess.run(command, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        result.check_returncode()

    def get_cert_data_from_live_dir(self, live_dir):
        """Load the PEM data from the given Certbot live directory.

        The directory must be a pathlib.Path object.
        """
        fullchain = (live_dir / "fullchain.pem").read_bytes()
        privkey = (live_dir / "privkey.pem").read_bytes()
        return fullchain + privkey

    def get_cert_data(self, main_domain):
        """Load the PEM data from Certbot's output directory."""
        live_dir = pathlib.Path("/etc/letsencrypt/live", main_domain)
        return self.get_cert_data_from_live_dir(live_dir)

    def remove_cert(self, main_domain):
        """Remove a certificate from Certbot and the backend storage."""
        command = [
            self.certbot_path, "delete",
            "--cert-name", main_domain,
        ]
        result = subprocess.run(command, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        result.check_returncode()

    def list_certs(self):
        """List the certificate names of all certificates currently managed by Certbot."""
        result = subprocess.run(
            [self.certbot_path, "certificates"],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
        result.check_returncode()
        return [
            line.partition(": ")[-1]
            for line in result.stdout.splitlines()
            if "Certificate Name:" in line
        ]
