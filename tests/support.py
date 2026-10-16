"""Portable, explicit lab configuration and subprocess handling."""
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from bloodyAD.network.config import Config, ConnectionHandler
from bloodyAD.network.ldap import Scope
from bloodyAD.exceptions import NoResultError

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class LabConfig:
    domain: str = "example.test"
    host: str = "dc.example.test"
    ip: str = "192.0.2.10"
    username: str = "lab-operator"
    password: str = field(default="", repr=False)
    ca_name: str | None = None
    ca_template: str | None = None

    @classmethod
    def from_environment(cls):
        path = ROOT / "tests" / "secrets.json"
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        config = cls(
            domain=os.getenv("BLOODYAD_LAB_DOMAIN", data.get("domain", cls.domain)),
            host=os.getenv("BLOODYAD_LAB_HOST", data.get("pdc", {}).get("hostname", cls.host)),
            ip=os.getenv("BLOODYAD_LAB_IP", data.get("pdc", {}).get("ip", cls.ip)),
            username=os.getenv("BLOODYAD_LAB_USER", data.get("admin_user", {}).get("username", cls.username)),
            password=os.getenv("BLOODYAD_LAB_PASSWORD", data.get("admin_user", {}).get("password", "")),
            ca_name=os.getenv("BLOODYAD_LAB_CA"), ca_template=os.getenv("BLOODYAD_LAB_TEMPLATE"),
        )
        if not config.password:
            raise ValueError("Provide BLOODYAD_LAB_PASSWORD or a local tests/secrets.json")
        return config

    def arguments(self):
        return ["--host", self.host, "--dc-ip", self.ip, "-d", self.domain, "-u", self.username]

    def connection(self, *, scheme="ldap", options=None):
        return ConnectionHandler(config=Config(host=self.host, dcip=self.ip, domain=self.domain,
                                               username=self.username, password=self.password,
                                               scheme=scheme, timeout=15), options=options)


class LabCommandError(RuntimeError):
    def __init__(self, returncode):
        self.returncode = returncode
        super().__init__(f"CLI exited with code {returncode}; arguments and output omitted")


def run_cli(argv: list[str], timeout: float = 30.0, *, env=None):
    environment = os.environ.copy()
    if env:
        environment.update(env)
    try:
        result = subprocess.run([sys.executable, str(ROOT / "bloodyAD.py"), *argv],
                                cwd=ROOT, env=environment, shell=False, timeout=timeout,
                                capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        raise LabCommandError(124) from None
    if result.returncode:
        raise LabCommandError(result.returncode)
    return result


def lab_cli(config, argv, timeout=30):
    return run_cli(config.arguments() + argv, timeout=timeout,
                   env={"BLOODYAD_PASSWORD": config.password})


@dataclass(frozen=True)
class LabCapabilities:
    host: str
    domain_dn: str
    schema_version: int
    ca_names: tuple[str, ...]
    certificate_templates: tuple[str, ...]

    @property
    def adcs(self):
        return bool(self.ca_names)


async def probe_lab(config: LabConfig) -> LabCapabilities:
    conn = config.connection()
    try:
        ldap = await conn.getLdap()
        expected = ",".join("DC=" + label for label in config.domain.split("."))
        if ldap.domainNC.lower() != expected.lower():
            raise ValueError("Configured domain differs from the DC naming context")
        raw = [entry async for entry in ldap.bloodysearch(ldap.schemaNC, attr=["objectVersion"], raw=True)]
        raw_version = raw[0]["objectVersion"]
        if isinstance(raw_version, list):
            raw_version = raw_version[0]
        names, templates = [], set()
        try:
            async for entry in ldap.bloodysearch(
                "CN=Enrollment Services,CN=Public Key Services,CN=Services," + ldap.configNC,
                "(objectClass=pKIEnrollmentService)", search_scope=Scope.SUBTREE,
                attr=["name", "certificateTemplates"],
            ):
                name = entry["name"]
                names.append(name[0] if isinstance(name, list) else name)
                values = entry.get("certificateTemplates", [])
                templates.update(values if isinstance(values, list) else [values])
        except NoResultError:
            pass
        return LabCapabilities(ldap._serverinfo["dnsHostName"], ldap.domainNC, int(raw_version),
                               tuple(names), tuple(sorted(templates)))
    finally:
        await conn.closeLdap()
