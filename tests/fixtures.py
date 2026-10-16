"""Owned temporary AD fixtures. Cleanup never uses name alone as identity."""
import uuid
import os
import asyncio
import json
from pathlib import Path

from bloodyAD.rollback import read_state
from bloodyAD.network.ldap import Scope
from bloodyAD.search_policy import SearchPolicy


class LabFixture:
    def __init__(self, config):
        self.config = config
        self.run_id = uuid.uuid4().hex
        self.short = self.run_id[:8]
        self.conn = None
        self.ldap = None
        self.base = None
        self.owned = []
        self.manifest = None

    def save_manifest(self):
        if self.manifest:
            self.manifest.write_text(json.dumps({"run_id": self.run_id, "base": self.base,
                                                "owned": self.owned}, indent=2), encoding="utf-8")

    async def start(self):
        if not os.getenv("BLOODYAD_LAB_SNAPSHOT"):
            raise RuntimeError("Provide the verified VirtualBox snapshot ID before mutative lab tests")
        self.conn = self.config.connection()
        self.ldap = await self.conn.getLdap()
        self.base = "OU=BA-" + self.run_id + "," + self.ldap.domainNC
        folder = Path(__file__).resolve().parent / "reports"
        folder.mkdir(exist_ok=True)
        self.manifest = folder / ("fixtures-" + self.run_id + ".json")
        await self.create(self.base, {"objectClass": ["top", "organizationalUnit"],
                                     "ou": "BA-" + self.run_id,
                                     "description": "bloodyAD safety test " + self.run_id})
        self.user = "CN=FixtureUser," + self.base
        self.group = "CN=FixtureGroup," + self.base
        await self.create(self.user, {"objectClass": ["top", "person", "organizationalPerson", "user"],
                                     "sAMAccountName": "bafu" + self.short, "userAccountControl": 514,
                                     "description": "before"})
        await self.create(self.group, {"objectClass": ["top", "group"], "groupType": -2147483646,
                                      "sAMAccountName": "bafg" + self.short})

    def expect(self, dn):
        SearchPolicy(self.base).validate_target(dn)
        self.owned.append({"dn": dn, "guid": None})
        self.save_manifest()

    async def identify(self, dn):
        state = await read_state(self.ldap, dn)
        if state is None:
            raise RuntimeError("Fixture object could not be identified")
        next(record for record in reversed(self.owned) if record["dn"] == dn)["guid"] = state["guid"]
        self.save_manifest()

    async def create(self, dn, attributes):
        self.expect(dn)
        _, error = await self.ldap.add(dn, attributes=attributes)
        if error:
            raise error
        await self.identify(dn)

    async def cleanup(self):
        residuals = []
        for record in reversed(self.owned):
            SearchPolicy(self.base).validate_target(record["dn"])
            try:
                state = await asyncio.wait_for(read_state(self.ldap, record["dn"]), timeout=5)
            except Exception:
                residuals.append(record["dn"])
                continue
            if state is None:
                continue
            if record["guid"] is None or state["guid"] != record["guid"]:
                residuals.append(record["dn"])
                continue
            try:
                _, error = await asyncio.wait_for(self.ldap.delete(record["dn"]), timeout=5)
            except Exception:
                residuals.append(record["dn"])
                continue
            if error:
                residuals.append(record["dn"])
        if residuals:
            self.save_manifest()
            raise RuntimeError("Fixture cleanup refused or failed for owned targets: " + "; ".join(residuals))
        self.owned.clear()
        self.save_manifest()

    async def close(self):
        try:
            if self.ldap is not None:
                await self.cleanup()
        finally:
            if self.conn is not None:
                await asyncio.wait_for(self.conn.closeLdap(), timeout=5)


async def snapshot_fixture_state(fixture):
    return {entry["distinguishedName"]: entry async for entry in fixture.ldap.bloodysearch(
        fixture.base, search_scope=Scope.SUBTREE,
        attr=["objectGUID", "description", "member", "sAMAccountName"], raw=True)}
