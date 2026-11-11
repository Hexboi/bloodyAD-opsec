"""LDAP-only AD CS configuration evidence, not an effective-access or exploit check.

Inspired by ADWSearch's certdump collection model. Uses this project's transport
and descriptor parser; no CA-side protocol or certificate enrollment is used.
"""
import re
import uuid
from contextlib import aclosing
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from bloodyAD import utils
from bloodyAD.exceptions import NoResultError
from bloodyAD.formatters import ldaptypes
from bloodyAD.formatters.adschema import SCHEMA_ATTRIBUTES
from bloodyAD.network.ldap import Scope


ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
ANY_PURPOSE = "2.5.29.37.0"
AGENT = "1.3.6.1.4.1.311.20.2.1"
AUTH_EKUS = {"1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4",
             "1.3.6.1.4.1.311.20.2.2", ANY_PURPOSE}
CHECKS = ["ESC1", "ESC2", "ESC3", "ESC4", "ESC9", "ESC13", "ESC15", "ESC17", "CA_OBJECT_ACL"]
UNVERIFIED_CHECKS = ["ESC5", "ESC6", "ESC7", "ESC8", "ESC10", "ESC11", "ESC12",
                     "ESC14", "ESC16"]
ACCESS_LIMIT = "Effective access, group memberships, deny effects and trustee privilege are not verified."
ISSUANCE_LIMITS = ["CA service enrollment permissions and issuance policy are not verified.",
                   "CA availability, trust chain and authentication acceptance are not verified."]
PRIVILEGED_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-9",
                   *{f"S-1-5-32-{rid}" for rid in (544, 548, 549, 550, 551, 552)}}
PRIVILEGED_RIDS = {498, 500, 512, 516, 518, 519, 520, 521}
SENSITIVE_ATTRIBUTES = {
    "ms-PKI-Certificate-Name-Flag", "ms-PKI-Enrollment-Flag", "ms-PKI-RA-Signature",
    "ms-PKI-Certificate-Application-Policy", "PKI-Extended-Key-Usage",
    "ms-PKI-Certificate-Policy", "ms-PKI-RA-Application-Policies",
}
SENSITIVE_GUIDS = {guid for guid, name in SCHEMA_ATTRIBUTES.items() if name in SENSITIVE_ATTRIBUTES}
CA_SENSITIVE_GUIDS = {guid for guid, name in SCHEMA_ATTRIBUTES.items()
                      if name in {"Certificate-Templates", "CA-Certificate", "DNS-Host-Name",
                                  "ms-PKI-Enrollment-Servers"}}
QUERY_ATTRIBUTES = {
    # bloodysearch supplies objectName as the DN; a requested raw DN would overwrite it with a list.
    "ca": ["name", "dNSHostName", "certificateTemplates", "nTSecurityDescriptor", "cACertificate"],
    "template": ["name", "displayName", "nTSecurityDescriptor",
                 "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                 "msPKI-RA-Signature", "msPKI-Template-Schema-Version",
                 "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
                 "msPKI-Certificate-Policy"],
    "policy": ["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"],
    "ntauth": ["cACertificate"],
    "dc": ["objectSid", "userAccountControl"],
}
QUERY_FILTERS = {"ca": "(objectClass=pKIEnrollmentService)",
                 "template": "(objectClass=pKICertificateTemplate)",
                 "policy": "(objectClass=msPKI-Enterprise-Oid)",
                 "ntauth": "(&(objectClass=certificationAuthority)(cn=NTAuthCertificates))",
                 "dc": "(&(objectClass=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)"
                       "(userAccountControl:1.2.840.113556.1.4.803:=67108864)))"}


def _values(attributes, name):
    value = attributes.get(name.casefold())
    return value if isinstance(value, list) else [] if value is None else [value]


def _strings(attributes, name, limitations):
    result = []
    for value in _values(attributes, name):
        try:
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            if not isinstance(value, str) or not value.strip():
                raise ValueError()
            result.append(value)
        except (UnicodeError, ValueError):
            limitations.append(f"Invalid {name} value; attribute assessment is incomplete.")
    return result


def _integer(attributes, name, limitations, flags=False):
    values = _values(attributes, name)
    try:
        if len(values) != 1 or isinstance(values[0], bool):
            raise ValueError()
        value = values[0]
        if not isinstance(value, (str, bytes, int)):
            raise ValueError()
        number = int(value)
        if not (-(2**31) <= number <= 0xFFFFFFFF if flags else 0 <= number < 2**31):
            raise ValueError()
        return number & 0xFFFFFFFF if flags else number
    except (ValueError, TypeError):
        limitations.append(f"Missing or invalid {name}; value remains unknown.")
        return None


def _privileged(sid):
    domain_sid = re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-(\d+)", sid)
    return sid in PRIVILEGED_SIDS or bool(domain_sid and int(domain_sid[1]) in PRIVILEGED_RIDS)


def _mask_rights(mask, guid):
    rights = []
    full = bool(mask & 0x10000000) or mask & 0xF01FF == 0xF01FF
    if full:
        rights.append("GenericAll")
    for bit, right in ((0x40000, "WriteDacl"), (0x80000, "WriteOwner")):
        if full or mask & bit:
            rights.append(right)
    if full or mask & 0x40000000:
        rights.append("GenericWrite")
    if full or mask & 0x40000020:
        rights.append("WriteProperty")
    if full or mask & 0x100:
        if guid in (None, ENROLL):
            rights.append("Enroll")
        if guid in (None, AUTOENROLL):
            rights.append("AutoEnroll")
    return rights


def acl_evidence(raw):
    """Return observed ACL rights and uncertainty; do not simulate a user token."""
    if not isinstance(raw, bytes) or len(raw) < 20:
        return [], ["Security descriptor missing or invalid; ACL assessment unavailable."]
    evidence, limitations = [], []
    try:
        if raw[0] != 1 or not int.from_bytes(raw[2:4], "little") & 0x8000:
            raise ValueError("Not a self-relative security descriptor")
        for start in (4, 8, 12, 16):
            offset = int.from_bytes(raw[start:start + 4], "little")
            if offset and not 20 <= offset < len(raw):
                raise ValueError("Descriptor offset outside buffer")
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
        if sd["OwnerSid"]:
            evidence.append({"sid": sd["OwnerSid"].formatCanonical(), "right": "Owns",
                             "effect": "allow", "inherited": False, "object_type": None})
        else:
            limitations.append("Owner SID was not returned.")
        if not sd["Control"] & 4:
            limitations.append("DACL not present; ACL assessment unavailable.")
        elif not sd["OffsetDacl"]:
            limitations.append("NULL DACL grants unrestricted access; confirm the returned descriptor is complete.")
            for right in _mask_rights(0x10000000, None):
                evidence.append({"sid": "S-1-1-0", "right": right, "effect": "allow",
                                 "inherited": False, "object_type": None})
        else:
            for ace in sd["Dacl"].aces:
                if ace["AceFlags"] & 8:
                    continue
                kind = ace["AceType"]
                if kind not in (0, 1, 5, 6):
                    limitations.append(f"Unsupported ACE type {kind}; conditional/effective access is unknown.")
                    continue
                body = ace["Ace"]
                guid = None
                if kind in (5, 6) and body["Flags"] & 1:
                    guid = str(uuid.UUID(bytes_le=body["ObjectType"]))
                    if guid == str(uuid.UUID(int=0)):
                        guid = None
                effect = "deny" if kind in (1, 6) else "allow"
                if effect == "deny":
                    limitations.append("Deny ACE present; allow entries do not establish effective access.")
                sid = body["Sid"].formatCanonical()
                for right in _mask_rights(body["Mask"]["Mask"], guid):
                    evidence.append({"sid": sid, "right": right, "effect": effect,
                                     "inherited": bool(ace["AceFlags"] & 16), "object_type": guid})
    except Exception:
        # Descriptor parsers raise several exception types for truncated ACEs.
        return [], ["Invalid security descriptor; ACL assessment unavailable."]
    return evidence, sorted(set(limitations))


def _principals(evidence, rights, template=False):
    return sorted({item["sid"] for item in evidence
                   if item["effect"] == "allow" and item["right"] in rights
                   and not _privileged(item["sid"])
                   and (item["right"] not in {"WriteProperty", "GenericWrite"}
                        or item["object_type"] is None
                        or item["object_type"] in (SENSITIVE_GUIDS if template else CA_SENSITIVE_GUIDS))})


def _candidate(row, identifier, reason, principals, conditions=(), unverified=()):
    if not principals or any(value is not True for value in conditions):
        return
    row["findings"].append({"id": identifier, "status": "potential", "reason": reason,
                            "principals": principals,
                            "unverified": [ACCESS_LIMIT, *unverified]})


def _record(attributes, kind):
    limitations = []
    names = _strings(attributes, "name", limitations)
    if not names:
        limitations.append("Object name was not returned; publication correlation may be incomplete.")
    raw_sd = _values(attributes, "nTSecurityDescriptor")
    evidence, acl_limits = acl_evidence(raw_sd[0] if len(raw_sd) == 1 else None)
    return {"distinguishedName": attributes["distinguishedname"], "kind": kind,
            "name": names[0] if names else "", "acl": evidence,
            "findings": [], "limitations": limitations + acl_limits}


def _bit(number, bit):
    return None if number is None else bool(number & bit)


def _template(attributes, published, policies):
    row = _record(attributes, "template")
    limits = row["limitations"]
    schema = _integer(attributes, "msPKI-Template-Schema-Version", limits)
    if schema == 0:
        schema = None
        limits.append("Invalid template schema version zero; version remains unknown.")
    name_flags = _integer(attributes, "msPKI-Certificate-Name-Flag", limits, flags=True)
    enrollment_flags = _integer(attributes, "msPKI-Enrollment-Flag", limits, flags=True)
    if schema == 1 and not _values(attributes, "msPKI-RA-Signature"):
        signatures = 0
        limits.append("Absent authorized-signature count uses the schema-v1 default; attribute visibility is unverified.")
    else:
        signatures = _integer(attributes, "msPKI-RA-Signature", limits)
    policy_attr = "msPKI-Certificate-Application-Policy"
    if schema == 1 or not _values(attributes, policy_attr):
        policy_attr = "pKIExtendedKeyUsage"
    ekus = _strings(attributes, policy_attr, limits)
    invalid_ekus = len(ekus) != len(_values(attributes, policy_attr)) or any(
        not re.fullmatch(r"[0-2](?:\.\d+)+", oid) for oid in ekus)
    if invalid_ekus:
        limits.append("Invalid application policy/EKU OID; effective usage is unknown.")
        ekus = None
    elif not ekus:
        limits.append("Absent application policies/EKUs imply unrestricted usage only if attributes are fully readable.")
    auth = None if ekus is None else not ekus or bool(AUTH_EKUS.intersection(ekus))
    any_purpose = None if ekus is None else not ekus or ANY_PURPOSE in ekus
    server_auth = None if ekus is None else any_purpose or "1.3.6.1.5.5.7.3.1" in ekus
    subject = _bit(name_flags, 1)
    approval = _bit(enrollment_flags, 2)
    row["settings"] = {"schema_version": schema, "name_flags": name_flags,
                       "enrollment_flags": enrollment_flags, "authorized_signatures": signatures,
                       "enrollee_supplies_subject": subject, "requires_manager_approval": approval,
                       "no_security_extension": _bit(enrollment_flags, 0x80000),
                       "effective_ekus": ekus, "effective_eku_source": policy_attr}
    row["published_on"] = sorted(published.get(row["name"].casefold(), []))
    row["publication"] = "published" if row["published_on"] else "unpublished or publication not visible"
    issuance = _strings(attributes, "msPKI-Certificate-Policy", limits)
    row["issuance_policies"] = issuance
    row["linked_groups"] = sorted({group for oid in issuance for group in policies.get(oid, [])})
    enroll = _principals(row["acl"], {"Enroll"})
    control = _principals(row["acl"], {"Owns", "GenericAll", "GenericWrite", "WriteDacl",
                                        "WriteOwner", "WriteProperty"}, template=True)
    _candidate(row, "ESC4", "Non-baseline trustee has template ownership or modification rights.", control)
    if row["published_on"]:
        gates = [None if approval is None else not approval, None if signatures is None else signatures == 0]
        _candidate(row, "ESC1", "Enrollee supplies subject on an authentication-capable template.", enroll,
                   [subject, auth, *gates], ISSUANCE_LIMITS)
        _candidate(row, "ESC2", "Template permits any-purpose or unrestricted certificate usage.", enroll,
                   [any_purpose, *gates], ISSUANCE_LIMITS)
        _candidate(row, "ESC3", "Template can issue enrollment-agent certificates; target-template restrictions remain unverified.", enroll,
                   [None if ekus is None else AGENT in ekus, *gates], ISSUANCE_LIMITS)
        _candidate(row, "ESC9", "Authentication template omits the SID security extension.", enroll,
                   [_bit(enrollment_flags, 0x80000), auth],
                   [*ISSUANCE_LIMITS, "DC mapping mode, identity-control prerequisites and issuance gates must be checked."])
        _candidate(row, "ESC13", "Authentication template references an issuance policy linked to an AD group.", enroll,
                   [bool(row["linked_groups"]), auth, *gates],
                   [*ISSUANCE_LIMITS, "Linked-group eligibility, privileges and KDC authentication behavior are unverified."])
        _candidate(row, "ESC15", "Schema-v1 template accepts an enrollee-supplied subject (CVE-2024-49019 prerequisites).", enroll,
                   [None if schema is None else schema == 1, subject, *gates],
                   [*ISSUANCE_LIMITS, "CA patch status for CVE-2024-49019 is unknown."])
        _candidate(row, "ESC17", "Enrollee supplies subject on a server-authentication-capable template.", enroll,
                   [subject, server_auth, *gates],
                   [*ISSUANCE_LIMITS, "A target service and additional server-impersonation prerequisites are unverified."])
    return row


def _certificates(attributes, limitations):
    result = []
    for blob in _values(attributes, "cACertificate"):
        try:
            cert = x509.load_der_x509_certificate(blob)
            now = datetime.now(timezone.utc)
            result.append({"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                           "sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
                           "not_before": cert.not_valid_before_utc.isoformat(),
                           "not_after": cert.not_valid_after_utc.isoformat(),
                           "validity": "expired" if now > cert.not_valid_after_utc else
                                       "not yet valid" if now < cert.not_valid_before_utc else "within validity period"})
        except (ValueError, TypeError):
            limitations.append("Invalid CA certificate blob; certificate assessment is incomplete.")
    return result


async def _collect(ldap, kind):
    attributes = QUERY_ATTRIBUTES[kind]
    rows = []
    base = ldap.domainNC if kind == "dc" else ldap.configNC
    async with aclosing(ldap.bloodysearch(base, QUERY_FILTERS[kind], search_scope=Scope.SUBTREE,
                                        attr=attributes, raw=True,
                                        control_flag=5 if "nTSecurityDescriptor" in attributes else 0)) as stream:
        try:
            async for entry in stream:
                rows.append({key.casefold(): value for key, value in entry.items()})
        except NoResultError:
            pass
    return rows


async def _domain_controller_sids(ldap, limitations):
    sids = set()
    for attributes in await _collect(ldap, "dc"):
        role_limits = []
        uac = _integer(attributes, "userAccountControl", role_limits, flags=True)
        if role_limits:
            limitations.append("Domain-controller role attribute missing or invalid; trustee remains unresolved.")
        # Writable DCs use SERVER_TRUST_ACCOUNT; RODCs use PARTIAL_SECRETS_ACCOUNT.
        if uac is None or not uac & 0x4002000:
            continue
        values = _values(attributes, "objectSid")
        try:
            if len(values) != 1 or not isinstance(values[0], bytes):
                raise ValueError()
            raw = values[0]
            if len(raw) < 8 or raw[0] != 1 or len(raw) != 8 + 4 * raw[1]:
                raise ValueError()
            sids.add(ldaptypes.LDAP_SID(data=raw).formatCanonical())
        except Exception:
            # Invalid SID bytes cannot justify suppressing a trustee's grants.
            limitations.append("Invalid domain-controller SID; trustee remains unresolved.")
    if not sids:
        limitations.append("No readable domain-controller SIDs; CA trustee roles remain unresolved.")
    return sids


async def analyze(conn):
    """Collect directory-visible evidence using only existing LDAP search calls."""
    ldap = await conn.getLdap()
    cas = await _collect(ldap, "ca")
    templates = await _collect(ldap, "template")
    oid_objects = await _collect(ldap, "policy")
    stores = await _collect(ldap, "ntauth")
    limits, policies, published = [], {}, {}
    dc_sids = await _domain_controller_sids(ldap, limits) if cas else set()
    for attributes in oid_objects:
        oids = _strings(attributes, "msPKI-Cert-Template-OID", limits)
        groups = _strings(attributes, "msDS-OIDToGroupLink", limits)
        for oid in oids:
            policies.setdefault(oid, set()).update(groups)
    store_dn = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services," + ldap.configNC
    trusted = {cert["sha256"] for store in stores if store["distinguishedname"].casefold() == store_dn.casefold()
               for cert in _certificates(store, limits)}
    ca_rows = []
    for attributes in cas:
        row = _record(attributes, "ca")
        row["host"] = _strings(attributes, "dNSHostName", row["limitations"])
        row["published_templates"] = _strings(attributes, "certificateTemplates", row["limitations"])
        for name in row["published_templates"]:
            published.setdefault(name.casefold(), set()).add(row["name"])
        row["certificates"] = _certificates(attributes, row["limitations"])
        if not row["certificates"]:
            row["limitations"].append("No readable CA certificates; certificate assessment unavailable.")
        for cert in row["certificates"]:
            cert["ntauth_match"] = cert["sha256"] in trusted if trusted else None
        ca_principals = set(_principals(row["acl"], {"Owns", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty"}))
        row["excluded_dc_sids"] = sorted(ca_principals & dc_sids)
        _candidate(row, "CA_OBJECT_ACL", "Non-baseline trustee can control the published CA directory object; this does not establish ESC7.",
                   sorted(ca_principals - dc_sids),
                   unverified=["CA service ManageCA/ManageCertificates rights are not collected."])
        ca_rows.append(row)
    template_rows = [_template(attributes, published, policies) for attributes in templates]
    coverage = {"distinguishedName": ldap.configNC, "kind": "coverage", "assessment": "directory-only",
                "ca_count": len(cas), "template_count": len(templates), "checks": CHECKS,
                "unverified_checks": UNVERIFIED_CHECKS,
                "limitations": [ACCESS_LIMIT, *ISSUANCE_LIMITS,
                                "Only directory-visible candidates are assessed; no findings does not establish safety.",
                                "CA registry/RPC settings, HTTP enrollment protections, patches and DC mapping modes are not checked.",
                                "CA certificates are not chain/revocation validated; NTAuth matching is certificate-context evidence only.",
                                "Missing objects/attributes can reflect permissions or visibility; absence is not proof of no AD CS.",
                                "DC role lookup covers the contacted DC's domain only; unresolved CA trustees remain reportable.",
                                *limits]}
    if not trusted:
        coverage["limitations"].append("No readable NTAuth certificates; trust comparison is unknown.")
    for row in [*ca_rows, *template_rows]:
        row["limitations"] = sorted(set(row["limitations"]))
        row["assessment"] = "incomplete" if row["limitations"] else "directory-only"
        row["limitations"].append(ACCESS_LIMIT)
    async def records():
        for row in [coverage, *ca_rows, *template_rows]:
            yield row
    async with aclosing(utils.renderSearchResult(records())) as rendered:
        async for row in rendered:
            yield row
