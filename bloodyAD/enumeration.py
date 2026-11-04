"""Query contracts and presentation for native read-only enumeration."""
import re

from ldap3.utils.conv import escape_filter_chars

from bloodyAD import utils
from bloodyAD.exceptions import NoResultError
from bloodyAD.network.ldap import Scope


POLICY_ATTRIBUTES = [
    "distinguishedName", "minPwdLength", "pwdHistoryLength", "minPwdAge",
    "maxPwdAge", "pwdProperties", "lockoutThreshold", "lockoutDuration",
    "lockOutObservationWindow", "forceLogoff",
]
SPN_ATTRIBUTES = ["sAMAccountName", "servicePrincipalName", "objectClass",
                  "userAccountControl", "adminCount"]
QUERIES = {
    "password_policy": (Scope.BASE, "(objectClass=domainDNS)", POLICY_ATTRIBUTES),
    "domain_level": (Scope.BASE, "(objectClass=*)", ["msDS-Behavior-Version"]),
    "maq": (Scope.BASE, "(objectClass=*)", ["ms-DS-MachineAccountQuota"]),
    "users_description": (Scope.SUBTREE, "(sAMAccountType=805306368)",
                          ["distinguishedName", "sAMAccountName", "description"]),
    "asrep": (Scope.SUBTREE, "(&(samAccountType=805306368)"
              "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
              ["sAMAccountName", "userAccountControl"]),
    "spn": (Scope.SUBTREE, "(servicePrincipalName=*)", SPN_ATTRIBUTES),
    "kerberoastable": (Scope.SUBTREE, "(&(samAccountType=805306368)(servicePrincipalName=*)"
                       "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                       [*SPN_ATTRIBUTES, "msDS-SupportedEncryptionTypes"]),
}
PASSWORD_FLAGS = [
    "DOMAIN_PASSWORD_COMPLEX", "DOMAIN_PASSWORD_NO_ANON_CHANGE",
    "DOMAIN_PASSWORD_NO_CLEAR_CHANGE", "DOMAIN_LOCKOUT_ADMINS",
    "DOMAIN_PASSWORD_STORE_CLEARTEXT", "DOMAIN_REFUSE_PASSWORD_CHANGE",
]


def format_policy_value(name, value):
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return value
    original = str(value)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return original
    try:
        number = int(value)
    except ValueError:
        return original
    name = name.casefold()
    label = None
    if name == "pwdproperties" and number >= 0:
        flags = [flag for bit, flag in enumerate(PASSWORD_FLAGS) if number & (1 << bit)]
        unknown = number & ~63
        if unknown:
            flags.append(f"unknown bits: 0x{unknown:X}")
        label = " | ".join(flags) or "no flags set"
    elif name == "lockoutthreshold" and number == 0:
        label = "lockout disabled"
    elif name == "maxpwdage" and number in (0, -(2**63)):
        label = "never expires"
    elif name == "lockoutduration" and number in (0, -(2**63)):
        label = "administrator unlock required when lockout is enabled"
    elif name == "minpwdage" and number == 0:
        label = "no minimum age"
    elif name == "forcelogoff" and number == -(2**63):
        label = "forced logoff disabled"
    elif name == "forcelogoff" and number == 0:
        label = "immediate logoff when logon hours expire"
    elif name in ("minpwdage", "maxpwdage", "lockoutduration", "lockoutobservationwindow", "forcelogoff") and -(2**63) < number <= 0:
        seconds, remainder = divmod(-number, 10_000_000)
        fraction = f".{remainder:07d}".rstrip("0") if remainder else ""
        label = f"{seconds}{fraction} seconds"
    return f"{original} ({label})" if label else original


async def query(conn, name, base="DOMAIN", raw=False, spn_class=""):
    scope, ldap_filter, attributes = QUERIES[name]
    if spn_class:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", spn_class):
            raise ValueError("SPN class must contain letters, digits, dots, underscores or hyphens")
        ldap_filter = f"(servicePrincipalName={escape_filter_chars(spn_class)}/*)"
    ldap = await conn.getLdap()
    if base == "DOMAIN":
        base = ldap.domainNC
    entries = ldap.bloodysearch(base, ldap_filter, search_scope=scope,
                               attr=attributes, control_flag=0,
                               raw=raw or name == "password_policy")

    async def project():
        try:
            async for entry in entries:
                if name == "password_policy":
                    names = {attr.casefold(): attr for attr in attributes}
                    entry = {names[key.casefold()]: value for key, value in entry.items()
                             if key.casefold() in names}
                    if not raw:
                        entry = {key: [format_policy_value(key, v) for v in value]
                                 if isinstance(value, list) else format_policy_value(key, value)
                                 for key, value in entry.items()}
                yield entry
        except NoResultError:
            return
        finally:
            await entries.aclose()

    projected = project()
    rendered = utils.renderSearchResult(projected)
    try:
        async for entry in rendered:
            yield entry
    finally:
        await rendered.aclose()
        await projected.aclose()
