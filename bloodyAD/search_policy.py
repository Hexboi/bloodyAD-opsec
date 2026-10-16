"""DN-aware confinement for application reads, separate from fixed metadata reads."""
import re
from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import parse_dn


class ScopeViolationError(ValueError):
    pass


def _value(value):
    if value.startswith("#"):
        raise ScopeViolationError("Hex-encoded BER RDN values are not supported for scope checks")
    data = bytearray()
    position = 0
    while position < len(value):
        char = value[position]
        if char == "\\":
            token = value[position + 1:position + 3]
            if len(token) == 2 and re.fullmatch("[0-9A-Fa-f]{2}", token):
                data.append(int(token, 16))
                position += 3
                continue
            position += 1
            if position >= len(value):
                raise ScopeViolationError("Invalid escaped RDN")
            char = value[position]
        data.extend(char.encode("utf-8"))
        position += 1
    decoded = data.decode("utf-8")
    # ASCII case-insensitivity covers ordinary AD names without guessing Unicode matching rules.
    return decoded.lower() if decoded.isascii() else decoded


def canonical_dn(dn):
    try:
        components = parse_dn(dn)
        rdns, current = [], []
        for attribute, value, separator in components:
            current.append((attribute.lower(), _value(value)))
            if separator != "+":
                rdns.append(tuple(sorted(current)))
                current = []
        if current:
            raise ScopeViolationError("Incomplete RDN")
        return tuple(rdns)
    except (LDAPInvalidDnError, UnicodeError, IndexError, TypeError) as error:
        raise ScopeViolationError("Malformed or unsupported distinguished name") from error


class SearchPolicy:
    def __init__(self, base_dn):
        self.base_dn = base_dn
        self._allowed = canonical_dn(base_dn) if base_dn else None

    def validate_target(self, dn):
        if self._allowed is None:
            return
        candidate = canonical_dn(dn)
        if len(candidate) < len(self._allowed) or candidate[-len(self._allowed):] != self._allowed:
            raise ScopeViolationError("Target is outside --base-dn")

    def resolve_base(self, base, scope):
        if self._allowed is None:
            return base
        candidate = canonical_dn(base)
        if len(candidate) >= len(self._allowed) and candidate[-len(self._allowed):] == self._allowed:
            return base
        if (getattr(scope, "value", scope) == 2 and candidate
                and len(candidate) < len(self._allowed)
                and self._allowed[-len(candidate):] == candidate):
            return self.base_dn
        raise ScopeViolationError("Search base or scope is incompatible with --base-dn")
