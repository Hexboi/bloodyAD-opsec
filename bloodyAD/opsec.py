"""
Immutable per-invocation safeguards for the bloodyAD-opsec fork.

main.py validates CLI options before creating a connection. Connection handlers
carry their own options; supported wrappers consult those options, not a mutable
global configuration. Defaults leave optional delays and control filtering off.
"""
import asyncio
import random
import math
from dataclasses import dataclass

# OID constants reused across the codebase
LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID = "1.2.840.113556.1.4.2065"
LDAP_SERVER_SEARCH_OPTIONS_OID = "1.2.840.113556.1.4.1340"  # phantom root


@dataclass(frozen=True)
class OpsecOptions:
    sleep: float = 0.0
    jitter: float = 0.3
    # Reserved: nonzero values are rejected; result-count pauses do not split searches.
    chunk_size: int = 0
    base_dn: str | None = None
    dry_run: bool = False
    strip_controls: frozenset[str] = frozenset()
    rollback_file: str | None = None

    def __post_init__(self):
        if not math.isfinite(self.sleep) or self.sleep < 0:
            raise ValueError("--sleep must be finite and nonnegative")
        if not math.isfinite(self.jitter) or not 0 <= self.jitter <= 1:
            raise ValueError("--jitter must be finite and between 0 and 1")
        if self.chunk_size != 0:
            raise ValueError("--chunk is not implemented; only 0 is supported")
        object.__setattr__(self, "strip_controls", frozenset(self.strip_controls))
        if self.base_dn is not None:
            if not isinstance(self.base_dn, str) or not self.base_dn.strip():
                raise ValueError("--base-dn must be a nonempty distinguished name")
            from bloodyAD.search_policy import SearchPolicy
            SearchPolicy(self.base_dn)

    @classmethod
    def from_namespace(cls, args):
        controls = set()
        if getattr(args, "no_tombstone", False):
            controls.update((LDAP_SERVER_SHOW_DELETED_OID, LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID))
        if getattr(args, "no_phantom_root", False):
            controls.add(LDAP_SERVER_SEARCH_OPTIONS_OID)
        return cls(sleep=getattr(args, "sleep", 0.0), jitter=getattr(args, "jitter", 0.3),
                   chunk_size=getattr(args, "chunk", 0), base_dn=getattr(args, "base_dn", None),
                   dry_run=getattr(args, "dry_run", False), strip_controls=frozenset(controls),
                   rollback_file=getattr(args, "rollback_file", None))

    async def pause(self):
        if self.sleep <= 0:
            return
        delta = self.sleep * self.jitter
        wait = random.uniform(max(0.0, self.sleep - delta), self.sleep + delta)
        await asyncio.sleep(wait)

    def should_send_control(self, oid: str) -> bool:
        return oid not in self.strip_controls

    def filter_controls(self, controls):
        if not controls or not self.strip_controls:
            return controls
        return [c for c in controls if c[0] not in self.strip_controls]

# Compatibility name for default options; CLI invocations do not mutate this object.
OpsecConfig = OpsecOptions()
