"""Fail closed when a command cannot enforce requested options."""
import functools
import inspect
from dataclasses import dataclass

from bloodyAD.opsec import OpsecOptions


class UnsupportedOptionError(ValueError):
    pass


@dataclass(frozen=True)
class CommandCapabilities:
    dry_run: bool = False
    search_scope: bool = False
    filtered_controls: bool = False
    delay: bool = False
    journal: bool = False


_BASIC_WRITES = {("add", n) for n in ("user", "computer", "groupMember")}
_BASIC_WRITES |= {("set", "object"), ("set", "password"),
                  ("remove", "object"), ("remove", "groupMember")}
_READS = {("get", n) for n in ("object", "search", "children", "membership", "trusts", "dnsDump", "writable")}
_JOURNAL = {("add", n) for n in ("user", "computer", "groupMember")} | {("set", "object")}


def capabilities_for(category, command, command_args):
    key = (category, command)
    if key == ("get", "writable") and command_args.get("bh"):
        return CommandCapabilities()
    return CommandCapabilities(
        dry_run=key in _BASIC_WRITES,
        search_scope=key in {("get", n) for n in ("object", "search", "children")}
                     and not command_args.get("transitive") and not command_args.get("resolve_sd"),
        filtered_controls=key in _READS | _BASIC_WRITES,
        delay=key in _READS | _BASIC_WRITES,
        journal=key in _JOURNAL and (key != ("set", "object") or command_args.get("bak", False)),
    )


def validate_capabilities(category, command, options, command_args):
    if (category, command) == ("set", "object") and command_args.get("bak"):
        from bloodyAD.rollback import validate_attribute
        validate_attribute(command_args["attribute"])
        if not options.rollback_file:
            raise UnsupportedOptionError("--bak requires --rollback-file for structured recovery")
    caps = capabilities_for(category, command, command_args)
    for name, active, supported in (
        ("--dry-run", options.dry_run, caps.dry_run),
        ("--base-dn", options.base_dn, caps.search_scope),
        ("control filtering", options.strip_controls, caps.filtered_controls),
        ("--sleep", options.sleep, caps.delay),
        ("--rollback-file", options.rollback_file, caps.journal),
    ):
        if active and not supported:
            raise UnsupportedOptionError(f"{category} {command} does not support {name}")


def guard_module(namespace, category):
    for name, function in list(namespace.items()):
        if name.startswith("_") or not inspect.isfunction(function):
            continue
        if function.__module__ == namespace["__name__"]:
            namespace[name] = _guard(function, category, name)


def _guard(function, category, name):
    signature = inspect.signature(function)

    def validate(args, kwargs):
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        conn = bound.arguments["conn"]
        validate_capabilities(category, name, getattr(conn, "options", OpsecOptions()), bound.arguments)

    if inspect.isasyncgenfunction(function):
        @functools.wraps(function)
        async def generator(*args, **kwargs):
            validate(args, kwargs)
            result = function(*args, **kwargs)
            try:
                async for item in result:
                    yield item
            finally:
                await result.aclose()
        return generator

    @functools.wraps(function)
    async def coroutine(*args, **kwargs):
        validate(args, kwargs)
        return await function(*args, **kwargs)
    return coroutine
