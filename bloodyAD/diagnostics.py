"""Diagnostic summaries deliberately omit credentials and attribute values."""


def describe_write(operation: str, target: str, attributes: list[str]) -> dict[str, object]:
    return {"operation": operation, "target": target, "attributes": list(attributes)}


def describe_connection(config) -> dict[str, object]:
    return {"host": config.host, "scheme": config.scheme,
            "authentication": "kerberos" if config.kerberos else "certificate" if config.certificate else "ntlm"}
