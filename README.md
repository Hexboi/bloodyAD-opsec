# bloodyAD-opsec

A command-line tool for Active Directory security testing, based on bloodyAD.
Read directory objects, perform authorized changes, and use scoped safeguards
for supported operations.

This tool can modify Active Directory. Use it only with explicit authorization.
OPSEC options do not hide activity from AD auditing or make changes atomic.

## What this fork adds

- **Scoped reads:** restrict supported searches to a distinguished name (DN).
- **Dry-run:** simulate supported writes before applying them.
- **Recovery:** record selected changes and restore them with conflict checks.
- **Execution controls:** optional delays, jitter, and LDAP control filtering.

These features apply to specific commands, not the entire upstream toolset.

## Installation

Requires **Python 3.10+**. Use a separate virtual environment: this fork and
upstream share the internal `bloodyAD` module and must not be installed together.
The installed command is **`bloodyad-opsec`**, not `bloodyAD`.

```text
git clone https://github.com/Hexboi/bloodyAD-opsec.git
cd bloodyAD-opsec
```

**Windows / PowerShell**, using Python 3.13:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install . -c constraints/tested-py313.txt
.\.venv\Scripts\Activate.ps1
```

For Python 3.10, use `py -3.10` and [tested-py310.txt](constraints/tested-py310.txt).
The [constraints](constraints/) record tested Windows dependencies, not universal compatibility.

**Linux**, using Python 3.10+:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Dependencies install automatically. With the environment active, run `bloodyad-opsec --help`.
Without activation on Windows, use `.\.venv\Scripts\bloodyad-opsec.exe` instead.

## Quick start

Online operations require a reachable domain controller and appropriate account permissions.
The following PowerShell examples use placeholder names. Replace them with your environment.

Set the authentication password without putting it directly in command history:

```powershell
$credential = Get-Credential -UserName tester -Message "Domain credentials"
$env:BLOODYAD_PASSWORD = $credential.GetNetworkCredential().Password
```

Read an object:

```powershell
bloodyad-opsec -H dc.example.test -d example.test -u tester get object tester --attr "distinguishedName,description"
```

Restrict a search to an assessment OU:

```powershell
bloodyad-opsec -H dc.example.test -d example.test -u tester --base-dn "OU=Assessment,DC=example,DC=test" get search --filter "(objectClass=user)"
```

Preview an attribute change without applying it:

```powershell
bloodyad-opsec -H dc.example.test -d example.test -u tester --dry-run set object tester description -v "Assessment note"
```

Dry-run may still authenticate and read AD; it does not prove write permissions.
Passwords in environment variables remain sensitive. Remove `BLOODYAD_PASSWORD`
when finished; avoid passing secrets with `-p` on the command line.

For command-specific options, run `bloodyad-opsec get object --help`.
Results go to stdout; diagnostics go to stderr. Add `--json` before the command for JSON output.

## Safeguards and limits

| Option | Supported use |
| --- | --- |
| `--dry-run` | Basic writes listed below; simulates changes, not server-side validation. |
| `--base-dn DN` | `get object`, `get search`, `get children`; rejects writes, transitive traversal, and security descriptor resolution. Fixed metadata reads are exceptions. |
| `--rollback-file PATH` | Recovery journal for the operations in the next section. |
| `--sleep SECONDS`, `--jitter RATIO` | Supported reads and basic writes. Search delays count yielded results, not LDAP requests. |
| `--no-tombstone`, `--no-phantom-root` | Filter the named LDAP controls on supported reads and basic writes. |

Basic writes: `add user/computer/groupMember`, `set object/password`,
and `remove object/groupMember`.
Supported reads: `get object/search/children/membership/trusts/dnsDump/writable`,
without `--bh`.

Unsupported combinations, including collector and `msldap` paths, reject safeguards
they cannot enforce. Chunking is not implemented: `--chunk` accepts only `0`.

## Recovery

Recovery is supported for `add user`, `add computer`, `add groupMember`, and
`set object --bak`. It is not a general undo mechanism for every command.

Record an attribute change, inspect its journal, then restore the original value:

```powershell
bloodyad-opsec -H dc.example.test -d example.test -u tester --rollback-file changes.jsonl set object tester description -v "Assessment note" --bak
bloodyad-opsec -H dc.example.test -d example.test -u tester rollback inspect changes.jsonl
bloodyad-opsec -H dc.example.test -d example.test -u tester rollback apply changes.jsonl
```

- Use the **same DC and domain**, without concurrent writers.
- Actions replay in reverse order. Object identity, values, and change counters are checked; conflicts or unconfirmed writes stop recovery. Recovery can partially complete.
- `--bak` requires `--rollback-file`. Allowed attributes: `description`, `displayName`, `info`, `title`, `department`, `telephoneNumber`, `mail`, `wWWHomePage`, `physicalDeliveryOfficeName`.
- For multivalue `description`, use `--raw --b64` with repeated `-v` values; recovery restores the original raw values.
- Keep journals private: they contain directory data. They are JSONL records, not executable scripts.

## Development and testing

From the repository folder, with the Python 3.13 environment active:

```powershell
python -m pip install -r requirements.txt -c constraints/tested-py313.txt
python -m tests.run_offline
python -m ruff check --select E9,F63,F7,F82 bloodyAD tests
python -m build --sdist --wheel --no-isolation
```

`requirements.txt` adds development tools. Offline tests do not contact a DC.

### Isolated lab tests

Copy [the configuration example](tests/secrets.json.example) to the ignored
`tests/secrets.json` and fill it locally, or set `BLOODYAD_LAB_DOMAIN`,
`BLOODYAD_LAB_HOST`, `BLOODYAD_LAB_IP`, `BLOODYAD_LAB_USER`, and `BLOODYAD_LAB_PASSWORD`.
Environment variables take precedence. Never commit credentials or lab reports.

Before write tests, create and verify a VM snapshot, set its UUID in
`BLOODYAD_LAB_SNAPSHOT`, then run `python -m tests.run_lab all`.
The runner checks the UUID format; it does not verify or restore the snapshot.

Installed-wheel E2E tests require committed source and a separate environment:

```powershell
python -m venv .venv-e2e
.\.venv-e2e\Scripts\python.exe -m pip install dist/bloodyad_opsec-0.1.0-py3-none-any.whl -c constraints/tested-py313.txt
python -m tests.e2e_installed --console .venv-e2e/Scripts/bloodyad-opsec.exe --wheel dist/bloodyad_opsec-0.1.0-py3-none-any.whl
```

The harness verifies installed code against the wheel before creating fixtures.
Certificate tests require an issued certificate in `BLOODYAD_LAB_CERTIFICATE`;
they do not enroll certificates. LDAPS trust-chain validation and execution of
every offensive command are not certified.

## Credits and license

Based on [bloodyAD 2.5.5](https://github.com/CravateRouge/bloodyAD) by CravateRouge.
Maintained independently by [HexKnight](https://github.com/Hexboi).
Licensing and required third-party notices are in [LICENSE](LICENSE).
