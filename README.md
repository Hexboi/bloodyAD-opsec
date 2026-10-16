# bloodyAD-opsec

Independent research fork of [bloodyAD 2.5.5](https://github.com/CravateRouge/bloodyAD)
by CravateRouge, maintained by **[HexKnight](https://github.com/Hexboi)**. Use only with explicit authorization.
This fork is distributed as `bloodyad-opsec` 0.1.0, not as the upstream package.

## Installation

Python 3.10+. Example for Python 3.13:

```powershell
git clone https://github.com/Hexboi/bloodyAD-opsec.git
cd bloodyAD-opsec
py -3.13 -m venv .venv
.venv/Scripts/python -m pip install . -c constraints/tested-py313.txt
.venv/Scripts/Activate.ps1
bloodyad-opsec --help
```

Use [tested-py310.txt](constraints/tested-py310.txt) for Python 3.10.
[Constraints](constraints/) record dependencies tested on Windows, not universal
compatibility. On Linux use `python3 -m venv .venv`, replace `.venv/Scripts/`
with `.venv/bin/` and activate with `source .venv/bin/activate`.
Dependencies install automatically. Only `bloodyad-opsec` is registered, not
`bloodyAD` or `bloodyad`. The internal module remains `bloodyAD`: do not install
this fork and upstream in the same environment. Existing `BLOODYAD_*` variables are unchanged.

## Usage

Supply credentials locally through `BLOODYAD_PASSWORD`; command-line secrets may be visible to other processes.
Results use stdout; diagnostics use stderr.

```powershell
bloodyad-opsec -H dc.example.test -d example.test -u tester get object tester
```

## Safeguards

| Option | Scope and limits |
| --- | --- |
| `--dry-run` | Basic writes below; no mutations, but bind/reads may occur. Does not prove permissions or server-side validation. |
| `--base-dn DN` | `get object/search/children`, without transitive traversal or SD resolution. Writes are rejected. |
| `--rollback-file PATH` | JSONL recovery journal for supported changes below; never shell commands. |
| `--sleep`, `--jitter` | Optional wrapper delays; search pauses count yielded results, not network requests. |
| `--no-tombstone`, `--no-phantom-root` | Filter the named controls on supported wrapper paths. |
| `--chunk` | Unimplemented; only zero is accepted. |

Basic writes: `add user/computer/groupMember`, `set object/password`, `remove object/groupMember`.
Delays/control filtering cover those writes and `get object/search/children/membership/trusts/dnsDump/writable` without `--bh`.
Unsupported combinations, including collector and `msldap` paths, reject protections they cannot enforce.

DN checks compare parsed components: BASE/LEVEL must be inside the boundary;
only ancestor SUBTREE searches are narrowed. Fixed RootDSE, query-policy and
default-container metadata reads are exceptions. Non-ASCII values use conservative exact-case matching.
Supported writes report `applied`, `simulated` or `unchanged`; partial failures report completed steps.
These safeguards do not suppress AD auditing or make operations atomic.

## Recovery

Journal sources: `add user/computer/groupMember` and `set object --bak`.
`--bak` requires `--rollback-file` and one of: `description`, `displayName`,
`info`, `title`, `department`, `telephoneNumber`, `mail`, `wWWHomePage`,
`physicalDeliveryOfficeName`. Unknown/credential attributes cannot be backed up.
For multivalue `description` writes use `--raw --b64` with repeated `-v`; recovery restores original raw values.

Inspect with `rollback inspect PATH`; recover with `rollback apply PATH` using the same server/domain.
Recovery runs in reverse order with GUID, value and USN checks, including unrelated subsequent changes.
Replaying recovered actions is idempotent; conflicts and unconfirmed `prepared` records stop replay.
Reconcile unconfirmed writes through read-only checks. Do not recover alongside concurrent writers.
Journals contain sensitive directory data; file access is restricted to owner/SYSTEM on Windows or mode 0600 on POSIX.

## Tests and build

Install development tools first:

```powershell
.venv/Scripts/python -m pip install -r requirements.txt -c constraints/tested-py313.txt
.venv/Scripts/python -m tests.run_offline
.venv/Scripts/python -m ruff check --select E9,F63,F7,F82 bloodyAD tests
.venv/Scripts/python -m build --sdist --wheel --no-isolation
```

Offline tests never contact a DC. Lab tests are opt-in; the legacy domain-wide mutation suite is omitted.

### Isolated lab

Set `BLOODYAD_LAB_DOMAIN`, `BLOODYAD_LAB_HOST`, `BLOODYAD_LAB_IP`, `BLOODYAD_LAB_USER`
and `BLOODYAD_LAB_PASSWORD`, or use the ignored `tests/secrets.json` following
[the example](tests/secrets.json.example). Environment variables take precedence.
Create and verify a VM snapshot, then set its UUID in `BLOODYAD_LAB_SNAPSHOT`;
the runner checks its format, not snapshot existence, and does not restore it.

Run `.venv/Scripts/python -m tests.run_lab all` (or `safety` / `auth`).
Fixtures use GUID-checked cleanup; inspect manifests after failures in ignored `tests/reports/`.
Installed CLI E2E checks require a separate noneditable installation and a local Git commit
(or `--source-revision` with a separately verified full SHA):

```powershell
python -m venv .venv-e2e
.venv-e2e/Scripts/python -m pip install dist/bloodyad_opsec-0.1.0-py3-none-any.whl -c constraints/tested-py313.txt
.venv/Scripts/python -m tests.e2e_installed --console .venv-e2e/Scripts/bloodyad-opsec.exe --wheel dist/bloodyad_opsec-0.1.0-py3-none-any.whl
```

The E2E harness verifies installed code/metadata against the supplied wheel before creating fixtures.
Certificate tests need an issued certificate in `BLOODYAD_LAB_CERTIFICATE`; no automatic enrollment/template changes occur.
LDAPS trust-chain validation and execution of every offensive command are not certified.

## License

Licensing and required third-party notices: [LICENSE](LICENSE).
