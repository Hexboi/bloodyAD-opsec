# bloodyAD-opsec

A command-line tool for Active Directory security testing, based on bloodyAD.
Read directory objects with ready-made enumeration presets, perform authorized
changes, and use scoped safeguards for supported operations.

This tool can modify Active Directory. Use it only with explicit authorization.
OPSEC options do not hide activity from AD auditing or make changes atomic.

## What this fork adds

- **Enumeration presets:** seven additional read-only checks for password policy,
  user descriptions, domain level, machine account quota, AS-REP exposure, SPNs
  and Kerberoasting exposure. See [enumeration commands](#enumeration-commands).
- **AD CS analysis:** `get adcs` reads certificate templates, published CAs and
  directory ACLs, with potential findings, LDAP-based DC recognition and explicit
  coverage limits. See [AD CS analysis](#read-only-ad-cs-analysis).
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

After updating an existing checkout, reinstall the project from its root with
the virtual environment active. This refreshes the installed command without
replacing its dependencies:

```powershell
python -m pip install --no-deps --force-reinstall .
bloodyad-opsec get adcs --help
```

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
Use `bloodyad-opsec --help`, `bloodyad-opsec get --help`, or
`bloodyad-opsec get adcs --help` for the command overview and detailed AD CS guide.
Help does not connect to a domain controller.

## Enumeration commands

Seven additional read-only enumeration presets select the LDAP filters and
attributes for you. Run `bloodyad-opsec get --help` to see all commands; the new
presets are marked `[preset]` in the `get commands` section. Use
`bloodyad-opsec get password-policy --help` for a preset's options.

Add these suffixes after your connection/authentication options:

| Command | Results |
| --- | --- |
| `get password-policy` | Default domain password, lockout and forced-logoff policy, with readable intervals and property flags. |
| `get users-description` | Users and descriptions, including disabled users and users without a returned description. |
| `get domain-level` | Functional level of the contacted DC's domain. |
| `get maq` | Domain MachineAccountQuota. |
| `get asrep` | Users with Kerberos preauthentication disabled, including disabled users. |
| `get spn` | All objects with SPNs; `--spn-class MSSQLSvc` selects a service class. |
| `get kerberoastable` | Enabled users with SPNs and `msDS-SupportedEncryptionTypes` account configuration. |

For example:

```powershell
bloodyad-opsec -H dc.example.test -d example.test -u tester get password-policy
bloodyad-opsec -H dc.example.test -d example.test -u tester --json get kerberoastable --raw
bloodyad-opsec -H dc.example.test -d example.test -u tester get users-description --base "OU=Assessment,DC=example,DC=test"
```

All seven commands support `--raw`, existing text/JSON output and an empty result
set. They use the contacted DC's domain automatically. The four subtree commands
(`users-description`, `asrep`, `spn`, `kerberoastable`) also accept `--base` and
respect `--base-dn`. Root reads reject an incompatible OU confinement. Underscore
aliases (`password_policy`, `users_description`, `domain_level`) are accepted.

Password policy retains original values alongside annotations, including exact
100-nanosecond interval conversion, special values and unknown password-property
bits. `--raw` omits annotations. Missing attributes stay absent. This reads domain
defaults, not FGPP/PSO or a user's resulting policy. `forceLogoff` concerns expiry
of allowed logon hours. A missing user description can mean insufficient read
permissions. `users-description` uses the existing text/JSON renderer, not a table.

These commands enumerate configuration; they do not request roasting tickets or
prove exploitability. Encryption types describe the account, not an issued ticket.
`domain-level` corresponds to ADWSearch's historically named `forest-level` preset.

Existing `get writable` and `get dnsDump` remain available. To approximate ADWSearch's
defaults use `get writable --detail --partition DOMAIN --exclude-del` and
`get dnsDump --no-detail`. BloodyAD's `writable --partition ALL` includes all
advertised naming contexts; ADWSearch's `all` selects domain, Configuration and
Schema. DNS coverage and aggregation differ, including TTL presentation; outputs
are not interchangeable. Enumeration commands do not support write `--dry-run`.

## Read-only AD CS analysis

`bloodyad-opsec get adcs --help` lists coverage, DC exclusions, examples and
unsupported options. Reuse the authentication setup from [Quick start](#quick-start).

```powershell
bloodyad-opsec -H dc.example.test -d example.test -u tester get adcs
bloodyad-opsec -H dc.example.test -d example.test -u tester --json get adcs
bloodyad-opsec -H dc.example.test -d example.test -u tester --json get adcs > adcs-results.json
```

`get adcs` uses only LDAP searches against the contacted DC's Configuration and
domain naming contexts. It reads published CAs, certificate templates, issuance-policy
OID/group links and NTAuth certificates. It does not enroll certificates, write
to AD, or contact CA HTTP/RPC services. No extra dependency is required.

Results contain a coverage record, all visible CAs and templates, publication
relationships, relevant template settings, observed ACL rights and trustee SIDs.
The JSON array contains these record types:

| `kind` | Main fields |
| --- | --- |
| `coverage` | `ca_count`, `template_count`, `checks`, `unverified_checks`, `limitations`. |
| `ca` | `host`, `published_templates`, `certificates`, `acl`, `excluded_dc_sids`, `findings`. |
| `template` | `settings`, `published_on`, `publication`, `issuance_policies`, `linked_groups`, `acl`, `findings`. |

Potential findings cover the following directory-visible conditions:

| Finding | Evidence reported |
| --- | --- |
| ESC1 | Enrollee-supplied subject and authentication usage, with observed enrollment grants. |
| ESC2 | Any Purpose or absent EKUs/application policies, with observed enrollment grants. |
| ESC3 | Certificate Request Agent usage, with observed enrollment grants. |
| ESC4 | Template ownership or relevant modification rights, including unpublished templates. |
| ESC9 | Omitted SID security extension on an authentication template; mapping prerequisites remain unverified. |
| ESC13 | Authentication template issuance policy linked to an AD group. |
| ESC15 | Schema-v1, enrollee-supplied-subject prerequisites; CA patch status remains unverified. |
| `CA_OBJECT_ACL` | CA directory-object ownership or modification rights held by a trustee outside the privileged/DC baseline. |

Active enrollment candidates require a published template. Known manager approval
or authorized-signature requirements block the automatic-issuance ESC1/2/3/15 rules.
ESC13 correlates issuance-policy OIDs with linked groups. Unpublished templates
remain visible; their modification rights can produce a latent ESC4 finding,
but they are not reported as active enrollment paths. `CA_OBJECT_ACL` identifies
dangerous grants on the CA's AD object; it does **not** establish ESC7 service
management rights. Published CA certificates include validity dates, SHA-256
fingerprints and exact-certificate NTAuth matching. This does not validate the
certificate chain, revocation or successful authentication.

Every finding is **potential**, not proof of exploitation or effective access by
the current user. GenericWrite and AutoEnroll alone do not count as Enroll.
Baseline privileged SIDs are excluded from findings; custom delegated accounts
and groups may still be administrators. For CA object ACL findings, one additional
read-only LDAP search identifies computer SIDs with `SERVER_TRUST_ACCOUNT` or
`PARTIAL_SECRETS_ACCOUNT` in the contacted DC's domain, covering writable and
read-only DCs. These SIDs are excluded from `CA_OBJECT_ACL` candidates and listed
as `excluded_dc_sids`; their
original ACL evidence remains visible. No hostname, OU or RID heuristic is used.
Unresolved/foreign-domain trustees remain reportable; missing or malformed role
data cannot suppress a grant. Template finding rules remain unchanged.
No group-membership or token evaluation is performed. Deny/conditional ACEs,
missing descriptors and malformed attributes
produce incomplete-assessment remarks. Missing EKUs are treated as unrestricted
only conditionally because LDAP cannot distinguish absence from hidden values.
Unknown required settings suppress the affected rule and remain
visible as limitations, rather than silently becoming zero or a safe verdict.

CA-side enrollment permissions, CA/DC registry settings, service availability,
patch status, agent restrictions and HTTP/RPC protections remain **unverified**.
In particular, ESC9 depends on external mapping/identity prerequisites and ESC15
depends on CA patch status. Other ESC techniques, including full ESC5 and
ESC6/7/8/10/11/12/14/16/17, are outside coverage. Empty results or no findings do
not establish safety: directory visibility and unverified prerequisites limit
both positive and negative conclusions. LDAP permission/transport errors fail
the command rather than being reported as a clean result.

The command supports `--sleep`, `--jitter`, `--no-tombstone` and
`--no-phantom-root` through the existing LDAP wrapper. It rejects `--base-dn`,
`--dry-run` and `--rollback-file` before connecting. Partial confinement would
invalidate correlations across the Configuration naming context. JSON uses the
existing CLI conventions, including string representations of scalar values.
Unlike the seven enumeration presets, `get adcs` has no `--raw` option.
The existing BloodHound collector's AD CS limitations are unchanged.

Rule references: [Microsoft certificate-template permissions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/211ab1e3-bad6-416d-9d56-8480b42617a4),
[Microsoft issuance-policy attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/8be64e60-4c61-4e20-bd89-0651970f8aa5),
and [Certipy's ESC reference](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation).
Attribute and publishing relationships were informed by ADWSearch's local
`certdump` implementation; its transport and BloodHound exporter are not imported.

## Safeguards and limits

| Option | Supported use |
| --- | --- |
| `--dry-run` | Basic writes listed below; simulates changes, not server-side validation. |
| `--base-dn DN` | `get object`, `get search`, `get children`, and the seven enumeration commands; root reads reject incompatible OU scope. Rejects writes, transitive traversal, and security descriptor resolution. Fixed metadata reads are exceptions. |
| `--rollback-file PATH` | Recovery journal for the operations in the next section. |
| `--sleep SECONDS`, `--jitter RATIO` | Supported reads and basic writes. Search delays count yielded results, not LDAP requests. |
| `--no-tombstone`, `--no-phantom-root` | Filter the named LDAP controls on supported reads and basic writes. |

Basic writes: `add user/computer/groupMember`, `set object/password`,
and `remove object/groupMember`.
Supported reads: `get object/search/children/membership/trusts/dnsDump/writable`,
without `--bh`.
The seven enumeration commands above and `get adcs` also support delays and control filtering.

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

For the new read-only enumeration commands, run `python -m tests.run_lab enumeration`
after configuring the lab credentials below. This suite needs no snapshot and
compares all seven raw outputs with an independent signed/sealed Windows LDAP
reference. It also checks CLI JSON/text, policy annotations, SPN classes, empty
results and OU confinement. Reports contain test status, not directory exports.

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
