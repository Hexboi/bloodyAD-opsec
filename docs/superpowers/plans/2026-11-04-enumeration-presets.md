# Enumeration presets implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Track verification here.

**Goal:** Expose the seven ADWSearch enumeration recipes as native read-only commands and validate them against the VirtualBox DC.

**Architecture:** Reuse the existing asynchronous LDAP wrapper, capability checks and human/JSON output. Add small command functions in `get.py` and keep policy constants/formatting in a separate module so CLI discovery does not expose helpers. Keep `writable` and `dnsDump` unchanged.

**Tech Stack:** Python >=3.10, existing badldap/ldap3 stack, unittest; no new runtime dependencies.

**Spec:** The user's approved mapping in this chat: password-policy, users-description, domain-level, maq, asrep, spn and kerberoastable. User explicitly requested planning followed by implementation and lab verification without another handoff.

## Global constraints

- Read-only lab verification: no fixture creation, policy changes, tickets for roasting, or directory writes.
- Native command names use hyphens; preserve existing CLI names and Python function names.
- Default base comes from the contacted DC's naming context, not the authentication domain.
- Policy formatting keeps raw values, exact 100-nanosecond intervals, unknown bits and absent attributes. `--raw` bypasses annotations.
- Policy means domain defaults; FGPP/PSO and per-user resulting policy are excluded.
- users-description uses existing text/JSON output; a table renderer is outside this implementation.
- No copying of the MPL ADWSearch implementation into this repository; independently implement the query contract.
- No changes to writable/DNS semantics, no new offline query-preview mode.
- Lab credentials only through existing local configuration or process environment; never in reports or command arguments.

## Review focus

- Hyphenated CLI names must dispatch to the correct Python function and capability key.
- Confined enumeration must not escape an OU; domain-root reads must reject an incompatible OU scope.
- Password policy special values, fractional seconds, invalid values, absent attributes and mixed attribute casing must remain distinguishable.
- SPN service classes must not inject LDAP filters or wildcards.
- Empty results must have predictable CLI behavior; authentication errors must never be reported as a successful empty enumeration.

## Task 1: Query contracts and policy formatter

Files: `bloodyAD/enumeration.py` (new), `bloodyAD/cli_modules/get.py`, `tests/test_enumeration.py` (new).

Interfaces: async generators `password_policy(conn, raw=False)`, `domain_level(conn, raw=False)`, `maq(conn, raw=False)`, `users_description(conn, base="DOMAIN", raw=False)`, `asrep(conn, base="DOMAIN", raw=False)`, `spn(conn, base="DOMAIN", spn_class="", raw=False)`, `kerberoastable(conn, base="DOMAIN", raw=False)`.

- [x] Write tests asserting BASE versus SUBTREE, explicit attributes and exact filters from the ADWSearch contract.
- [x] Write tests for policy flags (including unknown bits), zero and INT64_MIN sentinels, fractional intervals, malformed values, missing attributes and raw bypass.
- [x] Run focused tests; confirm failure before implementation.
- [x] Implement commands through `bloodysearch`, rendering through `renderSearchResult`; policy reads raw LDAP bytes before dedicated formatting.
- [x] Validate SPN classes before network access; escape LDAP filter metacharacters.
- [x] Run focused tests; require all passing.

## Task 2: CLI, scope and documentation

Files: `bloodyAD/main.py`, `bloodyAD/capabilities.py`, `tests/test_enumeration.py`, `README.md`.

Interfaces: canonical CLI names `password-policy`, `users-description`, `domain-level`; Python capability keys retain underscores. Preserve underscore aliases for these names and case-insensitive command handling.

- [x] Add failing CLI dispatch/help, scope, dry-run rejection, injection and empty-result tests.
- [x] Add explicit CLI name mappings without changing existing commands.
- [x] Register all seven commands as delay/control-filter aware reads. Allow scope on them; SearchPolicy enforces BASE domain reads versus OU enumeration.
- [x] Document seven commands, raw/JSON output, domain-level semantics and the writable/DNS differences.
- [x] Run `python -m tests.run_offline`, Ruff's existing fatal-error gate, and `git diff --check`.

## Task 3: Read-only DC comparison

Files: `tests/test_enumeration_lab.py` (new), `tests/run_lab.py`, ignored `tests/reports/`.

Interfaces: opt-in `BLOODYAD_LAB_TESTS=1`, existing `LabConfig`; extend `run_lab` with an enumeration-only suite requiring no mutation snapshot.

- [x] Verify runner selection offline.
- [x] Connect to the configured VirtualBox DC; verify naming context matches configured domain.
- [x] Compare each command's returned attributes/results against explicit LDAP queries, including raw policy and SPN class filtering.
- [x] Exercise real CLI text/JSON and raw output; verify empty searches and incompatible scope behavior.
- [x] Compare raw policy and enumeration sets with an independent LDAP reference when available.
- [x] Run enumeration lab suite; persist a sanitized report with counts and skips, no secrets or directory exports.
- [x] Review complete diff, fix relevant findings and rerun affected checks.

## Execution record

- Branch: `codex/enumeration-presets`; clean initial checkout. Work in place on a dedicated branch to keep changes visible in the user's current workspace.
- User authorized execution immediately after planning; no additional approval checkpoint.
- Initial host Python lacks project dependencies. Create ignored `.venv` and install existing requirements.
- Task 1: complete. Seven query contracts implemented; password policy has dedicated raw-byte formatting with exact intervals. Stream closure regression reproduced before fixing all command wrappers with `contextlib.aclosing`.
- Task 2: complete. Canonical CLI names, aliases, scope capabilities and README updated. Fourteen focused offline tests pass. Full offline run: 120 tests, 19 opt-in/legacy skips, zero failures (101 executed successfully).
- Task 3: complete. VirtualBox GOAD-Mini-DC01, kingslanding.sevenkingdoms.local / 192.168.56.10. Final enumeration run: eight tests, zero skips/failures. All seven commands match independent signed/sealed .NET LDAP, including raw library output, source CLI and installed wheel CLI outside the source tree. Policy annotations, HOST SPNs, empty results and OU confinement also pass.
- Live report: ignored `tests/reports/20261104-154034-enumeration.json`. Initial seven-test run passed; an expanded wheel run caught a test false positive when an enumerated account name equaled the lab password. Restricting credential detection to diagnostics resolved this; final full lab run passed. Failed comparisons now omit directory data.
- Environment: Windows, Python 3.14.3, isolated `.venv`, existing project dependencies only. Credentials supplied through a private process prompt, inherited only by test subprocesses; no credentials written to repository/configuration files.
- Verification: sdist/wheel build, installed console checks, fatal-error Ruff gate, pip dependency check and git whitespace check passed. Fresh independent review found no outstanding issues after the lifecycle correction.
- Ruling: retain native text/JSON output for users-description rather than add a table renderer; preserve writable/DNS behavior and document differences. Domain-root reads support compatible confinement and reject OU confinement through existing SearchPolicy. No FGPP or per-user policy resolution.
- No domain mutations, fixture creation, snapshot changes, ticket harvesting, merge, push or commit performed. VM left running. Changes remain reviewable on `codex/enumeration-presets`.
