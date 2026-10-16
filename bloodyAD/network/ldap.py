from bloodyAD.formatters import accesscontrol, common, formatters
from bloodyAD.exceptions import NoResultError, TooManyResultsError, LOG
from bloodyAD.opsec import OpsecOptions
from bloodyAD import diagnostics
from bloodyAD.operations import WriteOutcome, PartialWriteError
from bloodyAD.search_policy import SearchPolicy
from ldap3.utils.conv import escape_filter_chars
import re, os, enum, asyncio, urllib, collections
from functools import cached_property, lru_cache
from asn1crypto import core
from badldap.client import MSLDAPClient
from badldap.commons.factory import LDAPConnectionFactory
from badldap.commons.exceptions import LDAPModifyException
from badldap.protocol.messages import Change as LDAPChange, PartialAttribute, ModifyRequest, protocolOp, Control
from badldap.wintypes.asn1.sdflagsrequest import SDFlagsRequestValue
from badldap.network import reacher
from winacl import dtyp


class Scope(enum.Enum):
    BASE = 0
    LEVEL = 1
    SUBTREE = 2


class Change(enum.Enum):
    ADD = "add"
    DELETE = "delete"
    REPLACE = "replace"
    INCREMENT = "increment"


class NCType(enum.IntFlag):
    PARTIAL_DOM = 1
    FULL_DOM = 2
    APP = 4
    ALL = PARTIAL_DOM | FULL_DOM | APP


@lru_cache
def phantomRoot() -> list:
    # [MS-ADTS] 3.1.1.3.4.1.12
    # Search control to search in all NC replicas except applications replicas (DNS partitions)
    class SearchOptionsRequest(core.Sequence):
        _fields = [
            ("Flags", core.Integer),
        ]

    SERVER_SEARCH_FLAG_PHANTOM_ROOT = 2
    scontrols = SearchOptionsRequest({"Flags": SERVER_SEARCH_FLAG_PHANTOM_ROOT})
    LDAP_SERVER_SEARCH_OPTIONS_OID = "1.2.840.113556.1.4.1340"

    return [(LDAP_SERVER_SEARCH_OPTIONS_OID, False, scontrols.dump())]

@lru_cache
def showRecoverable() -> list:
    # Show link values stored and referring to deleted objects
    LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID = "1.2.840.113556.1.4.2065"
    # Show tombstoned and deleted objects (excluding recycled which are not recoverable using ldap)
    LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
    return [(LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID, True, None), (LDAP_SERVER_SHOW_DELETED_OID, True, None)]

class Ldap(MSLDAPClient):
    conf = None
    domainNC = None
    configNC = None
    # Parent ConnectionHandler; per-instance domain connections live in _trustmap.
    conn = None
    co_url = None

    def __init__(self, conn, target, credential):
        self._trustmap = collections.defaultdict(dict)
        self.conn = conn
        self.options = getattr(conn, "options", OpsecOptions())
        self.conf = conn.conf
        self.co_url = None
        super().__init__(target, credential, keepalive=True)
        self.isactive = False
        self._policy_cache = None
        self._policy_lock = None

    @classmethod
    async def create(cls, conn):
        """Async factory method to create and initialize an Ldap instance"""
        cnf = conn.conf

        # Because badldap uses a url format we have to encode everything properly
        encoded_cnf = {}
        for attr_name, attr_value in vars(cnf).items():
            if type(attr_value) is str:
                encoded_cnf[attr_name] = urllib.parse.quote(attr_value, safe="")
            else:
                encoded_cnf[attr_name] = attr_value

        auth = ""
        creds = ""
        username = ""
        key = ""
        params = "serverip=" + cnf.dcip

        if cnf.kerberos:
            username = "%s\\%s" % (encoded_cnf["domain"], encoded_cnf["username"])
            if cnf.dcip == cnf.host:
                raise ValueError(
                    "You can provide the IP in --dc-ip but you need to provide the"
                    " hostname in --host in order for kerberos to work"
                )
            params += "&dc=" + cnf.kdc
            if cnf.kdcc and cnf.realmc:
                params += f"&dcc={cnf.kdcc}&realmc={cnf.realmc}"
            auth = "kerberos-"
            key = encoded_cnf["key"]
            if cnf.crt:
                file_extension = cnf.crt.rsplit('.',1)[1]
                if file_extension in ["pfx", "p12"]:
                    auth += "pfx"
                elif file_extension == "pem":
                    auth += "pem"
                else:
                    LOG.warning("No .pem/.pfx extension detected, will try .pem")
                    auth += "pem"
                params += "&certdata=" + encoded_cnf["crt"]
                if cnf.key:
                    params += "&keydata=" + key
                    key = ""
                if cnf.password:
                    key = encoded_cnf["password"]
            elif key:
                auth += cnf.krbformat
                if cnf.format in ["b64", "hex"]:
                    auth += cnf.format
            else:
                if cnf.password:
                    if cnf.format in ["aes", "rc4"]:
                        auth += cnf.format
                    else:
                        auth += "password"
                    key = encoded_cnf["password"]
                else:
                    if os.name == "nt":
                        if cnf.certificate:
                            auth += "certstore"
                        else:
                            auth = "sspi-kerberos"
                    else:
                        raise ValueError(
                            "You should provide a -p 'password' or a kerberos ticket"
                            " via '-k <keyfile_type>=./myticket'"
                        )                   
        elif cnf.certificate:
            if cnf.crt:
                auth = "ssl"
                params += "&sslcert=" + encoded_cnf["crt"]
                if cnf.key:
                    params += "&sslkey=" + encoded_cnf["key"]
                if cnf.password:
                    params += "&sslpassword=" + encoded_cnf["password"]
            else:
                if os.name == "nt":
                    auth = "kerberos-certstore"
                else:
                    raise ValueError(
                        "Certstore only available on Windows, --certstore can't be left empty here"
                    )
        else:
            username = "%s\\%s" % (encoded_cnf["domain"], encoded_cnf["username"])
            if cnf.nthash:
                auth = "ntlm-nt"
                key = encoded_cnf["nthash"]
            else:
                key = encoded_cnf["password"]
                if not key:
                    if os.name == "nt":
                        auth = "sspi-ntlm"
                    else:
                        raise ValueError("You should provide a -p 'password'")
                else:
                    auth = "ntlm-pw"
                    if cnf.format in ["b64", "hex"]:
                        auth += cnf.format

        if cnf.timeout:
            params += f"&timeout={cnf.timeout}"
        if cnf.dns:
            params += "&dns=" + cnf.dns

        # If auth has been defined in config we replace auth we built with it
        if cnf.auth:
            auth = cnf.auth + '-' + auth.split("-",1)[1]
        auth = "+" + auth if auth else ""
        creds = username if username else ""
        creds = creds + ":" + key if key else creds
        creds = creds + "@" if creds else ""
        params = "/?" + params
        co_url = f"{cnf.scheme}{auth}://{creds}{encoded_cnf['host']}{params}"
        LOG.debug("Connection: %s", diagnostics.describe_connection(cnf))
        ldap_factory = LDAPConnectionFactory.from_url(co_url)
        
        # Create instance
        instance = cls(conn, ldap_factory.target, ldap_factory.credential)
        instance.co_url = co_url

        if cnf.debug == 3:
            instance._disable_channel_binding = True
            instance._disable_signing = True
            instance._null_channel_binding = True
        
        # Connect asynchronously
        try:
            LOG.debug(f"Trying to connect to {cnf.host}...")
            _, err = await instance.connect()
            if err:
                raise err
            LOG.debug("Connection successful")
            instance.isactive = True
            instance.domainNC = instance._serverinfo["defaultNamingContext"]
            instance.configNC = instance._serverinfo["configurationNamingContext"]
            instance.schemaNC = instance._serverinfo["schemaNamingContext"]
            instance.appNCs = []
            for nc in instance._serverinfo["namingContexts"]:
                if nc in [instance.domainNC, instance.configNC, instance.schemaNC]:
                    continue
                instance.appNCs.append(nc)
        except Exception as e:
            raise e
        
        return instance

    async def _complete_write(self, outcome):
        try:
            await self.options.pause()
        except (Exception, asyncio.CancelledError) as error:
            if outcome.completed_steps:
                raise PartialWriteError(WriteOutcome("partial", outcome.operation,
                                                    outcome.target, outcome.completed_steps)) from error
            raise
        return outcome

    async def bloodyadd(self, target, controls=None, **kwargs):
        if self.options.base_dn:
            raise ValueError("--base-dn is a search boundary and cannot authorize writes")
        # OPSEC: dry-run short-circuit
        if self.options.dry_run:
            LOG.warning("[DRY-RUN] %s", diagnostics.describe_write("add", target, list(kwargs.get("attributes", {}))))
            return WriteOutcome("simulated", "add", target)
        # OPSEC: strip controls operator asked to disable
        if controls is not None:
            controls = self.options.filter_controls(controls)
            t = []
            for control in controls:
                t.append(
                    {
                        "controlType": control[0].encode(),
                        "criticality": control[1],
                        "controlValue": control[2],
                    }
                )
            controls = t
        _, err = await self.add(await self.dnResolver(target), controls=controls, **kwargs)
        if err:
            raise err
        return await self._complete_write(WriteOutcome("applied", "add", target, ("add",)))

    async def close(self):
        if not self.isactive:
            return
        self.isactive = False
        for trust in self._trustmap.values():
            if "conn" in trust and trust["conn"] != self.conn:
                await trust["conn"].closeLdap()
        await self.disconnect()

    async def bloodydelete(self, target, *args):
        if self.options.base_dn:
            raise ValueError("--base-dn is a search boundary and cannot authorize writes")
        if self.options.dry_run:
            LOG.warning(f"[DRY-RUN] bloodydelete target={target}")
            return WriteOutcome("simulated", "delete", target)
        _, err = await self.delete(await self.dnResolver(target), *args)
        if err:
            raise err
        return await self._complete_write(WriteOutcome("applied", "delete", target, ("delete",)))

    async def dnResolver(self, identity):
        """
        Return the DN for the object based on the parameters identity
        Args:
            identity: sAMAccountName, DN, UPN, GPO name or SID of the object
        """
        if ",dc=" in identity.lower():
            # Explicit DNs skip name lookup, but must respect any configured boundary.
            SearchPolicy(self.options.base_dn).validate_target(identity)
            return identity

        identity = escape_filter_chars(identity)

        if identity.lower().startswith("s-1-"):
            # We assume identity is an SID
            ldap_filter = f"(objectSid={identity})"
        # For GPO name as GPO has no sAMAccountName
        elif identity.startswith("{"):
            ldap_filter = f"(name={identity})"
        elif "@" in identity:
            # Assume identity is a UPN
            ldap_filter = f"(userPrincipalName={identity})"
        else:
            # By default, we assume identity is a sam account name
            ldap_filter = f"(sAMAccountName={identity})"

        dn = ""
        entries = self.pagedsearch(
            ldap_filter, ["distinguishedName"], tree=self.options.base_dn or self.domainNC
        )
        async for entry, err in entries:
            if err:
                raise err
            if dn:
                raise TooManyResultsError(self.domainNC, ldap_filter, entries)
            dn = entry["attributes"]["distinguishedName"]

        if not dn and self.options.base_dn:
            raise NoResultError(self.options.base_dn, ldap_filter)
        if not dn:
            # Try ambiguous name resolution as last resort for debug
            entries = self.pagedsearch(
            f"(anr={identity})", ["distinguishedName"], tree=self.domainNC
            )
            anr_dn = []
            async for entry, err in entries:
                if err:
                    raise err
                anr_dn.append(entry["attributes"]["distinguishedName"])
            if anr_dn:
                LOG.error(
                    f"No results found for '{identity}' but found entries that could match: {anr_dn}"
                )
            raise NoResultError(self.domainNC, ldap_filter)

        SearchPolicy(self.options.base_dn).validate_target(dn)
        return dn

    async def _modify_raw(self, target_dn, changes, controls):
        """Send already encoded values without guessing schema cardinality."""
        try:
            encoded_changes = []
            for attribute, operations in changes.items():
                for operation, values in operations:
                    if values is None:
                        values = []
                    elif isinstance(values, bytes):
                        values = [values]
                    if not isinstance(values, (list, tuple)) or any(not isinstance(value, bytes) for value in values):
                        raise TypeError("Raw attribute values must be bytes")
                    encoded_changes.append(LDAPChange({
                        "operation": operation,
                        "modification": PartialAttribute({"type": attribute.encode("utf-8"), "attributes": list(values)}),
                    }))
            message = {"protocolOp": protocolOp({"modifyRequest": ModifyRequest({
                "object": target_dn.encode("utf-8"), "changes": encoded_changes,
            })})}
            if controls is not None:
                message["controls"] = [Control(control) for control in controls]
            message_id = await self._con.send_message(message)
            responses = await self._con.recv_message(message_id)
            for response in responses:
                if isinstance(response, Exception):
                    raise response
                if response["protocolOp"].name == "modifyResponse":
                    result = response.native["protocolOp"]
                    if result["resultCode"] != "success":
                        raise LDAPModifyException(target_dn, result["resultCode"], result["diagnosticMessage"])
                    return True, None
            raise RuntimeError("No modify response received")
        except Exception as error:
            return False, error

    async def bloodymodify(self, target, changes, controls=None, encode=True, is_restore=False):
        """
        Perform attribute changes and, unless restoring, a separate modify_dn operation.

        :param target: Name of the object whose attributes are to be modified
        :type target: str
        :param changes: Dictionary of {'attribute': [('change_type', [value])]}
        :type changes: dict
        :param controls: Optional LDAP control tuples (OID, criticality, value)
        :type controls: list
        :param encode: Encode values through the dependency's schema codecs when true; otherwise require bytes or lists/tuples of bytes, with None mapping to an empty value set
        :type encode: bool
        :param is_restore: if true, distinguishedName is handled in the same modify as other attributes (required for restore operations)
        :type is_restore: bool
        """
        if self.options.base_dn:
            raise ValueError("--base-dn is a search boundary and cannot authorize writes")
        if self.options.dry_run:
            LOG.warning("[DRY-RUN] %s", diagnostics.describe_write("modify", target, list(changes)))
            return WriteOutcome("simulated", "modify", target)
        if controls is not None:
            controls = self.options.filter_controls(controls)
            t = []
            for control in controls:
                t.append(
                    {
                        "controlType": control[0].encode(),
                        "criticality": control[1],
                        "controlValue": control[2],
                    }
                )
            controls = t

        new_dn = ""
        attr_changes = {}
        for attr_name in changes:
            if attr_name.lower() == "distinguishedname" and not is_restore:
                new_dn = changes[attr_name][0][1][0]
            else:
                attr_changes[attr_name] = changes[attr_name]
        target_dn = await self.dnResolver(target)
        if attr_changes:
            if encode:
                _, err = await self.modify(target_dn, attr_changes, controls, encode=True)
            else:
                _, err = await self._modify_raw(target_dn, attr_changes, controls)
            if err:
                raise err
        completed = ["modify"] if attr_changes else []
        if new_dn:
            try:
                new_rdn, new_superior = new_dn.split(",", 1)
                old_rdn, old_superior = target_dn.split(",", 1)
                new_superior = new_superior if new_superior != old_superior else None
                _, err = await self._con.modify_dn(target_dn, new_rdn, newSuperior=new_superior)
                if err:
                    raise err
                completed.append("modify_dn")
            except Exception as error:
                if completed:
                    raise PartialWriteError(WriteOutcome("partial", "modify", target, tuple(completed))) from error
                raise
        return await self._complete_write(WriteOutcome("applied" if completed else "unchanged", "modify", target, tuple(completed)))

    @cached_property
    def current_site(self):
        return (self._serverinfo["serverName"].rsplit(",CN=Sites")[0]).split(
            ",CN=Servers,CN="
        )[1]

    async def get_is_gc(self):
        # GC may omit the server's LDAP "options" attribute; this is not self.options.
        if self.conf.scheme == "gc":
            return True

        NTDSDSA_OPT_IS_GC = 1
        # Query the server's GC flag when the connection scheme is not already GC.
        entry = None
        async for e in self.bloodysearch(self._serverinfo["dsServiceName"], attr=["options"]):
            entry = e
            break
        if entry:
            nTDSDSA_options = entry["options"]
            return nTDSDSA_options & NTDSDSA_OPT_IS_GC
        return False
    
    @property
    def is_gc(self):
        # Scheme-only compatibility check; get_is_gc() can query the server's GC flag.
        return self.conf.scheme == "gc"

    async def read_metadata(self, kind):
        """Read fixed bootstrap metadata independently of application scope."""
        if kind == "default_containers":
            base, ldap_filter, attributes, scope = self.domainNC, "(objectClass=*)", ["wellKnownObjects"], 0
        elif kind == "rootdse":
            base, ldap_filter, attributes, scope = "", "(objectClass=*)", ["defaultNamingContext", "dnsHostName"], 0
        elif kind == "query_policy":
            server = self._serverinfo["dsServiceName"]
            default = "CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services," + self.configNC
            match = re.search("[^,]+,CN=Sites.+", server)
            site = "CN=NTDS Site Settings," + match.group() if match else None
            names = [server, default] + ([site] if site else [])
            base, scope = self.configNC, 2
            ldap_filter = "(|" + "".join("(distinguishedName=" + escape_filter_chars(dn) + ")" for dn in names) + ")"
            attributes = ["lDAPAdminLimits", "queryPolicyObject"]
        else:
            raise ValueError("Unknown metadata request")
        stream = self.pagedsearch(ldap_filter, attributes, tree=base, search_scope=scope, raw=True)
        entries = []
        try:
            async for entry, error in stream:
                if error:
                    raise error
                entries.append(entry)
        finally:
            await stream.aclose()
        if kind != "query_policy":
            return [{"distinguishedName": e["objectName"], **formatters.applyFormatters(e["attributes"])} for e in entries]
        return entries

    async def get_policy(self):
        if getattr(self, "_policy_cache", None) is not None:
            return dict(self._policy_cache)
        if getattr(self, "_policy_lock", None) is None:
            self._policy_lock = asyncio.Lock()
        async with self._policy_lock:
            if getattr(self, "_policy_cache", None) is not None:
                return dict(self._policy_cache)
            entries = await self.read_metadata("query_policy")
            server = self._serverinfo["dsServiceName"]
            raw_limits = None
            ordered = sorted(entries, key=lambda e: 2 if e["objectName"] == server else 0 if e["objectName"].startswith("CN=Default Query Policy,") else 1)
            for entry in ordered:
                attributes = entry.get("attributes", {})
                values = attributes.get("lDAPAdminLimits")
                references = attributes.get("queryPolicyObject", [])
                if not isinstance(references, list):
                    references = [references]
                for reference in references:
                    dn = reference.decode() if isinstance(reference, bytes) else reference
                    SearchPolicy(self.configNC).validate_target(dn)
                    stream = self.pagedsearch("(objectClass=*)", ["lDAPAdminLimits"], tree=dn, search_scope=0, raw=True)
                    try:
                        async for policy, error in stream:
                            if error:
                                raise error
                            values = policy.get("attributes", {}).get("lDAPAdminLimits", values)
                    finally:
                        await stream.aclose()
                if values:
                    raw_limits = values
            result = {"MaxPageSize": 1000}
            if raw_limits:
                if not isinstance(raw_limits, list):
                    raw_limits = [raw_limits]
                for raw_limit in raw_limits:
                    try:
                        text = raw_limit.decode() if isinstance(raw_limit, bytes) else raw_limit
                        key, value = text.split("=", 1)
                        number = int(value)
                        if number <= 0:
                            raise ValueError
                        result[key] = number
                    except (ValueError, TypeError, UnicodeError):
                        LOG.warning("Ignoring malformed LDAP query policy value")
            else:
                LOG.debug("No readable LDAP query policy; using MaxPageSize=1000")
            self._policy_cache = result
            return dict(result)

    async def getTrustMap(self, nctype=NCType.ALL):
        if self._trustmap and (self._nctype & nctype) == nctype:
            return self._trustmap
        await self.getTrusts(
            transitive=True,
            dns=self.conf.dns,
            allow_gc=(nctype == NCType.PARTIAL_DOM),
        )
        return self._trustmap

    async def interTrustOp(self, partition_map, op_params, op_name="bloodysearch"):
        async def partitionOp(conn_list):
            for conn in conn_list:
                try:
                    ldap = await conn.ldap
                    op_fn = getattr(ldap, op_name)
                    return op_fn(op_params)
                except Exception as e:
                    LOG.error(
                        "Inter-trust operation failed (%s); connection=%s",
                        type(e).__name__, diagnostics.describe_connection(conn.conf),
                    )

        tasks = []
        for pattr in partition_map.values():
            tasks.append(partitionOp(pattr["conn_list"]))
        op_results = await asyncio.gather(*tasks)
        return op_results

    async def bloodysearch(
        self,
        base,
        ldap_filter="(objectClass=*)",
        search_scope=Scope.BASE,
        attr=None,
        control_flag=(
            accesscontrol.OWNER_SECURITY_INFORMATION
            + accesscontrol.GROUP_SECURITY_INFORMATION
            + accesscontrol.DACL_SECURITY_INFORMATION
        ),
        controls=None,
        raw=False,
    ):          
        # Handles corner case where querying default partitions (no dn provided for that)
        if base and "=" not in base:
            base_dn = await self.dnResolver(base)
        else:
            base_dn = base

        # Compare parsed DN components. Only ancestor SUBTREE searches can be narrowed;
        # outside BASE/LEVEL requests and empty bases are rejected when confined.
        base_dn = SearchPolicy(self.options.base_dn).resolve_base(base_dn, search_scope)
        if self.options.base_dn and controls and any(c[0] == "1.2.840.113556.1.4.1340" for c in controls):
            raise ValueError("Phantom-root searches are incompatible with --base-dn")

        if attr is None:
            attr = ["*"]

        # Build a local controls list to avoid mutating caller-provided lists
        local_controls = list(controls) if controls else []
        if control_flag:
            # Search control to request security descriptor parts
            req_flags = SDFlagsRequestValue({"Flags": control_flag})
            local_controls.append(("1.2.840.113556.1.4.801", True, req_flags.dump()))

        # OPSEC: strip controls operator asked to disable
        local_controls = self.options.filter_controls(local_controls)

        policy = await self.get_policy()
        self.ldap_query_page_size = policy["MaxPageSize"]
        page_size = max(1, self.ldap_query_page_size)

        # Always get raw data from pagedsearch, then apply formatters ourselves
        search_generator = self.pagedsearch(
            ldap_filter,
            attr,
            tree=base_dn,
            search_scope=search_scope.value,
            controls=local_controls,
            raw=True,  # Always get raw data
        )

        isNul = True
        entry_count = 0
        try:
            async for entry, err in search_generator:
                if err:
                    raise err
                isNul = False

                # Apply formatting to attributes before yielding (only if not raw)
                attributes = entry["attributes"]
                if not raw:
                    attributes = formatters.applyFormatters(attributes)

                yield {
                    **{"distinguishedName": entry["objectName"]},
                    **attributes,
                }

                # Count yielded results, not transport page requests: no wire-spacing guarantee.
                entry_count += 1
                if self.options.sleep > 0 and entry_count % page_size == 0:
                    await self.options.pause()
        finally:
            await search_generator.aclose()
        if isNul:
            raise NoResultError(base_dn, ldap_filter)
        # Final pause after the search completes, between consecutive bloodysearch calls
        if self.options.sleep > 0:
            await self.options.pause()

    async def getTrusts(self, transitive=False, dns="", allow_gc=True):
        # We shouldn't need to make trust_dict async_safe cause there is no call to trust_dict before an await access it in fetchTrusts()
        trust_dict = {}
        trust_to_explore = await self.fetchTrusts(
            self.conn, trust_dict, dns, allow_gc=allow_gc
        )

        # We don't do it on foreign trust because there is no transitivity between 3 forests (A<->B<->C) A doesn't have trust on C even if B has it
        if transitive:
            if not self.conf.domain:
                LOG.warning(
                    "No domain (-d, --domain) provided, transitive trust search will not be"
                    " performed"
                )
            elif self.conf.domain not in trust_dict:
                LOG.warning(
                    "User doesn't belong to this forest, transitive trust search will not be"
                    " performed"
                )
            else:
                LOG.info(
                    "Forest trusts fetched, performing transitive trust search"
                )
                tasks = []
                for domain_name, parent_conn in trust_to_explore.items():
                    tasks.append(
                        self.fetchTrusts(
                            parent_conn, trust_dict, dns, domain_name, allow_gc=allow_gc
                        )
                    )
                await asyncio.gather(*tasks)

        if not trust_dict:
            LOG.warning("No Trusts found")
        return trust_dict

    async def fetchTrusts(self, conn, trust_dict, dns, domain_name="", allow_gc=True):
        # Search request to look into all available domain partitions on the dc for trusts relationships
        # We don't care if because of simultaneous dc search there are duplicates, the overhead is minor, trusts are not many
        search_params = {
            "base": "",
            "ldap_filter": "(objectClass=trustedDomain)",
            "attr": [
                "trustDirection",
                "trustPartner",
                "trustAttributes",
                "trustType",
                "securityIdentifier",
            ],
            "search_scope": Scope.SUBTREE,
            "raw": True,
            "controls": phantomRoot(),
        }
        trusts = await self.searchInForest(
            conn, search_params, dns, domain_name, allow_gc
        )
        # Tree root is the DC domain
        trust_to_explore = {}
        for trust in trusts:
            already_in_tree = (
                ((trust["distinguishedName"]).rsplit("CN=System,", 1)[1]).replace(
                    "DC=", ""
                )
            ).replace(",", ".")
            if already_in_tree not in trust_dict:
                trust_dict[already_in_tree] = {}
            trust_dict[already_in_tree][trust["trustPartner"][0].decode()] = trust

            # Let's not waste a run of fetchTrusts and keep active track of it so we can reuse it later
            self._trustmap[already_in_tree]["conn"] = trust["parent_conn"]
            self._trustmap[trust["trustPartner"][0].decode()]["domsid"] = str(
                dtyp.sid.SID.from_bytes(trust["securityIdentifier"][0])
            )

            # We already have access to all the partitions of the forest through the GC we don't need to connect to other forest DCs
            if (
                common.TRUST_ATTRIBUTES["WITHIN_FOREST"]
                & int(trust["trustAttributes"][0].decode())
                > 0
            ):
                continue
            # We assume user belongs to forest of provided DC in --host so we can explore external trusts only if we can auth on them (inbound)
            if (
                common.TRUST_DIRECTION["INBOUND"]
                & int(trust["trustDirection"][0].decode())
                > 0
            ):
                # NOTE: If we need later we can add more than one parent_conn as a failsafe and then try to co to trust with more than one parent_conn
                # Useful when using kerberos and performing cross realm
                trust_to_explore[trust["trustPartner"][0].decode()] = trust[
                    "parent_conn"
                ]
        return trust_to_explore

    async def searchInForest(
        self, conn, search_params, dns, domain_name="", allow_gc=True
    ):
        # If domain_name is provided it means we try to reach a domain outside of current "conn" forest so we have to find a server that we can reach for this outsider domain and then we search the entire forest related to this outsider domain
        newconn = conn
        if domain_name:
            ldap_conn = await newconn.getLdap()
            host_params = await reacher.findReachableDomainServer(
                domain_name,
                ldap_conn.current_site,
                server_type="" if allow_gc else "ldap",
                dns_addr=dns,
                dc_dns=newconn.conf.dcip,
            )
            if not host_params:
                LOG.warning(
                    f"No reachable server found for {domain_name}, try to provide one"
                    " manually in --host"
                )
                return {}
            schemes = {389: "ldap", 636: "ldaps", 3268: "gc", 3269: "gc-ssl"}
            newconn = conn.copy(
                scheme=schemes[host_params["port"]],
                host=host_params["name"],
                dcip=host_params["ip"],
            )

        search_results = []
        # dc is a gc for this forest, hosting every records we want, we don't need to look for other domain partitions on other dc
        # Except if we're looking for attributes no replicated in GC, then searchInForest must be called with allow_gc=False
        newconn_ldap = await newconn.getLdap()
        if newconn_ldap.is_gc and allow_gc:
            search_results = await self.searchInPartition(
                newconn, search_params, dns, allow_gc=allow_gc
            )
            if newconn != conn and newconn._ldap:
                await newconn._ldap.close()
            return search_results

        # Find all domain partitions in the forest and dc hosting them
        try:
            # Find nTDSDSA objects containing msDS-HasDomainNCs and server objects parents containing dNSHostname
            ldap_conn = await newconn.getLdap()
            entries = ldap_conn.bloodysearch(
                "CN=Sites," + ldap_conn.configNC,
                "(|(objectClass=nTDSDSA)(objectClass=server))",
                search_scope=Scope.SUBTREE,
                attr=["msDS-HasDomainNCs", "dNSHostName", "objectClass"],
            )
            # Put domain partitions and hostnames together by matching server distinguished name on them
            forest_servers = collections.defaultdict(dict)
            async for entry in entries:
                if "server" in entry["objectClass"]:
                    try:
                        forest_servers[entry["distinguishedName"]]["host"] = entry[
                            "dNSHostName"
                        ]
                    except KeyError:
                        LOG.warning(
                            f"No dNSHostName found for DC {entry['distinguishedName']}, the DC may have been demoted or have synchronization issues"
                        )
                else:
                    parent_name = (entry["distinguishedName"]).split(",", 1)[1]
                    try:
                        forest_servers[parent_name]["partitions"] = entry[
                            "msDS-HasDomainNCs"
                        ]
                    except:
                        print("There was some error here")

            # Reorganize dict on domain so domain becomes the key containing the hosts
            forest_partitions = collections.defaultdict(list)
            for dn, attributes in forest_servers.items():
                if "host" not in attributes:
                    LOG.warning(
                        f"No dNSHostName found for DC {dn}, the DC may have been demoted or have synchronization issues"
                    )
                for p in attributes.get("partitions"):
                    forest_partitions[p].append(
                        {"type": ["A", "AAAA"], "name": attributes["host"]}
                    )
            tasks = []
            for p, hosts in forest_partitions.items():
                host_list = hosts
                # if newconn already has this partition don't provide new hosts to connect to
                if p in ldap_conn._serverinfo["namingContexts"]:
                    host_list = []
                tasks.append(
                    self.searchInPartition(
                        newconn, search_params, dns, p, host_list, allow_gc=allow_gc
                    )
                )
            search_results = await asyncio.gather(*tasks)
            search_results = [entry for entries in search_results for entry in entries]
        except Exception as e:
            LOG.error(
                "Forest search failed (%s); connection=%s",
                type(e).__name__, diagnostics.describe_connection(newconn.conf),
            )
        finally:
            if newconn != conn and newconn._ldap:
                await newconn._ldap.close()
        return search_results

    async def searchInPartition(
        self,
        conn,
        bloodysearch_params,
        dns,
        partition="",
        host_records=None,
        allow_gc=True,
    ):
        schemes = {389: "ldap", 636: "ldaps", 3268: "gc", 3269: "gc-ssl"}
        ports = [389, 636]
        if allow_gc:
            ports += [3268, 3269]
        # If host_records empty means the dc in "conn" is already the one we want to query
        if host_records:
            host_params = await reacher.findReachableServer(
                host_records, dns, conn.conf.dcip, ports=ports
            )
            if not host_params:
                LOG.warning(
                    f"No reachable server found for {partition}, try to provide one"
                    " manually in --host"
                )
                return {}
            newconn = conn.copy(
                scheme=schemes[host_params["port"]],
                host=host_params["name"],
                dcip=host_params["ip"],
            )

        else:
            newconn = conn

        search_result = []
        try:
            newconn_ldap = await newconn.getLdap()
            if bloodysearch_params["base"] == "domainNC":
                # The directory can be handled by others instances of the function so we have to duplicate it before modifying it
                bloodysearch_params = dict(bloodysearch_params)
                bloodysearch_params["base"] = newconn_ldap.domainNC
            # We add parent_conn to know which conn has the trust, useful for krb cross realm
            search_result = [
                {"parent_conn": newconn, **entry}
                async for entry in newconn_ldap.bloodysearch(**bloodysearch_params)
            ]
        except Exception as e:
            LOG.error(
                "Partition search failed (%s); connection=%s",
                type(e).__name__, diagnostics.describe_connection(newconn.conf),
            )
        finally:
            if newconn != conn and newconn._ldap:
                await newconn._ldap.close()
        return search_result


