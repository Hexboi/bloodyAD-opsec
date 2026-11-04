param(
    [Parameter(Mandatory)][string]$Base,
    [Parameter(Mandatory)][string]$Filter,
    [Parameter(Mandatory)][string]$Attributes,
    [ValidateSet('Base','Subtree')][string]$Scope = 'Subtree'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices.Protocols
$identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($env:BLOODYAD_LAB_IP,389)
$connection = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
try {
    $connection.Timeout = [TimeSpan]::FromSeconds(15)
    $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $connection.SessionOptions.ProtocolVersion = 3
    $connection.SessionOptions.Signing = $true
    $connection.SessionOptions.Sealing = $true
    $connection.Credential = [System.Net.NetworkCredential]::new($env:BLOODYAD_LAB_USER,$env:BLOODYAD_LAB_PASSWORD,$env:BLOODYAD_LAB_DOMAIN)
    $connection.Bind()
    $request = [System.DirectoryServices.Protocols.SearchRequest]::new($Base,$Filter,[System.DirectoryServices.Protocols.SearchScope]::$Scope,[string[]]$Attributes.Split(','))
    $paging = [System.DirectoryServices.Protocols.PageResultRequestControl]::new(256)
    [void]$request.Controls.Add($paging)
    $rows = [System.Collections.Generic.List[object]]::new()
    do {
        $response = $connection.SendRequest($request)
        foreach ($entry in $response.Entries) {
            $row = @{}
            foreach ($name in $entry.Attributes.AttributeNames) {
                $row[$name] = @($entry.Attributes[$name].GetValues([string]))
            }
            $row['distinguishedName'] = @($entry.DistinguishedName)
            $rows.Add($row)
        }
        $page = @($response.Controls | Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] })
        if ($page.Count -ne 1) { throw 'Missing LDAP paging response' }
        $paging.Cookie = $page[0].Cookie
    } while ($paging.Cookie.Length -gt 0)
    ConvertTo-Json -InputObject @($rows.ToArray()) -Depth 6 -Compress
} catch {
    [Console]::Error.WriteLine('Independent LDAP reference failed: ' + $_.Exception.GetType().Name)
    exit 1
} finally {
    $connection.Dispose()
}
