<#
.SYNOPSIS
    Universal WHOIS lookup that routes domains and IP addresses automatically.
.DESCRIPTION
    This script accepts a single target and chooses the correct lookup method:
      - Domain names are sent to the installed Get-WHOIS PowerShell module.
      - IPv4 and IPv6 addresses are sent to ARIN's RDAP API.

    Full URLs are accepted too. The script strips http:// or https:// and any
    path after the hostname before running the lookup.

    The PowerShell profile defines a global alias named "whois" for this file,
    so it can be run from any new PowerShell session as:

        whois example.com
        whois 8.8.8.8
        whois https://example.com/page
.PARAMETER Target
    Domain name, URL, IPv4 address, or IPv6 address to look up.
.EXAMPLE
    .\whois-lookup.ps1 example.com
.EXAMPLE
    .\whois-lookup.ps1 8.8.8.8
.NOTES
    Domain dependency: Get-WHOIS module.
    IP data source: ARIN RDAP at https://rdap.arin.net.
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Target,
    # Internal switch used by Pester tests to load functions without running the dispatch.
    [switch]$TestMode
)

# Normalize accidental URL input into a bare hostname.
# Example: https://example.com/page becomes example.com.
$Target = $Target -replace '^https?://', '' -replace '/.*$', ''

function Lookup-Domain($domain) {
    # Load the module only for domain lookups so IP lookups do not depend on it.
    Import-Module Get-WHOIS -ErrorAction Stop

    # Get-WHOIS expects a bare fully-qualified domain name, not a URL or IP.
    $result = Get-WHOIS $domain

    # Return a compact object with the most useful WHOIS fields.
    [PSCustomObject]@{
        Type          = 'Domain'
        Query         = $domain
        Name          = $result.DomainName
        Registrar     = $result.Registrar
        Created       = $result.CreationDate
        Expires       = $result.RegistryExpiryDate
        DaysLeft      = $result.DaysUntilExpiration
        NameServers   = ($result.NameServer -join ', ')
        Status        = ($result.DomainStatus -join "`n         ")
        WHOISServer   = $result.RegistrarWHOISServer
    }
}

function Lookup-IP($ip) {
    # ARIN RDAP supports IP address lookups, unlike the Get-WHOIS module.
    $r = Invoke-RestMethod -Uri "https://rdap.arin.net/registry/ip/$ip" -ErrorAction Stop

    # RDAP returns entities by role. The registrant entity is usually the owner.
    $handle = ($r.entities | Where-Object { $_.roles -contains 'registrant' } | Select-Object -First 1).handle

    # Resolve the registrant handle to a human-readable organization name.
    $orgName = $null
    if ($handle) {
        try {
            $xml = [xml](Invoke-WebRequest -Uri "https://whois.arin.net/rest/org/$handle" -Headers @{Accept='application/xml'} -ErrorAction Stop).Content
            $orgName = $xml.org.name
        } catch {
            # If the secondary org lookup fails, continue with the handle only.
        }
    }

    # Return a compact object with the key network allocation fields.
    [PSCustomObject]@{
        Type         = 'IP'
        Query        = $ip
        Network      = $r.name
        Handle       = $r.handle
        Range        = "$($r.startAddress) to $($r.endAddress)"
        Version      = $r.ipVersion
        Allocation   = $r.type
        Organization = if ($orgName) { "$orgName ($handle)" } else { $handle }
        Country      = $r.country
    }
}

# Route IPv4/IPv6 targets to RDAP. Everything else is treated as a domain.
# -TestMode bypasses dispatch so Pester can dot-source and test functions in isolation.
if (-not $TestMode) {
    if ($Target -match '^\d{1,3}(\.\d{1,3}){3}$' -or $Target -match '^[0-9a-fA-F:]+:[0-9a-fA-F:]+$') {
        Write-Host "`nIP Lookup: $Target`n" -ForegroundColor Cyan
        Lookup-IP $Target | Format-List
    } else {
        Write-Host "`nDomain Lookup: $Target`n" -ForegroundColor Cyan
        Lookup-Domain $Target | Format-List
    }
}
