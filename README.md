# whois-lookup.ps1

Universal WHOIS lookup script for PowerShell on Windows. Automatically routes
domain names to the `Get-WHOIS` module and IP addresses to the ARIN RDAP API.

## Features

- Domain WHOIS via the `Get-WHOIS` PowerShell module (registrar, nameservers,
  expiry, status)
- IP WHOIS via ARIN RDAP — returns network block, owner organization, and
  allocation type
- Accepts full URLs (`https://example.com/page`) and strips the protocol/path
  automatically
- Supports IPv4 and IPv6 addresses
- Available as a global `whois` command after one-time profile setup

## Requirements

- Windows PowerShell 5.1 or later
- `Get-WHOIS` module (domain lookups only)
- Internet access

## Installation

### 1. Set the execution policy (required once)

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 2. Install the Get-WHOIS module (required once)

```powershell
Install-Module -Name Get-WHOIS -Scope CurrentUser -Force
```

### 3. Register the global alias (required once)

```powershell
Add-Content $PROFILE "`nSet-Alias whois '$HOME\Documents\WindowsPowerShell\whois-lookup.ps1'"
```

After completing these steps, the `whois` command will be available in every
new PowerShell session automatically.

## Usage

```powershell
# Domain lookup
whois example.com

# IP address lookup
whois 107.143.2.95

# URL — protocol and path are stripped automatically
whois https://example.com/page

# IPv6
whois 2001:4860:4860::8888
```

## Output

**Domain lookup** fields:

| Field | Description |
|---|---|
| Name | Registered domain name |
| Registrar | Registrar name |
| Created | Registration date |
| Expires | Expiration date |
| DaysLeft | Days until expiry |
| NameServers | Authoritative nameservers |
| Status | EPP status codes |
| WHOISServer | Upstream WHOIS server queried |

**IP lookup** fields:

| Field | Description |
|---|---|
| Network | Network block name |
| Handle | ARIN network handle |
| Range | Start and end address of the block |
| Version | IPv4 or IPv6 |
| Allocation | Allocation type (e.g. DIRECT ALLOCATION) |
| Organization | Registered owner name and handle |
| Country | Country code |

## Help

Full built-in help is available via:

```powershell
Get-Help whois -Full
```

## Notes

- `Get-WHOIS` only supports domain names. Passing an IP to it returns an
  "Invalid FQDN format" error — use this script instead, which routes IPs
  automatically.
- IP lookups query ARIN (American Registry for Internet Numbers). For IPs
  registered outside North America, ARIN may redirect to RIPE, APNIC, LACNIC,
  or AFRINIC — the script handles this transparently via RDAP bootstrapping.
