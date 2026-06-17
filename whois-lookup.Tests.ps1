#Requires -Module @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
.SYNOPSIS
    Pester v5 unit tests for whois-lookup.ps1.
.DESCRIPTION
    Tests cover:
      - Input normalization (URL stripping)
      - IP vs domain routing detection
      - Lookup-Domain return shape (mocked Get-WHOIS)
      - Lookup-IP return shape (mocked Invoke-RestMethod / Invoke-WebRequest)
      - Error handling when org lookup fails in Lookup-IP
#>

BeforeAll {
    # Dot-source the script in TestMode so functions are loaded without dispatching.
    $script:ScriptPath = Join-Path $PSScriptRoot 'whois-lookup.ps1'
    . $script:ScriptPath -Target 'placeholder' -TestMode
}

Describe 'Input normalization' {
    It 'strips http:// prefix' {
        $result = 'http://example.com' -replace '^https?://', '' -replace '/.*$', ''
        $result | Should -Be 'example.com'
    }

    It 'strips https:// prefix' {
        $result = 'https://example.com' -replace '^https?://', '' -replace '/.*$', ''
        $result | Should -Be 'example.com'
    }

    It 'strips path after hostname' {
        $result = 'https://example.com/some/page?q=1' -replace '^https?://', '' -replace '/.*$', ''
        $result | Should -Be 'example.com'
    }

    It 'leaves a bare domain unchanged' {
        $result = 'example.com' -replace '^https?://', '' -replace '/.*$', ''
        $result | Should -Be 'example.com'
    }

    It 'leaves a bare IP unchanged' {
        $result = '8.8.8.8' -replace '^https?://', '' -replace '/.*$', ''
        $result | Should -Be '8.8.8.8'
    }
}

Describe 'IP vs domain routing' {
    BeforeAll {
        # Use $script: scope so variables are accessible inside It blocks in Pester v5.
        $script:ipv4Pattern = '^\d{1,3}(\.\d{1,3}){3}$'
        $script:ipv6Pattern = '^[0-9a-fA-F:]+:[0-9a-fA-F:]+$'
    }

    It 'detects a standard IPv4 address' {
        '8.8.8.8' | Should -Match $script:ipv4Pattern
    }

    It 'detects a private IPv4 address' {
        '192.168.1.1' | Should -Match $script:ipv4Pattern
    }

    It 'detects a full IPv6 address' {
        '2001:4860:4860::8888' | Should -Match $script:ipv6Pattern
    }

    It 'does not match a domain as IPv4' {
        'example.com' | Should -Not -Match $script:ipv4Pattern
    }

    It 'does not match a domain as IPv6' {
        'example.com' | Should -Not -Match $script:ipv6Pattern
    }

    It 'does not match a subdomain as IPv4' {
        'sub.example.com' | Should -Not -Match $script:ipv4Pattern
    }
}

Describe 'Lookup-Domain' {
    BeforeAll {
        # Mock Get-WHOIS to avoid real network calls.
        Mock Import-Module {}
        Mock Get-WHOIS {
            [PSCustomObject]@{
                DomainName         = 'EXAMPLE.COM'
                Registrar          = 'Test Registrar Inc.'
                CreationDate       = '1995-08-14T04:00:00Z'
                RegistryExpiryDate = '2026-08-13T04:00:00Z'
                DaysUntilExpiration = 57
                NameServer         = @('NS1.EXAMPLE.COM', 'NS2.EXAMPLE.COM')
                DomainStatus       = @('clientDeleteProhibited')
                RegistrarWHOISServer = 'whois.example.com'
            }
        }
    }

    It 'returns an object with Type = Domain' {
        $result = Lookup-Domain 'example.com'
        $result.Type | Should -Be 'Domain'
    }

    It 'returns the correct domain name' {
        $result = Lookup-Domain 'example.com'
        $result.Name | Should -Be 'EXAMPLE.COM'
    }

    It 'returns the registrar' {
        $result = Lookup-Domain 'example.com'
        $result.Registrar | Should -Be 'Test Registrar Inc.'
    }

    It 'returns DaysLeft as a number' {
        $result = Lookup-Domain 'example.com'
        $result.DaysLeft | Should -Be 57
    }

    It 'joins nameservers as a comma-separated string' {
        $result = Lookup-Domain 'example.com'
        $result.NameServers | Should -Be 'NS1.EXAMPLE.COM, NS2.EXAMPLE.COM'
    }

    It 'passes the query value through' {
        $result = Lookup-Domain 'example.com'
        $result.Query | Should -Be 'example.com'
    }

    It 'calls Get-WHOIS exactly once' {
        Lookup-Domain 'example.com' | Out-Null
        Should -Invoke Get-WHOIS -Times 1 -Exactly
    }
}

Describe 'Lookup-IP' {
    BeforeAll {
        # Mock ARIN RDAP response.
        Mock Invoke-RestMethod {
            [PSCustomObject]@{
                name         = 'TEST-NET'
                handle       = 'NET-8-8-8-0-1'
                startAddress = '8.8.8.0'
                endAddress   = '8.8.8.255'
                ipVersion    = 'v4'
                type         = 'DIRECT ALLOCATION'
                country      = 'US'
                entities     = @(
                    [PSCustomObject]@{
                        roles  = @('registrant')
                        handle = 'GOGL'
                    }
                )
            }
        }

        # Mock the secondary org XML lookup.
        Mock Invoke-WebRequest {
            [PSCustomObject]@{
                Content = '<org xmlns="https://www.arin.net/whoisrws/core/v1"><name>Google LLC</name></org>'
            }
        }
    }

    It 'returns an object with Type = IP' {
        $result = Lookup-IP '8.8.8.8'
        $result.Type | Should -Be 'IP'
    }

    It 'returns the correct network name' {
        $result = Lookup-IP '8.8.8.8'
        $result.Network | Should -Be 'TEST-NET'
    }

    It 'formats the range correctly' {
        $result = Lookup-IP '8.8.8.8'
        $result.Range | Should -Be '8.8.8.0 to 8.8.8.255'
    }

    It 'returns the IP version' {
        $result = Lookup-IP '8.8.8.8'
        $result.Version | Should -Be 'v4'
    }

    It 'passes the query value through' {
        $result = Lookup-IP '8.8.8.8'
        $result.Query | Should -Be '8.8.8.8'
    }

    It 'calls the RDAP endpoint with the correct URI' {
        Lookup-IP '8.8.8.8' | Out-Null
        Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
            $Uri -eq 'https://rdap.arin.net/registry/ip/8.8.8.8'
        }
    }
}

Describe 'Lookup-IP org fallback' {
    BeforeAll {
        # RDAP returns a handle but the secondary org lookup throws.
        Mock Invoke-RestMethod {
            [PSCustomObject]@{
                name         = 'FALLBACK-NET'
                handle       = 'NET-1-2-3-0-1'
                startAddress = '1.2.3.0'
                endAddress   = '1.2.3.255'
                ipVersion    = 'v4'
                type         = 'DIRECT ALLOCATION'
                country      = 'US'
                entities     = @(
                    [PSCustomObject]@{
                        roles  = @('registrant')
                        handle = 'SOMEORG'
                    }
                )
            }
        }

        # Simulate the secondary lookup failing.
        Mock Invoke-WebRequest { throw 'Network error' }
    }

    It 'falls back to handle when org lookup fails' {
        $result = Lookup-IP '1.2.3.4'
        $result.Organization | Should -Be 'SOMEORG'
    }

    It 'still returns a valid object when org lookup fails' {
        $result = Lookup-IP '1.2.3.4'
        $result.Type    | Should -Be 'IP'
        $result.Network | Should -Be 'FALLBACK-NET'
    }
}
