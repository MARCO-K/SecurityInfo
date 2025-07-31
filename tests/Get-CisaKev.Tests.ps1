
Describe 'Get-CisaKev' {
    BeforeEach {
        # Mock data for a single CVE
        $script:mockCveData = @{
            cveID             = "CVE-2023-12345"
            vendorProject     = "TestVendor"
            product           = "TestProduct"
            vulnerabilityName = "Test Vulnerability"
            dateAdded         = "2023-01-01"
            shortDescription  = "A test vulnerability."
            requiredAction    = "Patch immediately."
            dueDate           = "2023-01-15"
            notes             = "Test notes."
            isRansomware      = $false
            kevInSince        = "2023-01-01"
        }

        $script:mockRecentData = @(
            @{
                cveID             = "CVE-2024-0001"
                vendorProject     = "VendorA"
                product           = "ProductA"
                vulnerabilityName = "Vuln A"
                dateAdded         = "2024-07-30"
                shortDescription  = "Desc A"
                requiredAction    = "Action A"
                dueDate           = "2024-08-15"
                notes             = ""
                isRansomware      = $false
                kevInSince        = "2024-07-30"
            },
            @{
                cveID             = "CVE-2024-0002"
                vendorProject     = "VendorB"
                product           = "ProductB"
                vulnerabilityName = "Vuln B"
                dateAdded         = "2024-07-29"
                shortDescription  = "Desc B"
                requiredAction    = "Action B"
                dueDate           = "2024-08-14"
                notes             = ""
                isRansomware      = $true
                kevInSince        = "2024-07-29"
            }
        )

        $script:mockVulnDetailsHigh = @{ cvssV3_severity = 'HIGH' }
        $script:mockVulnDetailsCritical = @{ cvssV3_severity = 'CRITICAL' }

        Mock -CommandName Invoke-RestMethod -MockWith {
            param($Uri)
            if ($Uri -like '*vulnerabilities/id/CVE-2023-12345*') {
                return $script:mockCveData
            }
            if ($Uri -like '*kev/recent?days=7*') {
                return $script:mockRecentData
            }
            if ($Uri -like '*vulnerabilities/search?q=TestKeyword*') {
                return $script:mockRecentData
            }
            if ($Uri -like '*vuln/CVE-2024-0001*') {
                return $script:mockVulnDetailsHigh
            }
            if ($Uri -like '*vuln/CVE-2024-0002*') {
                return $script:mockVulnDetailsCritical
            }
            if ($Uri -like '*vulnerabilities/id/CVE-9999-9999*') {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    (New-Object System.Exception "The remote server returned an error: (404) Not Found."),
                    'KEVinApiNotFound',
                    [System.Management.Automation.ErrorCategory]::InvalidResult,
                    $null
                )
                $errorRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
                    '{"error":"You found nothing! Congratulations!"}'
                )
                throw $errorRecord
            }
        }
        . "$PSScriptRoot/../functions/Get-CisaKev.ps1"
    }

    Context 'ByCveId' {
        It 'returns a single vulnerability for a specific CVE ID' {
            $result = Get-CisaKev -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result.cveID | Should -Be "CVE-2023-12345"
            $result.vendorProject | Should -Be "TestVendor"
        }

        It 'handles CVE IDs without the "CVE-" prefix' {
            $result = Get-CisaKev -CveId "2023-12345"
            $result | Should -Not -BeNull
            $result.cveID | Should -Be "CVE-2023-12345"
        }

        It 'returns nothing for a CVE that is not found' {
            $result = Get-CisaKev -CveId "CVE-9999-9999" -Verbose
            $result | Should -BeNull
        }
    }

    Context 'ByDays' {
        It 'returns a list of recent vulnerabilities' {
            $result = Get-CisaKev -Days 7
            $result | Should -Not -BeNull
            ($result | Measure-Object).Count | Should -Be 2
            $result[0].cveID | Should -Be "CVE-2024-0001"
        }
    }

    Context 'ByKeyword' {
        It 'returns a list of vulnerabilities matching the keyword' {
            $result = Get-CisaKev -Keyword "TestKeyword"
            $result | Should -Not -BeNull
            ($result | Measure-Object).Count | Should -Be 2
            $result[1].cveID | Should -Be "CVE-2024-0002"
        }
    }

    Context 'With Severity Filter' {
        It 'returns only CRITICAL vulnerabilities when -Severity CRITICAL is used' {
            $result = Get-CisaKev -Days 7 -Severity 'CRITICAL'
            $result | Should -Not -BeNull
            ($result | Measure-Object).Count | Should -Be 1
            $result.cveID | Should -Be "CVE-2024-0002"
        }

        It 'returns only HIGH vulnerabilities when -Severity HIGH is used' {
            $result = Get-CisaKev -Days 7 -Severity 'HIGH'
            $result | Should -Not -BeNull
            ($result | Measure-Object).Count | Should -Be 1
            $result.cveID | Should -Be "CVE-2024-0001"
        }
    }
}
