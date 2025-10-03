Describe "Get-MsrcPatchTuesday" {
    BeforeAll {
        # Mock data for a successful MSRC API response
        $script:mockMsrcResponse = [PSCustomObject]@{
            DocumentTitle = @{ Value = "October 2023 Security Updates" }
            Vulnerability = @(
                # RCE
                [PSCustomObject]@{
                    CVE   = "CVE-2023-1001"
                    Title = @{ Value = "Windows Kernel RCE" }
                    Threats = @(
                        [PSCustomObject]@{ Type = 0; Description = @{ Value = "Remote Code Execution" }; ProductID = @("11651") },
                        [PSCustomObject]@{ Type = 1; Description = @{ Value = "Exploitation More Likely" } }
                    )
                    CVSSScoreSets = @(
                        [PSCustomObject]@{ BaseScore = 9.8 }
                    )
                },
                # Exploited in the wild
                [PSCustomObject]@{
                    CVE   = "CVE-2023-1002"
                    Title = @{ Value = "Exchange Server Spoofing" }
                    Threats = @(
                        [PSCustomObject]@{ Type = 0; Description = @{ Value = "Spoofing" }; ProductID = @("11652") },
                        [PSCustomObject]@{ Type = 1; Description = @{ Value = "Exploited:Yes" } }
                    )
                    CVSSScoreSets = @(
                        [PSCustomObject]@{ BaseScore = 8.1 }
                    )
                },
                # High Severity
                [PSCustomObject]@{
                    CVE   = "CVE-2023-1003"
                    Title = @{ Value = "Azure Service Bus EOP" }
                    Threats = @(
                        [PSCustomObject]@{ Type = 0; Description = @{ Value = "Elevation of Privilege" }; ProductID = @("11653") }
                    )
                    CVSSScoreSets = @(
                        [PSCustomObject]@{ BaseScore = 8.8 }
                    )
                },
                # Edge-Chromium
                [PSCustomObject]@{
                    CVE   = "CVE-2023-1004"
                    Title = @{ Value = "Chromium Security Update" }
                    Threats = @(
                        [PSCustomObject]@{ Type = 0; Description = @{ Value = "Remote Code Execution" }; ProductID = @("11655") } # Chromium Product ID
                    )
                    CVSSScoreSets = @()
                }
            )
        }

        # Mock for Invoke-RestMethod
        Mock -CommandName Invoke-RestMethod -MockWith {
            param($Uri)
            if ($Uri -match '2023-Oct') {
                return $script:mockMsrcResponse
            }
            elseif ($Uri -match '2023-Jan') {
                # Simulate a "Not Found" error by throwing an exception with the required message
                throw "The remote server returned an error: (404) Not Found."
            }
            else {
                # Simulate a generic API error
                throw "Generic API Error"
            }
        }

        . "$PSScriptRoot/../functions/Get-MsrcPatchTuesday.ps1"
    }

    Context "Parameter Validation" {
        It "accepts a valid date format" {
            { Get-MsrcPatchTuesday -SecurityUpdate "2023-Oct" } | Should -Not -Throw
        }

        It "throws an error for an invalid date format" {
            { Get-MsrcPatchTuesday -SecurityUpdate "2023-10" } | Should -Throw "Invalid date format*"
        }
    }

    Context "API Interaction and Data Processing" {
        It "returns a summary object for a valid response" {
            $result = Get-MsrcPatchTuesday -SecurityUpdate "2023-Oct"
            $result | Should -Not -BeNull
            $result.TotalVulnerabilities | Should -Be 4
        }

        It "correctly counts vulnerabilities by type" {
            $result = Get-MsrcPatchTuesday -SecurityUpdate "2023-Oct"
            ($result.VulnerabilityBreakdown | Where-Object { $_.Type -eq 'Remote Code Execution' }).Count | Should -Be 1
            ($result.VulnerabilityBreakdown | Where-Object { $_.Type -eq 'Spoofing' }).Count | Should -Be 1
            ($result.VulnerabilityBreakdown | Where-Object { $_.Type -eq 'Edge - Chromium' }).Count | Should -Be 1
        }

        It "identifies exploited-in-the-wild vulnerabilities" {
            $result = Get-MsrcPatchTuesday -SecurityUpdate "2023-Oct"
            $result.ExploitedInTheWild.Count | Should -Be 1
            $result.ExploitedInTheWild[0].CVE | Should -Be "CVE-2023-1002"
        }

        It "identifies 'exploitation more likely' vulnerabilities" {
            $result = Get-MsrcPatchTuesday -SecurityUpdate "2023-Oct"
            $result.ExploitationMoreLikely.Count | Should -Be 1
            $result.ExploitationMoreLikely[0].CVE | Should -Be "CVE-2023-1001"
        }

        It "identifies high-severity vulnerabilities" {
            $result = Get-MsrcPatchTuesday -SecurityUpdate "2023-Oct"
            # Includes RCE (9.8), Exploited (8.1), and High Sev (8.8)
            $result.HighSeverityVulnerabilities.Count | Should -Be 3
        }
    }

    Context "Error Handling" {
        It "handles 'Not Found' API responses gracefully" {
            $warnings = @()
            $result = Get-MsrcPatchTuesday -SecurityUpdate "2023-Jan" -WarningVariable warnings
            $result | Should -BeNullOrEmpty
            $warnings.Count | Should -Be 1
            $warnings[0] | Should -Match "No security update found"
        }

        It "handles other API errors" {
            { Get-MsrcPatchTuesday -SecurityUpdate "2023-Feb" } | Should -Throw "An error occurred while querying the MSRC API: Generic API Error"
        }
    }

    Context "Output Structure" {
        It "returns a PSCustomObject" {
            $result = Get-MsrcPatchTuesday -SecurityUpdate "2023-Oct"
            $result | Should -BeOfType ([pscustomobject])
        }

        It "contains all expected properties" {
            $result = Get-MsrcPatchTuesday -SecurityUpdate "2023-Oct"
            $expectedProperties = @('Title', 'TotalVulnerabilities', 'VulnerabilityBreakdown', 'ExploitedInTheWild', 'ExploitationMoreLikely', 'HighSeverityVulnerabilities')
            foreach ($prop in $expectedProperties) {
                $result.PSObject.Properties.Name | Should -Contain $prop
            }
        }
    }
}