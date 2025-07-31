
Describe 'Get-CveOrg' {
    BeforeEach {
        # Mock data for a successful CVE lookup
        $script:mockCveData = @{
            cveMetadata = @{
                cveId             = "CVE-2023-12345"
                assignerShortName = "TestCNA"
                state             = "PUBLISHED"
                datePublished     = "2023-01-01T00:00:00.000Z"
                dateUpdated       = "2023-01-02T00:00:00.000Z"
            }
            containers  = @{
                cna = @{
                    title        = "Test Vulnerability Title"
                    descriptions = @(
                        @{ lang = "en-US"; value = "This is a test description." }
                    )
                    affected     = @(
                        @{ product = "Test Product 1" },
                        @{ product = "Test Product 2" }
                    )
                    metrics      = @(
                        @{ cvssV3_1 = @{ baseScore = 9.8; baseSeverity = "CRITICAL" } }
                    )
                    references   = @(
                        @{ url = "http://example.com/ref1" }
                    )
                }
            }
        } | ConvertTo-Json -Depth 10 | ConvertFrom-Json

        # Centralized Mock for Invoke-RestMethod
        Mock -CommandName Invoke-RestMethod -MockWith {
            param($Uri)
            switch -Wildcard ($Uri) {
                '*api/cve/CVE-2023-12345*' { return $script:mockCveData }
                '*api/cve/CVE-9999-9999*' {
                    # Throw an exception with 404 in the message for our error handler to catch
                    throw "Response status code does not indicate success: 404 (Not Found)."
                }
                '*api/cve/CVE-5000-5000*' {
                    # Throw an exception with 500 in the message for our error handler to catch
                    throw "Response status code does not indicate success: 500 (Internal Server Error)."
                }
            }
        }
        . "$PSScriptRoot/../functions/Get-CveOrg.ps1"
    }

    Context 'Successful Lookups' {
        It 'returns a formatted object for a valid CVE ID' {
            $result = Get-CveOrg -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result.CVEID | Should -Be "CVE-2023-12345"
            $result.Title | Should -Be "Test Vulnerability Title"
            $result.BaseSeverity | Should -Be "CRITICAL"
            ($result.AffectedProducts | Measure-Object).Count | Should -Be 2
        }
        It 'handles CVE IDs without the "CVE-" prefix' {
            $result = Get-CveOrg -CveId "2023-12345"
            $result | Should -Not -BeNull
            $result.CVEID | Should -Be "CVE-2023-12345"
        }
        It 'works with pipeline input' {
            $result = "2023-12345" | Get-CveOrg
            $result | Should -Not -BeNull
            $result.CVEID | Should -Be "CVE-2023-12345"
        }
    }

    Context 'Error Handling' {
        It 'warns the user when a CVE is not found (404)' {
            $warnings = & { Get-CveOrg -CveId "CVE-9999-9999" } 3>&1
            $messages = $warnings | ForEach-Object { $_.Message }
            $messages | Should -Contain "CVE record for 'CVE-9999-9999' not found on cve.org."
        }
        It 'writes an error for other API failures' {
            $errors = & { Get-CveOrg -CveId "CVE-5000-5000" } 2>&1
            $messages = $errors | ForEach-Object { $_.ToString() }
            $messages | Should -Match "An API error occurred while querying cve\.org.*500"
        }
    }
}
