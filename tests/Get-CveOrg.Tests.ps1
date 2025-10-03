
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
                default {
                    # Default behavior for error cases
                    $statusCode = 0
                    $statusDescription = ''
                    if ($Uri -like '*api/cve/CVE-9999-9999*') {
                        $statusCode = [System.Net.HttpStatusCode]::NotFound
                        $statusDescription = 'Not Found'
                    }
                    elseif ($Uri -like '*api/cve/CVE-5000-5000*') {
                        $statusCode = [System.Net.HttpStatusCode]::InternalServerError
                        $statusDescription = 'Internal Server Error'
                    }

                    # Create a mock exception that resembles System.Net.WebException
                    $response = [pscustomobject]@{
                        StatusCode        = $statusCode
                        StatusDescription = $statusDescription
                    }
                    $exception = [pscustomobject]@{ Response = $response }
                    # Add the type name to make it pass the '-is [System.Net.WebException]' check
                    $exception.psobject.TypeNames.Insert(0, 'System.Net.WebException')
                    throw $exception
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
        It 'writes a specific error for a 500 API failure' {
            { Get-CveOrg -CveId "CVE-5000-5000" } | Should -Throw "An API error occurred while querying cve.org: Response status code does not indicate success: 500 (Internal Server Error)."
        }
    }
}
