Describe 'Get-GitHubSecurityAdvisory' {
    BeforeEach {
        # Mock data for successful GitHub GraphQL API responses
        $script:mockGitHubAdvisoryData = [PSCustomObject]@{
            data = [PSCustomObject]@{
                securityAdvisories = [PSCustomObject]@{
                    nodes = @(
                        [PSCustomObject]@{
                            ghsaId          = "GHSA-xxxx-yyyy-zzzz"
                            summary         = "Critical vulnerability in test package"
                            description     = "This is a detailed description of the vulnerability that affects multiple systems."
                            severity        = "CRITICAL"
                            permalink       = "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"
                            publishedAt     = "2023-01-15T10:00:00Z"
                            updatedAt       = "2023-01-16T14:30:00Z"
                            withdrawnAt     = $null
                            origin          = "GITHUB"
                            cvss            = [PSCustomObject]@{
                                score        = 9.8
                                vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                            cwes            = [PSCustomObject]@{
                                nodes = @(
                                    [PSCustomObject]@{
                                        cweId = "CWE-78"
                                        name  = "OS Command Injection"
                                    },
                                    [PSCustomObject]@{
                                        cweId = "CWE-94"
                                        name  = "Code Injection"
                                    }
                                )
                            }
                            identifiers     = @(
                                [PSCustomObject]@{
                                    type  = "CVE"
                                    value = "CVE-2023-12345"
                                },
                                [PSCustomObject]@{
                                    type  = "GHSA"
                                    value = "GHSA-xxxx-yyyy-zzzz"
                                }
                            )
                            vulnerabilities = [PSCustomObject]@{
                                nodes = @(
                                    [PSCustomObject]@{
                                        package                = [PSCustomObject]@{
                                            ecosystem = "npm"
                                            name      = "vulnerable-package"
                                        }
                                        vulnerableVersionRange = ">= 1.0.0, < 1.2.3"
                                        firstPatchedVersion    = [PSCustomObject]@{
                                            identifier = "1.2.3"
                                        }
                                    },
                                    [PSCustomObject]@{
                                        package                = [PSCustomObject]@{
                                            ecosystem = "pip"
                                            name      = "another-package"
                                        }
                                        vulnerableVersionRange = "< 2.0.0"
                                        firstPatchedVersion    = [PSCustomObject]@{
                                            identifier = "2.0.0"
                                        }
                                    }
                                )
                            }
                        }
                    )
                }
            }
        }

        $script:mockEmptyAdvisoryData = [PSCustomObject]@{
            data = [PSCustomObject]@{
                securityAdvisories = [PSCustomObject]@{
                    nodes = @()
                }
            }
        }

        $script:mockAdvisoryWithoutCWE = [PSCustomObject]@{
            data = [PSCustomObject]@{
                securityAdvisories = [PSCustomObject]@{
                    nodes = @(
                        [PSCustomObject]@{
                            ghsaId          = "GHSA-aaaa-bbbb-cccc"
                            summary         = "Test advisory without CWE"
                            description     = "Basic vulnerability description"
                            severity        = "MEDIUM"
                            permalink       = "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
                            publishedAt     = "2023-02-01T08:00:00Z"
                            updatedAt       = "2023-02-01T08:00:00Z"
                            withdrawnAt     = $null
                            origin          = "GITHUB"
                            cvss            = [PSCustomObject]@{
                                score        = 5.3
                                vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
                            }
                            cwes            = [PSCustomObject]@{
                                nodes = @()
                            }
                            identifiers     = @(
                                [PSCustomObject]@{
                                    type  = "GHSA"
                                    value = "GHSA-aaaa-bbbb-cccc"
                                }
                            )
                            vulnerabilities = [PSCustomObject]@{
                                nodes = @()
                            }
                        }
                    )
                }
            }
        }

        # Store original environment variable
        $script:originalGitHubPat = $env:GITHUB_PAT

        # Set up mock environment variable
        $env:GITHUB_PAT = "ghp_mock_token_for_testing_1234567890abcdef"

        # Mock for Invoke-RestMethod
        Mock -CommandName Invoke-RestMethod -MockWith {
            param($Uri, $Method, $Headers, $Body)

            # Parse the GraphQL query to determine what to return
            $bodyObj = $Body | ConvertFrom-Json
            $query = $bodyObj.query

            if ($query -match 'CVE-2023-12345') {
                return $script:mockGitHubAdvisoryData
            }
            elseif ($query -match 'GHSA-xxxx-yyyy-zzzz') {
                return $script:mockGitHubAdvisoryData
            }
            elseif ($query -match 'GHSA-aaaa-bbbb-cccc') {
                return $script:mockAdvisoryWithoutCWE
            }
            elseif ($query -match 'CVE-9999-9999' -or $query -match 'GHSA-9999-9999-9999') {
                return $script:mockEmptyAdvisoryData
            }
            elseif ($query -match 'CVE-5000-5000' -or $query -match 'GHSA-5000-5000-5000') {
                throw "Simulated GitHub API Error"
            }
            else {
                return $script:mockEmptyAdvisoryData
            }
        }

        . "$PSScriptRoot/../functions/Get-GitHubSecurityAdvisory.ps1"
    }

    AfterEach {
        # Restore original environment variable
        $env:GITHUB_PAT = $script:originalGitHubPat
    }

    Context 'Authentication and Setup' {
        It 'throws error when GITHUB_PAT is not set' {
            $env:GITHUB_PAT = ""
            { Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345" } | Should -Throw "*GitHub PAT not found*"
        }

        It 'uses custom token when provided' {
            $customToken = "ghp_custom_token_12345"
            Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345" -Token $customToken

            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Headers.Authorization -eq "bearer $customToken"
            }
        }

        It 'uses environment variable token by default' {
            Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345"

            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Headers.Authorization -eq "bearer $env:GITHUB_PAT"
            }
        }
    }

    Context 'ByCveId Parameter Set' {
        It 'returns advisory details for CVE ID' {
            $result = Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result.GhsaId | Should -Be "GHSA-xxxx-yyyy-zzzz"
            $result.CveId | Should -Be "CVE-2023-12345"
            $result.Summary | Should -Be "Critical vulnerability in test package"
            $result.Severity | Should -Be "CRITICAL"
            $result.CVSSScore | Should -Be 9.8
            $result.CVSSVector | Should -Be "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            $result.Permalink | Should -Be "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"
        }

        It 'handles CVE IDs without the CVE- prefix' {
            $result = Get-GitHubSecurityAdvisory -CveId "2023-12345"
            $result | Should -Not -BeNull
            $result.CveId | Should -Be "CVE-2023-12345"
        }

        It 'returns null when no advisory is found' {
            $result = Get-GitHubSecurityAdvisory -CveId "CVE-9999-9999"
            $result | Should -BeNull
        }

        It 'includes CWE information when available' {
            $result = Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result.CWEs | Should -Not -BeNull
            ($result.CWEs | Measure-Object).Count | Should -Be 2
            $result.CWEs[0].CweId | Should -Be "CWE-78"
            $result.CWEs[0].Name | Should -Be "OS Command Injection"
            $result.CWEs[1].CweId | Should -Be "CWE-94"
            $result.CWEs[1].Name | Should -Be "Code Injection"
        }

        It 'includes vulnerability information when available' {
            $result = Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result.Vulnerabilities | Should -Not -BeNull
            ($result.Vulnerabilities | Measure-Object).Count | Should -Be 2

            $result.Vulnerabilities[0].Ecosystem | Should -Be "npm"
            $result.Vulnerabilities[0].PackageName | Should -Be "vulnerable-package"
            $result.Vulnerabilities[0].VersionRange | Should -Be ">= 1.0.0, < 1.2.3"
            $result.Vulnerabilities[0].PatchedVersion | Should -Be "1.2.3"

            $result.Vulnerabilities[1].Ecosystem | Should -Be "pip"
            $result.Vulnerabilities[1].PackageName | Should -Be "another-package"
        }
    }

    Context 'ByGhsaId Parameter Set' {
        It 'returns advisory details for GHSA ID' {
            $result = Get-GitHubSecurityAdvisory -GhsaId "GHSA-xxxx-yyyy-zzzz"
            $result | Should -Not -BeNull
            $result.GhsaId | Should -Be "GHSA-xxxx-yyyy-zzzz"
            $result.Summary | Should -Be "Critical vulnerability in test package"
            $result.Severity | Should -Be "CRITICAL"
            # Should not have CveId property when queried by GHSA
            $result.PSObject.Properties.Name | Should -Not -Contain "CveId"
        }

        It 'handles advisory without CWE information' {
            $result = Get-GitHubSecurityAdvisory -GhsaId "GHSA-aaaa-bbbb-cccc"
            $result | Should -Not -BeNull
            $result.GhsaId | Should -Be "GHSA-aaaa-bbbb-cccc"
            $result.Severity | Should -Be "MEDIUM"
            # Should not have CWEs property when no CWE data
            $result.PSObject.Properties.Name | Should -Not -Contain "CWEs"
        }

        It 'returns null when no advisory is found' {
            $result = Get-GitHubSecurityAdvisory -GhsaId "GHSA-9999-9999-9999"
            $result | Should -BeNull
        }
    }

    Context 'GraphQL Query Construction' {
        It 'sends correct GraphQL query structure' {
            Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345"

            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Method -eq "Post" -and
                $Uri -eq "https://api.github.com/graphql" -and
                $Headers["Content-Type"] -eq "application/json" -and
                ($Body | ConvertFrom-Json).query -match "securityAdvisories"
            }
        }

        It 'includes all required fields in GraphQL query' {
            Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345"

            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $queryBody = ($Body | ConvertFrom-Json).query
                $queryBody -match "ghsaId" -and
                $queryBody -match "summary" -and
                $queryBody -match "description" -and
                $queryBody -match "severity" -and
                $queryBody -match "cvss" -and
                $queryBody -match "cwes" -and
                $queryBody -match "vulnerabilities"
            }
        }
    }

    Context 'Error Handling' {
        It 'writes an error on API failure' {
            $errors = @()
            $result = Get-GitHubSecurityAdvisory -CveId "CVE-5000-5000" -ErrorVariable errors
            $result | Should -BeNull
            $errors.Count | Should -BeGreaterThan 0
            # Verify that an error was generated
            $errors[0] | Should -Not -BeNull
            $errors[0].Exception | Should -BeOfType [System.Management.Automation.RuntimeException]
        }

        It 'provides detailed error information' {
            $errors = @()
            Get-GitHubSecurityAdvisory -CveId "CVE-5000-5000" -ErrorVariable errors
            $errors[0].Exception.Message | Should -Match "Simulated GitHub API Error"
        }
    }

    Context 'Data Type Validation' {
        It 'returns proper data types for all fields' {
            $result = Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result.GhsaId | Should -BeOfType [string]
            $result.Summary | Should -BeOfType [string]
            $result.Description | Should -BeOfType [string]
            $result.Severity | Should -BeOfType [string]
            $result.CVSSScore | Should -BeOfType [double]
            $result.CVSSVector | Should -BeOfType [string]
            $result.Permalink | Should -BeOfType [string]
            $result.PublishedAt | Should -BeOfType [string]
            $result.UpdatedAt | Should -BeOfType [string]
        }

        It 'properly structures CWE data when present' {
            $result = Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            # CWEs can be a single object or array depending on count
            if ($result.CWEs -is [array]) {
                $result.CWEs[0] | Should -BeOfType [pscustomobject]
                $result.CWEs[0].CweId | Should -BeOfType [string]
                $result.CWEs[0].Name | Should -BeOfType [string]
            }
            else {
                $result.CWEs | Should -BeOfType [pscustomobject]
                $result.CWEs.CweId | Should -BeOfType [string]
                $result.CWEs.Name | Should -BeOfType [string]
            }
        }

        It 'properly structures vulnerability data when present' {
            $result = Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            # Vulnerabilities can be a single object or array depending on count
            if ($result.Vulnerabilities -is [array]) {
                $result.Vulnerabilities[0] | Should -BeOfType [pscustomobject]
                $result.Vulnerabilities[0].Ecosystem | Should -BeOfType [string]
                $result.Vulnerabilities[0].PackageName | Should -BeOfType [string]
                $result.Vulnerabilities[0].VersionRange | Should -BeOfType [string]
                $result.Vulnerabilities[0].PatchedVersion | Should -BeOfType [string]
            }
            else {
                $result.Vulnerabilities | Should -BeOfType [pscustomobject]
                $result.Vulnerabilities.Ecosystem | Should -BeOfType [string]
                $result.Vulnerabilities.PackageName | Should -BeOfType [string]
                $result.Vulnerabilities.VersionRange | Should -BeOfType [string]
                $result.Vulnerabilities.PatchedVersion | Should -BeOfType [string]
            }
        }
    }

    Context 'Parameter Set Validation' {
        It 'requires exactly one parameter set' {
            # This test verifies that the function definition requires mutually exclusive parameters
            { Get-GitHubSecurityAdvisory -CveId "CVE-2023-12345" -GhsaId "GHSA-xxxx-yyyy-zzzz" } | Should -Throw
        }
    }

    Context 'Verbose Output' {
        It 'writes verbose messages when no advisory found' {
            $VerboseMessages = @()
            Get-GitHubSecurityAdvisory -CveId "CVE-9999-9999" -Verbose 4>&1 | ForEach-Object {
                if ($_ -is [System.Management.Automation.VerboseRecord]) {
                    $VerboseMessages += $_.Message
                }
            }

            $VerboseMessages | Should -Contain "No GitHub Security Advisory found for CVE-9999-9999"
        }
    }
}
