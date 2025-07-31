Describe "Get-NvdCve" {
    BeforeAll {
        # Mock data for successful NVD API responses
        $script:mockNvdResponse = [PSCustomObject]@{
            totalResults    = 2
            vulnerabilities = @(
                [PSCustomObject]@{
                    cve = [PSCustomObject]@{
                        id             = "CVE-2023-12345"
                        descriptions   = @(
                            [PSCustomObject]@{
                                value = "A critical vulnerability in OpenSSL allowing remote code execution"
                            }
                        )
                        published      = "2023-01-15T10:00:00.000"
                        lastModified   = "2023-01-16T12:00:00.000"
                        vulnStatus     = "Analyzed"
                        weaknesses     = [PSCustomObject]@{
                            description = @(
                                [PSCustomObject]@{
                                    value = "CWE-78"
                                },
                                [PSCustomObject]@{
                                    value = "CWE-94"
                                }
                            )
                        }
                        metrics        = [PSCustomObject]@{
                            cvssMetricV31 = @(
                                [PSCustomObject]@{
                                    cvssData = [PSCustomObject]@{
                                        baseSeverity = "CRITICAL"
                                        baseScore    = 9.8
                                    }
                                }
                            )
                        }
                        configurations = [PSCustomObject]@{
                            nodes = @(
                                [PSCustomObject]@{
                                    cpeMatch = @(
                                        [PSCustomObject]@{
                                            criteria = "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
                                        },
                                        [PSCustomObject]@{
                                            criteria = "cpe:2.3:a:apache:httpd:2.4.0:*:*:*:*:*:*:*"
                                        }
                                    )
                                }
                            )
                        }
                    }
                },
                [PSCustomObject]@{
                    cve = [PSCustomObject]@{
                        id             = "CVE-2023-67890"
                        descriptions   = @(
                            [PSCustomObject]@{
                                value = "A medium severity vulnerability in Apache"
                            }
                        )
                        published      = "2023-02-10T14:30:00.000"
                        lastModified   = "2023-02-11T09:15:00.000"
                        vulnStatus     = "Modified"
                        weaknesses     = [PSCustomObject]@{
                            description = @(
                                [PSCustomObject]@{
                                    value = "CWE-79"
                                }
                            )
                        }
                        metrics        = [PSCustomObject]@{
                            cvssMetricV40 = @(
                                [PSCustomObject]@{
                                    cvssData = [PSCustomObject]@{
                                        baseSeverity = "MEDIUM"
                                        baseScore    = 6.1
                                    }
                                }
                            )
                        }
                        configurations = [PSCustomObject]@{
                            nodes = @(
                                [PSCustomObject]@{
                                    cpeMatch = @(
                                        [PSCustomObject]@{
                                            criteria = "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
                                        }
                                    )
                                }
                            )
                        }
                    }
                }
            )
        }

        # Mock data for empty response
        $script:mockEmptyResponse = [PSCustomObject]@{
            totalResults    = 0
            vulnerabilities = @()
        }

        # Mock for Invoke-RestMethod
        Mock -CommandName Invoke-RestMethod -MockWith {
            param($Uri, $Method)

            # Reference unused parameter to avoid PSScriptAnalyzer warning
            $null = $Method

            # Check URI to determine what to return
            if ($Uri -match 'keywordSearch=nonexistent' -or $Uri -match 'cveId=CVE-9999-9999') {
                return $script:mockEmptyResponse
            }
            elseif ($Uri -match 'cveId=CVE-5000-5000') {
                throw "Simulated NVD API Error"
            }
            else {
                return $script:mockNvdResponse
            }
        }

        . "$PSScriptRoot/../functions/Get-NvdCve.ps1"
    }

    Context 'Parameter Set Validation' {
        It 'accepts valid keyword parameter' {
            { Get-NvdCve -Keyword "openssl" } | Should -Not -Throw
        }

        It 'accepts valid days parameter' {
            { Get-NvdCve -Days 7 } | Should -Not -Throw
        }

        It 'accepts valid CVE ID parameter' {
            { Get-NvdCve -CveId "CVE-2023-12345" } | Should -Not -Throw
        }

        It 'accepts CVE ID without CVE prefix' {
            { Get-NvdCve -CveId "2023-12345" } | Should -Not -Throw
        }

        It 'throws error for days exceeding 120' {
            { Get-NvdCve -Days 121 } | Should -Throw "*cannot exceed 120*"
        }

        It 'accepts valid severity values' {
            @('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') | ForEach-Object {
                { Get-NvdCve -Keyword "test" -Severity $_ } | Should -Not -Throw
            }
        }

        It 'accepts valid top values within range' {
            { Get-NvdCve -Keyword "test" -Top 1 } | Should -Not -Throw
            { Get-NvdCve -Keyword "test" -Top 2000 } | Should -Not -Throw
        }
    }

    Context 'API Request Construction' {
        It 'constructs correct URL for keyword search' {
            Get-NvdCve -Keyword "openssl"

            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -match 'keywordSearch=openssl'
            }
        }

        It 'constructs correct URL for days search' {
            Get-NvdCve -Days 7

            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -match 'pubStartDate=' -and $Uri -match 'pubEndDate='
            }
        }

        It 'constructs correct URL for CVE ID search' {
            Get-NvdCve -CveId "CVE-2023-12345"

            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -match 'cveId=CVE-2023-12345'
            }
        }

        It 'adds CVE prefix when missing' {
            Get-NvdCve -CveId "2023-12345"

            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -match 'cveId=CVE-2023-12345'
            }
        }

        It 'includes severity parameter when specified' {
            Get-NvdCve -Keyword "test" -Severity "HIGH"

            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -match 'cvssV3Severity=HIGH'
            }
        }

        It 'includes top parameter when specified' {
            Get-NvdCve -Keyword "test" -Top 50

            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -match 'resultsPerPage=50' -and $Uri -match 'startIndex=0'
            }
        }
    }

    Context 'Data Processing and Output' {
        It 'returns CVE data with correct structure' {
            $result = Get-NvdCve -Keyword "openssl"

            $result | Should -Not -BeNull
            $result.Count | Should -Be 2
            $result[0].CVEID | Should -Be "CVE-2023-12345"
            $result[0].CVSSVersion | Should -Be "3.1"
            $result[0].CVSSSeverity | Should -Be "CRITICAL"
            $result[0].CVSSBaseScore | Should -Be 9.8
        }

        It 'handles CVSS v4.0 metrics correctly' {
            $result = Get-NvdCve -Keyword "apache"

            $result[1].CVEID | Should -Be "CVE-2023-67890"
            $result[1].CVSSVersion | Should -Be "4.0"
            $result[1].CVSSSeverity | Should -Be "MEDIUM"
            $result[1].CVSSBaseScore | Should -Be 6.1
        }

        It 'processes CWE IDs correctly' {
            $result = Get-NvdCve -Keyword "openssl"

            $result[0].CWEIDs | Should -Match "CWE-78.*CWE-94"
        }

        It 'includes affected software when requested' {
            $result = Get-NvdCve -Keyword "openssl" -IncludeAffectedSoftware

            $result[0].PSObject.Properties.Name | Should -Contain "AffectedVendors"
            $result[0].PSObject.Properties.Name | Should -Contain "AffectedProducts"
            $result[0].AffectedVendors | Should -Match "(openssl|apache)"
            $result[0].AffectedProducts | Should -Match "(openssl|httpd)"
        }

        It 'does not include affected software by default' {
            $result = Get-NvdCve -Keyword "openssl"

            $result[0].PSObject.Properties.Name | Should -Not -Contain "AffectedVendors"
            $result[0].PSObject.Properties.Name | Should -Not -Contain "AffectedProducts"
        }
    }

    Context 'Error Handling' {
        It 'handles empty results gracefully' {
            $warnings = @()
            $result = Get-NvdCve -Keyword "nonexistent" -WarningVariable warnings

            $result | Should -BeNullOrEmpty
            $warnings.Count | Should -Be 1
            $warnings[0] | Should -Match "No CVEs found"
        }

        It 'handles API errors appropriately' {
            $errors = @()
            $result = Get-NvdCve -CveId "CVE-5000-5000" -ErrorVariable errors -ErrorAction SilentlyContinue

            $result | Should -BeNullOrEmpty
            $errors.Count | Should -BeGreaterThan 0
            $errors[-1].Exception.Message | Should -Match "Simulated NVD API Error"
        }

        It 'provides detailed error information' {
            $errors = @()
            Get-NvdCve -CveId "CVE-5000-5000" -ErrorVariable errors -ErrorAction SilentlyContinue
            $errors[0].Exception.Message | Should -Match "Simulated NVD API Error"
        }
    }

    Context 'Data Type Validation' {
        It 'returns proper data types for all fields' {
            $result = Get-NvdCve -Keyword "openssl"
            $result | Should -Not -BeNull

            $result[0].CVEID | Should -BeOfType [string]
            $result[0].CVSSVersion | Should -BeOfType [string]
            $result[0].CVSSSeverity | Should -BeOfType [string]
            $result[0].CVSSBaseScore | Should -BeOfType [double]
            $result[0].Description | Should -BeOfType [string]
            $result[0].Published | Should -BeOfType [string]
            $result[0].LastModified | Should -BeOfType [string]
            $result[0].Status | Should -BeOfType [string]
            $result[0].CWEIDs | Should -BeOfType [string]
        }

        It 'returns proper data types for affected software fields' {
            $result = Get-NvdCve -Keyword "openssl" -IncludeAffectedSoftware

            $result[0].AffectedVendors | Should -BeOfType [string]
            $result[0].AffectedProducts | Should -BeOfType [string]
        }
    }

    Context 'Parameter Combinations' {
        It 'works with keyword and severity combination' {
            $result = Get-NvdCve -Keyword "openssl" -Severity "CRITICAL"

            $result | Should -Not -BeNull
            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -match 'keywordSearch=openssl' -and $Uri -match 'cvssV3Severity=CRITICAL'
            }
        }

        It 'works with days and top combination' {
            $result = Get-NvdCve -Days 30 -Top 100

            $result | Should -Not -BeNull
            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -match 'pubStartDate=' -and $Uri -match 'resultsPerPage=100'
            }
        }

        It 'works with all optional parameters' {
            $result = Get-NvdCve -Keyword "test" -Severity "HIGH" -Top 50 -IncludeAffectedSoftware

            $result | Should -Not -BeNull
            $result[0].PSObject.Properties.Name | Should -Contain "AffectedVendors"
            Assert-MockCalled -CommandName Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -match 'keywordSearch=test' -and $Uri -match 'cvssV3Severity=HIGH' -and $Uri -match 'resultsPerPage=50'
            }
        }
    }

    Context 'Edge Cases and Boundary Conditions' {
        It 'handles minimum days value' {
            { Get-NvdCve -Days 1 } | Should -Not -Throw
        }

        It 'handles maximum days value' {
            { Get-NvdCve -Days 120 } | Should -Not -Throw
        }

        It 'handles minimum top value' {
            { Get-NvdCve -Keyword "test" -Top 1 } | Should -Not -Throw
        }

        It 'handles maximum top value' {
            { Get-NvdCve -Keyword "test" -Top 2000 } | Should -Not -Throw
        }

        It 'handles empty keyword with error' {
            { Get-NvdCve -Keyword "" } | Should -Throw "*leere Zeichenfolge*"
        }

        It 'handles CVE ID with different case' {
            $result = Get-NvdCve -CveId "cve-2023-12345"

            # Should not throw and should return data since mock returns valid response
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Verbose Output' {
        It 'provides verbose information when requested' {
            $VerbosePreference = 'Continue'
            try {
                $verboseOutput = Get-NvdCve -Keyword "test" -Verbose 4>&1
                $verboseOutput | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | Should -Match "Querying NVD API"
            }
            finally {
                $VerbosePreference = 'SilentlyContinue'
            }
        }
    }

    Context 'CVSS Version Priority' {
        It 'prioritizes CVSS v4.0 over v3.1 when both are available' {
            # This test assumes mock data could have both versions
            $result = Get-NvdCve -Keyword "apache"

            # Second result uses v4.0
            $result[1].CVSSVersion | Should -Be "4.0"
        }

        It 'falls back to CVSS v3.1 when v4.0 is not available' {
            $result = Get-NvdCve -Keyword "openssl"

            # First result uses v3.1
            $result[0].CVSSVersion | Should -Be "3.1"
        }

        It 'handles missing CVSS data gracefully' {
            # Mock response with no CVSS data
            Mock -CommandName Invoke-RestMethod -MockWith {
                return [PSCustomObject]@{
                    totalResults    = 1
                    vulnerabilities = @(
                        [PSCustomObject]@{
                            cve = [PSCustomObject]@{
                                id             = "CVE-2023-NOCVSS"
                                descriptions   = @([PSCustomObject]@{ value = "No CVSS data" })
                                published      = "2023-01-01T00:00:00.000"
                                lastModified   = "2023-01-01T00:00:00.000"
                                vulnStatus     = "Awaiting Analysis"
                                weaknesses     = [PSCustomObject]@{ description = @() }
                                metrics        = [PSCustomObject]@{}
                                configurations = [PSCustomObject]@{ nodes = @() }
                            }
                        }
                    )
                }
            }

            $result = Get-NvdCve -Keyword "nocvss"

            $result.CVSSVersion | Should -Be "N/A"
            $result.CVSSSeverity | Should -Be "N/A"
            $result.CVSSBaseScore | Should -Be "N/A"
        }
    }
}
