
Describe 'Get-EpssScore' {
    BeforeEach {
        # Mock data for successful API lookups
        $script:mockEpssData = @{
            status        = "OK"
            "status-code" = 200
            version       = "1.0"
            total         = 2
            offset        = 0
            limit         = 100
            data          = @(
                @{
                    cve        = "CVE-2023-12345"
                    epss       = "0.97000"
                    percentile = "0.99000"
                    date       = "2023-01-01"
                },
                @{
                    cve        = "CVE-2022-54321"
                    epss       = "0.05000"
                    percentile = "0.80000"
                    date       = "2022-12-31"
                }
            )
        }

        $script:mockNoData = @{
            status        = "OK"
            "status-code" = 200
            version       = "1.0"
            total         = 0
            data          = @()
        }

        # Mock for Invoke-RestMethod
        Mock -CommandName Invoke-RestMethod -MockWith {
            param($Uri, $Body)

            if ($Body.cve -eq 'CVE-2023-12345,CVE-2022-54321') {
                return $script:mockEpssData
            }
            elseif ($Body.cve -eq 'CVE-2023-12345') {
                # Return single item for data type validation test
                $singleData = @{
                    status        = "OK"
                    "status-code" = 200
                    version       = "1.0"
                    total         = 1
                    data          = @($script:mockEpssData.data[0])
                }
                return $singleData
            }
            elseif ($Body.days -eq 7) {
                return $script:mockEpssData
            }
            elseif ($Body.'epss-gt' -eq 0.5) {
                return $script:mockEpssData
            }
            elseif ($Body.cve -eq 'CVE-9999-9999') {
                return $script:mockNoData
            }
            elseif ($Body.cve -eq 'CVE-5000-5000') {
                throw "Simulated API Error"
            }
            else {
                return $script:mockNoData
            }
        }

        . "$PSScriptRoot/../functions/Get-EpssScore.ps1"
    }

    Context 'ByCveId Parameter Set' {
        It 'returns scores for multiple CVEs' {
            $result = Get-EpssScore -CveId "CVE-2023-12345", "CVE-2022-54321"
            $result | Should -Not -BeNull
            ($result | Measure-Object).Count | Should -Be 2
            $result[0].epssScore | Should -Be 0.97
            $result[0].cveID | Should -Be "CVE-2023-12345"
            $result[1].epssScore | Should -Be 0.05
            $result[1].cveID | Should -Be "CVE-2022-54321"
        }

        It 'handles CVEs without the CVE- prefix' {
            $result = Get-EpssScore -CveId "2023-12345", "2022-54321"
            $result | Should -Not -BeNull
            ($result | Measure-Object).Count | Should -Be 2
            $result[0].cveID | Should -Be "CVE-2023-12345"
            $result[1].cveID | Should -Be "CVE-2022-54321"
        }

        It 'returns null and warns when no data is found' {
            $warnings = @()
            $result = Get-EpssScore -CveId "CVE-9999-9999" -WarningVariable warnings
            $result | Should -BeNull
            $warnings[0].Message | Should -Be "No EPSS data found for the specified criteria."
        }
    }

    Context 'ByDays Parameter Set' {
        It 'returns scores for recent days' {
            $result = Get-EpssScore -Days 7
            $result | Should -Not -BeNull
            ($result | Measure-Object).Count | Should -Be 2
            $result[0].epssScore | Should -Be 0.97
            $result[1].epssScore | Should -Be 0.05
        }
    }

    Context 'ByFilter Parameter Set' {
        It 'returns scores filtered by EpssGreaterThan' {
            $result = Get-EpssScore -EpssGreaterThan 0.5
            $result | Should -Not -BeNull
            ($result | Measure-Object).Count | Should -Be 2
            $result[0].epssScore | Should -Be 0.97
        }
    }

    Context 'Error Handling' {
        It 'writes an error on API failure' {
            $errors = @()
            $result = Get-EpssScore -CveId "CVE-5000-5000" -ErrorVariable errors
            $result | Should -BeNull
            $errors.Count | Should -BeGreaterThan 0
            # Verify that an error was generated - the error record contains the original exception
            # The console shows the formatted Write-Error message, but ErrorVariable captures the record
            $errors[0] | Should -Not -BeNull
            # The original exception is RuntimeException from the throw, wrapped by Write-Error
            $errors[0].Exception | Should -BeOfType [System.Management.Automation.RuntimeException]
        }
    }

    Context 'Data Type Validation' {
        It 'converts string values to proper types' {
            $result = Get-EpssScore -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result[0].epssScore | Should -BeOfType [double]
            $result[0].percentile | Should -BeOfType [double]
            $result[0].date | Should -BeOfType [datetime]
            $result[0].cveID | Should -BeOfType [string]
        }
    }
}
