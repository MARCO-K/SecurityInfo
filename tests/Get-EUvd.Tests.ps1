Describe 'Get-Euvd' {
    BeforeEach {
        # Mock data for successful EUVD API lookups
        $script:mockEuvdSingleData = [PSCustomObject]@{
            ID              = "EUVD-2023-12345"
            description     = "Critical vulnerability in test application"
            datePublished   = "2023-01-01T10:00:00.000Z"
            dateUpdated     = "2023-01-15T14:30:00.000Z"
            baseScore       = 9.8
            baseScoreVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            enisaIdVendor   = @{
                vendor = @{
                    Name = "Test Vendor Inc."
                }
            }
            enisaIdProduct  = @(
                @{
                    product         = @{
                        Name = "Test Application"
                    }
                    product_version = "1.0.0"
                },
                @{
                    product         = @{
                        Name = "Test Library"
                    }
                    product_version = "2.1.0"
                }
            )
        }

        $script:mockEuvdSearchData = [PSCustomObject]@{
            items = @(
                [PSCustomObject]@{
                    ID              = "EUVD-2023-11111"
                    description     = "OpenSSL vulnerability affecting encryption"
                    datePublished   = "2023-02-01T08:00:00.000Z"
                    dateUpdated     = "2023-02-10T12:00:00.000Z"
                    baseScore       = 7.5
                    baseScoreVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                    enisaIdVendor   = @{
                        vendor = @{
                            Name = "OpenSSL Foundation"
                        }
                    }
                    enisaIdProduct  = @(
                        @{
                            product         = @{
                                Name = "OpenSSL"
                            }
                            product_version = "1.1.1"
                        }
                    )
                },
                [PSCustomObject]@{
                    ID              = "EUVD-2023-22222"
                    description     = "Another OpenSSL related issue"
                    datePublished   = "2023-03-01T09:30:00.000Z"
                    dateUpdated     = "2023-03-05T16:45:00.000Z"
                    baseScore       = 5.3
                    baseScoreVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
                    enisaIdVendor   = @{
                        vendor = @{
                            Name = "OpenSSL Foundation"
                        }
                    }
                    enisaIdProduct  = @(
                        @{
                            product         = @{
                                Name = "OpenSSL"
                            }
                            product_version = "3.0.0"
                        }
                    )
                }
            )
        }

        $script:mockEmptyData = [PSCustomObject]@{}

        $script:mockEmptySearchData = [PSCustomObject]@{
            items = @()
        }

        # Mock for Invoke-RestMethod
        Mock -CommandName Invoke-RestMethod -MockWith {
            param($Uri)

            if ($Uri -match "enisaid\?id=CVE-2023-12345") {
                return $script:mockEuvdSingleData
            }
            elseif ($Uri -match "enisaid\?id=CVE-2023-12345") {
                return $script:mockEuvdSingleData
            }
            elseif ($Uri -match "enisaid\?id=EUVD-2023-67890") {
                return $script:mockEuvdSingleData
            }
            elseif ($Uri -match "enisaid\?id=EUVD-2023-67890") {
                return $script:mockEuvdSingleData
            }
            elseif ($Uri -match "search\?text=openssl") {
                return $script:mockEuvdSearchData
            }
            elseif ($Uri -match "enisaid\?id=CVE-9999-9999") {
                return $script:mockEmptyData
            }
            elseif ($Uri -match "search\?text=nonexistent") {
                return $script:mockEmptySearchData
            }
            elseif ($Uri -match "enisaid\?id=CVE-5000-5000") {
                throw "Simulated API Error"
            }
            else {
                return $script:mockEmptyData
            }
        }

        . "$PSScriptRoot/../functions/Get-EUvd.ps1"
    }

    Context 'ByCveId Parameter Set' {
        It 'returns vulnerability details for CVE ID' {
            $result = Get-Euvd -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result.EuvdId | Should -Be "EUVD-2023-12345"
            $result.Description | Should -Be "Critical vulnerability in test application"
            $result.CVSSScore | Should -Be 9.8
            $result.Vector | Should -Be "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            $result.Vendor | Should -Be "Test Vendor Inc."
        }

        It 'handles CVE IDs without the CVE- prefix' {
            $result = Get-Euvd -CveId "2023-12345"
            $result | Should -Not -BeNull
            $result.EuvdId | Should -Be "EUVD-2023-12345"
        }

        It 'returns nothing when no data is found' {
            $result = Get-Euvd -CveId "CVE-9999-9999"
            $result | Should -BeNull
        }
    }

    Context 'ByEUVDId Parameter Set' {
        It 'returns vulnerability details for EUVD ID' {
            $result = Get-Euvd -EuvdId "EUVD-2023-67890"
            $result | Should -Not -BeNull
            $result.EuvdId | Should -Be "EUVD-2023-12345"
            $result.Description | Should -Be "Critical vulnerability in test application"
            $result.CVSSScore | Should -Be 9.8
        }

        It 'handles EUVD IDs without the EUVD- prefix' {
            $result = Get-Euvd -EuvdId "2023-67890"
            $result | Should -Not -BeNull
            $result.EuvdId | Should -Be "EUVD-2023-12345"
        }
    }

    Context 'ByKeyword Parameter Set' {
        It 'returns search results for keyword' {
            $result = Get-Euvd -Keyword "openssl"
            $result | Should -Not -BeNull
            ($result | Measure-Object).Count | Should -Be 2
            $result[0].EuvdId | Should -Be "EUVD-2023-11111"
            $result[0].Description | Should -Be "OpenSSL vulnerability affecting encryption"
            $result[1].EuvdId | Should -Be "EUVD-2023-22222"
            $result[1].Vendor | Should -Be "OpenSSL Foundation"
        }

        It 'returns nothing when keyword search finds no results' {
            $result = Get-Euvd -Keyword "nonexistent"
            $result | Should -BeNull
        }
    }

    Context 'Error Handling' {
        It 'writes an error on API failure' {
            $errors = @()
            $result = Get-Euvd -CveId "CVE-5000-5000" -ErrorVariable errors
            $result | Should -BeNull
            $errors.Count | Should -BeGreaterThan 0
            # Verify that an error was generated
            $errors[0] | Should -Not -BeNull
            # The original exception is RuntimeException from the throw, wrapped by Write-Error
            $errors[0].Exception | Should -BeOfType [System.Management.Automation.RuntimeException]
        }
    }

    Context 'Data Type Validation' {
        It 'converts date strings to proper datetime types' {
            $result = Get-Euvd -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result.Published | Should -BeOfType [datetime]
            $result.LastModified | Should -BeOfType [datetime]
            $result.EuvdId | Should -BeOfType [string]
            $result.Description | Should -BeOfType [string]
            $result.CVSSScore | Should -BeOfType [double]
        }

        It 'properly structures product details' {
            $result = Get-Euvd -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result.ProductDetails | Should -Not -BeNull
            ($result.ProductDetails | Measure-Object).Count | Should -Be 2
            $result.ProductDetails[0].ProductName | Should -Be "Test Application"
            $result.ProductDetails[0].ProductVersion | Should -Be "1.0.0"
            $result.ProductDetails[1].ProductName | Should -Be "Test Library"
            $result.ProductDetails[1].ProductVersion | Should -Be "2.1.0"
        }

        It 'handles null date values gracefully' {
            # Create mock data with null dates
            Mock -CommandName Invoke-RestMethod -MockWith {
                return [PSCustomObject]@{
                    ID              = "EUVD-2023-99999"
                    description     = "Test vulnerability with no dates"
                    datePublished   = $null
                    dateUpdated     = $null
                    baseScore       = 5.0
                    baseScoreVector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
                    enisaIdVendor   = @{
                        vendor = @{
                            Name = "Test Vendor"
                        }
                    }
                    enisaIdProduct  = @()
                }
            }

            $result = Get-Euvd -CveId "CVE-2023-99999"
            $result | Should -Not -BeNull
            $result.Published | Should -BeNull
            $result.LastModified | Should -BeNull
        }
    }

    Context 'Parameter Set Validation' {
        It 'requires exactly one parameter set' {
            # This test verifies that the function definition requires mutually exclusive parameters
            { Get-Euvd -CveId "CVE-2023-12345" -Keyword "test" } | Should -Throw
        }
    }
}
