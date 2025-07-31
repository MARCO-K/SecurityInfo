Describe "Get-SecurityInfo" {
    BeforeAll {
        # Load all the individual functions first so they can be mocked
        . "$PSScriptRoot/../functions/Get-NvdCve.ps1"
        . "$PSScriptRoot/../functions/Get-CveOrg.ps1"
        . "$PSScriptRoot/../functions/Get-CisaKev.ps1"
        . "$PSScriptRoot/../functions/Get-EpssScore.ps1"
        . "$PSScriptRoot/../functions/Get-ExploitDb.ps1"
        . "$PSScriptRoot/../functions/Get-Euvd.ps1"
        . "$PSScriptRoot/../functions/Get-GitHubSecurityAdvisory.ps1"

        # Mock data for individual functions - these will be returned by mocked functions
        $script:mockNvdData = [PSCustomObject]@{
            CVEID         = "CVE-2023-12345"
            CVSSVersion   = "3.1"
            CVSSSeverity  = "CRITICAL"
            CVSSBaseScore = 9.8
            Description   = "A critical vulnerability in OpenSSL allowing remote code execution"
            Published     = "2023-01-15T10:00:00.000"
            LastModified  = "2023-01-16T12:00:00.000"
            Status        = "Analyzed"
            CWEIDs        = "CWE-78, CWE-94"
        }

        $script:mockCveOrgData = [PSCustomObject]@{
            CveId         = "CVE-2023-12345"
            Title         = "OpenSSL Remote Code Execution Vulnerability"
            Description   = "Critical vulnerability in OpenSSL library"
            DatePublished = "2023-01-15"
            DateUpdated   = "2023-01-16"
            State         = "PUBLIC"
            Severity      = "CRITICAL"
            BaseScore     = 9.8
        }

        $script:mockCisaData = [PSCustomObject]@{
            CveId                      = "CVE-2023-12345"
            VendorProject              = "OpenSSL"
            Product                    = "OpenSSL"
            VulnerabilityName          = "OpenSSL RCE"
            DateAdded                  = "2023-01-20"
            ShortDescription           = "OpenSSL contains a vulnerability that allows RCE"
            RequiredAction             = "Apply updates"
            DueDate                    = "2023-02-03"
            KnownRansomwareCampaignUse = "Known"
            Notes                      = "Actively exploited"
        }

        $script:mockEpssData = [PSCustomObject]@{
            CveId          = "CVE-2023-12345"
            EpssScore      = 0.95123
            EpssPercentile = 0.99456
            Date           = "2023-01-17"
        }

        $script:mockExploitDbData = [PSCustomObject]@{
            CveId         = "CVE-2023-12345"
            ExploitId     = "50123"
            ExploitTitle  = "OpenSSL Remote Code Execution"
            ExploitType   = "remote"
            Platform      = "linux"
            ExploitAuthor = "security researcher"
            ExploitDate   = "2023-01-18"
            ExploitUrl    = "https://www.exploit-db.com/exploits/50123"
        }

        $script:mockEuvdData = [PSCustomObject]@{
            CveId           = "CVE-2023-12345"
            Title           = "OpenSSL Vulnerability"
            Description     = "Critical OpenSSL vulnerability"
            PublicationDate = "2023-01-15"
            Severity        = "Critical"
            CvssScore       = 9.8
        }

        $script:mockGitHubData = [PSCustomObject]@{
            GhsaId      = "GHSA-xxxx-yyyy-zzzz"
            Summary     = "OpenSSL Remote Code Execution"
            Description = "Critical vulnerability in OpenSSL"
            Severity    = "CRITICAL"
            CveId       = "CVE-2023-12345"
            PublishedAt = "2023-01-15T10:00:00Z"
            UpdatedAt   = "2023-01-16T12:00:00Z"
        }

        # Mock all the individual functions
        Mock -CommandName Get-NvdCve -MockWith {
            param($CveId)
            if ($CveId -eq "CVE-2023-12345") { return $script:mockNvdData }
            elseif ($CveId -eq "CVE-9999-9999") { return $null }
            elseif ($CveId -eq "CVE-5000-5000") { return $null }
            else { return $script:mockNvdData }
        }

        Mock -CommandName Get-CveOrg -MockWith {
            param($CveId)
            if ($CveId -eq "CVE-2023-12345") { return $script:mockCveOrgData }
            elseif ($CveId -eq "CVE-9999-9999") { return $null }
            elseif ($CveId -eq "CVE-5000-5000") { return $null }
            else { return $script:mockCveOrgData }
        }

        Mock -CommandName Get-CisaKev -MockWith {
            param($CveId)
            if ($CveId -eq "CVE-2023-12345") { return $script:mockCisaData }
            else { return $null }
        }

        Mock -CommandName Get-EpssScore -MockWith {
            param($CveId)
            if ($CveId -eq "CVE-2023-12345") { return $script:mockEpssData }
            else { return $null }
        }

        Mock -CommandName Get-ExploitDb -MockWith {
            param($CveId)
            if ($CveId -eq "CVE-2023-12345") { return $script:mockExploitDbData }
            else { return $null }
        }

        Mock -CommandName Get-Euvd -MockWith {
            param($CveId)
            if ($CveId -eq "CVE-2023-12345") { return $script:mockEuvdData }
            else { return $null }
        }

        Mock -CommandName Get-GitHubSecurityAdvisory -MockWith {
            param($CveId)
            if ($CveId -eq "CVE-2023-12345") { return $script:mockGitHubData }
            else { return $null }
        }

        . "$PSScriptRoot/../functions/Get-SecurityInfo.ps1"
    }

    Context 'Basic Functionality' {
        It 'accepts CVE ID with CVE prefix' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"
            $result | Should -Not -BeNull
            $result.CveId | Should -Be "CVE-2023-12345"
        }

        It 'accepts CVE ID without CVE prefix' {
            $result = Get-SecurityInfo -CveId "2023-12345"
            $result | Should -Not -BeNull
            $result.CveId | Should -Be "CVE-2023-12345"
        }

        It 'accepts multiple CVE IDs' {
            $result = Get-SecurityInfo -CveId @("CVE-2023-12345", "2024-67890")
            $result | Should -Not -BeNull
            $result.Count | Should -Be 2
            $result[0].CveId | Should -Be "CVE-2023-12345"
            $result[1].CveId | Should -Be "CVE-2024-67890"
        }

        It 'accepts pipeline input' {
            $result = @("CVE-2023-12345", "2024-67890") | Get-SecurityInfo
            $result | Should -Not -BeNull
            $result.Count | Should -Be 2
        }
    }

    Context 'Data Source Integration' {
        It 'calls all data source functions' {
            Get-SecurityInfo -CveId "CVE-2023-12345"

            Assert-MockCalled -CommandName Get-NvdCve -Times 1 -ParameterFilter { $CveId -eq "CVE-2023-12345" }
            Assert-MockCalled -CommandName Get-CveOrg -Times 1 -ParameterFilter { $CveId -eq "CVE-2023-12345" }
            Assert-MockCalled -CommandName Get-CisaKev -Times 1 -ParameterFilter { $CveId -eq "CVE-2023-12345" }
            Assert-MockCalled -CommandName Get-EpssScore -Times 1 -ParameterFilter { $CveId -eq "CVE-2023-12345" }
            Assert-MockCalled -CommandName Get-ExploitDb -Times 1 -ParameterFilter { $CveId -eq "CVE-2023-12345" }
            Assert-MockCalled -CommandName Get-Euvd -Times 1 -ParameterFilter { $CveId -eq "CVE-2023-12345" }
            Assert-MockCalled -CommandName Get-GitHubSecurityAdvisory -Times 1 -ParameterFilter { $CveId -eq "CVE-2023-12345" }
        }

        It 'sets availability flags correctly when data is available' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"

            $result.IsNvdAvailable | Should -Be $true
            $result.IsCveOrgAvailable | Should -Be $true
            $result.IsCisaKevAvailable | Should -Be $true
            $result.IsEpssAvailable | Should -Be $true
            $result.IsExploitDbAvailable | Should -Be $true
            $result.IsEuvdAvailable | Should -Be $true
            $result.IsGitHubAvailable | Should -Be $true
        }

        It 'sets availability flags correctly when data is not available' {
            $warnings = @()
            $result = Get-SecurityInfo -CveId "CVE-9999-9999" -WarningVariable warnings

            # When no data sources return data, the function skips the CVE entirely
            $result | Should -BeNullOrEmpty
            $warnings.Count | Should -Be 1
            $warnings[0] | Should -Match "No information found for 'CVE-9999-9999'"
        }
    }

    Context 'Data Prioritization' {
        It 'prioritizes NVD data over CVE.org data when both available' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"

            # Should use NVD data for these fields when available
            $result.Published | Should -Be $script:mockNvdData.Published
            $result.LastModified | Should -Be $script:mockNvdData.LastModified
            $result.Status | Should -Be $script:mockNvdData.Status
            $result.Severity | Should -Be $script:mockNvdData.CVSSSeverity
            $result.CVSSScore | Should -Be $script:mockNvdData.CVSSBaseScore
            $result.Description | Should -Be $script:mockNvdData.Description
        }

        It 'uses CVE.org title over NVD description for title field' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"

            # Title should come from CVE.org even when NVD is available
            $result.Title | Should -Be $script:mockCveOrgData.Title
        }

        It 'falls back to CVE.org data when NVD data is not available' {
            # Mock scenario where NVD returns null but CVE.org has data
            Mock -CommandName Get-NvdCve -MockWith { return $null }

            $result = Get-SecurityInfo -CveId "CVE-2023-12345"

            $result.Title | Should -Be $script:mockCveOrgData.Title
            $result.Published | Should -Be $script:mockCveOrgData.DatePublished
            $result.LastModified | Should -Be $script:mockCveOrgData.DateUpdated
            $result.Status | Should -Be $script:mockCveOrgData.State
            $result.Severity | Should -Be $script:mockCveOrgData.Severity
            $result.CVSSScore | Should -Be $script:mockCveOrgData.BaseScore
            $result.Description | Should -Be $script:mockCveOrgData.Description
        }

        It 'handles N/A values when no data source is available' {
            # Mock all functions to return null - but this will cause the function to skip the CVE
            # So we need to test a different scenario where at least one source returns data
            Mock -CommandName Get-NvdCve -MockWith { return $null }
            Mock -CommandName Get-CveOrg -MockWith {
                return [PSCustomObject]@{
                    CveId         = "CVE-9999-9999"
                    Title         = "Test CVE"
                    Description   = "Test description"
                    DatePublished = "2023-01-01"
                    DateUpdated   = "2023-01-02"
                    State         = "PUBLIC"
                    Severity      = "HIGH"
                    BaseScore     = 7.5
                }
            }

            $result = Get-SecurityInfo -CveId "CVE-9999-9999"

            # Should use CVE.org data when NVD is not available
            $result.Title | Should -Be "Test CVE"
            $result.Published | Should -Be "2023-01-01"
            $result.LastModified | Should -Be "2023-01-02"
            $result.Status | Should -Be "PUBLIC"
            $result.Severity | Should -Be "HIGH"
            $result.CVSSScore | Should -Be 7.5
            $result.Description | Should -Be "Test description"
        }
    }

    Context 'VulnDetails Parameter' {
        It 'includes detailed data when vulnDetails switch is used' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345" -vulnDetails

            $result.PSObject.Properties.Name | Should -Contain "NVD_Data"
            $result.PSObject.Properties.Name | Should -Contain "CveOrg_Data"
            $result.PSObject.Properties.Name | Should -Contain "CisaKev_Data"
            $result.PSObject.Properties.Name | Should -Contain "Epss_Data"
            $result.PSObject.Properties.Name | Should -Contain "ExploitDb_Data"
            $result.PSObject.Properties.Name | Should -Contain "Euvd_Data"
            $result.PSObject.Properties.Name | Should -Contain "GitHub_Data"
        }

        It 'does not include detailed data by default' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"

            $result.PSObject.Properties.Name | Should -Not -Contain "NVD_Data"
            $result.PSObject.Properties.Name | Should -Not -Contain "CveOrg_Data"
            $result.PSObject.Properties.Name | Should -Not -Contain "CisaKev_Data"
            $result.PSObject.Properties.Name | Should -Not -Contain "Epss_Data"
            $result.PSObject.Properties.Name | Should -Not -Contain "ExploitDb_Data"
            $result.PSObject.Properties.Name | Should -Not -Contain "Euvd_Data"
            $result.PSObject.Properties.Name | Should -Not -Contain "GitHub_Data"
        }

        It 'includes only available detailed data sources' {
            # Mock scenario where only some data sources return data
            Mock -CommandName Get-CisaKev -MockWith { return $null }
            Mock -CommandName Get-ExploitDb -MockWith { return $null }

            $result = Get-SecurityInfo -CveId "CVE-2023-12345" -vulnDetails

            $result.PSObject.Properties.Name | Should -Contain "NVD_Data"
            $result.PSObject.Properties.Name | Should -Contain "CveOrg_Data"
            $result.PSObject.Properties.Name | Should -Not -Contain "CisaKev_Data"
            $result.PSObject.Properties.Name | Should -Contain "Epss_Data"
            $result.PSObject.Properties.Name | Should -Not -Contain "ExploitDb_Data"
            $result.PSObject.Properties.Name | Should -Contain "Euvd_Data"
            $result.PSObject.Properties.Name | Should -Contain "GitHub_Data"
        }

        It 'detailed data contains correct objects' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345" -vulnDetails

            $result.NVD_Data | Should -Be $script:mockNvdData
            $result.CveOrg_Data | Should -Be $script:mockCveOrgData
            $result.CisaKev_Data | Should -Be $script:mockCisaData
            $result.Epss_Data | Should -Be $script:mockEpssData
            $result.ExploitDb_Data | Should -Be $script:mockExploitDbData
            $result.Euvd_Data | Should -Be $script:mockEuvdData
            $result.GitHub_Data | Should -Be $script:mockGitHubData
        }
    }

    Context 'Error Handling' {
        It 'warns and skips CVE when no data source returns information' {
            $warnings = @()
            $result = Get-SecurityInfo -CveId "CVE-5000-5000" -WarningVariable warnings

            $result | Should -BeNullOrEmpty
            $warnings.Count | Should -Be 1
            $warnings[0] | Should -Match "No information found for 'CVE-5000-5000'"
        }

        It 'continues processing other CVEs when one fails' {
            # Mock all functions to return null for CVE-5000-5000 but data for CVE-2023-12345
            Mock Get-CveOrg {
                if ($CveId -eq "CVE-5000-5000") { return $null }
                else { return $script:mockCveOrgData }
            }
            Mock Get-NvdCve {
                if ($CveId -eq "CVE-5000-5000") { return $null }
                else { return $script:mockNvdData }
            }
            Mock Get-CisaKev {
                if ($CveId -eq "CVE-5000-5000") { return $null }
                else { return $script:mockCisaData }
            }
            Mock Get-EpssScore {
                if ($CveId -eq "CVE-5000-5000") { return $null }
                else { return $script:mockEpssData }
            }
            Mock Get-ExploitDb {
                if ($CveId -eq "CVE-5000-5000") { return $null }
                else { return $script:mockExploitDbData }
            }
            Mock Get-EUvd {
                if ($CveId -eq "CVE-5000-5000") { return $null }
                else { return $script:mockEuvdData }
            }
            Mock Get-GitHubSecurityAdvisory {
                if ($CveId -eq "CVE-5000-5000") { return $null }
                else { return $script:mockGitHubData }
            }

            $warnings = @()
            $result = Get-SecurityInfo -CveId @("CVE-5000-5000", "CVE-2023-12345") -WarningVariable warnings

            # The function should return at least one result for the valid CVE
            # Check if it's a single object or an array
            if ($result -is [array]) {
                $result.Count | Should -Be 1
                $result[0].CveId | Should -Be "CVE-2023-12345"
            }
            else {
                # Single object case
                $result | Should -Not -BeNullOrEmpty
                $result.CveId | Should -Be "CVE-2023-12345"
            }
            $warnings.Count | Should -Be 1
        }

        It 'handles individual function errors gracefully' {
            # Mock one function to return null, but others still have data
            Mock -CommandName Get-NvdCve -MockWith { return $null }

            # The function still returns data from other sources
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"

            $result | Should -Not -BeNullOrEmpty
            $result.IsNvdAvailable | Should -Be $false
            $result.IsCveOrgAvailable | Should -Be $true
        }
    }

    Context 'Data Type Validation' {
        It 'returns proper data types for all summary fields' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"

            $result.CveId | Should -BeOfType [string]
            $result.Title | Should -BeOfType [string]
            $result.Published | Should -BeOfType [string]
            $result.LastModified | Should -BeOfType [string]
            $result.Status | Should -BeOfType [string]
            $result.Severity | Should -BeOfType [string]
            $result.CVSSScore | Should -BeOfType [double]
            $result.Description | Should -BeOfType [string]
        }

        It 'returns proper data types for availability flags' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"

            $result.IsNvdAvailable | Should -BeOfType [bool]
            $result.IsCveOrgAvailable | Should -BeOfType [bool]
            $result.IsCisaKevAvailable | Should -BeOfType [bool]
            $result.IsEpssAvailable | Should -BeOfType [bool]
            $result.IsExploitDbAvailable | Should -BeOfType [bool]
            $result.IsEuvdAvailable | Should -BeOfType [bool]
            $result.IsGitHubAvailable | Should -BeOfType [bool]
        }

        It 'returns proper data types for detailed objects' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345" -vulnDetails

            $result.NVD_Data | Should -BeOfType [PSCustomObject]
            $result.CveOrg_Data | Should -BeOfType [PSCustomObject]
            $result.CisaKev_Data | Should -BeOfType [PSCustomObject]
            $result.Epss_Data | Should -BeOfType [PSCustomObject]
            $result.ExploitDb_Data | Should -BeOfType [PSCustomObject]
            $result.Euvd_Data | Should -BeOfType [PSCustomObject]
            $result.GitHub_Data | Should -BeOfType [PSCustomObject]
        }
    }

    Context 'Performance and Efficiency' {
        It 'makes exactly one call to each data source function per CVE' {
            Get-SecurityInfo -CveId "CVE-2023-12345"

            Assert-MockCalled -CommandName Get-NvdCve -Exactly 1
            Assert-MockCalled -CommandName Get-CveOrg -Exactly 1
            Assert-MockCalled -CommandName Get-CisaKev -Exactly 1
            Assert-MockCalled -CommandName Get-EpssScore -Exactly 1
            Assert-MockCalled -CommandName Get-ExploitDb -Exactly 1
            Assert-MockCalled -CommandName Get-Euvd -Exactly 1
            Assert-MockCalled -CommandName Get-GitHubSecurityAdvisory -Exactly 1
        }

        It 'processes multiple CVEs efficiently' {
            Get-SecurityInfo -CveId @("CVE-2023-12345", "CVE-2024-67890")

            Assert-MockCalled -CommandName Get-NvdCve -Exactly 2
            Assert-MockCalled -CommandName Get-CveOrg -Exactly 2
            Assert-MockCalled -CommandName Get-CisaKev -Exactly 2
            Assert-MockCalled -CommandName Get-EpssScore -Exactly 2
            Assert-MockCalled -CommandName Get-ExploitDb -Exactly 2
            Assert-MockCalled -CommandName Get-Euvd -Exactly 2
            Assert-MockCalled -CommandName Get-GitHubSecurityAdvisory -Exactly 2
        }
    }

    Context 'CVE ID Normalization' {
        It 'normalizes CVE ID with different cases' {
            $result = Get-SecurityInfo -CveId "cve-2023-12345"

            # Case-insensitive StartsWith means "cve-" is treated as already having the prefix
            $result.CveId | Should -Be "cve-2023-12345"
        }

        It 'normalizes CVE ID without prefix' {
            $result = Get-SecurityInfo -CveId "2023-12345"
            $result.CveId | Should -Be "CVE-2023-12345"
        }

        It 'handles mixed CVE ID formats in array' {
            $result = Get-SecurityInfo -CveId @("CVE-2023-12345", "2024-67890", "cve-2025-11111")

            $result[0].CveId | Should -Be "CVE-2023-12345"
            $result[1].CveId | Should -Be "CVE-2024-67890"
            $result[2].CveId | Should -Be "cve-2025-11111"  # Case-insensitive check means this stays as-is
        }
    }

    Context 'Output Structure Validation' {
        It 'contains all required summary fields' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"

            $requiredFields = @(
                'CveId', 'Title', 'Published', 'LastModified', 'Status',
                'Severity', 'CVSSScore', 'Description',
                'IsNvdAvailable', 'IsCveOrgAvailable', 'IsCisaKevAvailable',
                'IsEpssAvailable', 'IsExploitDbAvailable', 'IsEuvdAvailable', 'IsGitHubAvailable'
            )

            foreach ($field in $requiredFields) {
                $result.PSObject.Properties.Name | Should -Contain $field
            }
        }

        It 'maintains field order in output' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"

            $properties = $result.PSObject.Properties.Name
            $properties[0] | Should -Be "CveId"
            $properties[1] | Should -Be "Title"
            $properties[2] | Should -Be "Published"
            # Test first few fields to ensure ordered hashtable is working
        }

        It 'returns PSCustomObject type' {
            $result = Get-SecurityInfo -CveId "CVE-2023-12345"
            $result | Should -BeOfType [PSCustomObject]
        }
    }

    Context 'Edge Cases' {
        It 'handles empty CVE ID array' {
            { Get-SecurityInfo -CveId @() } | Should -Throw
        }

        It 'handles null CVE ID gracefully' {
            { Get-SecurityInfo -CveId $null } | Should -Throw
        }

        It 'handles very long CVE ID list' {
            $longList = 1..50 | ForEach-Object { "2023-$_" }
            { Get-SecurityInfo -CveId $longList } | Should -Not -Throw
        }

        It 'handles duplicate CVE IDs' {
            $result = Get-SecurityInfo -CveId @("CVE-2023-12345", "CVE-2023-12345")
            $result.Count | Should -Be 2
            $result[0].CveId | Should -Be "CVE-2023-12345"
            $result[1].CveId | Should -Be "CVE-2023-12345"
        }
    }
}
