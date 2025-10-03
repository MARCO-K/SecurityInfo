#requires -Modules Pester

# Import the function to be tested.
. "$PSScriptRoot/../functions/Get-SqlServerCve.ps1"

Describe 'Get-SqlServerCve' {
    Context 'With sample HTML content' {
        # Sample HTML content mimicking the structure of the target website.
        $sampleHtml = @"
Microsoft SQL Server 2022 Builds
... some other content ...
16.0.4120.1 16.00.4120.1 2022.160.4120.1 Q5036343 KB5036343 Security update for SQL Server 2022 CU12: April 9, 2024 CVE-2024-28906 CVE-2024-28908 2024-04-09
16.0.1110.1 16.00.1110.1 2022.160.1110.1 Q5032968 KB5032968 Security update for SQL Server 2022 GDR: January 9, 2024 CVE-2024-0056 2024-01-09

Microsoft SQL Server 2019 Builds
... some other content ...
15.0.4360.2 15.00.4360.2 2019.150.4360.2 Q5036335 KB5036335 Security update for SQL Server 2019 CU25: April 9, 2024 CVE-2024-29985 2024-04-09
15.0.2000.5 15.00.2000.5 2019.150.2000.5 Microsoft SQL Server 2019 RTM RTM 2019-11-04

Microsoft SQL Server 2017 Builds
... some other content ...
14.0.3015.40 14.00.3015.40 2017.140.3015.40 Q4052987 KB4052987 Cumulative update 3 (CU3) for SQL Server 2017 – Security Advisory ADV180002 CVE-2017-5715 CVE-2017-5753 CVE-2017-5754 2018-01-04
"@

        $results = $sampleHtml | Get-SqlServerCve

        It 'should return the correct number of CVE objects' {
            $results.Count | Should -Be 6
        }

        It 'should extract the correct SQL Server versions' {
            ($results | Where-Object { $_.SqlVersion -eq 'SQL Server 2022' }).Count | Should -Be 3
            ($results | Where-Object { $_.SqlVersion -eq 'SQL Server 2019' }).Count | Should -Be 1
            ($results | Where-Object { $_.SqlVersion -eq 'SQL Server 2017' }).Count | Should -Be 2
        }

        It 'should extract the correct dates' {
            $cve1 = $results | Where-Object { $_.Number -eq 'CVE-2024-28906' }
            $cve1.Date | Should -Be (Get-Date '2024-04-09')

            $cve2 = $results | Where-Object { $_.Number -eq 'CVE-2024-0056' }
            $cve2.Date | Should -Be (Get-Date '2024-01-09')
        }

        It 'should extract the correct CU versions' {
            ($results | Where-Object { $_.Number -eq 'CVE-2024-28906' }).CU | Should -Be 'CU12'
            ($results | Where-Object { $_.Number -eq 'CVE-2024-0056' }).CU | Should -Be 'GDR'
            ($results | Where-Object { $_.Number -eq 'CVE-2024-29985' }).CU | Should -Be 'CU25'
            ($results | Where-Object { $_.Number -eq 'CVE-2017-5715' }).CU | Should -Be 'CU3'
        }

        It 'should correctly handle multiple CVEs in a single line' {
            $cvesFor2022CU12 = $results | Where-Object { $_.Date -eq (Get-Date '2024-04-09') -and $_.SqlVersion -eq 'SQL Server 2022' }
            $cvesFor2022CU12.Count | Should -Be 2
            $cvesFor2022CU12.Number | Should -Be @('CVE-2024-28906', 'CVE-2024-28908')
        }

        It 'should ignore lines without CVEs' {
            $results.Number | Should -Not -Contain 'RTM'
        }
    }

    Context 'With malformed or empty content' {
        It 'should return no objects for empty HTML content' {
            $results = '' | Get-SqlServerCve
            $results.Count | Should -Be 0
        }

        It 'should return no objects for HTML content without CVEs' {
            $htmlWithoutCves = @"
Microsoft SQL Server 2022 Builds
16.0.1000.6 16.00.1000.6 2022.160.1000.6 Microsoft SQL Server 2022 RTM RTM 2022-11-16
"@
            $results = $htmlWithoutCves | Get-SqlServerCve
            $results.Count | Should -Be 0
        }
    }
}