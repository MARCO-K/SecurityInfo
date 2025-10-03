<#
.SYNOPSIS
    Extracts CVE information for Microsoft SQL Server from HTML content.
.DESCRIPTION
    This function parses HTML content from the SQL Server Builds website (or a similar format)
    to extract information about security vulnerabilities (CVEs). It identifies the SQL Server
    version, release date, Cumulative Update (CU) version, and specific CVE numbers.
.PARAMETER HtmlContent
    The HTML content from the SQL Server Builds website as a single string. This parameter is mandatory.
.OUTPUT
    An array of PSCustomObject instances, where each object represents a single CVE and contains
    the following properties:
    - Date (DateTime): The release date of the update.
    - Number (string): The CVE identifier (e.g., "CVE-2024-28906").
    - CU (string): The Cumulative Update version (e.g., "CU12") or "GDR" if not specified.
    - SqlVersion (string): The version of SQL Server the CVE applies to (e.g., "SQL Server 2022").
.EXAMPLE
    PS > $html = Invoke-WebRequest -Uri 'https://sqlserverbuilds.blogspot.com/'
    PS > $html.Content | Get-SqlServerCve
    This example fetches the content from the SQL Server Builds blog and pipes it to
    Get-SqlServerCve to extract all listed CVEs.
#>
function Get-SqlServerCve {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "The HTML content from the SQL Server Builds website.")]
        [string]$HtmlContent
    )

    begin {
        # Regex to identify the header for a specific SQL Server version's build table.
        $versionHeaderRegex = 'Microsoft SQL Server (\d{4}) Builds'

        # Regex to find lines containing CVE information.
        $cveLineRegex = 'CVE-[\d-]+'

        # Regex to extract the release date, which is typically at the end of the line.
        $dateRegex = '(\d{4}-\d{2}-\d{2})$'

        # Regex to extract the Cumulative Update (CU) number from the description.
        $cuRegex = '(CU\d+)'

        # Regex to find all individual CVE numbers in a line.
        $cveNumberRegex = '(CVE-\d{4,}-\d{4,})'

        $currentSqlVersion = $null
        $allCves = [System.Collections.Generic.List[pscustomobject]]::new()
    }

    process {
        # Split the multiline string content into an array of individual lines.
        $lines = $HtmlContent -split '(\r?\n)'

        foreach ($line in $lines) {
            # Check if the line is a header for a new SQL version.
            if ($line -match $versionHeaderRegex) {
                $currentSqlVersion = "SQL Server $($matches[1])"
                # Skip to the next line after identifying the version header.
                continue
            }

            # Process the line only if a SQL version has been identified and the line contains CVE data.
            if ($currentSqlVersion -and $line -match $cveLineRegex) {

                # Extract the release date from the line.
                $releaseDateMatch = [regex]::Match($line, $dateRegex)
                $releaseDate = if ($releaseDateMatch.Success) {
                    try {
                        Get-Date $releaseDateMatch.Groups[1].Value
                    } catch {
                        $null
                    }
                } else {
                    $null
                }

                # Extract the CU version from the line.
                $cuMatch = [regex]::Match($line, $cuRegex)
                $cuVersion = if ($cuMatch.Success) { $cuMatch.Groups[1].Value } else { 'GDR' } # Assume GDR if CU is not found

                # Find all CVE numbers present in the line.
                $cveMatches = [regex]::Matches($line, $cveNumberRegex)

                if ($cveMatches.Count -gt 0) {
                    foreach ($cveMatch in $cveMatches) {
                        $cveNumber = $cveMatch.Value

                        # Create a custom object for each CVE found.
                        $cveObject = [PSCustomObject]@{
                            Date       = $releaseDate
                            Number     = $cveNumber
                            CU         = $cuVersion
                            SqlVersion = $currentSqlVersion
                        }
                        $allCves.Add($cveObject)
                    }
                }
            }
        }
    }

    end {
        # Output all the collected CVE objects.
        Write-Output $allCves
    }
}