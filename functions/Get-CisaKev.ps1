<#
.SYNOPSIS
    Retrieves vulnerability information from the CISA KEV (Known Exploited Vulnerabilities) API.

.DESCRIPTION
    This function queries the CISA KEV API for vulnerabilities using a CVE ID, keyword, or recent days.
    Results include details such as CVE ID, vendor, product, vulnerability name, date added, description, required action, due date, notes, ransomware status, and KEV inclusion date.
    Optionally, results can be filtered by CVSS severity.

.PARAMETER CveId
    The CVE ID (e.g., "2023-12345") to retrieve vulnerability details.

.PARAMETER Keyword
    A keyword to search for vulnerabilities in the CISA KEV database.

.PARAMETER Days
    The number of recent days to retrieve vulnerabilities added to the CISA KEV list.

.PARAMETER Severity
    Filter results by CVSS v3 severity: LOW, MEDIUM, HIGH, or CRITICAL.

.EXAMPLE
    Get-CisaKev -CveId "2023-12345"
    # Retrieves details for CVE-2023-12345 from the CISA KEV API.

.EXAMPLE
    Get-CisaKev -Keyword "Exchange"
    # Searches for vulnerabilities related to "Exchange" in the CISA KEV database.

.EXAMPLE
    Get-CisaKev -Days 7
    # Retrieves vulnerabilities added to the CISA KEV list in the last 7 days.

.EXAMPLE
    Get-CisaKev -Days 30 -Severity "CRITICAL"
    # Retrieves CRITICAL vulnerabilities added in the last 30 days.

.OUTPUTS
    [pscustomobject] containing vulnerability details for each matching entry.

.LINK
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    The function uses the public KEVin API and may be subject to availability or rate limits.
#>
function Get-CisaKev {
    [CmdletBinding(DefaultParameterSetName = 'ByCveId')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByCveId')]
        [string]$CveId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByKeyword')]
        [string]$Keyword,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByDays')]
        [int]$Days,

        [Parameter(Mandatory = $false)]
        [ValidateSet('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')]
        [string]$Severity
    )

    begin {
        $baseApiUrl = "https://kevin.gtfkd.com/api/v1"
        $apiUrl = ""

        switch ($PSCmdlet.ParameterSetName) {
            'ByCveId' {
                if (-not $CveId.StartsWith('CVE-', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $CveId = "CVE-$CveId"
                }
                $apiUrl = "$baseApiUrl/vulnerabilities/id/$CveId"
                break
            }
            'ByKeyword' {
                $apiUrl = "$baseApiUrl/vulnerabilities/search?q=$Keyword"
                break
            }
            'ByDays' {
                $apiUrl = "$baseApiUrl/kev/recent?days=$Days"
                break
            }
        }
    }

    process {
        try {
            $response = Invoke-RestMethod -Method Get -Uri $apiUrl
            $results = $response | ForEach-Object {
                [pscustomobject]@{
                    "cveID"             = $_.cveID
                    "vendorProject"     = $_.vendorProject
                    "product"           = $_.product
                    "vulnerabilityName" = $_.vulnerabilityName
                    "dateAdded"         = $_.dateAdded
                    "shortDescription"  = $_.shortDescription
                    "requiredAction"    = $_.requiredAction
                    "dueDate"           = $_.dueDate
                    "notes"             = $_.notes
                    "isRansomware"      = $_.isRansomware
                    "kevInSince"        = $_.kevInSince
                }
            }

            if ($PSBoundParameters.ContainsKey('Severity')) {
                $filteredResults = @()
                foreach ($result in $results) {
                    try {
                        $vulnDetails = Invoke-RestMethod -Method Get -Uri "$baseApiUrl/vuln/$($result.cveID)"
                        if ($vulnDetails.cvssV3_severity -eq $Severity) {
                            $filteredResults += $result
                        }
                    }
                    catch {
                        Write-Warning "Could not retrieve vulnerability details for $($result.cveID) to filter by severity."
                    }
                }
                $filteredResults
            }
            else {
                $results
            }
        }
        catch {
            # Check if the error is the specific "not found" message from the API
            $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($errorMessage -and $errorMessage.error -eq "You found nothing! Congratulations!") {
                # This is a valid "not found" response. Inform the user if they are running in verbose mode.
                Write-Verbose "CVE '$CveId' was not found in the CISA KEV catalog."
                return
            }
            else {
                # It's a different, unexpected error, so we report it.
                Write-Error "Error fetching data from KEVin API: $_"
            }
        }
    }
}
