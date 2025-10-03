<#
.SYNOPSIS
    Retrieves data from the CISA Known Exploited Vulnerabilities (KEV) catalog.

.DESCRIPTION
    This function queries the CISA KEV catalog to determine if a vulnerability is known to be actively exploited in the wild.
    This is a critical data source for prioritizing remediation efforts. The function can query by a specific CVE ID, a general keyword, or for vulnerabilities added within a recent number of days.

.PARAMETER CveId
    The CVE ID (e.g., "2023-12345" or "CVE-2023-12345") to check against the KEV catalog.

.PARAMETER Keyword
    A keyword to search for in the KEV database. This can be a product name, vendor, or any other term.

.PARAMETER Days
    The number of recent days to retrieve vulnerabilities that were added to the KEV list.

.PARAMETER Severity
    An optional parameter to filter the results by CVSS v3 severity. Accepted values are LOW, MEDIUM, HIGH, CRITICAL.
    Note: This requires an additional API call per vulnerability and may slow down the query.

.EXAMPLE
    Get-CisaKev -CveId "2023-12345"
    # Retrieves the KEV entry for CVE-2023-12345, if it exists.

.EXAMPLE
    Get-CisaKev -Keyword "Exchange"
    # Searches for all KEV entries related to "Exchange".

.EXAMPLE
    Get-CisaKev -Days 7
    # Retrieves all vulnerabilities added to the KEV catalog in the last 7 days.

.EXAMPLE
    Get-CisaKev -Days 30 -Severity "CRITICAL"
    # Retrieves CRITICAL vulnerabilities added to the KEV list in the last 30 days.

.OUTPUTS
    [pscustomobject]
    Returns a custom object for each matching KEV entry with properties such as:
    - cveID
    - vendorProject, product, vulnerabilityName
    - dateAdded, dueDate
    - shortDescription, requiredAction
    - isRansomware

.LINK
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    https://kevin.gtfkd.com/api/v1/docs

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    This function uses the community-maintained KEVin API, which is a wrapper around the official CISA KEV data.
    The API may be subject to availability or rate limits.
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
            Write-Verbose "--- Querying CISA KEV API: $apiUrl ---"
            $OriginalVerbosePreference = $VerbosePreference
            try {
                $VerbosePreference = 'SilentlyContinue'
                $response = Invoke-RestMethod -Method Get -Uri $apiUrl -ErrorAction Stop
            }
            finally {
                $VerbosePreference = $OriginalVerbosePreference
            }

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
