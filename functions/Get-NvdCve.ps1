<#
.SYNOPSIS
    Retrieves CVE information from the NVD API based on a keyword, date range, or specific CVE ID.

.DESCRIPTION
    This function queries the National Vulnerability Database (NVD) API 2.0 to fetch CVE details.
    It supports searching by a general keyword, retrieving CVEs published within a recent number of days, or looking up a single CVE by its ID.

    The function automatically determines the best available CVSS score, prioritizing v4.0, then falling back to v3.1.
    Results can be filtered by severity and the total number of records can be limited using the -Top parameter.

.PARAMETER Keyword
    A keyword to search for in the NVD database. The search is performed against the entire CVE record.

.PARAMETER Days
    The number of recent days for which to retrieve published CVEs. The NVD API limits this to a maximum of 120 days.

.PARAMETER CveId
    The specific CVE ID (e.g., "2023-12345" or "CVE-2023-12345") to retrieve.

.PARAMETER Severity
    Filters the results by the specified CVSS severity. Accepted values are LOW, MEDIUM, HIGH, CRITICAL.
    This filter applies to both CVSS v3 and v4 metrics.

.PARAMETER Top
    Limits the number of results returned. The valid range is from 1 to 2000.

.PARAMETER IncludeAffectedSoftware
    If specified, the output object will include two additional properties: 'AffectedVendors' and 'AffectedProducts',
    which are comma-separated strings derived from the CVE's CPE (Common Platform Enumeration) data.

.EXAMPLE
    Get-NvdCve -Keyword "openssl" -Severity "HIGH" -Top 5
    # Retrieves up to 5 HIGH severity CVEs related to "openssl".

.EXAMPLE
    Get-NvdCve -Days 7 -Severity "CRITICAL"
    # Retrieves CRITICAL CVEs published in the last 7 days.

.EXAMPLE
    Get-NvdCve -CveId "2023-12345" -IncludeAffectedSoftware
    # Retrieves details for CVE-2023-12345 and includes its affected software.

.OUTPUTS
    [pscustomobject]
    Returns one or more custom objects with the following properties:
    - CVEID
    - CVSSVersion (e.g., "4.0" or "3.1")
    - CVSSSeverity
    - CVSSBaseScore
    - Description
    - Published (date)
    - LastModified (date)
    - Status
    - CWEIDs (if available)
    - AffectedVendors (if -IncludeAffectedSoftware is used)
    - AffectedProducts (if -IncludeAffectedSoftware is used)

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    API: NVD REST API v2.0
    The NVD API has rate limits. Frequent, rapid requests may result in temporary throttling.

.LINK
    https://nvd.nist.gov/developers/vulnerabilities
#>
function Get-NvdCve {
    [CmdletBinding(DefaultParameterSetName = 'ByKeyword')]
    [OutputType([pscustomobject])]
    [Alias('Get-NvdCveDetails', 'NvdCve')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByKeyword')]
        [string]$Keyword,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByDays')]
        [int]$Days,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByCveId')]
        [string]$CveId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')]
        [string]$Severity,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 2000)]
        [int]$Top,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeAffectedSoftware
    )

    begin {
        $baseApiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        $requestUrl = $baseApiUrl
        $params = [ordered]@{}

        switch ($PSCmdlet.ParameterSetName) {
            'ByKeyword' {
                $params.keywordSearch = $Keyword
            }
            'ByDays' {
                if ($Days -gt 120) {
                    throw "The value for -Days cannot exceed 120."
                }
                $endDateValue = (Get-Date).ToUniversalTime()
                $startDateValue = $endDateValue.AddDays(-$Days)
                $params.pubStartDate = $startDateValue.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                $params.pubEndDate = $endDateValue.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }
            'ByCveId' {
                if (-not $CveId.StartsWith('CVE-', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $CveId = "CVE-$CveId"
                }
                $params.cveId = $CveId
            }
        }

        # --- Add common optional parameters if they were bound ---
        # Add Severity if specified (applies to ByKeyword and ByDays)
        if ($PSBoundParameters.ContainsKey('Severity')) {
            $params.cvssV3Severity = $Severity
        }

        # Add Top/resultsPerPage and startIndex (applies to ByKeyword and ByDays, harmless for ByCveId)
        # We always set startIndex to 0 for simplicity, could be a new parameter for full pagination
        if ($PSBoundParameters.ContainsKey('Top')) {
            $params.resultsPerPage = $Top
            $params.startIndex = 0
        }

        # --- Construct the Query String ---
        # This collects all key=value pairs and joins them with '&'
        $queryString = ($params.GetEnumerator() | ForEach-Object {
                # URL encode both the key and the value to handle any special characters
                $encodedKey = [uri]::EscapeDataString($_.Name)
                $encodedValue = [uri]::EscapeDataString($_.Value)
                "$encodedKey=$encodedValue"
            }) -join '&'

        # --- Combine Base URL and Query String ---
        $requestUrl = "$baseApiUrl`?$queryString"

    }

    process {
        try {
            Write-Verbose "--- Querying NVD API: $requestUrl ---"

            $OriginalVerbosePreference = $VerbosePreference
            try {
                $VerbosePreference = 'SilentlyContinue'
                $response = Invoke-RestMethod -Method Get -Uri $requestUrl -ErrorAction Stop
            }
            finally {
                $VerbosePreference = $OriginalVerbosePreference
            }


            if ($response.totalResults -gt 0) {

                foreach ($vulnerability in $response.vulnerabilities) {
                    $cve = $vulnerability.cve

                    # --- cwe handling ---
                    $cweIds = ($cve.weaknesses.description.value | Where-Object { $_ -like 'CWE-*' }) -join ', '



                    # Initialize variables for severity and score
                    $CVSSSeverity, $baseScore, $cvssVersion = "N/A", "N/A", "N/A"

                    # 1. Prioritize CVSS v4.0
                    if ($cve.metrics.cvssMetricV40 -and $cve.metrics.cvssMetricV40.Count -gt 0) {
                        # Assuming the first metric is the primary one
                        $cvssV40 = $cve.metrics.cvssMetricV40[0]
                        $CVSSSeverity = $cvssV40.cvssData.baseSeverity # BaseSeverity for v4.0
                        $baseScore = $cvssV40.cvssData.baseScore   # BaseScore for v4.0
                        $cvssVersion = "4.0"
                    }
                    # 2. Fall back to CVSS v3.1 if v4.0 is not available
                    elseif ($cve.metrics.cvssMetricV31 -and $cve.metrics.cvssMetricV31.Count -gt 0) {
                        # Assuming the first metric is the primary one
                        $cvssV31 = $cve.metrics.cvssMetricV31[0]
                        $CVSSSeverity = $cvssV31.cvssData.baseSeverity # BaseSeverity for v3.1
                        $baseScore = $cvssV31.cvssData.baseScore   # BaseScore for v3.1
                        $cvssVersion = "3.1"
                    }

                    # --- Output Section ---
                    $cveOutput =
                    [pscustomobject]@{
                        CVEID         = $cve.id
                        CVSSVersion   = $cvssVersion
                        CVSSSeverity  = $CVSSSeverity
                        CVSSBaseScore = $baseScore
                        Description   = $cve.descriptions[0].value
                        Published     = $cve.published
                        LastModified  = $cve.lastModified
                        Status        = $cve.vulnStatus
                        CWEIDs        = $cweIds

                    }
                    # Conditionally add AffectedVendors and AffectedProducts to the output object
                    # --- CRITICAL FIX: Add logic to populate affected software details ---
                    if ($IncludeAffectedSoftware) {
                        $cpeUris = @()
                        # Traverse the complex 'configurations' node to find all CPE URIs
                        if ($cve.configurations) {
                            $cpeUris = $cve.configurations.nodes.cpeMatch.criteria
                        }

                        # From the CPEs, extract unique vendors and products
                        $affectedVendors = $cpeUris | ForEach-Object { $_.Split(':')[3] } | Sort-Object -Unique
                        $affectedProducts = $cpeUris | ForEach-Object { $_.Split(':')[4] } | Sort-Object -Unique

                        $cveOutput | Add-Member -MemberType NoteProperty -Name AffectedVendors -Value ($affectedVendors -join ', ')
                        $cveOutput | Add-Member -MemberType NoteProperty -Name AffectedProducts -Value ($affectedProducts -join ', ')
                    }


                    $cveOutput # Output the final object
                }

            }
            else {
                Write-Warning "No CVEs found for the specified criteria."
            }
        }
        catch {
            Write-Error "An error occurred while querying the NVD API: $_"
        }
    }
}

