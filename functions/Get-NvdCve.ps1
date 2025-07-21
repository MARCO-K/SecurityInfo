<#
.SYNOPSIS
    Retrieves CVE information from the NVD API based on keyword, days, or CVE ID.

.DESCRIPTION
    This function queries the National Vulnerability Database (NVD) API for CVEs using a keyword, a date range, or a specific CVE ID.
    You can filter by severity, limit the number of results, and optionally include affected software details.

.PARAMETER Keyword
    Search for CVEs containing the specified keyword.

.PARAMETER Days
    Retrieve CVEs published in the last N days (maximum 120).

.PARAMETER CveId
    Retrieve details for a specific CVE ID (e.g., "2023-12345").

.PARAMETER Severity
    Filter results by CVSS v3/v4 severity: LOW, MEDIUM, HIGH, or CRITICAL.

.PARAMETER Top
    Limit the number of results returned (1-2000).

.PARAMETER IncludeAffectedSoftware
    If specified, includes affected vendors and products in the output.

.EXAMPLE
    Get-NvdCve -Keyword "openssl" -Severity "HIGH" -Top 5

    Retrieves up to 5 HIGH severity CVEs related to "openssl".

.EXAMPLE
    Get-NvdCve -Days 7 -Severity "CRITICAL"

    Retrieves CRITICAL CVEs published in the last 7 days.

.EXAMPLE
    Get-NvdCve -CveId "2023-12345"

    Retrieves details for CVE-2023-12345.

.EXAMPLE
    Get-NvdCve -Keyword "windows" -IncludeAffectedSoftware

    Retrieves CVEs related to "windows" and includes affected vendors/products.

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    API: NVD REST API v2.0

.LINK
    https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

    This function is part of the NVD PowerShell module.
    Ensure you have the required permissions to access the NVD API.
    The API has rate limits; avoid excessive requests in a short time.
#>
function Get-NvdCve
{
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

    begin
    {
        $baseApiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        $requestUrl = $baseApiUrl
        $params = @{}

        switch ($PSCmdlet.ParameterSetName)
        {
            'ByKeyword'
            {
                $params.keywordSearch = $Keyword
            }
            'ByDays'
            {
                if ($Days -gt 120)
                {
                    throw "The value for -Days cannot exceed 120."
                }
                $endDateValue = (Get-Date).ToUniversalTime()
                $startDateValue = $endDateValue.AddDays(-$Days)
                $params.pubStartDate = $startDateValue.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                $params.pubEndDate = $endDateValue.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }
            'ByCveId'
            {
                #$requestUrl = "$baseApiUrl`?cveId=CVE-$CveId"
                $params.cveId = "CVE-$CveId"

            }
        }

        # --- Add common optional parameters if they were bound ---
        # Add Severity if specified (applies to ByKeyword and ByDays)
        if ($PSBoundParameters.ContainsKey('Severity'))
        {
            $params.cvssV3Severity = $Severity
        }

        # Add Top/resultsPerPage and startIndex (applies to ByKeyword and ByDays, harmless for ByCveId)
        # We always set startIndex to 0 for simplicity, could be a new parameter for full pagination
        $params.resultsPerPage = $Top
        $params.startIndex = 0

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


        Write-Verbose "Final Request URL: $requestUrl"


    }

    process
    {
        try
        {

            $response = Invoke-RestMethod -Method Get -Uri $requestUrl

            if ($response.vulnerabilities)
            {
                foreach ($vulnerability in $response.vulnerabilities)
                {
                    $cve = $vulnerability.cve

                    # --- cwe handling ---
                    if ($cve.weaknesses -and $cve.weaknesses.Count -gt 0)
                    {
                        $cweIDs =
                        foreach ($weakness in $cve.weaknesses)
                        {
                            if ($weakness.description -and $weakness.description.Count -gt 0)
                            {
                                # Assuming the first description value is the CWE ID (e.g., "CWE-89")
                                $cweIdText = $weakness.description[0].value
                                # Extract just the "CWE-XXX" part using regex if needed, or take as is
                                if ($cweIdText -match '^(CWE-\d+)$')
                                {
                                    $Matches[1] # Add the extracted CWE ID (e.g., "CWE-89")
                                }
                            }
                        }
                    }


                    # Initialize variables for severity and score
                    $CVSSSeverity = "N/A"
                    $baseScore = "N/A"
                    $cvssVersion = "N/A"

                    # 1. Prioritize CVSS v4.0
                    if ($cve.metrics.cvssMetricV40 -and $cve.metrics.cvssMetricV40.Count -gt 0)
                    {
                        # Assuming the first metric is the primary one
                        $cvssV40 = $cve.metrics.cvssMetricV40[0]
                        $CVSSSeverity = $cvssV40.cvssData.baseSeverity # BaseSeverity for v4.0
                        $baseScore = $cvssV40.cvssData.baseScore   # BaseScore for v4.0
                        $cvssVersion = "4.0"
                    }
                    # 2. Fall back to CVSS v3.1 if v4.0 is not available
                    elseif ($cve.metrics.cvssMetricV31 -and $cve.metrics.cvssMetricV31.Count -gt 0)
                    {
                        # Assuming the first metric is the primary one
                        $cvssV31 = $cve.metrics.cvssMetricV31[0]
                        $CVSSSeverity = $cvssV31.cvssData.baseSeverity # BaseSeverity for v3.1
                        $baseScore = $cvssV31.cvssData.baseScore   # BaseScore for v3.1
                        $cvssVersion = "3.1"
                    }

                    $originalCveId = $cve.id

                    # If you need to remove "CVE-" for some other purpose
                    $processedCveId = if ($originalCveId.StartsWith("CVE-"))
                    {
                        $originalCveId.Replace("CVE-", "")
                    }
                    else
                    {
                        $originalCveId
                    }

                    # --- Conditionally initialize for Affected Software/Vendors ---
                    $affectedVendors = $null # Initialize as $null or empty string if not included
                    $affectedProducts = $null # Initialize as $null or empty string if not included

                    if ($IncludeAffectedSoftware)
                    {
                        # Only run this block if -IncludeAffectedSoftware is used
                        # Use generic lists for better performance and predictable behavior when adding items in a loop
                        $tempVendors = [System.Collections.Generic.List[string]]::new()
                        $tempProducts = [System.Collections.Generic.List[string]]::new()
                        $cpeUris = [System.Collections.Generic.List[string]]::new()

                        if ($cve.configurations -and $cve.configurations.nodes -and $cve.configurations.nodes.Count -gt 0)
                        {
                            Write-Verbose "Found $($cve.configurations.nodes.Count) configuration nodes."
                            foreach ($node in $cve.configurations.nodes)
                            {
                                if ($node.cpeMatch -and $node.cpeMatch.Count -gt 0)
                                {
                                    foreach ($cpeMatch in $node.cpeMatch)
                                    {
                                        if ($cpeMatch.vulnerable -eq $true -and $cpeMatch.criteria)
                                        {
                                            Write-Verbose "    Processing CPE Match: vulnerable=$($cpeMatch.vulnerable), criteria='$($cpeMatch.criteria)'"
                                            $cpeUri = $cpeMatch.criteria
                                            $cpeUris += $cpeUri

                                            $cpeParts = $cpeUri.Split(':')
                                            $vendor = "Unknown"
                                            $product = "Unknown"

                                            if ($cpeParts.Length -ge 5 -and $cpeParts[1] -eq "2.3")
                                            {
                                                $vendor = $cpeParts[3]
                                                $product = $cpeParts[4]
                                            }
                                            elseif ($cpeParts.Length -ge 4 -and $cpeParts[1].StartsWith("/"))
                                            {
                                                $vendor = $cpeParts[2]
                                                $product = $cpeParts[3]
                                            }
                                            else
                                            {
                                                Write-Verbose "Could not parse standard CPE URI format for: '$cpeUri'"
                                            }

                                            # Check if vendor is valid and not already in the list
                                            if (-not [string]::IsNullOrWhiteSpace($vendor) -and $vendor -ne '-' -and $vendor -ne 'Unknown')
                                            {
                                                if (-not $tempVendors.Contains($vendor))
                                                {
                                                    # Use .Contains() for List[string]
                                                    $tempVendors.Add($vendor)
                                                }
                                            }
                                            # Check if product is valid and not already in the list
                                            if (-not [string]::IsNullOrWhiteSpace($product) -and $product -ne '-' -and $product -ne 'Unknown')
                                            {
                                                if (-not $tempProducts.Contains($product))
                                                {
                                                    # Use .Contains() for List[string]
                                                    $tempProducts.Add($product)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        # Assign the collected unique lists to the output variables
                        $affectedVendors = $tempVendors
                        $affectedProducts = $tempProducts
                    }
                    # --- End Conditional Section --

                    # --- Output Section ---
                    $cveOutput =
                    [pscustomobject]@{
                        CVEID         = $processedCveId
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
                    if ($IncludeAffectedSoftware)
                    {
                        $cveOutput | Add-Member -MemberType NoteProperty -Name AffectedVendors -Value $affectedVendors -Force
                        $cveOutput | Add-Member -MemberType NoteProperty -Name AffectedProducts -Value $affectedProducts -Force
                        $cveOutput | Add-Member -MemberType NoteProperty -Name FullCPEURIs -Value ($cpeUris -join ', ')
                    }
                    $cveOutput # Output the final object
                }

            }
            else
            {
                Write-Warning "No CVEs found for the specified criteria."
            }
        }
        catch
        {
            Write-Error "An error occurred while querying the NVD API: $_"
        }
    }
}

