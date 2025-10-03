<#
.SYNOPSIS
    Retrieves Exploit Prediction Scoring System (EPSS) scores from the FIRST.org API.

.DESCRIPTION
    This function queries the official FIRST.org API for EPSS scores, which represent the probability of a vulnerability being exploited in the wild within the next 30 days.
    The function provides multiple ways to query the data: by one or more CVE IDs, by the number of recent days, or by filtering based on EPSS and percentile score thresholds.

.PARAMETER CveId
    An array of one or more CVE IDs (e.g., "2023-12345") to retrieve EPSS scores for. The 'CVE-' prefix is optional.

.PARAMETER Days
    The number of recent days to retrieve EPSS scores for. This returns all CVEs with scores updated in that timeframe.

.PARAMETER EpssGreaterThan
    Filters results to only include vulnerabilities with an EPSS score greater than this value (e.g., 0.5 for 50%).

.PARAMETER EpssLessThan
    Filters results to only include vulnerabilities with an EPSS score less than this value.

.PARAMETER PercentileGreaterThan
    Filters results to only include vulnerabilities with a percentile rank greater than this value (e.g., 0.9 for 90th percentile).

.PARAMETER PercentileLessThan
    Filters results to only include vulnerabilities with a percentile rank less than this value.

.EXAMPLE
    Get-EpssScore -CveId "2023-12345", "2022-5678"
    # Retrieves EPSS scores for the two specified CVEs.

.EXAMPLE
    Get-EpssScore -Days 7
    # Retrieves EPSS scores for all vulnerabilities scored in the last 7 days.

.EXAMPLE
    Get-EpssScore -EpssGreaterThan 0.8
    # Retrieves all vulnerabilities with an EPSS score greater than 80%.

.EXAMPLE
    Get-EpssScore -PercentileGreaterThan 0.95
    # Retrieves vulnerabilities that are in the top 5% of all scored vulnerabilities (95th percentile or higher).

.OUTPUTS
    [pscustomobject]
    Returns a custom object for each vulnerability with the following properties:
    - cveID: The CVE identifier.
    - epssScore: The EPSS score as a [double] (e.g., 0.095).
    - percentile: The percentile rank as a [double] (e.g., 0.93).
    - date: The date the score was calculated.

.LINK
    https://www.first.org/epss/data-and-api

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    The function uses the public FIRST.org EPSS API and may be subject to availability or rate limits.
#>
function Get-EpssScore {
    [CmdletBinding(DefaultParameterSetName = 'ByCveId')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByCveId')]
        [string[]]$CveId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByDays')]
        [int]$Days,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByFilter')]
        [double]$EpssGreaterThan,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByFilter')]
        [double]$EpssLessThan,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByFilter')]
        [double]$PercentileGreaterThan,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByFilter')]
        [double]$PercentileLessThan
    )

    begin {
        $apiUrl = "https://api.first.org/data/v1/epss"
        $params = @{}

        switch ($PSCmdlet.ParameterSetName) {
            'ByCveId' {
                $CveId = $CveId | ForEach-Object {
                    if (-not $_.StartsWith('CVE-', [System.StringComparison]::OrdinalIgnoreCase)) {
                        "CVE-$_"
                    }
                    else {
                        $_
                    }
                }
                $params.cve = $CveId -join ','
                break
            }
            'ByDays' {
                $params.days = $Days
                break
            }
            'ByFilter' {
                if ($PSBoundParameters.ContainsKey('EpssGreaterThan')) {
                    $params.'epss-gt' = $EpssGreaterThan
                }
                if ($PSBoundParameters.ContainsKey('EpssLessThan')) {
                    $params.'epss-lt' = $EpssLessThan
                }
                if ($PSBoundParameters.ContainsKey('PercentileGreaterThan')) {
                    $params.'percentile-gt' = $PercentileGreaterThan
                }
                if ($PSBoundParameters.ContainsKey('PercentileLessThan')) {
                    $params.'percentile-lt' = $PercentileLessThan
                }
                break
            }
        }
    }

    process {
        try {
            Write-Verbose "--- Querying EPSS API: $apiUrl ---"
            $OriginalVerbosePreference = $VerbosePreference
            try {
                $VerbosePreference = 'SilentlyContinue'
                $response = Invoke-RestMethod -Method Get -Uri $apiUrl -Body $params -ErrorAction Stop
            }
            finally {
                $VerbosePreference = $OriginalVerbosePreference
            }

            if ($response.data) {
                foreach ($item in $response.data) {
                    [pscustomobject]@{
                        cveID      = $item.cve
                        epssScore  = [double]$item.epss
                        percentile = [double]$item.percentile
                        date       = [datetime]$item.date
                    }
                }
            }
            else {
                Write-Warning "No EPSS data found for the specified criteria."
                return $null
            }
        }
        catch {
            Write-Error "An error occurred while querying the EPSS API: $_"
            return $null
        }
    }
}
