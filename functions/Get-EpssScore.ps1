<#
.SYNOPSIS
    Retrieves Exploit Prediction Scoring System (EPSS) scores for CVEs from the FIRST EPSS API.

.DESCRIPTION
    This function queries the FIRST EPSS API for vulnerability exploitability scores.
    You can retrieve scores by CVE ID, by recent days, or filter by EPSS score and percentile thresholds.
    Results include CVE ID, EPSS score, percentile, and date.

.PARAMETER CveId
    One or more CVE IDs (e.g., "2023-12345") to retrieve EPSS scores for.

.PARAMETER Days
    The number of recent days to retrieve EPSS scores for.

.PARAMETER EpssGreaterThan
    Filter results to only include vulnerabilities with an EPSS score greater than this value.

.PARAMETER EpssLessThan
    Filter results to only include vulnerabilities with an EPSS score less than this value.

.PARAMETER PercentileGreaterThan
    Filter results to only include vulnerabilities with a percentile greater than this value.

.PARAMETER PercentileLessThan
    Filter results to only include vulnerabilities with a percentile less than this value.

.EXAMPLE
    Get-EpssScore -CveId "2023-12345","2022-5678"
    # Retrieves EPSS scores for the specified CVEs.

.EXAMPLE
    Get-EpssScore -Days 7
    # Retrieves EPSS scores for vulnerabilities from the last 7 days.

.EXAMPLE
    Get-EpssScore -EpssGreaterThan 0.5 -PercentileLessThan 0.9
    # Retrieves vulnerabilities with EPSS score > 0.5 and percentile < 0.9.

.OUTPUTS
    [pscustomobject] containing cveID, epssScore, percentile, and date for each matching entry.

.LINK
    https://www.first.org/epss/

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    The function uses the public FIRST EPSS API and may be subject to availability or rate limits.
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
