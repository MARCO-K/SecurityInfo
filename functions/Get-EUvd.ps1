<#
.SYNOPSIS
    Retrieves vulnerability information from the ENISA EU Vulnerability Database (EUVD) by ENISA ID or keyword.

.DESCRIPTION
    This function queries the ENISA EUVD API for vulnerability details using either an ENISA ID or a keyword. It returns information such as CVE ID, description, publication date, last modified date, severity, CVSS score, vector, and vendor.

.PARAMETER CveId
    The ENISA ID (e.g., "2023-12345") to retrieve vulnerability details for. The function will prepend 'EUVD-' if not present.

.PARAMETER Keyword
    A keyword to search for vulnerabilities in the ENISA EUVD database.

.EXAMPLE
    Get-Euvd -CveId "2023-12345"
    # Retrieves vulnerability details for ENISA ID 2023-12345.

.EXAMPLE
    Get-Euvd -Keyword "openssl"
    # Searches for vulnerabilities related to 'openssl' in the ENISA EUVD database.

.OUTPUTS
    [pscustomobject] containing vulnerability details for each matching entry.

.LINK
    https://euvd.enisa.europa.eu/

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    The function uses the public ENISA EUVD API and may be subject to availability or rate limits.
#>
function Get-Euvd {

    [CmdletBinding(DefaultParameterSetName = 'ByCveId')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByCveId')]
        [string]$CveId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByKeyword')]
        [string]$Keyword

    )

    begin {
        $baseApiUrl = "https://euvdservices.enisa.europa.eu/api/"


        switch ($PSCmdlet.ParameterSetName) {
            'ByCveId' {
                if (-not $CveId.StartsWith('EUVD-', [System.StringComparison]::OrdinalIgnoreCase)) {
                    # Remove CVE- prefix if present, then prepend EUVD-
                    if ($CveId.StartsWith('CVE-', [System.StringComparison]::OrdinalIgnoreCase)) {
                        $CveId = $CveId.Substring(4)
                    }
                    $CveId = "EUVD-$CveId"
                }
                $apiUrl = "$($baseApiUrl)enisaid?id=$CveId"
            }
            'ByKeyword' {
                $apiUrl = "$($baseApiUrl)search?text=$Keyword"
            }
        }
    }
    process {
        try {
            $response = Invoke-RestMethod -Method Get -Uri $apiUrl -ErrorAction Stop
            Write-Verbose "Querying EUVD API: $apiUrl"

            if ($PSCmdlet.ParameterSetName -eq 'ByCveId' -and -not $response.PSObject.Properties['ID']) {
                Write-Verbose "API returned an empty object for ID '$CveId'. No match found."
                return # Return nothing
            }

            # Determine if the response is a search result (with an .items property) or a direct lookup
            $itemsToProcess = if ($response.PSObject.Properties.Name -contains 'items') {
                $response.items
            }
            else {
                $response
            }

            # If there are no items to process after normalization, return nothing
            if ($null -eq $itemsToProcess) { return }

            $results = foreach ($item in $itemsToProcess) {
                [pscustomobject]@{
                    EuvdId       = $item.ID
                    Description  = $item.description
                    # Convert dates to [datetime] objects for better usability (sorting, filtering)
                    Published    = if ($item.datePublished) { [datetime]$item.datePublished } else { $null }
                    LastModified = if ($item.dateUpdated) { [datetime]$item.dateUpdated } else { $null }
                    Severity     = $item.severity
                    CVSSScore    = $item.baseScore
                    Vector       = $item.baseScoreVector
                    Vendor       = $item.enisaIdVendor.vendor.Name
                }
            }

            # Return the populated array of results
            $results
        }
        catch {
            Write-Error "Failed to retrieve data from EUVD for URI '$apiUrl'. Error: $($_.Exception.Message)"
        }
    }
}
