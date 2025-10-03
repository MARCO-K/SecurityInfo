<#
.SYNOPSIS
    Retrieves vulnerability information from the ENISA EU Vulnerability Database (EUVD) by CVE ID, EUVD ID, or keyword.

.DESCRIPTION
    This function queries the ENISA EUVD API to find vulnerability details. It can search using three distinct methods:
    1. By the vulnerability's official CVE ID.
    2. By its unique ENISA EUVD ID (e.g., "EUVD-2024-12345").
    3. By a general keyword search across the database.

    The function returns key details such as the EUVD ID, description, publication and modification dates, CVSS score and vector, and vendor information.

.PARAMETER CveId
    The CVE ID (e.g., "2023-12345" or "CVE-2023-12345") to look up in the EUVD.

.PARAMETER EuvdId
    The unique ENISA ID (e.g., "EUVD-2024-12345") to retrieve. The function will prepend 'EUVD-' if it is not already present.

.PARAMETER Keyword
    A keyword to search for vulnerabilities in the ENISA EUVD database.

.EXAMPLE
    Get-Euvd -CveId "2023-12345"
    # Retrieves vulnerability details by its CVE ID.

.EXAMPLE
    Get-Euvd -EuvdId "EUVD-2024-0123"
    # Retrieves vulnerability details for the specific ENISA EUVD ID.

.EXAMPLE
    Get-Euvd -Keyword "openssl"
    # Searches for vulnerabilities related to 'openssl' in the ENISA EUVD database.

.OUTPUTS
    [pscustomobject] containing vulnerability details for each matching entry.

.LINK
    https://euvd.enisa.europa.eu/
    https://euvdservices.enisa.europa.eu/api/docs

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

        [Parameter(Mandatory = $true, ParameterSetName = 'ByEUVDId')]
        [string]$EuvdId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByKeyword')]
        [string]$Keyword

    )

    begin {
        $baseApiUrl = "https://euvdservices.enisa.europa.eu/api/"


        switch ($PSCmdlet.ParameterSetName) {
            'ByCveId' {
                if (-not $CveId.StartsWith('CVE-', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $CveId = "CVE-$CveId"
                }
                $apiUrl = "$($baseApiUrl)enisaid?id=$CveId"
            }
            'ByEUVDId' {
                # Remove CVE- prefix if present, then prepend EUVD-
                if (-not $EuvdId.StartsWith('EUVD-', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $EuvdId = "EUVD-$EuvdId"
                }
                $apiUrl = "$($baseApiUrl)enisaid?id=$EuvdId"
            }
            'ByKeyword' {
                $apiUrl = "$($baseApiUrl)search?text=$Keyword"
            }
        }
    }
    process {
        try {
            Write-Verbose "--- Querying EUVD API: $apiUrl ---"

            $OriginalVerbosePreference = $VerbosePreference
            try {
                $VerbosePreference = 'SilentlyContinue'
                $response = Invoke-RestMethod -Method Get -Uri $apiUrl -ErrorAction Stop
            }
            finally {
                $VerbosePreference = $OriginalVerbosePreference
            }

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
                    EuvdId         = $item.ID
                    Description    = $item.description
                    # Convert dates to [datetime] objects for better usability (sorting, filtering)
                    Published      = if ($item.datePublished) { [datetime]$item.datePublished } else { $null }
                    LastModified   = if ($item.dateUpdated) { [datetime]$item.dateUpdated } else { $null }
                    CVSSScore      = $item.baseScore
                    Vector         = $item.baseScoreVector
                    Vendor         = $item.enisaIdVendor.vendor.Name
                    ProductDetails = foreach ($product in $item.enisaIdProduct) {
                        [pscustomobject]@{
                            ProductName    = $product.product.Name
                            ProductVersion = $product.product_version
                        }
                    }
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
