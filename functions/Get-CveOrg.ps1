<#
.SYNOPSIS
    Retrieves the official CVE record from the cve.org API.

.DESCRIPTION
    This function queries the CVE Services API (cve.org) for the authoritative record of a specific CVE ID.
    This is the direct source of information from the CVE Numbering Authority (CNA) and is often the first place a new CVE's details are published.

.PARAMETER CveId
    The CVE ID (e.g., "2023-12345" or "CVE-2023-12345") to retrieve.

.EXAMPLE
    Get-CveOrg -CveId "CVE-2024-0078"

    Retrieves the official record for CVE-2024-0078.

.EXAMPLE
    "2024-21501" | Get-CveOrg

    Retrieves the record for CVE-2024-21501 using pipeline input.

.OUTPUTS
    [pscustomobject] containing the official CVE record details.

.LINK
    https://www.cve.org/AllResources/CveServices
    https://cveawg.mitre.org/api-docs/

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    This function uses the public CVE Services API and may be subject to rate limits.
#>
function Get-CveOrg {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$CveId
    )

    process {
        if (-not $CveId.StartsWith('CVE-', [System.StringComparison]::OrdinalIgnoreCase)) {
            $CveId = "CVE-$CveId"
        }

        $apiUrl = "https://cveawg.mitre.org/api/cve/$CveId"
        Write-Verbose "Querying CVE.org API: $apiUrl"

        try {
            $response = Invoke-RestMethod -Method Get -Uri $apiUrl -ErrorAction Stop

            $cnaContainer = $response.containers.cna

            # Safely get the title
            $title = if ($cnaContainer.title) { $cnaContainer.title } else { 'N/A' }

            # Safely find the primary US English description
            $description = 'N/A'
            if ($cnaContainer.descriptions) {
                $enDescription = $cnaContainer.descriptions | Where-Object { $_.lang -eq 'en-US' } | Select-Object -First 1
                if ($enDescription) {
                    $description = $enDescription.value
                }
            }

            # Safely extract affected products
            $affectedProducts = @()
            if ($cnaContainer.affected) {
                $affectedProducts = $cnaContainer.affected.product
            }

            # Format the output object
            [pscustomobject]@{
                CVEID            = $response.cveMetadata.cveId
                Title            = $title
                State            = $response.cveMetadata.state
                AssigningCNA     = $response.cveMetadata.assignerShortName
                DatePublished    = $response.cveMetadata.datePublished
                DateUpdated      = $response.cveMetadata.dateUpdated
                Description      = $description
                AffectedProducts = $affectedProducts
                BaseScore        = $cnaContainer.metrics.cvssV3_1.baseScore
                BaseSeverity     = $cnaContainer.metrics.cvssV3_1.baseSeverity
                References       = $cnaContainer.references
            }
        }
        catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            if ($_.Exception.Response.StatusCode -eq 'NotFound') {
                Write-Warning "CVE record for '$CveId' not found on cve.org."
            }
            else {
                Write-Error "An API error occurred while querying cve.org: $($_.Exception.Message)"
            }
        }
        catch {
            Write-Error "An unexpected error occurred: $_"
        }
    }
}
