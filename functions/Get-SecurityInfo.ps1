
function Get-SecurityInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string[]]$CveId
    )

    process {
        foreach ($id in $CveId) {
            $cve = $id
            if (-not $cve.StartsWith('CVE-', [System.StringComparison]::OrdinalIgnoreCase)) {
                $cve = "CVE-$cve"
            }

            $nvdData = Get-NvdCve -CveId $cve -ErrorAction SilentlyContinue
            $cisaData = Get-CisaKev -CveId $cve -ErrorAction SilentlyContinue
            $epssData = Get-EpssScore -CveId $cve -ErrorAction SilentlyContinue
            $exploitDbData = Get-ExploitDb -CveId $cve -ErrorAction SilentlyContinue

            if ($null -eq $nvdData -and $null -eq $cisaData -and $null -eq $epssData -and $null -eq $exploitDbData) {
                Write-Warning "No information found for '$cve' in any of the available sources (NVD, CISA KEV, EPSS, Exploit-DB)."
            }
            else {
                $result = [pscustomobject]@{
                    CveId             = $cve
                    Published         = $nvdData.Published
                    LastModified      = $nvdData.LastModified
                    Status            = $nvdData.Status
                    Severity          = $nvdData.CVSSSeverity
                    CVSSScore         = $nvdData.CVSSBaseScore
                    Description       = $nvdData.Description
                    CISA_KEV          = if ($null -ne $cisaData) { $true } else { $false }
                    EPSS              = if ($null -ne $epssData) { $true } else { $false }
                    ExploitDB         = if ($null -ne $exploitDbData) { $true } else { $false }
                    NVD_Details       = $nvdData
                    EPSS_Details      = $epssData
                    ExploitDB_Details = $exploitDbData
                }
                Write-Output $result
            }
        }
    }
}
