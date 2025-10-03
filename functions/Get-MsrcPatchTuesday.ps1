<#
.SYNOPSIS
    Retrieves and summarizes Microsoft Patch Tuesday vulnerabilities for a specific month.

.DESCRIPTION
    This function queries the Microsoft Security Response Center (MSRC) API for a specific month's security updates,
    often referred to as "Patch Tuesday." It provides a summary of the vulnerabilities, including counts by type,
    exploited vulnerabilities, and high-severity issues.

.PARAMETER SecurityUpdate
    The date string for the security update query, in "YYYY-Mmm" format (e.g., "2023-Oct").

.EXAMPLE
    Get-MsrcPatchTuesday -SecurityUpdate "2023-Oct"

    Retrieves and displays the vulnerability summary for October 2023.

.NOTES
    Author: Jules
    Date: October 2025
    API: MSRC API v2.0

.LINK
    https://api.msrc.microsoft.com/cvrf/v2.0
#>
function Get-MsrcPatchTuesday {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SecurityUpdate
    )

    begin {
        # Validate the date format
        if ($SecurityUpdate -notmatch '^\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$') {
            throw "Invalid date format. Please use 'YYYY-Mmm' (e.g., '2023-Oct')."
        }

        $base_url = 'https://api.msrc.microsoft.com/cvrf/v2.0/'
        $headers = @{
            'Accept' = 'application/json'
        }
        $requestUrl = "$($base_url)cvrf/$($SecurityUpdate)"
    }

    process {
        try {
            Write-Verbose "Querying MSRC API for $SecurityUpdate"
            $response = Invoke-RestMethod -Method Get -Uri $requestUrl -Headers $headers -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -match '\(404\) Not Found') {
                Write-Warning "No security update found for '$SecurityUpdate'. It may not be released yet."
            }
            else {
                throw "An error occurred while querying the MSRC API: $($_.Exception.Message)"
            }
            return # Exit the function
        }

        # Store the response for processing in the end block
        $script:PatchTuesdayData = $response
    }

    end {
        if ($null -eq $script:PatchTuesdayData) {
            return
        }

        # Analysis logic
        $all_vulns = $script:PatchTuesdayData.Vulnerability
        $title = $script:PatchTuesdayData.DocumentTitle.Value
        Write-Verbose "Found $($all_vulns.Count) total vulnerabilities in '$title'."

        $vuln_types = @(
            'Elevation of Privilege',
            'Security Feature Bypass',
            'Remote Code Execution',
            'Information Disclosure',
            'Denial of Service',
            'Spoofing',
            'Edge - Chromium'
        )

        $vulnerabilityBreakdown = foreach ($vuln_type in $vuln_types) {
            $count = 0
            foreach ($vuln in $all_vulns) {
                foreach ($threat in $vuln.Threats) {
                    if ($threat.Type -eq 0) { # Impact
                        if ($vuln_type -eq "Edge - Chromium") {
                            if ($threat.ProductID -contains '11655') {
                                $count++
                                break
                            }
                        }
                        elseif ($threat.Description.Value -eq $vuln_type) {
                            if ($threat.ProductID -notcontains '11655') {
                                $count++
                                break
                            }
                        }
                    }
                }
            }
            [pscustomobject]@{ Type = $vuln_type; Count = $count }
        }

        $exploitedInTheWild = foreach ($vuln in $all_vulns) {
            foreach ($threat in $vuln.Threats) {
                if ($threat.Type -eq 1 -and $threat.Description.Value -match 'Exploited:Yes') {
                    [pscustomobject]@{
                        CVE         = $vuln.CVE
                        CVSSScore   = if ($vuln.CVSSScoreSets.Count -gt 0) { $vuln.CVSSScoreSets[0].BaseScore } else { 'N/A' }
                        Title       = $vuln.Title.Value
                    }
                    break
                }
            }
        }

        $exploitationMoreLikely = foreach ($vuln in $all_vulns) {
            foreach ($threat in $vuln.Threats) {
                if ($threat.Type -eq 1 -and $threat.Description.Value -match 'Exploitation More Likely') {
                    [pscustomobject]@{
                        CVE   = $vuln.CVE
                        Title = $vuln.Title.Value
                        Link  = "https://www.cve.org/CVERecord?id=$($vuln.CVE)"
                    }
                    break
                }
            }
        }

        $highSeverityVulns = foreach ($vuln in $all_vulns) {
            if ($vuln.CVSSScoreSets.Count -gt 0 -and $vuln.CVSSScoreSets[0].BaseScore -ge 8.0) {
                [pscustomobject]@{
                    CVE       = $vuln.CVE
                    CVSSScore = $vuln.CVSSScoreSets[0].BaseScore
                    Title     = $vuln.Title.Value
                }
            }
        }

        # --- Final Output ---
        [pscustomobject]@{
            Title                    = $title
            TotalVulnerabilities     = $all_vulns.Count
            VulnerabilityBreakdown   = $vulnerabilityBreakdown
            ExploitedInTheWild       = $exploitedInTheWild
            ExploitationMoreLikely   = $exploitationMoreLikely
            HighSeverityVulnerabilities = $highSeverityVulns
        }

        # Clean up the script-scoped variable
        Remove-Variable -Name PatchTuesdayData -Scope Script -ErrorAction SilentlyContinue
    }
}