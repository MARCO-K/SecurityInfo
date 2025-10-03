<#
.SYNOPSIS
    Retrieves GitHub Security Advisory details by CVE or GHSA ID.

.DESCRIPTION
    This function queries the GitHub GraphQL API to fetch detailed information about a specific security advisory.
    It can identify the advisory using either a CVE ID or a GHSA (GitHub Security Advisory) ID.

    Authentication is required. The function uses a GitHub Personal Access Token (PAT).
    You must either provide the token via the -Token parameter or have it set in the $env:GITHUB_PAT environment variable.

.PARAMETER CveId
    The Common Vulnerabilities and Exposures (CVE) ID to search for (e.g., "CVE-2023-12345").
    If the 'CVE-' prefix is omitted, it will be added automatically.

.PARAMETER GhsaId
    The GitHub Security Advisory ID (e.g., "GHSA-xxxx-xxxx-xxxx") to retrieve directly.

.PARAMETER Token
    A GitHub Personal Access Token (PAT) used to authenticate with the GitHub GraphQL API.
    If not provided, the function will attempt to use the value from the $env:GITHUB_PAT environment variable.

.EXAMPLE
    Get-GitHubSecurityAdvisory -CveId "2023-12345"
    # Retrieves the GitHub Security Advisory associated with CVE-2023-12345.

.EXAMPLE
    Get-GitHubSecurityAdvisory -GhsaId "GHSA-abcd-1234-efgh"
    # Retrieves the advisory with the specified GHSA ID.

.EXAMPLE
    $myToken = "ghp_..."
    Get-GitHubSecurityAdvisory -CveId "2023-12345" -Token $myToken
    # Retrieves the advisory using a token provided directly as a parameter.

.OUTPUTS
    [pscustomobject]
    Returns a single custom object containing the full details of the security advisory, including:
    - GhsaId, Summary, Description, Severity, Permalink
    - Dates (Published, Updated, Withdrawn)
    - CVSS score and vector
    - A list of associated CWEs
    - Details on vulnerable packages, version ranges, and patched versions.
    If no advisory is found, it returns $null.

.LINK
    https://docs.github.com/en/graphql/explorer
    https://docs.github.com/en/code-security/security-advisories/about-github-security-advisories

.NOTES
    Author: Marco Kleinert
    Date: July 2025
    A GitHub PAT with the 'security_events' scope may be required for accessing some security advisory data.
#>
function Get-GitHubSecurityAdvisory {
    [CmdletBinding(DefaultParameterSetName = 'ByCveId')]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [string]$Token = $env:GITHUB_PAT,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByCveId')]
        [string]$CveId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByGhsaId')]
        [string]$GhsaId
    )

    begin {
        if ([string]::IsNullOrEmpty($Token)) {
            throw "GitHub PAT not found in environment variable `$env:GITHUB_PAT"
        }
        $headers = @{
            "Authorization" = "bearer $Token"
            "Content-Type"  = "application/json"
        }
        $uri = "https://api.github.com/graphql"
        # validate the CveId or GhsaId format
        switch ($PSCmdlet.ParameterSetName) {
            'ByCveId' {
                if (-not $CveId.StartsWith('CVE-', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $CveId = "CVE-$CveId"
                }
                $identifierType = 'CVE'
                $identifierValue = $CveId
            }
            'ByGhsaId' {
                $identifierType = 'GHSA'
                $identifierValue = $GhsaId
            }
        }
        # Write-Verbose "Querying GitHub for advisory with Identifier Type: $($identifierType), Value: $($identifierValue)"
    }

    process {
        # This query is now expanded to include the new, valuable fields
        $query = @"
query {
    securityAdvisories(identifier: {type: $IdentifierType, value: `"$IdentifierValue`"}, first: 1) {
        nodes {
            ghsaId
            summary
            description
            severity
            permalink
            publishedAt
            updatedAt
            withdrawnAt
            origin
            cvss {
                score
                vectorString
            }
            cwes(first: 5) {
                nodes {
                    cweId
                    name
                }
            }
            identifiers {
                type
                value
            }
            vulnerabilities(first: 10) {
                nodes {
                    package {
                        ecosystem
                        name
                    }
                    vulnerableVersionRange
                    firstPatchedVersion {
                        identifier
                    }
                }
            }
        }
    }
}
"@

        $body = @{ query = $query } | ConvertTo-Json

        try {
            Write-Verbose "--- Querying GitHub API: $uri ---"

            $OriginalVerbosePreference = $VerbosePreference
            try {
                $VerbosePreference = 'SilentlyContinue'
                $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body
            }
            finally {
                $VerbosePreference = $OriginalVerbosePreference
            }

            $advisoryNode = $response.data.securityAdvisories.nodes[0]

            if ($null -eq $advisoryNode) {
                Write-Verbose "No GitHub Security Advisory found for $identifierValue"
                return $null
            }

            # Create a clean, useful PowerShell object from the response
            $GHData =
            [pscustomobject]@{
                GhsaId          = $advisoryNode.ghsaId
                Summary         = $advisoryNode.summary
                Description     = $advisoryNode.description
                Severity        = $advisoryNode.severity
                Permalink       = $advisoryNode.permalink
                PublishedAt     = $advisoryNode.publishedAt
                UpdatedAt       = $advisoryNode.updatedAt
                WithdrawnAt     = $advisoryNode.withdrawnAt
                Origin          = $advisoryNode.origin
                AllIdentifiers  = $advisoryNode.identifiers # Useful for seeing all linked IDs
                Vulnerabilities = foreach ($vuln in $advisoryNode.vulnerabilities.nodes) {
                    [pscustomobject]@{
                        Ecosystem      = $vuln.package.ecosystem
                        PackageName    = $vuln.package.name
                        VersionRange   = $vuln.vulnerableVersionRange
                        PatchedVersion = $vuln.firstPatchedVersion.identifier
                    }
                }
                CVSSScore       = $advisoryNode.cvss.score
                CVSSVector      = $advisoryNode.cvss.vectorString
            }
            # if cveId was provided, add it to the object
            if ($PSCmdlet.ParameterSetName -eq 'ByCveId') {
                $GHData | Add-Member -MemberType NoteProperty -Name CveId -Value $CveId
            }
            if ($null -ne $advisoryNode.cwes -and $null -ne $advisoryNode.cwes.nodes -and $advisoryNode.cwes.nodes.Count -gt 0) {
                $GHData | Add-Member -MemberType NoteProperty -Name CWEs -Value (@(
                        foreach ($cwe in $advisoryNode.cwes.nodes) {
                            [pscustomobject]@{
                                CweId = $cwe.cweId
                                Name  = $cwe.name
                            }
                        }
                    ))
            }
            $GHData
        }
        catch {
            # Provide the detailed error message from GitHub, with null check fallback
            $errorDetail = $null
            if ($_.Exception.Response -and ($_.Exception.Response -is [System.Net.WebResponse])) {
                try {
                    $errorDetail = $_.Exception.Response.GetResponseStream() | New-Object System.IO.StreamReader | ForEach-Object { $_.ReadToEnd() }
                }
                catch {
                    # If we can't read the response stream, fall back to the basic exception message
                    Write-Verbose "Could not read response stream: $($_.Exception.Message)"
                }
            }
            if (-not $errorDetail) {
                $errorDetail = $_.Exception.Message
            }
            Write-Error "Failed to retrieve data from GitHub GraphQL API. Details: $errorDetail"
        }
    }
}
