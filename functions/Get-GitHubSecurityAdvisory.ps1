<#
.SYNOPSIS
    Retrieves GitHub Security Advisory details by CVE or GHSA ID.

.DESCRIPTION
    Queries the GitHub GraphQL API for security advisories using either a CVE or GHSA identifier.
    Returns one or more advisories, depending on the Count parameter. Requires a GitHub Personal Access Token (PAT) in the $env:GITHUB_PAT environment variable.

.PARAMETER CveId
    The CVE ID (e.g., "2023-12345") to search for.

.PARAMETER GhsaId
    The GitHub Security Advisory ID (e.g., "GHSA-xxxx-xxxx-xxxx") to search for.

.PARAMETER Token
    The GitHub Personal Access Token (PAT) to use for authentication. Defaults to $env:GITHUB_PAT.


.EXAMPLE
    Get-GitHubSecurityAdvisory -CveId "2023-12345"

.EXAMPLE
    Get-GitHubSecurityAdvisory -GhsaId "GHSA-xxxx-xxxx-xxxx"

.EXAMPLE
    Get-GitHubSecurityAdvisory -CveId "2023-12345"
    # Returns up to 5 advisories for the given CVE ID.

.OUTPUTS
    [pscustomobject] with advisory details. If multiple advisories are found, an array of objects is returned.

.LINK
    https://docs.github.com/en/graphql
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
