@{
    # Script module or binary module file associated with this manifest
    RootModule           = 'SecurityInfo.psm1'

    # Version number of this module.
    ModuleVersion        = '1.0.0'

    # ID used to uniquely identify this module
    GUID                 = 'd3b2e8e1-1234-4e2a-9a1b-abcdef123456'

    # Author of this module
    Author               = 'Marco Kleinert'

    # Company or vendor of this module
    CompanyName          = 'Netz-Weise'

    # Copyright statement for this module
    Copyright            = '(c) 2025 Marco Kleinert. All rights reserved.'

    # Description of the module
    Description          = 'PowerShell module for querying and analyzing security vulnerability data from multiple sources including NVD, CVE.org, CISA KEV, EPSS, Exploit-DB, EU Vulnerability Database, and GitHub Security Advisories.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    # Functions to export from this module
    FunctionsToExport    = @(
        'Get-SecurityInfo',
        'Get-NvdCve',
        'Get-CveOrg',
        'Get-CisaKev',
        'Get-EpssScore',
        'Get-ExploitDb',
        'Get-Euvd',
        'Get-GitHubSecurityAdvisory'
    )

    # Cmdlets to export from this module
    CmdletsToExport      = @()

    # Variables to export from this module
    VariablesToExport    = @()

    # Aliases to export from this module
    AliasesToExport      = @()

    # Private data to pass to the module specified in RootModule
    PrivateData          = @{
        PSData = @{
            # Tags for this module (used for discovery in PowerShell Gallery)
            Tags                 = @('Security', 'CVE', 'Vulnerability', 'NVD', 'CISA', 'EPSS', 'ExploitDB', 'InfoSec', 'ThreatIntel')

            # License URI for this module
            LicenseUri           = 'https://github.com/MARCO-K/SecurityInfo/blob/main/LICENSE'

            # Project URI for this module
            ProjectUri           = 'https://github.com/MARCO-K/SecurityInfo'

            # Icon URI for this module
            # IconUri              = 'https://github.com/MARCO-K/SecurityInfo/raw/main/assets/icon.png'

            # Release notes for this module
            ReleaseNotes         = @'
## 1.0.0 - Initial Release
- Comprehensive vulnerability intelligence aggregation
- Support for 7 major security data sources
- 137 Pester tests with 100% pass rate
- Cross-platform PowerShell 5.1+ compatibility
- Enterprise-ready error handling and logging
'@

            # Additional metadata for PowerShell Gallery
            Prerelease   = ''
            RequireLicenseAcceptance = $false
            ExternalModuleDependencies = @()
        }
    }

    # External module dependencies
    RequiredModules      = @()

    # File list of this module
    FileList             = @(
        'SecurityInfo.psm1',
        'SecurityInfo.psd1',
        'functions/Get-SecurityInfo.ps1',
        'functions/Get-NvdCve.ps1',
        'functions/Get-CveOrg.ps1',
        'functions/Get-CisaKev.ps1',
        'functions/Get-EpssScore.ps1',
        'functions/Get-ExploitDb.ps1',
        'functions/Get-Euvd.ps1',
        'functions/Get-GitHubSecurityAdvisory.ps1'
    )

    # Help info URI
    HelpInfoURI          = 'https://github.com/MARCO-K/SecurityInfo'

    # Default prefix for exported commands
    DefaultCommandPrefix = ''
}
