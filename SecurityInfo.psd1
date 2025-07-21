@{
    # Script module or binary module file associated with this manifest
    RootModule           = 'SecurityInfo.psm1'

    # Version number of this module.
    ModuleVersion        = '0.9.9'

    # ID used to uniquely identify this module
    GUID                 = 'd3b2e8e1-1234-4e2a-9a1b-abcdef123456'

    # Author of this module
    Author               = 'Marco Kleinert'

    # Company or vendor of this module
    CompanyName          = 'Netz-Weise'

    # Description of the module
    Description          = 'PowerShell module for querying and analyzing security vulnerability data from NVD, CISA KEV, Exploit-DB, and FIRST EPSS.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    # Functions to export from this module
    FunctionsToExport    = '*'

    # Cmdlets to export from this module
    CmdletsToExport      = @()

    # Variables to export from this module
    VariablesToExport    = @()

    # Aliases to export from this module
    AliasesToExport      = @()

    # Private data to pass to the module specified in RootModule
    PrivateData          = @{}

    # External module dependencies
    RequiredModules      = @()

    # File list of this module
    FileList             = @('SecurityInfo.psm1')

    # Help info URI
    HelpInfoURI          = 'https://github.com/marco-k/SecurityInfo'


    # Default prefix for exported commands
    DefaultCommandPrefix = ''
}
