# Get the directory of the current script
$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

# Find all .ps1 files in the 'functions' subdirectory
$FunctionFiles = Get-ChildItem -Path "$PSScriptRoot\functions" -Filter "*.ps1" -Recurse

# Dot-source each function file to make the functions available in the module's scope
foreach ($File in $FunctionFiles) {
    . $File.FullName
}

# Export only public functions (those with comment-based help and not marked as private)
$publicFunctions = $FunctionFiles | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($content -match '<#.*\.SYNOPSIS.*#>') {
        $_.BaseName
    }
} | Where-Object { $_ -ne $null }

Export-ModuleMember -Function $publicFunctions
