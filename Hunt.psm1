# Module wrapper. hunt.ps1 is the single source of truth so the same file can
# be dot-sourced, iex'd from a URL, or imported as a module.
. "$PSScriptRoot\hunt.ps1"
Export-ModuleMember -Function Invoke-Hunt, Search-HuntEvents, New-HuntQuery, Test-HuntQuery,
    Resolve-HuntSource, ConvertTo-HuntTimeSpan, ConvertFrom-HuntEventXml, New-HuntRecord,
    Show-HuntHelp, Show-HuntSources, Show-HuntPlays, Show-HuntIds, Find-HuntTarget -Alias hunt
