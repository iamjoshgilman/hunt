@{
    RootModule        = 'Hunt.psm1'
    ModuleVersion     = '0.2.0'
    GUID              = 'a3f1c6d2-7b48-4e19-9c35-2d8e6f0b41a7'
    Author            = 'Josh Gilman'
    Description       = 'Two-word threat hunting over Windows event logs. hunt sysmon mimikatz.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-Hunt','Search-HuntEvents','Show-HuntHelp','Show-HuntSources',
                          'Show-HuntPlays','Show-HuntIds','Find-HuntTarget')
    AliasesToExport   = @('hunt')
    PrivateData = @{ PSData = @{
        Tags       = @('security','dfir','threat-hunting','sysmon','eventlog','blueteam','ctf')
        ProjectUri = 'https://github.com/iamjoshgilman/hunt'
    }}
}
