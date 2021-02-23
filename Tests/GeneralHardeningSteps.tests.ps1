$currentTestsFolder = (Split-Path -Parent $MyInvocation.MyCommand.Path)
BeforeAll{
    $module = 'GeneralHardeningSteps'
    $modulePath = Join-Path -Path (Split-Path -Parent $currentTestsFolder) -ChildPath "CYBRHardeningCheck\bin"
    $moduleContent = Get-Content -Path "$modulePath\$module.psm1"
}

Describe -Tags ('Unit','Acceptance') "$module Module Tests"  {

  Context 'Module Setup' {
    It "has the root module $module.psm1" {
      "$modulePath\$module.psm1" | Should -Exist
    }

    It "has the a manifest file of $module.psd1" {
      "$modulePath\$module.psd1" | Should -Exist
      "$modulePath\$module.psd1" | Should -FileContentMatch "$module.psm1"
    }
    
    It "$module is valid PowerShell code" {
      $psFile = Get-Content -Path "$modulePath\$module.psm1" `
                            -ErrorAction Stop
      $errors = $null
      $null = [System.Management.Automation.PSParser]::Tokenize($psFile, [ref]$errors)
      $errors.Count | Should -Be 0
    }

  } # Context 'Module Setup'

  $moduleFunctions = @('ImportingINFConfiguration',
                    'ValidateServerRoles',
                    'DisableScreenSaver',
                    'AdvancedAuditPolicyConfiguration',
                    'RemoteDesktopServices',
                    'EventLogSizeAndRetention',
                    'RegistryAudits',
                    'RegistryPermissions',
                    'FileSystemPermissions',
                    'FileSystemAudit',
                    'DisableServices'
            )

    $moduleFunctionsContent = $(Get-FunctionDefinition -Path (Join-Path -Path $modulePath -ChildPath "$module.psm1")).Name
    $externalFunctions = $(Get-Module $module).ExportedCommands.Keys
    $internalFunctions = $($moduleFunctionsContent | Where-Object { $_ -NotIn $externalFunctions })
    Context "Test External Functions (from list)" -ForEach $moduleFunctions {
        BeforeEach{
            $function = $_ 
            $filename = ("{0}.{1}.Tests.ps1" -f $module, $function)
            $filePath = Join-Path -Path $currentTestsFolder -ChildPath $filename
        }
        It '<function> should exist in Module file' {
            $function | Should -BeInModule
        }

        It 'Tests file <filename> should exist' {
            $filePath | Should -Exist
        }
    } # Context foreach

    Context "Verify no new External functions" {
        It "There are no additional (undocumented) external functions" {
            ($externalFunctions.Count -eq $moduleFunctions.Count) | Should -Be $true
        }
    }

    Context "Test internal functions" -Foreach $internalFunctions {
        BeforeEach{
            $function = $_ 
            $filename = ("{0}.{1}.Tests.ps1" -f $module, $function)
            $filePath = Join-Path -Path $currentTestsFolder -ChildPath $filename
        }
            It "Test file <filename> should exist" {
                $filePath | Should -Exist
            }
    }
}


function BeInModule($ActualValue, [switch] $Negate)
{
    $funcString = ($moduleContent | Select-String "^Function $ActualValue")
    [bool] $succeeded = $([string]::IsNullOrEmpty($funcString) -ne $true)
    if ($Negate) { $succeeded = -not $succeeded }
    if (-not $succeeded)
    {
        if ($Negate)
        {
            $failureMessage = "{$ActualValue} is not in the module '$module'"
        }
        else
        {
            $failureMessage = "{$ActualValue} is not in the module '$module'"
        }
    }
    return New-Object psobject -Property @{
        Succeeded      = $succeeded
        FailureMessage = $failureMessage
    }
}
Add-AssertionOperator -Name  BeInModule `
                    -Test  $function:BeInModule `
                    -Alias 'BA'

Function Get-FunctionDefinition {
    <#
    .SYNOPSIS
        Gets all the function definitions in the specified files.
    .DESCRIPTION
        Gets all the function definitions (including private functions but excluding nested functions) in the specified PowerShell file.
    
    .PARAMETER Path
        To specify the path of the file to analyze.
    
    .EXAMPLE
        PS C:\> Get-FunctionDefinition -Path C:\GitRepos\MyModule\MyModule.psd1
    
        Gets all function definitions in the module specified by its manifest, as FunctionDefinitionAst objects.
    
    .OUTPUTS
        System.Management.Automation.Language.FunctionDefinitionAst
    
    .NOTES
        PSCodeHealth\0.2.26\Private\Metrics\Get-FunctionDefinition.ps1
    #>
        [CmdletBinding()]
        [OutputType([System.Management.Automation.Language.FunctionDefinitionAst[]])]
        Param (
            [Parameter(Position=0, Mandatory, ValueFromPipeline=$True)]
            [ValidateScript({ Test-Path $_ -PathType Leaf })]
            [string]$Path
        )
        Process {
            $PowerShellFile = (Resolve-Path -Path $Path).Path
            $FileAst = [System.Management.Automation.Language.Parser]::ParseFile($PowerShellFile, [ref]$Null, [ref]$Null)
            
            $AstToInclude = [System.Management.Automation.Language.FunctionDefinitionAst]
            # Excluding class methods, since we don't support classes
            $AstToExclude = [System.Management.Automation.Language.FunctionMemberAst]

            $Predicate = { $args[0] -is $AstToInclude -and $args[0].Parent -isnot $AstToExclude }
            return $FileAst.FindAll($Predicate, $False)
        }
}