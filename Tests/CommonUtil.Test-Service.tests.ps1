$currentTestsFolder = (Split-Path -Parent $MyInvocation.MyCommand.Path)
BeforeDiscovery{   
    $module = 'CommonUtil'
    $function = "Test-Service"
    $modulePath = Join-Path -Path (Split-Path -Parent $currentTestsFolder) -ChildPath "CYBRHardeningCheck\bin"
    # Set the temporary log file path
    $script:LOG_FILE_PATH = (Join-Path -Path $currentTestsFolder -ChildPath "$function-tests.log")
    # Import the module
    Import-Module (Join-Path -Path $modulePath -ChildPath "$module.psd1")

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
}

# Run only for internal Functions
if(-not $(Get-Module $module).ExportedFunctions.Keys.Contains($function))
{
    $functionBody = $(Get-FunctionDefinition -Path (Join-Path -Path $modulePath -ChildPath "$module.psm1") | Where-Object { $_.Name -eq $function}).Body
    If($null -ne $functionBody)
    {
        Invoke-Expression -Command $functionBody.Parent
    }
}


# Test functions
Describe -Tags ('Unit') -Name "<function> checks" {
    Context 'Checking existing Services' {    
        $testCases = @(
            @{ ServiceName="Workstation"; ExpectedStatus="Running" }
            @{ ServiceName="Fax"; ExpectedStatus="Stopped" }
        )

        It "Check <ServiceName> service" -TestCases $testCases{
            param($ServiceName, $ExpectedStatus)
            Test-Service -ServiceName $ServiceName -Debug -Verbose | Should -Be $ExpectedStatus
        }
    
        It 'Log file should contain Service status' -TestCases $testCases{
            param($ServiceName, $ExpectedStatus)
            $LOG_FILE_PATH | Should -FileContentMatch "$ServiceName Service Status is: $ExpectedStatus"
        }
    }

    Context 'Check non-existing service' {
        It 'Service does not exist' {
            Test-Service -ServiceName "NoService" -Debug -Verbose | Should -Be $null
        }

        It 'Check log for errors' {
            $LOG_FILE_PATH | Should -FileContentMatch "\[ERROR\].*"
        }
    }
}

AfterAll{
    Remove-Module CommonUtil
    If(Test-Path $LOG_FILE_PATH)
    {
        Remove-Item $LOG_FILE_PATH
    }
}