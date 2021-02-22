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

  $moduleFunctionsContent = $(Get-Content -Path "$modulePath\$module.psm1" | Select-String "^Function *")
  $externalFunctions = $moduleFunctions | ForEach-Object { "Function $_" }
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

Context "Test internal functions" -Foreach $internalFunctions {
    BeforeEach{
        $function = $_ 
        $filename = ("{0}.{1}.Tests.ps1" -f $module, $($function -Replace "Function ",''))
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