$currentTestsFolder = (Split-Path -Parent $MyInvocation.MyCommand.Path)
BeforeAll{
    $module = 'CommonUtil'
    $function = "Test-Service"
    $modulePath = Join-Path -Path (Split-Path -Parent $currentTestsFolder) -ChildPath "CYBRHardeningCheck\bin"
    # Set the temporary log file path
    $script:LOG_FILE_PATH = (Join-Path -Path $currentTestsFolder -ChildPath "$function-tests.log")
}

# Test functions
Describe -Tags ('Unit') -Name "<function> checks" {
    # Import the module
    Import-Module (Join-Path -Path $modulePath -ChildPath "$module.psd1")
    Context 'Checking existing Services' {    
        $testCases = @(
            @{ ServiceName="Workstation"; ExpectedStatus="Running" }
            @{ ServiceName="Fax"; ExpectedStatus="Stopped" }
        )

        It 'Check Workstation service' -TestCases $testCases{
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