$currentTestsFolder = (Split-Path -Parent $MyInvocation.MyCommand.Path)
BeforeAll{
    $module = 'CommonUtil'
    $function = "Write-LogMessage"
    $modulePath = Join-Path -Path (Split-Path -Parent $currentTestsFolder) -ChildPath "CYBRHardeningCheck\bin"
    # Set the temporary log file path
    $script:logFilePath = (Join-Path -Path $currentTestsFolder -ChildPath "$function-tests.log")
}

# Test functions
Describe -Tags ('Unit') -Name "<function> checks" {
    # Import the module
    Import-Module (Join-Path -Path $modulePath -ChildPath "$module.psd1")
    Context 'Checking Informational message' {
        Write-LogMessage -Type Info -Msg "Info Message" -LogFile $logFilePath
    
        It 'Check the log file' {
            $logFilePath | Should -Exist
        }
    
        It 'Log file should contain Info message' {
            $logFilePath | Should -FileContentMatch "\[INFO\]\sInfo Message"
        }
    }

    Context 'Checking Warning message' {
        Write-LogMessage -Type Warning -Msg "Warning Message" -LogFile $logFilePath
    
        It 'Log file should contain Warning message' {
            $logFilePath | Should -FileContentMatch "\[WARNING\]\sWarning Message"
        }
    }

    Context 'Checking Error message' {
        Write-LogMessage -Type Error -Msg "Error Message" -LogFile $logFilePath
    
        It 'Log file should contain Error message' {
            $logFilePath | Should -FileContentMatch "\[ERROR\]\sError Message"
        }
    }

    Context 'Checking Success message' {
        Write-LogMessage -Type Success -Msg "Success Message" -LogFile $logFilePath
    
        It 'Log file should contain Success message' {
            $logFilePath | Should -FileContentMatch "\[SUCCESS\]\sSuccess Message"
        }
    }

    Context 'Checking Debug message' {
        Write-LogMessage -Type Debug -Msg "Debug Message" -LogFile $logFilePath -Debug
    
        It 'Log file should contain Debug message' {
            $logFilePath | Should -FileContentMatch "\[DEBUG\]\sDebug Message"
        }
    }

    Context 'Checking Verbose message' {
        Write-LogMessage -Type Verbose -Msg "Verbose Message" -LogFile $logFilePath -Verbose
    
        It 'Log file should contain Verbose message' {
            $logFilePath | Should -FileContentMatch "\[VERBOSE\]\sVerbose Message"
        }
    }

    Context 'Checking no passwords in log file' {
        $testCases = @(
            @{ Message="Logon user=admin password=P@ssw0rd1!"; Password="P@ssw0rd1!" }
            @{ Message="username=admin;password=P@ssw0rd1!"; Password="P@ssw0rd1!" }
            @{ Message="user=admin;secret=P@ssw0rd1!"; Password="P@ssw0rd1!" }
            @{ Message="user=admin;segret=P@ssw0rd1!"; Password="P@ssw0rd1!" } # This test should fail
        )
        
        It 'Log file should not contain the password' -TestCases $testCases {
            param ($message,$password)
            Write-LogMessage -Type Info -Msg $message -LogFile $logFilePath -Verbose
            $logFilePath | Should -Not -FileContentMatch "\[INFO\]\s.*$password$"
        }
    }
}

AfterAll{
    Remove-Module CommonUtil
    If(Test-Path $logFilePath)
    {
        Remove-Item $logFilePath
    }
}