$currentTestsFolder = (Split-Path -Parent $MyInvocation.MyCommand.Path)
$module = 'CommonUtil'
$function = "Write-LogMessage"
$modulePath = Join-Path -Path (Split-Path -Parent $currentTestsFolder) -ChildPath "CYBRHardeningCheck\bin"
# Set the temporary log file path
$script:LOG_FILE_PATH = (Join-Path -Path $currentTestsFolder -ChildPath "$function-tests.log")

# Test functions
Describe -Tags ('Unit') -Name "<function> checks" {
    # Import the module
    Import-Module (Join-Path -Path $modulePath -ChildPath "$module.psd1")
    Context 'Checking Informational message' {
        Write-LogMessage -Type Info -Msg "Info Message" -LogFile $LOG_FILE_PATH
    
        It 'Check the log file' {
            $LOG_FILE_PATH | Should -Exist
        }
    
        It 'Log file should contain Info message' {
            $LOG_FILE_PATH | Should -FileContentMatch "\[INFO\]\sInfo Message"
        }
    }

    Context 'Checking Warning message' {
        Write-LogMessage -Type Warning -Msg "Warning Message" -LogFile $LOG_FILE_PATH
    
        It 'Log file should contain Warning message' {
            $LOG_FILE_PATH | Should -FileContentMatch "\[WARNING\]\sWarning Message"
        }
    }

    Context 'Checking Error message' {
        Write-LogMessage -Type Error -Msg "Error Message" -LogFile $LOG_FILE_PATH
    
        It 'Log file should contain Error message' {
            $LOG_FILE_PATH | Should -FileContentMatch "\[ERROR\]\sError Message"
        }
    }

    Context 'Checking Success message' {
        Write-LogMessage -Type Success -Msg "Success Message" -LogFile $LOG_FILE_PATH
    
        It 'Log file should contain Success message' {
            $LOG_FILE_PATH | Should -FileContentMatch "\[SUCCESS\]\sSuccess Message"
        }
    }

    # Context 'Checking Debug message' {
    #     Write-LogMessage -Type Debug -Msg "Debug Message" -LogFile $LOG_FILE_PATH -Debug
    
    #     It 'Log file should contain Debug message' {
    #         $LOG_FILE_PATH | Should -FileContentMatch "\[DEBUG\]\sDebug Message"
    #     }
    # }

    Context 'Checking Verbose message' {
        Write-LogMessage -Type Verbose -Msg "Verbose Message" -LogFile $LOG_FILE_PATH -Verbose
    
        It 'Log file should contain Verbose message' {
            $LOG_FILE_PATH | Should -FileContentMatch "\[VERBOSE\]\sVerbose Message"
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
            Write-LogMessage -Type Info -Msg $message -LogFile $LOG_FILE_PATH -Verbose
            $LOG_FILE_PATH | Should -Not -FileContentMatch "\[INFO\]\s.*$password$"
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