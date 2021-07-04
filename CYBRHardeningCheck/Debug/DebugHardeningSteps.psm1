# @FUNCTION@ ======================================================================================================================
# Name...........: Debug_CheckFolder
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Debug_CheckFolder
{
<#
.SYNOPSIS
	Method to query a service status
.DESCRIPTION
	Returns the Status of a Service, Using Get-Service.
.PARAMETER Parameters
	(Optional) Parameters from the Configuration
.PARAMETER Reference Status
	Reference to the Step Status
#>
	param(
		[Parameter(Mandatory=$false)]
		[array]$Parameters = $null,
		[Parameter(Mandatory=$false)]
		[ref]$refOutput
	)

	Begin {
		$res = "Good"
		$tmpStatus = ""
		$myRef = ""
        $DebugFolder = "C:\Temp"
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating Debug folder existence"
			
            If(Test-Path -Path $DebugFolder)
            {
                if((Compare-UserPermissions -path $DebugFolder -identity $(Get-LocalAdministrators) -rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
                {
                    $res = "Warning"
                }
                $tmpStatus += $myRef.Value
            }
            Else
            {
                $res = "Bad"
                $tmpStatus += "Folder $DebugFolder does not exist"
            } 

            
            [ref]$refOutput.Value = $tmpStatus

			Write-LogMessage -Type Info -Msg "Finish validating Debug folder existence"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate Debug folder existence.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate Debug folder existence."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}