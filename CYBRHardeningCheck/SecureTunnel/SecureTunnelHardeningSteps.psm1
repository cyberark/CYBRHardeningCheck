# @FUNCTION@ ======================================================================================================================
# Name...........: SecureTunnel_Permissions
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function SecureTunnel_Permissions
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
        $tunnelFolderLocalAdmins = $true
        $tunnelFolderLocalSystem = $true
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating Privilege Cloud Secure Tunnel Service configuration"
            $tunnelServicesPath = (Get-DetectedComponents -Component "SecureTunnel").Path
            if((Compare-UserPermissions -path $tunnelServicesPath -identity $(Get-LocalAdministrators) -rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
            {
                $tunnelFolderLocalAdmins = $false
                $res = "Warning"
            }
            $tmpStatus += "<li>" + $myRef.Value + "</li>"

            if((Compare-UserPermissions -path $tunnelServicesPath -identity $(Get-LocalSystem) -rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
            {
                $tunnelFolderLocalAdmins = $false
                $res = "Warning"
            }
            $tmpStatus += "<li>" + $myRef.Value + "</li>"
            # Verify if Administrators and System are the only ones that has permissions
            if(($tunnelFolderLocalAdmins -eq $true) -and ($tunnelFolderLocalSystem -eq $true) -and ($tunnelFolderLocalCPMUser -eq $true))
            {
                If((Compare-AmountOfUserPermissions -Path $tunnelServicesPath -amount 2 -outStatus ([ref]$myRef)) -ne "Good")
                {
                    $tmpStatus += "<li>" + $myRef.Value + "</li>"
                    $res = "Warning"
                }
                Else{$tmpStatus += "<li> Permissions are set correctly on the path: " + $tunnelServicesPath + "</li>"}
            }
            Else{
                $tmpStatus += "<li>" + "The permissions need to be reviewed. Permissions are not set correctly for the Local Administrators and the local System user" + "</li>"
                $res = "Warning"
            }
            [ref]$refOutput.Value = "<ul>$tmpStatus</ul>"

            Write-LogMessage -Type Info -Msg "Finish validating Privilege Cloud Secure Tunnel Service configuration"

            return $res
        }
        catch{
            Write-LogMessage -Type "Error" -Msg "Could not validate Privilege Cloud Secure Tunnel Service configuration.  Error: $(Join-ExceptionMessage $_.Exception)"
            [ref]$refOutput.Value = "Could not validate Privilege Cloud Secure Tunnel Service configuration."
            return "Bad"
        }
    }
    End {
        # Write output to HTML
    }
}