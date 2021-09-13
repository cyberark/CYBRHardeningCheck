# @FUNCTION@ ======================================================================================================================
# Name...........: CPM_Password_Manager_Services_LocalUser
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function CPM_Password_Manager_Services_LocalUser
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
        $CPMFolderLocalAdmins = $true
        $CPMFolderLocalSystem = $true
        $CPMFolderLocalCPMUser = $true
		$CPMServiceName = "CyberArk Password Manager"
		$ScannerServiceName = "CyberArk Central Policy Manager Scanner"
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating CPM Service configuration"
			$CPMServiceUserName = $($Parameters | Where-Object Name -eq "CPMServiceUserName").Value

			# Get the CPM working directories
			$cpmServicesPath = (Get-DetectedComponents -Component "CPM").Path
			$drive = Split-Path -Path $cpmServicesPath -Qualifier
            $python27Path = Join-Path -Path $drive -ChildPath "Python27"
            $oraclePath = Join-Path -Path $drive -ChildPath "oracle"

			if((Test-ServiceRunWithLocalUser -serviceName $CPMServiceName -userName $CPMServiceUserName -outStatus ([ref]$myRef)) -ne "Good")
			{
				$res = "Warning"
			}
			$tmpStatus += "<li>" + $myRef.Value + "</li>"

			if((Test-ServiceRunWithLocalUser -serviceName $ScannerServiceName -userName $CPMServiceUserName -outStatus ([ref]$myRef)) -ne "Good")
			{
				$res = "Warning"
			}
			$tmpStatus += "<li>" + $myRef.Value + "</li>"

			if((Compare-UserPermissions -path $cpmServicesPath -identity $(Get-LocalAdministrators) -rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
			{
                $CPMFolderLocalAdmins = $false
				$res = "Warning"
			}
			$tmpStatus += "<li>" + $myRef.Value + "</li>"

			if((Compare-UserPermissions -path $cpmServicesPath -identity $(Get-LocalSystem) -rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
			{
	            $CPMFolderLocalSystem = $false
    	        $res = "Warning"
			}
            $tmpStatus += "<li>" + $myRef.Value + "</li>"

			if((Compare-UserPermissions -path $cpmServicesPath -identity $CPMServiceUserName -rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
			{
			    $CPMFolderLocalCPMUser = $false
				$res = "Warning"
			}
            $tmpStatus += "<li>" + $myRef.Value + "</li>"
			If(Test-Path $python27Path)
			{
				# Check Python only if exists
				if((Compare-UserPermissions -path $python27Path -identity $CPMServiceUserName -rights "ReadAndExecute" -outStatus ([ref]$myRef)) -ne "Good")
				{
					$res = "Warning"
				}
				$tmpStatus += "<li>" + $myRef.Value + "</li>"
			}
			If(Test-Path $oraclePath)
			{
				# Check Oracle Client only if exists
				if((Compare-UserPermissions -path $oraclePath -identity $CPMServiceUserName -rights "ReadAndExecute" -outStatus ([ref]$myRef)) -ne "Good")
				{
					$res = "Warning"
				}
				$tmpStatus += "<li>" + $myRef.Value + "</li>"
			}

			# Verify if Administrators, System and the CPM User are the only ones that has permissions
            if(($CPMFolderLocalAdmins -eq $true) -and ($CPMFolderLocalSystem -eq $true) -and ($CPMFolderLocalCPMUser -eq $true))
            {
                If((Compare-AmountOfUserPermissions -Path $cpmServicesPath -amount 3 -outStatus ([ref]$myRef)) -ne "Good")
			    {
		        	$tmpStatus += "<li>" + $myRef.Value + "</li>"
				    $res = "Warning"
			    }
			    Else{$tmpStatus += "<li> Permissions are set correctly on the path: " + $cpmServicesPath + "</li>"}
			}
            Else{
                $tmpStatus += "<li>" + "The permissions need to be reviewed. Permissions are not set correctly for the Local Administrators, the local System user and the CPM user" + "</li>"
                $res = "Warning"
                }
            [ref]$refOutput.Value = "<ul>$tmpStatus</ul>"

			Write-LogMessage -Type Info -Msg "Finish validating CPM Service configuration"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate CPM Service configuration.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate CPM Service configuration."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CPM_EnableFIPSCryptography
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function CPM_EnableFIPSCryptography
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
		$serviceRegValue = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Services\CyberArk Password Manager' -name ImagePath).ImagePath
		$res = "Good"
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start verification if FIPS cryptography is enabled on CPM"
			If(($serviceRegValue) -match 'PMEngine.exe" /SERVICE /AdvancedFipsCryptography')
			{
				Write-LogMessage -Type Info -Msg "FIPS cryptography is enabled on the CPM service"
                [ref]$refOutput.Value = "FIPS cryptography is enabled on the CPM service"
			}
			else
			{
				[ref]$refOutput.Value = "Could not find FIPS cryptography on the CPM service"
				$res = "Warning"
			}

			Write-LogMessage -Type Info -Msg "Finish verification if FIPS cryptography is enabled on CPM"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate FIPS cryptography on CPM.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate FIPS cryptography on CPM."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CPM_DisableDEPForExecutables
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function CPM_DisableDEPForExecutables
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
		# Set DEP Registry path
		$DEP_REG_PATH = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
		$res = "Good"
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start verifying DEP For Executables"

			$retDEPSettings = @()
			$depPolicyLevel = Get-WMIItem -Class Win32_OperatingSystem -Item "DataExecutionPrevention_SupportPolicy"
			if ($depPolicyLevel -eq 3)
			{
				If (Test-Path $DEP_REG_PATH)
				{
					$depExclusions = Get-ItemProperty $DEP_REG_PATH | Select-Object * -ExcludeProperty PS*
					$depExclusionsList = $depExclusions.PSObject.Properties | Select-Object Name
				}
				else
				{
					$retDEPSettings += "DEP is enabled for all processes with no exclusions. If using, PMTerminal might not work correctly"
					$res = "Warning"
				}
			}
			Switch($depPolicyLevel.DataExecutionPrevention_SupportPolicy)
			{
				# DataExecutionPrevention_SupportPolicy  | Policy Level | Description
				# 2 | OptIn (default configuration) | Only Windows system components and services have DEP applied
				# 3 | OptOut | DEP is enabled for all processes. Administrators can manually create a list of specific applications which do not have DEP applied
				# 1 | AlwaysOn | DEP is enabled for all processes
				# 0 | AlwaysOff | DEP is not enabled for any processes

				0 { 
					$res = "Bad"; 
					$retDEPSettings += "DEP is not enabled for any processes (Always Off)"; 
					break 
				}
				1 {
                    $retDEPSettings += "DEP is enabled for all processes (Always On)"; $res = "Warning"
                    $retDEPSettings += "The PMTerminal application may not work, "
					$retDEPSettings += "PMTerminal's replacement (TPC) does not require DEP exceptions"
					break
                }
				2 { 
					$res = "Warning"; 
					$retDEPSettings += "Only Windows system components and services have DEP applied (OptIn [default])"; 
					break 
				}
				3 {
					$res = "Good"
					$retDEPSettings += "DEP is enabled for all processes. Administrators can manually create a list of specific applications which do not have DEP applied (OptOut)."
                    $retDEPSettings += "This is required for PMTerminal but not for the replacement application TPC."
					If($depExclusionsList.Count -eq 0)
					{
						Write-LogMessage -Type Error "Could not get DEP Exclusions List"
					}
					else {
						$retDEPSettings += "The current Exclusions are:<ul>"
						ForEach ($exc in $depExclusionsList)
						{
							$retDEPSettings += "<li>$($exc.Name)</li>"
						}
						$retDEPSettings += "</ul>"
					}
                    $retDEPSettings += "Note that PMTerminal is end of life in December 2021"
					$retDEPSettings += "'TPC' is the replacement application that does not require DEP exceptions"
					break
				}
			}

			[ref]$refOutput.Value = $($retDEPSettings -join "<BR>")

			Write-LogMessage -Type Info -Msg "Finish verifying DEP For Executables"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify DEP For Executables.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify DEP For Executables."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CPM_CredFileHardening
# Description....: Return type of restrictions added the the credential file
# Parameters.....: Credential file location
# Return Values..: Verification Type
# =================================================================================================================================
Function CPM_CredFileHardening
{
<#
.SYNOPSIS
	Return verification type on credential file
.DESCRIPTION
	Return the verification type on the credential file used by the components to log back in to the vault
.PARAMETER parameters
	Credential file location
#>
	param(
		[Parameter(Mandatory=$false)]
		[array]$Parameters = $null,
		[Parameter(Mandatory=$false)]
		[ref]$refOutput
	)

	Begin {
        $res = 'Good'
        $myRef = ""
        $cpmPath = ""
        $tmpValue = ""
        }

    Process {
        Try{
   			Write-LogMessage -Type Info -Msg "Start validating hardening of CPM credential file"
            $cpmPath = (Get-DetectedComponents -Component "CPM").Path
            $credentialsFolder = join-path -Path $cpmPath -ChildPath 'Vault'
			# Go over all CPM Cred Files in the folder
			ForEach ($credFile in (Get-ChildItem -Path $credentialsFolder -Filter *.ini -File | Where-Object { $_.Name -ne "Vault.ini" }))
			{
				Write-LogMessage -Type Debug -Msg "Checking '$($credFile.Name)' credential file"
				if((Test-CredFileVerificationType -CredentialFilePath $credFile.FullName -outStatus ([ref]$myRef)) -ne "Good")
				{
					$res = "Warning"
				}
				$tmpValue += $myRef.value + "<BR>"
			}

            [ref]$refOutput.Value = $tmpValue
            Write-LogMessage -Type Info -Msg "Finish validating CPM component credential file"
   			return $res
        } catch {
			Write-LogMessage -Type "Error" -Msg "Could not validate the CPM component credential file.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate CPM component credential file."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

