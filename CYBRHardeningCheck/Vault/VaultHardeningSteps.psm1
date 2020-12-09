# @FUNCTION@ ======================================================================================================================
# Name...........: Vault_NICHardening
# Description....: NIC Hardening
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Vault_NICHardening
{
<#
.SYNOPSIS
	Method to validate if the Vault NIC is Hardened
.DESCRIPTION
	Returns the Status of the Vault NIC
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
		$myRef = ""
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify Vault NIC is Hardened"
			# Get all Network Bindings that are not TCP/IPv4
			$netBindings = Get-NetAdapterBinding | Where-Object { $_.ComponentID -ne "ms_tcpip" }
			If ($netBindings.Count -gt 0)
			{
				ForEach($net in $netBindings)
				{
					If (($net.ComponentID -eq "ms_tcpip6") -and ($net.Enabled -eq $True))
					{
						$myRef += "TCP/IPv6 needs to be Disabled<BR>"
					}
					elseif ($net.DisplayName -match "Microsoft Network Adapter Multiplexor Protocol")
					{
						# If the Vault has NIC Teaming, then this is OK - just report it
						$nicTeam = Get-NetLbfoTeam | Where-Object { $_.Status -eq "Up" }
						$myRef += "NIC Teaming is enabled.<BR>Team Name: {0}<BR>Team NIC Members: {1}" -f $nicTeam.Name, $($nicTeam.Members -join ", ")
					}
					else
					{
						$myRef += "{0} needs to be Uninstalled<BR>" -f $net.DisplayName
					}
				}
				[ref]$refOutput.Value = $myRef
				$res = "Warning"
			}

			Write-LogMessage -Type Info -Msg "Finish verify Vault NIC is Hardened"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify Vault NIC is Hardened.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify Vault NIC is Hardened."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Vault_StaticIP
# Description....: Check that the Vault has Static IP
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Vault_StaticIP
{
<#
.SYNOPSIS
	Method to Check that the Vault has Static IP
.DESCRIPTION
	Returns the Status of the Vault NIC, Static IP
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
		$myRef = ""

	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify Vault has static IP"
			$getdhcpstatus = Get-NetIPAddress -InterfaceAlias "Ethernet" -AddressFamily IPv4
			ForEach ($item in $getdhcpstatus)
			{
				if ($item.PrefixOrigin -eq "Dhcp")
				{
					[ref]$refOutput.Value = "Static IP is not set on network device $($item.InterfaceAlias.ToString())"
					$res = "Warning"
				}
			}

			Write-LogMessage -Type Info -Msg "Finish verify Vault has static IP"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify Vault has static IP.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify Vault has static IP."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Vault_WindowsFirewall
# Description....: Check that the Vault has the Firewall active
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Vault_WindowsFirewall
{
<#
.SYNOPSIS
	Method to Check that the Vault has the Firewall active
.DESCRIPTION
	Returns the Status of the Vault Firewall
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
		$myRef = ""
		$firewallServiceName = "MpsSvc"
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify Vault Firewall is Active and Hardened"
			$res = (Compare-ServiceStatus -ServiceName $firewallServiceName -ServiceStatus "Running" -outStatus ([ref]$myRef))
			[ref]$refOutput.Value = $myRef

			Write-LogMessage -Type Info -Msg "Finish verify Vault Firewall is Active and Hardened"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify Vault Firewall is Active and Hardened.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify Vault Firewall is Active and Hardened."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Vault_DomainJoined
# Description....: Check that the Vault was not joined to a domain
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Vault_DomainJoined
{
<#
.SYNOPSIS
	Method to Check that the Vault was not joined to a domain
.DESCRIPTION
	Returns if the vault was joined (ever) to a domain
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
		$myRef = ""
		$NSLog =  "$($ENV:SystemRoot)\debug\NetSetup.LOG"
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify Vault was not joined to a Domain"
			If(Test-Path $NSLog)
			{
				If((Get-Content $NSLog -ErrorAction SilentlyContinue | Select-String "DomainJoin") -match "(\d{2}\/\d{2}\/\d{4}\s\d{2}:\d{2}:\d{2}:\d{3})\sNetpJoinDomain.*(?=NetpComplete\w{0,}Domain.*0x0)")
				{
					$res = "Warning"
					$domainJoinedDate = $Matches[1]
					[ref]$refOutput.Value = "Machine was joined to a domain on $domainJoinedDate according to machine logs"
				}
			}

			Write-LogMessage -Type Info -Msg "Finish verify Vault was not joined to a Domain"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify Vault was not joined to a Domain.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not Vault was not joined to a Domain."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Vault_LogicContainerServiceLocalUser
# Description....: Check that the Vault Logic Container is running with a local user
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Vault_LogicContainerServiceLocalUser 
{
<#
.SYNOPSIS
	Validates that the Vault Logic Container Service is running with a local user and has the appropriate rights on the Logic Container folders
.DESCRIPTION
	Validates that the Vault Logic Container Service is running with a local user and has the appropriate rights on the Logic Container folders
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
		$changeStatus = $false
		$myRef = ""
		$serviceName = "CyberArk Logic Container"
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating Logic Container Service configuration"
			$LCServiceUserName = $($Parameters | Where-Object Name -eq "LCServiceUserName").Value

			# Get the Vault working directory
			$vaultServicePath = (Find-Components -Component "Vault").Path
			$lcServicePath = Join-Path -Path $vaultServicePath -ChildPath "LogicContainer"
            $lcServiceArchiveLogsPath = Join-Path -Path $vaultServicePath -ChildPath "Logs\Archive"

			$lcService = @{
				"serviceName" = $serviceName;
				"userName" = $LCServiceUserName;
				"outStatus" = ([ref]$myRef);
			}
			if((Test-ServiceRunWithLocalUser @lcService) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$changeStatus = $true
			}

			$userPermissions = @{
				"Path"="";
				"Identity"=$LCServiceUserName;
				"Rights"="FullControl";
				"ACLType"="Allow";
				"outStatus"=([ref]$myRef);
			}

			# Verify the Local user has Full Control rights on the Logic Container installation path
			$userPermissions["Path"] = $lcServicePath
			if((Compare-UserPermissions @userPermissions) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$changeStatus = $true
			}
			# Verify Local user has Full Control rights on the Archive Logs path
			$userPermissions["Path"] = $lcServiceArchiveLogsPath
			if((Compare-UserPermissions @userPermissions) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$changeStatus = $true
			}

			If($changeStatus)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			[ref]$refOutput.Value = $myRef.Value

			Write-LogMessage -Type Info -Msg "Finish validating Logic Container Service configuration"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate Logic Container Service configuration.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate Logic Container Service configuration."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}