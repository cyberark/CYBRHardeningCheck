$script:NICteamingName = ""

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
						$script:NICteamingName = $nicTeam.Name
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
		$interfaceAliasPattern = "Eth*"
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify Vault has static IP"
			If(! [string]::IsNullOrEmpty($NICteamingName))
			{
				Write-LogMessage -Type Verbose -Msg "Checking Team ($NICteamingName) and not Ethernet"
				$interfaceAliasPattern = $NICteamingName
			}
			$getdhcpstatus = Get-NetIPAddress -InterfaceAlias $interfaceAliasPattern -AddressFamily IPv4
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
		$statusChanged = $false
		$myRef = ""
		$serviceName = "CyberArk Logic Container"
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating Logic Container Service configuration"
			$LCServiceUserName = $($Parameters | Where-Object Name -eq "LCServiceUserName").Value

			# Get the Vault working directory
			$vaultServicePath = (Get-DetectedComponents -Component "Vault").Path
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
				$statusChanged = $true
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
				$statusChanged = $true
			}
			# Verify Local user has Full Control rights on the Archive Logs path
			$userPermissions["Path"] = $lcServiceArchiveLogsPath
			if((Compare-UserPermissions @userPermissions) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

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

# @FUNCTION@ ======================================================================================================================
# Name...........: Vault_FirewallNonStandardRules
# Description....: Check that all the existing firewall rules are allowed (either standard or documented non-standard in the DBParm.ini)
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Vault_FirewallNonStandardRules
{
<#
.SYNOPSIS
	Method to Check that all the existing firewall rules are allowed
.DESCRIPTION
	Returns true if all firewall rules are either standard or documented non-standard in the DBParm.ini
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
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start validation of Vault Firewall Non-Standard rules"
			$vaultFolder = $(Get-DetectedComponents -Component Vault).Path
			# Find the DBParm.ini file
			$DBParmFile = $(Get-ChildItem -Path $vaultFolder -Include "DBParm.ini" -Recurse).FullName
			$dbParmFWRules = @()
			ForEach($rule in $(Get-Content -Path $DBParmFile | Select-String "AllowNonStandardFWAddresses=").Line)
			{
				# Rule Parts: [0] - Address; [1] - Enabled; [2-3] - <Port>:<Direction>/<Protocol>
				$ruleParts = $rule.Replace("AllowNonStandardFWAddresses=","").Split(',')
				Foreach($direction in $ruleParts[2..5])
				{
					If($direction -Match "(\d{1,}):(\w{1,})/(\w{1,})")
					{
						$fwRule = "" | Select-Object DisplayGroup,Enabled,Direction,LocalAddress,RemoteAddress,Protocol,LocalPort,RemotePort	
						$fwRule | Add-Member -MemberType ScriptProperty -Name "FWRuleLine" -Value {
							"[{0}],{1},{2}:{3}/{4}" -f $this.RemoteAddress,$this.Enabled,$(If($this.Direction -eq "inbound") {$this.LocalPort} else {$this.RemotePort}),$this.Direction,$this.Protocol
						}
						$fwRule.DisplayGroup = "CYBERARK_RULE_NON_STD_ADDRESS"
						If($ruleParts[1] -eq "Yes")
						{
							$fwRule.Enabled = "True"
						}
						$fwRule.Direction = $Matches[2]
						$fwRule.LocalAddress = "Any"
						$fwRule.RemoteAddress = $ruleParts[0].Replace("[","").Replace("]","")
						$fwRule.Protocol = $Matches[3]
						Switch ($fwRule.Direction)
						{
							"inbound" {
								$fwRule.LocalPort = $Matches[1]
								$fwRule.RemotePort = "Any"
								break
							}
							"outbound" {
								$fwRule.LocalPort = "Any"
								$fwRule.RemotePort = $Matches[1]
								break
							}
						}
						Write-LogMessage -Type Verbose -Msg "Added DBParm.ini rule: $($fwRule.FWRuleLine)"
						$dbParmFWRules += $fwRule
					}
					Else
					{
						Write-Host "Non valid rule line ($rule)"
					}
				}
			}
			
			Write-LogMessage -Type Verbose -Msg "There are $($dbParmFWRules.count) Non-Standard Firewall rules defined in DBParm.ini"
			Write-LogMessage -Type Verbose -Msg "Adding ICMP rules for the DBParm.ini collection"

			# Add ICMPv4
			If($dbParmFWRules.count -gt 0)
			{
				# Add an ICMP rule for every address
				$addresses = @($dbParmFWRules.RemoteAddress | select-object -Unique)
				# Add general ICMP rule (any - any)
				$addresses += "Any"
				Foreach ($address in $addresses) {
					Foreach ($direction in @("inbound","outbound"))
					{
						$fwRule = "" | Select-Object DisplayGroup,Enabled,Direction,LocalAddress,RemoteAddress,Protocol,LocalPort,RemotePort	
						$fwRule | Add-Member -MemberType ScriptProperty -Name "FWRuleLine" -Value {
							"[{0}],{1},{2}:{3}/{4}" -f $this.RemoteAddress,$this.Enabled,$(If($this.Direction -eq "inbound") {$this.LocalPort} else {$this.RemotePort}),$this.Direction,$this.Protocol
						}
						$fwRule.DisplayGroup = "CYBERARK_RULE_NON_STD_ADDRESS"
						$fwRule.Protocol = "ICMPv4"
						$fwRule.Enabled = "True"
						$fwRule.LocalPort = "Any"
						$fwRule.RemotePort = "Any"
						$fwRule.LocalAddress = "Any"
						$fwRule.RemoteAddress = $address
						$fwRule.Direction = $direction
						Write-LogMessage -Type Verbose -Msg "Added DBParm.ini rule: $($fwRule.FWRuleLine)"
						$dbParmFWRules += $fwRule
					}
				}
			}

			$FWRules = @()
			ForEach($rule in $(get-netfirewallrule -policystore ActiveStore))
			{
				$addressFilter = $($rule | Get-NetFirewallAddressFilter)
				$portFilter = $($rule | Get-NetFirewallPortFilter)
				$fwRule = "" | Select-Object DisplayGroup,Enabled,Direction,LocalAddress,RemoteAddress,Protocol,LocalPort,RemotePort
				$fwRule | Add-Member -MemberType ScriptProperty -Name "FWRuleLine" -Value {
					"[{0}],{1},{2}:{3}/{4}" -f $this.RemoteAddress,$this.Enabled,$(If($this.Direction -eq "inbound") {$this.LocalPort} else {$this.RemotePort}),$this.Direction,$this.Protocol
				}
				$fwRule.DisplayGroup = $rule.DisplayGroup
				$fwRule.Enabled = $rule.Enabled.ToString()
				$fwRule.Direction = $rule.Direction.ToString()
				$fwRule.LocalAddress = $addressFilter.LocalAddress
				$fwRule.RemoteAddress = $addressFilter.RemoteAddress
				$fwRule.Protocol = $portFilter.Protocol
				$fwRule.LocalPort = $portFilter.LocalPort
				$fwRule.RemotePort = $portFilter.RemotePort
				Write-LogMessage -Type Verbose -Msg "Added Configured Firewall rule: $($fwRule.FWRuleLine)"
				$FWRules += $fwRule
			}

			Write-LogMessage -Type Verbose -Msg "There are $($FWRules.count) Firewall rules currently configured"
			Write-LogMessage -Type Verbose -Msg "There are $(($FWRules | Where-Object { $_.DisplayGroup -match "NON_STD" }).count) Non-Standard CyberArk Firewall rules currently configured"
			If($(($FWRules | Where-Object { $_.DisplayGroup -notmatch "CYBERARK_" }).count) -gt 0)
			{
				$res = "Warning"
				$tmpStatus += "<li>There are $(($FWRules | Where-Object { $_.DisplayGroup -notmatch "CYBERARK_" }).count) Firewall rules that were not created by CyberArk Vault currently configured </li>"
			}
			
			ForEach($rule in $($FWRules | Where-Object { $_.DisplayGroup -match "NON_STD" }))
			{
				# Checking that all Non-Standard rules currently configured also appear in the DBParm.ini
				If($dbParmFWRules.FWRuleLine -notcontains $rule.FWRuleLine)
				{
					$res = "Warning"
					$tmpStatus += "<li>Non-Standard Firewall rule ($($rule.FWRuleLine)) is applied but not configured in DBParm.ini </li>"
				}
			}

			ForEach($rule in $dbParmFWRules)
			{
				# Checking that all Non-Standard rules currently configured also appear in the DBParm.ini
				If($FWRules.FWRuleLine -notcontains $rule.FWRuleLine)
				{
					$res = "Warning"
					$tmpStatus += "<li>Non-Standard Firewall rule ($($rule.FWRuleLine)) is configured in DBParm.ini but does not exist in the Vault Firewall policy </li>"
				}
			}

			[ref]$refOutput.Value = "<ul>$tmpStatus</ul>"

			Write-LogMessage -Type Info -Msg "Finish validation of Vault Firewall Non-Standard rules"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify Vault Firewall Non-Standard rules.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify Vault Firewall Non-Standard rules."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Vault_ServerCertificate
# Description....: Check that the Vault has a signed CA certificate
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Vault_ServerCertificate
{
<#
.SYNOPSIS
	Method to Check that the Vault has a signed CA certificate
.DESCRIPTION
	Returns the Status of the Vault certificate
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
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start validating Vault Server Certificate"
			# Run the CACert tool
			$vaultFolder = $(Get-DetectedComponents -Component Vault).Path
			Push-Location $vaultFolder
			$caCertOutput = .\cacert.exe show
			Pop-Location
			# Parse the output
			$selfSigned = $(($caCertOutput | Select-String "Subject:").line.Replace("Subject:","").Trim() -match "self-signed")
			$algorithm = ""
			foreach ($line in $($caCertOutput | Select-String "Signature Algorithm:").Line) {
				$algorithm = $line.Replace("Signature Algorithm:","").Trim()
				break
			}
			If($selfSigned)
			{
				$res = "Warning"
				$tmpStatus += "Vault currently using Self-Signed certificate<BR>"
			}
			If($algorithm -match "sha1")
			{
				$res = "Warning"
				$tmpStatus += "Vault Certificate is using SHA1 encryption ($algorithm)"
			}

			[ref]$refOutput.Value = $tmpStatus
			
			Write-LogMessage -Type Info -Msg "Finish validating  Vault Server Certificate"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify Vault Server Certificate.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify Vault Server Certificate."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Vault_KeysProtection
# Description....: Check that the Vault Encryption keys are protected and have the right permissions
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Vault_KeysProtection
{
<#
.SYNOPSIS
	Method to Check that the Vault Encryption keys are protected and have the right permissions
.DESCRIPTION
	Returns the Status of the Vault Encryption keys permissions
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
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start validating Vault Encryption keys permissions"
			$vaultFolder = $(Get-DetectedComponents -Component Vault).Path
			$DBParmFile = $(Get-ChildItem -Path $vaultFolder -Include "DBParm.ini" -Recurse).FullName
			# Get the location of all Vault Keys
			$keysList = $(Get-Content -Path $DBParmFile | Select-String -List "RecoveryPubKey","ServerKey","ServerPrivateKey","RecoveryPrvKey","BackupKey").Line
			Write-LogMessage -Type Verbose -Msg "Found the following Keys paths: $($KeysList -join '; ')"
			$KeysLocations = @()
			$KeysLocations += $($keysList | ForEach-Object { Split-Path -Parent -Path $($_.Split("=")[1]) } ) | Select-Object -Unique
			
			# Check if the Recovery key exists on the server
			$RecoveryKey = ($keysList | Where-Object { $_ -match "RecoveryPrvKey=" })
			Write-LogMessage -Type Verbose -Msg "Checking if the RecoveryKey exists on the machine"
			Write-LogMessage -Type Verbose -Msg "Current RecoveryKey path: $RecoveryKey"
			If(Test-Path $RecoveryKey)
			{
				$res = "Warning"
				$tmpStatus += "<li>It is not recommended to have the Recovery Key on the Vault server.</li>"
			}
			else {
				Write-LogMessage -Type Verbose -Msg "RecoveryKey is not accessible on machine"
			}

			# Check that all paths have the right permissions
			$KeysFolderLocalAdmins = $KeysFolderLocalSystem = $true
			foreach ($path in $KeysLocations) {
				Write-LogMessage -Type Verbose -Msg "Checking '$path' permissions..."
				if((Compare-UserPermissions -path $path -identity $(Get-LocalAdministrators) -rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
				{
					$KeysFolderLocalAdmins = $false
					$res = "Warning"
				}
				$tmpStatus += "<li>" + $myRef.Value + "</li>"

				if((Compare-UserPermissions -path $path -identity $(Get-LocalSystem) -rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
				{
					$KeysFolderLocalSystem = $false
					$res = "Warning"
				}
				$tmpStatus += "<li>" + $myRef.Value + "</li>"

				# Verify if Administrators, System and the CPM User are the only ones that has permissions
				if(($KeysFolderLocalAdmins -eq $true) -and ($KeysFolderLocalSystem -eq $true))
				{
					If((Compare-AmountOfUserPermissions -Path $path -amount 2 -outStatus ([ref]$myRef)) -ne "Good")
					{
						$tmpStatus += "<li>" + $myRef.Value + "</li>"
						$res = "Warning"
					}
					Else { $tmpStatus += "<li> Permissions are set correctly on the path: " + $path + "</li>" }
				}
				Else {
					$tmpStatus += "<li>" + "The permissions need to be reviewed. Permissions are not set correctly for the Local Administrators and the local System user" + "</li>"
					$res = "Warning"
				}
			}

			[ref]$refOutput.Value = "<ul>"+$tmpStatus+"</ul>"
			
			Write-LogMessage -Type Info -Msg "Finish validating Vault Encryption keys permissions"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify Vault Server Certificate. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify Vault Server Certificate."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}