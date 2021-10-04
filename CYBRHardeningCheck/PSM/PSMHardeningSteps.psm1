﻿# Const
Set-Variable PSM_CONNECT -value "PSMConnect"
Set-Variable PSM_ADMIN_CONNECT -value "PSMAdminConnect"
Set-Variable PSM_SHADOW_USERS -value "PSMShadowUsers"

# @FUNCTION@ ======================================================================================================================
# Name...........: ConfigureUsersForPSMSessions
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function ConfigureUsersForPSMSessions
{
<#
.SYNOPSIS

.DESCRIPTION

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
		$user_names = ($PSM_CONNECT, $PSM_ADMIN_CONNECT)
		$DONT_EXPIRE_PASSWD = "65536"
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify ConfigureUsersForPSMSessions"
			ForEach ($user in $user_names)
			{
				if((Compare-UserFlags -userName $user -flagName "UserFlags" -userFlagValue "DONT_EXPIRE_PASSWD" -flagValue $DONT_EXPIRE_PASSWD -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
				if((Compare-UserFlags -userName $user -flagName "MaxDisconnectionTime" -flagValue 1 -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
				if((Compare-UserFlags -userName $user -flagName "MaxConnectionTime" -flagValue 0 -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
				if((Compare-UserFlags -userName $user -flagName "ReconnectionAction" -flagValue 1 -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
				if((Compare-UserFlags -userName $user -flagName "BrokenConnectionAction" -flagValue 0 -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verify ConfigureUsersForPSMSessions"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify ConfigureUsersForPSMSessions.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify ConfigureUsersForPSMSessions."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: EnableUsersToPrintPSMSessions
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function EnableUsersToPrintPSMSessions
{
<#
.SYNOPSIS

.DESCRIPTION

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
		$user_names = ($PSM_CONNECT, $PSM_ADMIN_CONNECT)
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify EnableUsersToPrintPSMSessions"

			ForEach ($user in $user_names)
			{
				if((Compare-UserFlags -userName $user -flagName "ConnectClientPrintersAtLogon" -flagValue 1 -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
				if((Compare-UserFlags -userName $user -flagName "DefaultToMainPrinter" -flagValue 1 -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verify EnableUsersToPrintPSMSessions"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify EnableUsersToPrintPSMSessions.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify EnableUsersToPrintPSMSessions."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: SupportWebApplications
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function SupportWebApplications
{
<#
.SYNOPSIS

.DESCRIPTION

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
		$tmpStatus = ""
		$changeStatus = $false
		$PSM_IE_Hardening = Resolve-Path -Path $(Get-CurrentComponentFolderPath -FileName "PSMIEHardening.csv")
		$PSM_Chrome_Hardening = Resolve-Path -Path $(Get-CurrentComponentFolderPath -FileName "PSMChromeHardening.csv")
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify SupportWebApplications"
			# Check the hardening of the Installed browsers
			Write-LogMessage -Type Debug -Msg "Checking IE hardening"
			$hardeningData = @()
			If(Test-Path $PSM_IE_Hardening)
			{
				$hardeningData += Import-Csv $PSM_IE_Hardening -Header Path,ValueName,ValueType,ValueData
			}
			# Check if Chrome is installed
			If(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe")
			{
				If(Test-Path $PSM_Chrome_Hardening)
				{
					$hardeningData += Import-Csv $PSM_Chrome_Hardening -Header Path,ValueName,ValueType,ValueData
				}	
			}
			ForEach($line in $hardeningData)
			{
				$regHardening = @{
					"Path" = "HKLM:\"+$line.Path;
					"ValueName" = $line.ValueName;
					"ValueData" = $line.ValueData;
					"outStatus" = ([ref]$myRef);
				}
		
				if((Compare-RegistryValue @regHardening) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$changeStatus = $true
				}
			}
			
			# IE Specific hardening settings check
			# Check Disable Internet Explorer Enhanced Security Configuration
			$regESC = @{
				"Path" = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
				"ValueName" = "IsInstalled";
				"ValueData" = 0;
				"outStatus" = ([ref]$myRef);
			}

			if((Compare-RegistryValue @regESC) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$changeStatus = $true
			}

			# Check Prevent-RunningFirstRunWizard
			$regFRW = @{
				"Path" = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main";
				"ValueName" = "DisableFirstRunCustomize";
				"ValueData" = 2;
				"outStatus" = ([ref]$myRef);
			}

			if((Compare-RegistryValue @regFRW) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$changeStatus = $true
			}

			If($changeStatus)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verify SupportWebApplications"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify SupportWebApplications.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify SupportWebApplications."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ClearRemoteDesktopUsers
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function ClearRemoteDesktopUsers
{
<#
.SYNOPSIS

.DESCRIPTION

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
		$REMOTE_DESKTOP_USERS_GROUP_SID = "S-1-5-32-555"
		[Array]$MembersOfRDUsersGroup =$null
		[Array]$MembersOfADGroups = $null
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify ClearRemoteDesktopUsers"
			# Get the Remote Desktop USers group members
			$MembersOfRDUsersGroup = Get-LocalGroupMember -SID $REMOTE_DESKTOP_USERS_GROUP_SID
            If ($null -ne $MembersOfRDUsersGroup)
            {
				# Check if the PSMConnect and PSMAdminConnect have permissions
				$psmAccess = $($MembersOfRDUsersGroup | Where-Object { $_.Name -like "*$PSM_CONNECT*" } ) -and $($MembersOfRDUsersGroup | Where-Object { $_.Name -like "*$PSM_ADMIN_CONNECT*" })
				# Check other Domain users and groups access
				ForEach ($item in $($MembersOfRDUsersGroup | Where-Object { $_.PrincipalSource -eq "ActiveDirectory" -and $_.ObjectClass -eq "Group" }))
				{
					if($null -ne $item)
					{
						try{
							$Search = New-Object DirectoryServices.DirectorySearcher("(objectSID=$($item.SID))")
							$Search.PropertiesToLoad.Add("member") | Out-Null
							$Results = $Search.FindOne()
							$MembersOfADGroups += $Results.Properties["Member"]
						} catch {
							Throw $(New-Object System.Exception ("ClearRemoteDesktopUsers: Active Directory Cannot be contacted. Check that you are logged in with a domain user"),$_.Exception)
						}
					}
				}

				If($psmAccess)
				{
					If($MembersOfRDUsersGroup.count -gt 2)
					{
						$res = "Warning"
						$tmpStatus += "<B>Too many users/groups in Remote Desktop Users group</B><BR>"
						$tmpStatus += "Current direct members of the 'Remote Desktop Users' group are:<BR>"
						$tmpStatus += ("<ul><li>" + $($MembersOfRDUsersGroup.Name -join "<li>") + "</ul>")
						if($null -ne $MembersOfADGroups)
						{
							$tmpStatus += "<b>Members of the AD groups that are members of the 'Remote Desktop Users' Group are: </b><br>"
							$tmpStatus += "<ul>"
							forEach($item in $MembersOfADGroups)
							{
								If($item -match "^CN=([\w\s]{1,}),(?:CN|OU|DC)")
								{
									$tmpStatus += ("<li>" + ($Matches[1].Trim()) + "</li>")
								}
							}
							$tmpStatus += "</ul>"
						}
					}
				}
				Else
				{
					$res = "Bad"
					$tmpStatus += "PSMConnect and PSMAdminConnect should have access to 'Remote Desktop Users' group"
				}
			}
            Else {
                Write-LogMessage -Type "Error" -Msg "The local Remote Desktop User groups contains no members.  Error: $(Join-ExceptionMessage $_.Exception)"
			    $tmpStatus += "The local Remote Desktop User groups contains no members"
			    $res = "Bad"
            }

		    Write-LogMessage -Type Info -Msg "Finish verify ClearRemoteDesktopUsers"

			[ref]$refOutput.Value = $tmpStatus
			return $res
		} catch {
			Write-LogMessage -Type "Error" -Msg "Could not verify ClearRemoteDesktopUsers.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify ClearRemoteDesktopUsers."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: RunAppLocker
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function RunAppLocker
{
<#
.SYNOPSIS

.DESCRIPTION

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
		$PSM_AppLockerConfiguration = Join-Path -Path $(Get-DetectedComponents -Component "PSM").Path -ChildPath "Hardening\PSMConfigureAppLocker.xml"
		$ruleTypesList = @("Exe","Script","Msi","Dll")
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify RunAppLocker"
			If(Test-Path $PSM_AppLockerConfiguration)
			{

				# Get current AppLocker configuration (incase it wasn't configured, an empty policy will be returned)
				$xmlAppLockerConfiguration = [xml](get-AppLockerPolicy -effective -xml)
				# Load the current PSM AppLocker Configuration
				$xmlPSM_AppLockerConfig = [xml](Get-Content $PSM_AppLockerConfiguration)
				If(($null -ne $xmlAppLockerConfiguration) -and ($null -ne $xmlPSM_AppLockerConfig))
				{
					# For each type check that all rules exist
					ForEach($type in $ruleTypesList)
					{
						Write-LogMessage -type Verbose "Checking rules for '$type'..."
						$psmAppLockerConfig = $xmlPSM_AppLockerConfig.PSMAppLockerConfiguration.SelectNodes("//Application[@Type='$type']")
						$currentAppLockerConfig = $xmlAppLockerConfiguration.SelectSingleNode("//RuleCollection[@Type='$type']")
						$compareResult = Compare-Object -ReferenceObject $currentAppLockerConfig.Conditions.FilePathCondition.Path -DifferenceObject $psmAppLockerConfig.Path
						If($compareResult.Count -gt 0)
						{
							$tmpStatus += "The following '$type' rules are different between the current AppLocker configuration and the PSM AppLocker configuration file<BR><ul>"
							# Get the rules missing from the PSM AppLocker config
							$tmpStatus += ($compareResult | Where-Object { $_.SideIndicator -eq "<="}) -join "<li>(Effective)"
							# Get the rules missing in the effective AppLocker config
							$tmpStatus += ($compareResult | Where-Object { $_.SideIndicator -eq "=>"}) -join "<li>(PSM Config)"
							$tmpStatus += "</ul>"
							$changeStatus = $true
						}
					}
				}
				else {
					Write-LogMessage -Type Warning -Msg "AppLocker configuration files are empty"
				}
				If($changeStatus)
				{
					$res = "Warning"
					[ref]$refOutput.Value = $tmpStatus
				}
			}
			else {
				Write-LogMessage -Type Warning -Msg "PSM AppLocker configuration file does not exist in $PSM_AppLockerConfiguration. Skipping AppLocker check"
				$res = "Warning"
				[ref]$refOutput.Value = "PSM AppLocker configuration file does not exist in $PSM_AppLockerConfiguration"
			}
			
			Write-LogMessage -Type Info -Msg "Finish verify RunAppLocker"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify RunAppLocker.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify RunAppLocker."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConfigureOutOfDomainPSMServer
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function ConfigureOutOfDomainPSMServer
{
<#
.SYNOPSIS

.DESCRIPTION

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
		$user_names = ($PSM_CONNECT, $PSM_ADMIN_CONNECT)
		# Check which path to use
		If(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services")
		{
			$regTSPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
		}
		ElseIf(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Services")
		{
			$regTSPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Services"
		}
		Else
		{
			# Getting the default path for this test
			$regTSPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
		}
		$regTimeLimitForIdleSessions = @{
				"Path" = $regTSPath
				"ValueName" = "MaxIdleTime";
				"ValueData" = 172800000;
				"outStatus" = ([ref]$myRef);
			}

		$regRemoteSessionControl = @{
				"Path" = $regTSPath
				"ValueName" = "Shadow";
				"ValueData" = 2;
				"outStatus" = ([ref]$myRef);
			}
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify ConfigureOutOfDomainPSMServer"

			if((Compare-UserRight -userName $PSM_SHADOW_USERS -userRight "SeInteractiveLogonRight" -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			ForEach($user in $user_names)
			{
				if((Compare-UserRight -userName $user -userRight "SeRemoteInteractiveLogonRight" -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			}
			if((Compare-RegistryValue @regTimeLimitForIdleSessions) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			if((Compare-RegistryValue @regRemoteSessionControl) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verify ConfigureOutOfDomainPSMServer"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify ConfigureOutOfDomainPSMServer.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify ConfigureOutOfDomainPSMServer."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: DisableTheScreenSaverForThePSMLocalUsers
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function DisableTheScreenSaverForThePSMLocalUsers
{
<#
.SYNOPSIS

.DESCRIPTION

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
		$user_names = ($PSM_CONNECT, $PSM_ADMIN_CONNECT)
		$RegPath = "Software\Policies\Microsoft\Windows\Control Panel\Desktop"
		$UserDir = "$($ENV:WinDir)\system32\GroupPolicyUsers\{0}\User\registry.pol"
	}
	Process {
		try{
			# Disable Screen Saver on server
			If((EnableScreenSaver -refOutput ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value
			}

			Write-LogMessage -Type Info -Msg "Start verify DisableTheScreenSaverForThePSMLocalUsers"

			ForEach ($user in $user_names)
			{
				$usrSID = $null
				try{
					$usrSID = Convert-NameToSID $user
				}
				catch{
					$tmpStatus += $($_.Exception.Message) + "<BR>"
					$statusChanged = $true
				}
				if($null -ne $usrSID)
				{
					$currUserDir = $UserDir -f $usrSID
					if((Compare-PolicyEntry -EntryTitle "Disable screen saver" -UserDir $currUserDir -RegPath $RegPath -RegName 'ScreenSaveActive' -RegData '1' -outStatus ([ref]$myRef)) -ne "Good")
					{
						$tmpStatus += $myRef.Value + "<BR>"
						$statusChanged = $true
					}
				}
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verify DisableTheScreenSaverForThePSMLocalUsers"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify DisableTheScreenSaverForThePSMLocalUsers.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify DisableTheScreenSaverForThePSMLocalUsers."
			return "Bad"
		}
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: HidePSMDrives
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function HidePSMDrives
{
<#
.SYNOPSIS

.DESCRIPTION

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
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify HidePSMDrives"
			# Define the HKEY_USERS root as a new drive
			New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -Scope Global | out-Null
			# Get a list of all User SID to check
			$arrRegUsers = Get-ChildItem -Path HKU:\ -ErrorAction Ignore | Select-Object Name -ErrorAction Ignore

			ForEach($user in $arrRegUsers)
			{
				$userSID = $user.Name.Replace("HKEY_USERS\","")
				Write-LogMessage -Type Debug -Msg "Checking NoDrives for user $userSID..."
				# Check PSM Local drives configuration
				$regNoDrives = @{
					"Path" = "HKU:\{0}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -f $userSID
					"ValueName" = "NoDrives";
					"ValueData" = 12;
					"outStatus" = ([ref]$myRef);
				}

				if((Compare-RegistryValue @regNoDrives) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			}
			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verify HidePSMDrives"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify HidePSMDrives.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify HidePSMDrives."
			return "Bad"
		}
	}
	End {
		Remove-PSDrive -Name HKU | out-null
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: BlockIETools
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function BlockIETools
{
<#
.SYNOPSIS

.DESCRIPTION

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
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify BlockIETools"

			# Check that IE developer tools are blocked
			$regIEDevTools = @{
				"Path" = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\IEDevTools"
				"ValueName" = "Disabled";
				"ValueData" = 1;
				"outStatus" = ([ref]$myRef);
			}

			if((Compare-RegistryValue @regIEDevTools) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			# Check that IE context menu is blocked
			$regIEContext = @{
				"Path" = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions"
				"ValueName" = "NoBrowserContextMenu";
				"ValueData" = 1;
				"outStatus" = ([ref]$myRef);
			}

			if((Compare-RegistryValue @regIEContext) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verify BlockIETools"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify BlockIETools.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify BlockIETools."
			return "Bad"
		}
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: HardenRDS
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function HardenRDS
{
<#
.SYNOPSIS

.DESCRIPTION

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
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify HardenRDS"

			# Check that IE developer tools are blocked
			$regRDPPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
			$regMinEncrypt = @{
				"Path" = $regRDPPath;
				"ValueName" = "MinEncryptionLevel";
				"ValueData" = 3;
				"outStatus" = ([ref]$myRef);
			}

			if((Compare-RegistryValue @regMinEncrypt) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			# Check that IE context menu is blocked
			$regSecurityLayer = @{
				"Path" = $regRDPPath;
				"ValueName" = "SecurityLayer";
				"ValueData" = 1;
				"outStatus" = ([ref]$myRef);
			}

			if((Compare-RegistryValue @regSecurityLayer) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verify HardenRDS"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify HardenRDS.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify HardenRDS."
			return "Bad"
		}
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: HardenPSMUsersAccess
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function HardenPSMUsersAccess
{
<#
.SYNOPSIS

.DESCRIPTION

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

        $PSM_PATH = (Get-DetectedComponents -Component "PSM").Path
		$PSM_VAULT_FILE_PATH = Join-Path -Path $PSM_PATH -ChildPath "Vault"
		$PSM_PVCONF_FILE_PATH = Join-Path -Path $PSM_PATH -ChildPath "temp\PVConfiguration.xml"
		$PSM_BASICPSM_FILE_PATH = Join-Path -Path $PSM_PATH -ChildPath "basic_psm.ini"

        [XML]$xmlPSMConfig = Get-Content -Path $PSM_PVCONF_FILE_PATH
        $PSM_RECORDING_PATH = ($xmlPSMConfig | Select-XML -XPath "//RecorderSettings" | Select-Object -ExpandProperty Node).LocalRecordingsFolder

        $PSM_BasicPSM = get-content -Path $PSM_BASICPSM_FILE_PATH | Select-String 'LogsFolder'
        $PSM_LOGS_PATH = $PSM_BasicPSM -Replace "LogsFolder=", '' -Replace '"', ''
        $PSM_LOGS_OLD_PATH = (Join-Path -Path $PSM_LOGS_PATH -ChildPath 'old')

		$PVWAInstallationPath = (Get-DetectedComponents -Component "PVWA").Path
		If($null -ne $PVWAInstallationPath)
		{
			$PVWAWebSitePath = Join-Path -Path (Get-ItemProperty HKLM:\Software\Microsoft\INetStp -Name "PathWWWRoot").PathWWWRoot -ChildPath "PasswordVault"
		}
		$CPMPath = (Get-DetectedComponents -Component "CPM").Path
		$AWS_FOLDER_PATH = Join-Path -Path $env:ProgramFiles -ChildPath "Amazon"
		$AZURE_FOLDER_PATH = "C:\WindowsAzure"
		$AZURE_PACKAGES_FOLDER_PATH = "C:\Packages"

		$userPermissions = @{
			"Path"="";
			"Identity"="";
			"Rights"="FullControl";
			"ACLType"="Deny";
			"outStatus"=([ref]$myRef);
		}
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify HardenPSMUsersAccess"
			# Set a list of paths of paths to get access to
			# OS Paths
			$accessPaths = @("$($env:SystemRoot)\explorer.exe", "$($env:SystemRoot)\SysWOW64\explorer.exe", "$($env:SystemRoot)\System32\taskmgr.exe", "$($env:SystemRoot)\SysWOW64\taskmgr.exe")
			# PSM paths
			$accessPaths += @($PSM_PATH, $PSM_VAULT_FILE_PATH)
			# PVWA paths (if installed on the same server)
			if(($null -ne $PVWAInstallationPath) -and (Test-Path $PVWAWebSitePath))
			{
				$accessPaths += @($PVWAInstallationPath, $PVWAWebSitePath)
			}
			# CPM paths (if installed on the same server)
			if(($null -ne $CPMPath) -and (Test-Path $CPMPath))
			{
				$accessPaths += @($CPMPath)
			}
			# Azure paths (if installed on the same server)
			If(($null -ne $AZURE_FOLDER_PATH) -and (Test-Path $AZURE_FOLDER_PATH))
			{
				$accessPaths += @($AZURE_FOLDER_PATH, $AZURE_PACKAGES_FOLDER_PATH)
			}
			# AWS paths (if installed on the same server)
			if(($null -ne $AWS_FOLDER_PATH) -and (Test-Path $AWS_FOLDER_PATH))
			{
				$accessPaths += @($AWS_FOLDER_PATH)
			}

			$IEPaths = @("$($env:ProgramFiles)\Internet Explorer\iexplore.exe","$(${env:ProgramFiles(x86)})\Internet Explorer\iexplore.exe")

			# Check Deny Full Control to PSMConnect, PSMAdminConnect, PSMShadowUsers
			ForEach($path in $accessPaths)
			{
				$userPermissions["Path"] = $path
				ForEach($user in @($PSM_CONNECT, $PSM_ADMIN_CONNECT, $PSM_SHADOW_USERS))
				{
					$userPermissions["Identity"] = $user
					If((Compare-UserPermissions @userPermissions) -ne "Good")
					{
						$tmpStatus += $myRef.Value + "<BR>"
						$statusChanged = $true
					}
				}
			}

			# Check deny access for IE folders for the PSM Connect and Admin Connect users
			ForEach($path in $IEPaths)
			{
				$userPermissions["Path"] = $path
				ForEach($user in @($PSM_CONNECT, $PSM_ADMIN_CONNECT))
				{
					$userPermissions["Identity"] = $user
					If((Compare-UserPermissions @userPermissions) -ne "Good")
					{
						$tmpStatus += $myRef.Value + "<BR>"
						$statusChanged = $true
					}
				}
			}

			# Check that System and Administrators group have Full control over PSM Folders
			$userPermissions["ACLType"] = "Allow"
			ForEach($path in @($PSM_VAULT_FILE_PATH, $PSM_RECORDING_PATH, $PSM_LOGS_PATH, $PSM_LOGS_OLD_PATH, $(Join-Path -Path $PSM_LOGS_PATH -ChildPath "Components"), $(Join-Path -Path $PSM_PATH -ChildPath "Components")))
			{
				$userPermissions["Path"] = $path
				ForEach($user in @($(Get-LocalAdministratorsGroupName), $(Get-LocalSystemGroupName)))
				{
					$userPermissions["Identity"] = $user
					If((Compare-UserPermissions @userPermissions) -ne "Good")
					{
						$tmpStatus += $myRef.Value + "<BR>"
						$statusChanged = $true
					}
				}
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verify HardenPSMUsersAccess"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify HardenPSMUsersAccess.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify HardenPSMUsersAccess."
			return "Bad"
		}
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: HardenSMBServices
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function HardenSMBServices
{
<#
.SYNOPSIS

.DESCRIPTION

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
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify HardenSMBServices"

			# Verify SMB Server is Disabled
			$regSMB1 = @{
				"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
				"ValueName" = "SMB1";
				"ValueData" = 0;
				"outStatus" = ([ref]$myRef);
			}

			if((Compare-RegistryValue @regSMB1) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			# Verify MRXSMB10 client service is Disabled
			$regSMB10 = @{
				"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
				"ValueName" = "Start";
				"ValueData" = 4;
				"outStatus" = ([ref]$myRef);
			}

			if((Compare-RegistryValue @regSMB10) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			# Check if the XB Services are installed
			$regXblGameSavePath = "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave"
			$regXblAuthManagerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager "
			$regXbl = @{
				"Path" = ""
				"ValueName" = "Start";
				"ValueData" = 4;
				"outStatus" = ([ref]$myRef);
			}

			If(Test-Path $regXblGameSavePath)
			{
				$regXbl["Path"] = $regXblGameSavePath
				if((Compare-RegistryValue @regXbl) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			}

			If(Test-Path $regXblAuthManagerPath)
			{
				$regXbl["Path"] = $regXblAuthManagerPath
				if((Compare-RegistryValue @regXbl) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verify HardenSMBServices"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify HardenSMBServices.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify HardenSMBServices."
			return "Bad"
		}
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PSM_CredFileHardening
# Description....: Return type of restrictions added the the credential file
# Parameters.....: Credential file location
# Return Values..: Verification Type
# =================================================================================================================================
Function PSM_CredFileHardening
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
        $PSMPath = ""
        $tmpValue = ""
    }

    Process {
        Try{
   			Write-LogMessage -Type Info -Msg "Start validating hardening of PSM credential file"
            $PSMPath = (Get-DetectedComponents -Component "PSM").Path
            $credentialsFolder = join-path -Path $PSMPath -ChildPath 'Vault'
			# Go over all PSM Cred Files in the folder
			ForEach ($credFile in (Get-ChildItem -Path $credentialsFolder -Filter *.cred))
			{
				Write-LogMessage -Type Debug -Msg "Checking '$($credFile.Name)' credential file"
				if((Test-CredFileVerificationType -CredentialFilePath $credFile.FullName -outStatus ([ref]$myRef)) -ne "Good")
				{
					$res = "Warning"
				}
				$tmpValue += $myRef.value + "<BR>"
			}

            [ref]$refOutput.Value = $tmpValue
            Write-LogMessage -Type Info -Msg "Finish validating PSM component credential file"
   			return $res
        } catch {
			Write-LogMessage -Type "Error" -Msg "Could not validate the PSM component credential file.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate PSM component credential file [0]."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}