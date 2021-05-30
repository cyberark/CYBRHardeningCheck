﻿# @FUNCTION@ ======================================================================================================================
# Name...........: ImportingINFConfiguration
# Description....: Importing an INF File to the Local Machine
# Parameters.....: Parameters, Reference Status
# Return Values..: $true / $false
# =================================================================================================================================
Function ImportingINFConfiguration
{
<#
.SYNOPSIS
	Importing an INF File to the Local Machine
.DESCRIPTION
	Importing an INF File to the Local Machine
.PARAMETER Parameters
	(Optional) Parameters from the Configuration
.PARAMETER Reference Output
	Reference to the Step Output
#>
	param(
		[Parameter(Mandatory=$false)]
		[array]$Parameters = $null,
		[Parameter(Mandatory=$false)]
		[ref]$refOutput
	)

	Begin {
		$SDBFileName = Get-CurrentComponentFolderPath -FileName "CYBR_Hardening_secedit_DB.sdb"
		$logName = "CYBR_Hardening_secedit_$((Get-Date -Format $g_DateTimePattern).Replace("/","-").Replace(":","-").Replace(" ","_")).log"
		$AnalyzeLogName = Get-CurrentComponentFolderPath -FileName $logName
		$myRef = ""
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start comparing security configurations"
			Write-LogMessage -Type Verbose -Msg "Passing $($Parameters.Count) parameters"

			If($(Get-DetectedComponents).DomainMember)
			{
				Write-LogMessage -Type Debug -Msg "Analyzing secedit INF file with the Domain GPO Machine security policy"
				$INFconfigFileName = $($Parameters | Where-Object { $_.Name -eq "DomainINFconfigFileName" }).Value
			}
			Else
			{				
				Write-LogMessage -Type Debug -Msg "Analyzing secedit INF file with the Local Machine security policy"
				$INFconfigFileName = $($Parameters | Where-Object { ($_.Name -eq "INFconfigFileName") -or ($_.Name -eq "LocalINFconfigFileName") }).Value
			}
			# OS Specific treatment
			If($INFconfigFileName -match "@OS@")
			{
				$INFconfigFileName = Get-ParsedFileNameByOS -fileName $INFconfigFileName
			}
			# Components specific treatment
			If($INFconfigFileName -match "@Component@")
			{
				$INFconfigFileName = Get-ParsedFileNameByComponent -fileName $INFconfigFileName
			}

			# Get the Component relative INF file path
			$INFconfigFilePath = Get-CurrentComponentFolderPath -FileName $INFconfigFileName
			
			# $seceditRetVaule = secedit /import /db $SDBFileName /cfg $INFconfigFilePath /overwrite /quiet

			# if ((-not (Test-Path $SDBFileName)) -Or ($LASTEXITCODE -eq 1))
			# {
			# 	throw "Importing INF file: $INFconfigFileName has failed - Unable to create SDB file"
			# 	return "Bad"
			# }

			$seceditRetVaule = secedit /analyze /db $SDBFileName /cfg $INFconfigFilePath /overwrite /quiet /log $AnalyzeLogName
			# $seceditRetVaule = secedit /analyze /db $SDBFileName /log $AnalyzeLogName

			if ($LASTEXITCODE -eq 1)
			{
				throw "Analyze security configuration has failed - analysis log: $AnalyzeLogName. Error: $seceditRetVaule"
				return "Bad"
			}

			Write-LogMessage -Type Debug -Msg "Review the analysis log: $AnalyzeLogName for more information"

			Write-LogMessage -Type Info -Msg "Finished comparing security configurations"
			$retValue = $(Get-SeceditAnalysisResults -path $AnalyzeLogName -outStatus ([ref]$myRef))

			[ref]$refOutput.Value = $myRef.Value
			return $retValue

		} Catch {
			Write-LogMessage -Type "Error" -Msg "Could not complete security analysis.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not complete security analysis."
			return "Bad"
		}
	}
	End {
		If(Test-Path $SDBFileName)
		{
			Remove-Item -Path $SDBFileName -Force
		}
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ValidateServerRoles
# Description....: This function checks for unnecessary roles
# Parameters.....: Parameters, Reference Status
# Return Values..: $true / $false
# =================================================================================================================================
Function ValidateServerRoles
{
<#
.SYNOPSIS
	Validate only necessary Windows Roles and Features
.DESCRIPTION
	This function checks for unnecessary roles
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
		# Pre-Checks
		$myRef = ""
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start validating server roles and features"
			Write-LogMessage -Type Verbose -Msg "Passing $($Parameters.Count) parameters"

			$rolesToCheck = @("AS-TCP-Port-Sharing","AS-Named-Pipes","AS-TCP-Activation","DirectAccess-VPN","Routing","Web-Application-Proxy","Web-Log-Libraries","Web-Http-Tracing","Web-CertProvider","Web-Client-Auth","Web-Digest-Auth","Web-Cert-Auth","Web-IP-Security","Web-Url-Auth","Web-Includes","WDS")
			$featuresToCheck = @("GPMC","Web-WHC","InkAndHandwritingServices","Server-Media-Foundation","CMAK","RSAT","Telnet-Client","Windows-Internal-Database","FS-SMB1")

			if($Parameters.Count -gt 0)
			{
				#remove Server-Media-Foundation from features list if PSM is part of the installation
				$isPSMInstalledParam = $($Parameters | Where-Object Name -eq "IsPSMInstalled").Value
				#$isPsmInstalled = Test-IsPSMInstalled
				if (($isPSMInstalledParam -eq 'True') -or $isPsmInstalled) {
					$featuresToCheck = $featuresToCheck | Where-Object {$_ -ne "Server-Media-Foundation"}
				}
			}

			Write-LogMessage -Type Debug -Msg "Validate roles $($rolesToCheck -join ',')"
			Write-LogMessage -Type Debug -Msg "Validate features $($featuresToCheck -join ',')"
			$result = Test-InstalledWindowsRole ($rolesToCheck+$featuresToCheck) ([ref]$myRef)
			[ref]$refOutput.Value = $myRef.Value

			Write-LogMessage -Type Info -Msg "Finish validating server roles and features"
			return $result
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate all roles/features.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate all roles/features.  Error: $($_.Exception.Message)"
			return "Bad"
		}
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: EnableScreenSaver
# Description....: Checks if the screen saver is disabled
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function EnableScreenSaver
{
<#
.SYNOPSIS
	Checks if the screen saver is disabled
.DESCRIPTION
	Checks if the screen saver is disabled
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
			Write-LogMessage -Type Info -Msg "Start EnableScreenSaver"

			$UserDir = "$($env:windir)\system32\GroupPolicy\User\registry.pol"
			$RegPath = "Software\Policies\Microsoft\Windows\Control Panel\Desktop"
			try{
				if((Compare-PolicyEntry -EntryTitle "Enable screen saver" -UserDir $UserDir -RegPath $RegPath -RegName 'ScreenSaveActive' -RegData '1' -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			} catch {
				Write-LogMessage -Type "Error" -Msg "EnableScreenSaver: Could not validate 'Enable screen saver' property.  Error: $(Join-ExceptionMessage $_.Exception)"
				$tmpStatus += "Error validating 'Enable screen saver' property<BR>"
				$statusChanged = $true
			}
			try{
				if((Compare-PolicyEntry -EntryTitle "Force specific screen saver" -UserDir $UserDir -RegPath $RegPath -RegName 'SCRNSAVE.EXE' -RegData 'C:\Windows\System32\Ribbons.scr' -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			} catch {
				Write-LogMessage -Type "Error" -Msg "EnableScreenSaver: Could not validate 'Force specific screen saver' property.  Error: $(Join-ExceptionMessage $_.Exception)"
				$tmpStatus += "Error validating 'Force specific screen saver' property<BR>"
				$statusChanged = $true
			}
			try{
				if((Compare-PolicyEntry -EntryTitle "Password protect the screen saver" -UserDir $UserDir -RegPath $RegPath -RegName 'ScreenSaverIsSecure' -RegData '1' -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			} catch {
				Write-LogMessage -Type "Error" -Msg "EnableScreenSaver: Could not validate 'Password protect the screen saver' property.  Error: $(Join-ExceptionMessage $_.Exception)"
				$tmpStatus += "Error validating 'Password protect the screen saver' property<BR>"
				$statusChanged = $true
			}
			try{
				if((Compare-PolicyEntry -EntryTitle "Screen saver timeout" -UserDir $UserDir -RegPath $RegPath -RegName 'ScreenSaveTimeOut' -RegData '600' -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			} catch {
				Write-LogMessage -Type "Error" -Msg "EnableScreenSaver: Could not validate 'Screen saver timeout' property.  Error: $(Join-ExceptionMessage $_.Exception)"
				$tmpStatus += "Error validating 'Screen saver timeout' property<BR>"
				$statusChanged = $true
			}
			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}
			Write-LogMessage -Type Info -Msg "Finish EnableScreenSaver"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate screen saver status.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate screen saver status.  Error: $($_.Exception.Message)"
			return "Bad"
		}
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: AdvancedAuditPolicyConfiguration
# Description....: Advanced Audit Policy Configuration
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function AdvancedAuditPolicyConfiguration
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
		# Pre-Checks
		$myRef = ""
		$res = "Good"
		$tmpStatus = ""
		$statusChanged = $false
	}
	Process {
		Try {
			Write-LogMessage -Type Info -Msg "Start validating Advanced Audit Policy Configuration"
			Write-LogMessage -Type Verbose -Msg "Passing $($Parameters.Count) parameters"
			If($(Get-DetectedComponents).DomainMember)
			{
				$AuditConfigFile = $($Parameters | Where-Object { $_.Name -eq "DomainAuditConfigFileName" }).Value
			}
			Else
			{				
				$AuditConfigFile = $($Parameters | Where-Object { ($_.Name -eq "AuditConfigFileName") -or ($_.Name -eq "LocalAuditConfigFileName") }).Value
			}
			# OS Specific treatment
			If($AuditConfigFile -match "@OS@")
			{
				$AuditConfigFile = Get-ParsedFileNameByOS -fileName $AuditConfigFile
			}
			# Components specific treatment
			If($AuditConfigFile -match "@Component@")
			{
				$AuditConfigFile = Get-ParsedFileNameByComponent -fileName $AuditConfigFile
			}

			# Get the Component relative INF file path
			$AuditConfigFilePath = Get-CurrentComponentFolderPath -FileName $AuditConfigFile

			ForEach ($audit in $(Import-Csv $AuditConfigFilePath))
			{
				switch($audit.'Setting Value')
				{
					0 {
						if((Compare-AdvancedAuditPolicySubCategory -subcategory $audit.Subcategory -success "disable" -failure "disable" -outStatus ([ref]$myRef)) -ne "Good")
						{
							$tmpStatus += $myRef.Value + "<BR>"
							$statusChanged = $true
						}
						break
					}
					1 {
						if((Compare-AdvancedAuditPolicySubCategory -subcategory $audit.Subcategory -success "enable" -failure "disable" -outStatus ([ref]$myRef)) -ne "Good")
						{
							$tmpStatus += $myRef.Value + "<BR>"
							$statusChanged = $true
						}
						break
					}
					2 {
						if((Compare-AdvancedAuditPolicySubCategory -subcategory $audit.Subcategory -success "disable" -failure "enable" -outStatus ([ref]$myRef)) -ne "Good")
						{
							$tmpStatus += $myRef.Value + "<BR>"
							$statusChanged = $true
						}
						break
					}
					3 {
						if((Compare-AdvancedAuditPolicySubCategory -subcategory $audit.Subcategory -success "enable" -failure "enable" -outStatus ([ref]$myRef)) -ne "Good")
						{
							$tmpStatus += $myRef.Value + "<BR>"
							$statusChanged = $true
						}
						break
					}
				}
				$output += $myRef.Value
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}
			Write-LogMessage -Type Info -Msg "Finish validating Advanced Audit Policy Configuration"

			return $res

		} Catch {
			Write-LogMessage -Type "Error" -Msg "Could not complete Advanced Audit Policy Configuration validation.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not complete Advanced Audit Policy Configuration validation."
			return "Bad"
		}
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: RemoteDesktopServices
# Description....: Check Remote Desktop Services settings
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function RemoteDesktopServices
{
<#
.SYNOPSIS
	Remote Desktop Services
.DESCRIPTION
	Remote Desktop Services
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
			Write-LogMessage -Type Info -Msg "Start RemoteDesktopServices"

			$UserDir = "$($env:windir)\system32\GroupPolicy\User\registry.pol"
			$RegPath = "Software\Policies\Microsoft\Windows NT\Terminal Services"

			if((Compare-PolicyEntry -EntryTitle "Set rules for remote control of Remote Desktop Services user sessions" -UserDir $UserDir -RegPath $RegPath -RegName 'Shadow' -RegData '4' -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			if((Compare-PolicyEntry -EntryTitle "Set time limit for active but idle Remote Desktop Services sessions" -UserDir $UserDir -RegPath $RegPath -RegName 'MaxIdleTime' -RegData '1800000' -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			if((Compare-PolicyEntry -EntryTitle "Do not allow Clipboard redirection" -UserDir $UserDir -RegPath $RegPath -RegName 'fDisableClip' -RegData '1' -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			if((Compare-PolicyEntry -EntryTitle "End session when time limits are reached" -UserDir $UserDir -RegPath $RegPath -RegName 'fResetBroken' -RegData '1' -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}
			Write-LogMessage -Type Info -Msg "Finish RemoteDesktopServices"

			return $res
		}
		catch{
			Write-LogMessage -Type Error -Msg "Could not validate Remote Server Services status.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate Remote Server Services status."
			return "Bad"
		}
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: EventLogSizeAndRetention
# Description....: Check Event Log and Retention settings
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function EventLogSizeAndRetention
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
		$maxsize=102432768
		$retention="false"
		$res = "Good"
		$tmpStatus = ""
		$myRef = ""
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start validating Event Log Size And Retention"
			If((Compare-EventLogSizeAndRetentionSettings -LogName "Application" -Size $maxsize -SaveRetention $retention -outStatus ([ref]$myRef)) -ne "Good")
			{
                $res = "Warning"
			}
			$tmpStatus += $myRef.Value + "<BR>"

			If((Compare-EventLogSizeAndRetentionSettings -LogName "Security" -Size $maxsize -SaveRetention $retention -outStatus ([ref]$myRef)) -ne "Good")
			{
                $res = "Warning"
			}
			$tmpStatus += $myRef.Value + "<BR>"

			If((Compare-EventLogSizeAndRetentionSettings -LogName "System" -Size $maxsize -SaveRetention $retention -outStatus ([ref]$myRef)) -ne "Good")
			{
                $res = "Warning"
			}
			$tmpStatus += $myRef.Value + "<BR>"

            [ref]$refOutput.Value = $tmpStatus
			Write-LogMessage -Type Info -Msg "Finish validating Event Log Size And Retention"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate Event log size and retention status.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate Event log size and retention status."
			return "Bad"
		}
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: RegistryAudits
# Description....: Check Registry Audits access control
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function RegistryAudits
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
		# Pre-Checks
		$res = "Good"
		$tmpStatus = ""
		$statusChanged = $false
		$myRef = ""
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start validating Registry Audits"

			$AccessRulesArray = @()
			# principal, rightsToAudit, inheritanceFlags, propagationFlags, auditFlags
			$AccessRule1 = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone","SetValue","ContainerInherit","none","Success")

			$AccessRule2 = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone","CreateSubKey, CreateLink, Delete,ReadPermissions,ChangePermissions","ContainerInherit","none","Success, Failure")
			$AccessRulesArray += $AccessRule1, $AccessRule2
			If((Compare-AuditRulesFromPath -Path "HKLM:\SOFTWARE" -AccessRules $AccessRulesArray -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += "SOFTWARE registry Key does not have the required access control rules."
				$tmpStatus += $myRef.output + "<BR>"
				$statusChanged = $true
			}
			If((Compare-AuditRulesFromPath -Path "HKLM:\SYSTEM" -AccessRules $AccessRulesArray -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += "SYSTEM registry Key does not have the required access control rules."
				$tmpStatus += $myRef.output + "<BR>"
				$statusChanged = $true
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}
			Write-LogMessage -Type Info -Msg "Finish validating Registry Audits"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate Registry Audits status.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate Registry Audits status."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: RegistryPermissions
# Description....: Check Registry permissions
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function RegistryPermissions
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
		# Pre-Checks
		$myRef = ""
		$res = "Good"
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start validating Registry Permissions"

			$path = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg"

			$res = Compare-UserPermissions -Path $path -Identity $(Get-LocalAdministrators) -Rights "FullControl" -outStatus ([ref]$myRef)
			[ref]$refOutput.Value = $myRef.Value

			Write-LogMessage -Type Info -Msg "Finish validating Registry Permissions"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate Registry permissions.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate Registry permissions."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: FileSystemPermissions
# Description....: Validates unnecessary permissions on %SystemRoot%\System32\Config and %SystemRoot%\System32\Config\RegBack.
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function FileSystemPermissions
{
<#
.SYNOPSIS
	Validates unnecessary permissions on %SystemRoot%\System32\Config and %SystemRoot%\System32\Config\RegBack.
.DESCRIPTION
	Validates unnecessary permissions on %SystemRoot%\System32\Config and %SystemRoot%\System32\Config\RegBack.
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
		# Pre-Checks
		$myRef = ""
		$tmpStatus = ""
		$res = "Good"
		$ConfigPath = "$($env:SystemRoot)\System32\config"
		$ConfigRegBackPath = "$ConfigPath\RegBack"
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start validating File System Permissions"

			# Check Administrators Access
			If((Compare-UserPermissions -Path $ConfigPath -Identity $(Get-LocalAdministrators) -Rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			If((Compare-UserPermissions -Path $ConfigRegBackPath -Identity $(Get-LocalAdministrators) -Rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			# Check System Access
			If((Compare-UserPermissions -Path $ConfigPath -Identity $(Get-LocalSystem) -Rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			If((Compare-UserPermissions -Path $ConfigRegBackPath -Identity $(Get-LocalSystem) -Rights "FullControl" -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			# Verify if Administrators and System are the only ones that has permissions
			If((Compare-AmountOfUserPermissions -Path $ConfigPath -amount 2 -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			If((Compare-AmountOfUserPermissions -Path $ConfigRegBackPath -amount 2 -outStatus ([ref]$myRef)) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			[ref]$refOutput.Value = $myRef.Value

			Write-LogMessage -Type Info -Msg "Finish validating File System Permissions"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate File System permissions.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate File System permissions."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: FileSystemAudit
# Description....: Check audit access rules on %SystemRoot%\System32\Config and %SystemRoot%\System32\Config\RegBack.
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function FileSystemAudit
{
<#
.SYNOPSIS
	Method to query a service status
.DESCRIPTION
	Check Registry Audits settings
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

	Begin{
		$tmpStatus = ""
		$statusChanged = $false
		$myRef = ""
		$res = "Good"
	}
	Process{
			try{
				$systemConfig = "$env:SystemRoot\system32\config"
				$ConfigRegBackPath = "$env:SystemRoot\System32\Config\RegBack"

				Write-LogMessage -Type Info -Msg "Checking audit rules configuration for: $systemConfig"

				$AccessRulesArray = @()
				# principal, rightsToAudit, inheritanceFlags, propagationFlags, auditFlags
				$AccessRule1 = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","ExecuteFile,ReadData,ReadAttributes,ReadExtendedAttributes","ContainerInherit","none","Failure")

				$AccessRule2 = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","CreateFiles,AppendData,WriteAttributes,WriteExtendedAttributes,DeleteSubdirectoriesAndFiles,Delete,ChangePermissions,TakeOwnership","ContainerInherit","none","Success, Failure")
				$AccessRulesArray += $AccessRule1, $AccessRule2


				If((Compare-AuditRulesFromPath -path $systemConfig -accessRules $AccessRulesArray -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
				If((Compare-AuditRulesFromPath -path $ConfigRegBackPath -accessRules $AccessRulesArray -outStatus ([ref]$myRef)) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}

				If($statusChanged)
				{
					$res = "Warning"
					[ref]$refOutput.Value = $tmpStatus
				}
			}
			catch
			{
				Write-LogMessage -Type "Error" -Msg "Failed to check file system audit access rules."
				[ref]$refOutput.Value = "Failed to check file system audit access rules."
				$res = "Bad"
			}
			return $res
	}
	End{
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: DisableServices
# Description....: Disabling The following services:  "Routing and Remote Access", "Smart Card", "Smart Card Removal Policy", "SNMP Trap", "Special Administration Console Helper","Windows Error Reporting Service", "WinHTTP Web Proxy Auto-Discovery Service"
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function DisableServices
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
		# Pre-Checks
		$myRef = ""
		$res = "Good"
		$tmpStatus = ""
		$statusChanged = $false
		$serviceList = @("Routing and Remote Access", "Smart Card", "Smart Card Removal Policy",
						 "SNMP Trap", "Special Administration Console Helper","Windows Error Reporting Service",
						 "WinHTTP Web Proxy Auto-Discovery Service")
	}
	Process {

		Write-LogMessage -Type Info -Msg "Start verification of disabled status of the following services: $($serviceList -join ", ")"
		try{
			ForEach ($svc in $serviceList)
			{
				Try {
					If((Compare-ServiceStatus -ServiceName $svc -ServiceStartMode "Disabled" -outStatus ([ref]$myRef)) -ne "Good")
					{
						$tmpStatus += $myRef.Value + "<BR>"
						$statusChanged = $true
					}
				} Catch {
					Write-LogMessage -Type "Error" -Msg "Could not validate service '$svc' status.  Error: $(Join-ExceptionMessage $_.Exception)"
					$tmpStatus += "Could not validate service '$svc' status."
					$statusChanged = $true
				}
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish verification of disabled status of the following services: $($serviceList -join ", ")"
		}
		catch
		{
			Write-LogMessage -Type "Error" -Msg "Failed to verify services status for disabled."
			[ref]$refOutput.Value = "Failed to verify services status for disabled."
			$res = "Bad"
		}
		return $res
	}
	End {
		# Write output to HTML
	}
}
