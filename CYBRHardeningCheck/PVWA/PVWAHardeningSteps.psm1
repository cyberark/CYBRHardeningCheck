# @FUNCTION@ ======================================================================================================================
# Name...........: Initialize-WebAdministrationModule
# Description....: Loads the Web Administration IIS module to run IIS commands
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Initialize-WebAdministrationModule
{
<#
.SYNOPSIS
	Loads the Web Administration module
.DESCRIPTION
	Loads the Web Administration IIS module to run IIS commands
#>
	param(
	)

	If (Get-Module -ListAvailable -Name WebAdministration) {
		If(-not (Get-Module -Name WebAdministration)) {
			Write-LogMessage -Type Debug -Msg "Loading WebAdministration Module..."
			Import-Module WebAdministration
			Write-LogMessage -Type Debug -Msg "WebAdministration Module loaded"
		}
	}
	Else
	{
		throw "WebAdministration Module doesn't exists"
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_IIS_Registry_Shares
# Description....: DisableAdminShares. This function makes a registry change that disables automatic shares on the PVWA server.
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_IIS_Registry_Shares
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
		$myRef = ""
		$regAutoShare = @{
				"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
				"ValueName" = "AutoShareServer";
				"ValueData" = 0;
				"outStatus" = ([ref]$myRef);
			}
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify PVWA IIS Registry Shares"
			$res = (Compare-RegistryValue @regAutoShare)
			[ref]$refOutput.Value = $myRef.Value

			Write-LogMessage -Type Info -Msg "Finish verify PVWA IIS Registry Shares"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify PVWA IIS Registry Shares.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify PVWA IIS Registry Shares."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_IIS_WebDAV
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_IIS_WebDAV
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
		$myRef = ""
		$webDAVRoleName = "Web-DAV-Publishing"
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify if Web DAV Publishing is installed"

			$res = (Test-InstalledWindowsRole -Roles $webDAVRoleName -outStatus ([ref]$myRef))
			[ref]$refOutput.Value = $myRef.Value

			Write-LogMessage -Type Info -Msg "Finish verify if Web DAV Publishing is installed"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify if Web DAV Publishing is installed.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify if Web DAV Publishing is installed."
			return "Bad"
		}

	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_Cryptography_Settings
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_Cryptography_Settings
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
		[ref]$refOutputs
	)

	Begin {
		$res = "Good"
		$iisPath = "iis:\Sites\Default Web Site\PasswordVault"
		$filter = "/appSettings/add[@key='AdvancedFIPSCryptography']"
		$value = "yes"
	}
	Process {
		try{
			Write-LogMessage -Type Info -Msg "Start verify PVWA Cryptography Mode Settings"

			Initialize-WebAdministrationModule

			$currentValue = Get-WebConfigurationProperty -pspath $iisPath -filter $filter -name $value
			if($null -ne $currentValue)
			{
				if($currentValue.ToLower() -ne $value)
				{
					$res = "Warning"
					[ref]$refOutput.Value = "AdvancedFIPSCryptography is not properly set in PVWA Configuration. Current value: $currentValue"
				}
			}
			else
			{
				$res = "Warning"
				[ref]$refOutput.Value = "AdvancedFIPSCryptography is not set in PVWA Configuration"
			}

			Write-LogMessage -Type Info -Msg "Finish verify if Web DAV Publishing is installed"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify PVWA Cryptography Mode Settings.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify PVWA Cryptography Mode Settings."
			return "Bad"
		}

	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_IIS_MimeTypes
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_IIS_MimeTypes
{
<#
.SYNOPSIS
	Check IIS Mime Types
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
		$allowedMimeTypes = ".css",".csv",".dll",".dll.config",".eot",".gif",".htc",".htm",".html",".jar",".jpe",".jpeg",".jpg",".js",".json",".png",".swf",".ttf",".txt",".xls",".xlsx",".xml",".svg",".ico"
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start verify allowed mime types"

			$sysdir = [environment]::SystemDirectory
			$configPath = "$sysdir\inetsrv\config\applicationHost.config"
			$configXML = [xml](Get-Content $configPath)
			$NotAllowedMimeTypes = ($configXML.configuration.'system.webServer'.staticContent.mimeMap | Where-Object { $_.FileExtension -notin $allowedMimeTypes })
			if($NotAllowedMimeTypes.Count -gt 0)
			{
				[ref]$refOutput.Value = "There are $($NotAllowedMimeTypes.Count) mime types that does not adhere the Hardening best practice"
				Write-LogMessage -Type Info -Msg "Not allowed mime types found: $($NotAllowedMimeTypes.FileExtension -join ",")"
				$res = "Warning"
			}

			Write-LogMessage -Type Info -Msg "Finish verify allowed mime types"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify allowed mime types.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify allowed mime types."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_AnonymousAuthentication
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_AnonymousAuthentication
{
<#
.SYNOPSIS
	Check if Application Pools use Anonymous Authentication
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
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start verify Anonymous Authentication in application pools"

			$sysdir = [environment]::SystemDirectory
			$configPath = "$sysdir\inetsrv\config\applicationHost.config"
			$configXML = [xml](Get-Content $configPath)
			$AnonAuth = ($configXML.configuration.'system.webServer'.security.authentication.anonymousAuthentication)
			ForEach($auth in $AnonAuth)
			{
				if(![string]::IsNullOrEmpty($auth.userName))
				{
					[ref]$refOutput.Value = "There are Application pools that are using default user. Set anonymous user identity to Application pool identity."
					Write-LogMessage -Type Info -Msg "There are Application pools that are using default user (User name: $($auth.userName). Set anonymous user identity to Application pool identity."
					$res = "Warning"
				}
			}
			Write-LogMessage -Type Info -Msg "Finish verify Anonymous Authentication in application pools"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify Anonymous Authentication in application pools.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify Anonymous Authentication in application pools."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_DirectoryBrowsing
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_DirectoryBrowsing
{
<#
.SYNOPSIS
	Check if PVWA uses Directory Browsing
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
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start verify Directory Browsing"

			$sysdir = [environment]::SystemDirectory
			$configPath = "$sysdir\inetsrv\config\applicationHost.config"
			$configXML = [xml](Get-Content $configPath)
			$DirectoryBrowsing = ($configXML.configuration.directoryBrowse)
			ForEach($item in $DirectoryBrowsing)
			{
				if($item.enabled)
				{
					[ref]$refOutput.Value = "PVWA is using Directory Browsing feature. Disable this feature."
					Write-LogMessage -Type Info -Msg "PVWA is using Directory Browsing feature. Disable this feature."
					$res = "Warning"
				}
			}
			Write-LogMessage -Type Info -Msg "Finish verify Directory Browsing"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not verify Directory Browsing.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not verify Directory Browsing."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_IIS_SSL_TLS_Settings
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_IIS_SSL_TLS_Settings
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
		$statusChanged = $false
		$myRef = ""
		$versionsToDisable = "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"
		$versionToEnable = "TLS 1.2"
		$clientPathFormat = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\Client"
		$serverPathFormat = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\Server"
		$DOT_NET_64bit_Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
		$DOT_NET_32bit_Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
		$DOT_NET = @{
				"Path" = ""
				"ValueName" = "SchUseStrongCrypto";
				"ValueData" = 1;
				"outStatus" = ([ref]$myRef);
			}
		$disabled = @{
				"Path" = ""
				"ValueName" = "DisabledByDefault";
				"ValueData" = 0;
				"outStatus" = ([ref]$myRef);
			}
		$enabled = @{
				"Path" = ""
				"ValueName" = "Enabled";
				"ValueData" = 1;
				"outStatus" = ([ref]$myRef);
			}
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating hardening machine use only TLS 1.2"

			$clientPathVersionToEnable = $clientPathFormat -f $versionToEnable
			$serverPathVersionToEnable = $serverPathFormat -f $versionToEnable


			For ($i=0; $i -lt $versionsToDisable.Count; $i++)
			{
				$version = $versionsToDisable[$i]
				$regClientPath = $clientPathFormat -f $version
				$regServerPath = $serverPathFormat -f $version
				$disabled["ValueData"] = 1
				$enabled["ValueData"] = 0
				# Verify client version is Disabled
				$disabled["Path"] = $regClientPath
				if((Compare-RegistryValue @disabled) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
				$enabled["Path"] = $regClientPath
				if((Compare-RegistryValue @enabled) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}

				# Verify server version is Disabled
				$disabled["Path"] = $regServerPath
				if((Compare-RegistryValue @disabled) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
				$enabled["Path"] = $regServerPath
				if((Compare-RegistryValue @enabled) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			}

			# Verify TLS 1.2 client version is enabled
			$disabled["Path"] = $clientPathVersionToEnable
			$disabled["ValueData"] = 0
			$enabled["Path"] = $clientPathVersionToEnable
			$enabled["ValueData"] = 1
			if((Compare-RegistryValue @disabled) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			if((Compare-RegistryValue @enabled) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			# Verify TLS 1.2 server version is enabled
			$disabled["Path"] = $serverPathVersionToEnable
			$enabled["Path"] = $serverPathVersionToEnable
			if((Compare-RegistryValue @disabled) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			if((Compare-RegistryValue @enabled) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			# Verify .NET framework TLS1.2 is enabled
			$DOT_NET["Path"] = $DOT_NET_64bit_Path
			if((Compare-RegistryValue @DOT_NET) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			$DOT_NET["Path"] = $DOT_NET_32bit_Path
			if((Compare-RegistryValue @DOT_NET) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish validating hardening machine use only TLS 1.2"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate hardening machine use only TLS 1.2.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate hardening machine use only TLS 1.2."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_IIS_Cypher_Suites
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_IIS_Cypher_Suites
{
<#
.SYNOPSIS
	Method to check the IIS Chyper suites
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
		$regCyphersSuites = @{
				"Path" = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
				"ValueName" = "Functions";
				"ValueData" = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 TLS_RSA_WITH_AES_128_GCM_SHA256";
				"outStatus" = ([ref]$myRef);
			}
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating IIS Cypher Suites"
			Write-LogMessage -Type Info -Msg "Start validating Cryptography Cypher Suites configuration"

			if((Compare-RegistryValue @regCyphersSuites) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			Write-LogMessage -Type Info -Msg "Finish validating Cryptography Cypher Suites configuration"

			Write-LogMessage -Type Info -Msg "Start validating RC4 Cypher Suites configuration"

			$regCyphersSuites.Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\{0}"
			$regCyphersSuites.ValueName = "Enabled"
			$regCyphersSuites.ValueData = 0
			#For example: RC4 40$([char]0x2215)128 will be RC4 40\128
			$RC4versions = "RC4 40$([char]0x2215)128",
							"RC4 56$([char]0x2215)128",
							"RC4 64$([char]0x2215)128",
							"RC4 128$([char]0x2215)128"

			ForEach($version in $RC4versions)
			{
				$regRC4Config = $regCyphersSuites
				$regRC4Config.Path = $regCyphersSuites.Path -f $version
				if((Compare-RegistryValue @regRC4Config) -ne "Good")
				{
					$tmpStatus += $myRef.Value + "<BR>"
					$statusChanged = $true
				}
			}

			Write-LogMessage -Type Info -Msg "Finish validating RC4 Cypher Suites configuration"

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish validating IIS Cypher Suites"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate Cypher Suites.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate Cypher Suites."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_Scheduled_Task_Service_LocalUser
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_Scheduled_Task_Service_LocalUser
{
<#
.SYNOPSIS
	Validates that the PVWA Scheduled Task Service is running with a local user and has the appropriate rights to run as a service
.DESCRIPTION
	Validates that the PVWA Scheduled Task Service is running with a local user and has the appropriate rights to run as a service
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
		$serviceName = "CyberArk Scheduled Tasks"
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating Scheduled Task Service configuration"
			$PVWAServiceUserName = $($Parameters | Where-Object Name -eq "PVWAServiceUserName").Value

			# Get the PVWA working directory
            $pvwaPath = (Get-DetectedComponents -Component "PVWA").Path
			$pvwaServicesPath = join-path -path $pvwaPath -ChildPath 'services'
            $pvwaServicesLogsPath = Join-Path -Path $pvwaServicesPath -ChildPath "Logs"

			$pvwaService = @{
				"serviceName" = $serviceName;
				"userName" = $PVWAServiceUserName;
				"outStatus" = ([ref]$myRef);
			}
			if((Test-ServiceRunWithLocalUser @pvwaService) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			$userPermissions = @{
				"Path"=$pvwaPath;
				"Identity"="";
				"Rights"="FullControl";
				"ACLType"="Allow";
				"outStatus"=([ref]$myRef);
			}

			# Verify Local Administrator has Full Control rights on the PVWA installation path
			$userPermissions["Identity"] = $(Get-LocalAdministrators)
			if((Compare-UserPermissions @userPermissions) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			# Verify Local System has Full Control rights on the PVWA installation path
			$userPermissions["Identity"] = $(Get-LocalSystem)
			if((Compare-UserPermissions @userPermissions) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			# Verify the PVWA Local user has Read and Execute rights on the PVWA installation path
			$userPermissions["Identity"] = $PVWAServiceUserName
			$userPermissions["Rights"] = "ReadAndExecute"
			if((Compare-UserPermissions @userPermissions) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			# Verify if Administrators, System and the PVWA User are the only ones that has permissions
			$pvwaFolderPermissionsAmount = @{
				"Path"=$pvwaPath;
				"Amount"=3;
				"outStatus"=([ref]$myRef);
			}
			If((Compare-AmountOfUserPermissions @pvwaFolderPermissionsAmount) -ne "Good")
			{
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}
			$pvwaFolderPermissionsAmount["Path"] = $pvwaServicesLogsPath
			If((Compare-AmountOfUserPermissions @pvwaFolderPermissionsAmount) -ne "Good")
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

			Write-LogMessage -Type Info -Msg "Finish validating Scheduled Task Service configuration"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate Scheduled Task Service configuration.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate Scheduled Task Service configuration."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_NonSystemDrive
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_NonSystemDrive
{
<#
.SYNOPSIS
	Validates that PVWA is not installed on the system drive
.DESCRIPTION
	Returns the Status of the validation of PVWA installed on System drive
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
		$regIISSettings = @{
				"Path" = ""
				"ValueName" = "";
				"ValueData" = "";
				"outStatus" = ([ref]$myRef);
			}
		$systemDriveIISPath = Join-Path -Path $ENV:SystemDrive -ChildPath "inetpub\wwwroot"
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating PVWA is not installed on the system drive"
			$PVWAIISDrive = $($Parameters | Where-Object Name -eq "PVWAIISDrive").Value
			$PVWAIISLogsDrive = $($Parameters | Where-Object Name -eq "PVWAIISLogsDrive").Value

			Initialize-WebAdministrationModule

			# Check Inetpub and wwwroot location
			$currentIISPath = (Get-WebFilePath IIS:\Sites\'Default Web Site').FullName
			If($currentIISPath -like $systemDriveIISPath)
			{
				# IIS is installed on the system drive
				$tmpStatus += "IIS is installed on the System Drive in the defualt location"
				$statusChanged = $true
			}
			else
			{
				# IIS is not installed on system drive, validate other configurations
				If((Split-Path -Path $currentIISPath -Qualifier) -like $PVWAIISDrive)
				{
					$regIISSettings["Path"] = "HKLM:\Software\Microsoft\inetstp"
					$regIISSettings["ValueName"] = "PathWWWRoot"
					$regIISSettings["ValueData"] = "$PVWAIISDrive\wwwroot"
					if((Compare-RegistryValue @regIISSettings) -ne "Good")
					{
						$tmpStatus += $myRef.Value + "<BR>"
						$statusChanged = $true
					}

					$regIISSettings["Path"] = "HKLM:\Software\Wow6432Node\Microsoft\inetstp"
					$regIISSettings["ValueName"] = "PathWWWRoot"
					if((Compare-RegistryValue @regIISSettings) -ne "Good")
					{
						$tmpStatus += $myRef.Value + "<BR>"
						$statusChanged = $true
					}

					# Check the IIS Application pool isolation directory
					$regIISSettings["Path"] = "HKLM:\System\CurrentControlSet\Services\WAS\Parameters"
					$regIISSettings["ValueName"] = "ConfigIsolationPath"
					$regIISSettings["ValueData"] = "$PVWAIISDrive\temp\appPools"
					if((Compare-RegistryValue @regIISSettings) -ne "Good")
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

			Write-LogMessage -Type Info -Msg "Finish validating PVWA is not installed on the system drive"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate PVWA is not installed on the system drive.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate PVWA is not installed on the system drive."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_IIS_Hardening
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_IIS_Hardening
{
<#
.SYNOPSIS
	Validates PVWA IIS Hardening settings
.DESCRIPTION
	Validates PVWA IIS Hardening settings
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

		# Set Registry values for
		$regHTTPService = @{
			"Path"="HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters";
			"ValueName" = "";
			"ValueData" = 0;
			"outStatus" = ([ref]$myRef);
		}
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating PVWA IIS hardening configuration"

			# Check Registry values for MaxFieldLength
			$regHTTPService["ValueName"] = "MaxFieldLength"
			$regHTTPService["ValueData"] = "65534"
			if((Compare-RegistryValue @regHTTPService) -ne "Good")
			{
				$tmpStatus += "$($regHTTPService["ValueName"]) registry value does not equal $($regHTTPService["ValueData"])."
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			# Check Registry values for MaxRequestBytes
			$regHTTPService["ValueName"] = "MaxRequestBytes"
			$regHTTPService["ValueData"] = "5000000"
			if((Compare-RegistryValue @regHTTPService) -ne "Good")
			{
				$tmpStatus += "$($regHTTPService["ValueName"]) registry value does not equal $($regHTTPService["ValueData"])."
				$tmpStatus += $myRef.Value + "<BR>"
				$statusChanged = $true
			}

			If($statusChanged)
			{
				$res = "Warning"
				[ref]$refOutput.Value = $tmpStatus
			}

			Write-LogMessage -Type Info -Msg "Finish validating PVWA IIS hardening configuration"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate PVWA IIS hardening configuration.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate PVWA IIS hardening configuration."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_AdditionalAppPool
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function PVWA_AdditionalAppPool
{
<#
.SYNOPSIS
	Validates PVWA pplication pool configuration
.DESCRIPTION
	Validates PVWA pplication pool configuration.
	If PVWA shuold be installed on a dedicated server, no other application pools should exist
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
	}
	Process {
		Try{
			Write-LogMessage -Type Info -Msg "Start validating PVWA application pool settings"
			$PVWADedicatedServer = (ConvertTo-Bool $($Parameters | Where-Object Name -eq "DedicatedServer").Value)
			If($PVWADedicatedServer -eq $True)
			{
				Write-LogMessage -Type Info -Msg "PVWA is configured to be on a dedicated server - no other application pools should exist"
			}

			Initialize-WebAdministrationModule

			$iisWebApplications = $(Get-ChildItem IIS:\AppPools)
			# Get all non-PVWA applications installed on the server
			$nonPVWAAppPools = ""
			if($iisWebApplications.Count -gt 2)
			{
				$nonPVWAAppPools = ($iisWebApplications | Select-Object Name | Where-Object { $_.Name -notlike "PasswordVault*" -and $_.Name -ne "DefaultAppPool" })
				Write-LogMessage -Type Verbose -Msg "Existing Application Pools: $($nonPVWAAppPools | ForEach-Object{$_.Name + '`n'})"
				[ref]$refOutput.Value = "The following Application Pools are installed on the PVWA server: $($nonPVWAAppPools | ForEach-Object{$_.Name + '<BR>'})"
				If($PVWADedicatedServer)
				{
					$res = "Bad"
				}
				Else
				{
					$res = "Warning"
				}
			}

			Write-LogMessage -Type Info -Msg "Finish validating PVWA application pool settings"

			return $res
		}
		catch{
			Write-LogMessage -Type "Error" -Msg "Could not validate PVWA application pool settings.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate PVWA application pool settings."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PVWA_CredFileHardening
# Description....: Return type of restrictions added the the credential file
# Parameters.....: Credential file location
# Return Values..: Verification Type
# =================================================================================================================================
Function PVWA_CredFileHardening
{
<#
.SYNOPSIS
	Return verficiation type on credential file
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
        $pvwaPath = ""
        $tmpValue = ""
    }

    Process {
        Try{
   			Write-LogMessage -Type Info -Msg "Start validating hardening of PVWA credential file"
            $pvwaPath = (Get-DetectedComponents -Component "PVWA").Path
            $credentialsfolder = join-path -Path $pvwaPath -ChildPath 'CredFiles'
			# Go over all PVWA Cred Files in the folder
			ForEach ($credFile in (Get-ChildItem -Path $credentialsfolder -Filter *.ini))
			{
				Write-LogMessage -Type Debug -Msg "Checking '$($credFile.Name)' credential file"
				if((Test-CredFileVerificationType -CredentialFilePath $credFile.FullName -outStatus ([ref]$myRef)) -ne "Good")
				{
					$res = "Warning"
				}
				$tmpValue += $myRef.value + "<BR>"
			}

            [ref]$refOutput.Value = $tmpValue
            Write-LogMessage -Type Info -Msg "Finish validating PVWA component credential file"
   			return $res
        } catch {
			Write-LogMessage -Type "Error" -Msg "Could not validate the PVWA component credential file.  Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$refOutput.Value = "Could not validate PVWA component credential file."
			return "Bad"
		}
	}
	End {
		# Write output to HTML
	}
}
