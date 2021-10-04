Set-Variable -Name DetectionSupportedComponents -Option ReadOnly -Value @("Vault","CPM","PVWA","PSM","AIM","EPM","SecureTunnel")
Set-Variable -Name UnsupportedHardeningComponents -Option ReadOnly -Value @("AIM","EPM","SecureTunnel")

#region Writer Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
Function Write-LogMessage
{
<# 
.SYNOPSIS 
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type
.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
	param(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory=$false)]
		[Switch]$Header,
		[Parameter(Mandatory=$false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory=$false)]
		[Switch]$Footer,
		[Parameter(Mandatory=$false)]
		[Bool]$WriteLog = $true,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Info","Warning","Error","Debug","Verbose", "Success", "LogOnly")]
		[String]$type = "Info",
		[Parameter(Mandatory=$false)]
		[String]$LogFile = $LOG_FILE_PATH
	)
	Try{
		If([string]::IsNullOrEmpty($LogFile) -and $WriteLog)
		{
			# User wanted to write logs, but did not provide a log file - Create a temporary file
			$LogFile = Join-Path -Path $ENV:Temp -ChildPath "$((Get-Date).ToShortDateString().Replace('/','_')).log"
			Write-Host "No log file path inputted, created a temporary file at: '$LogFile'"
		}
		If ($Header -and $WriteLog) {
			"=======================================" | Out-File -Append -FilePath $LogFile 
			Write-Host "=======================================" -ForegroundColor Magenta
		}
		ElseIf($SubHeader -and $WriteLog) { 
			"------------------------------------" | Out-File -Append -FilePath $LogFile 
			Write-Host "------------------------------------" -ForegroundColor Magenta
		}
		
		# Replace empty message with 'N/A'
		if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		$msgToWrite = ""
		
		# Mask Passwords
		if($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))')
		{
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		# Check the message type
		switch ($type)
		{
			{($_ -eq "Info") -or ($_ -eq "LogOnly")} 
			{ 
				If($_ -eq "Info")
				{
					Write-Host $MSG.ToString() -ForegroundColor $(If($Header -or $SubHeader) { "Magenta" } Else { "White" })
				}
				$msgToWrite = "[INFO]`t$Msg"
				break
			}
			"Success" { 
				Write-Host $MSG.ToString() -ForegroundColor Green
				$msgToWrite = "[SUCCESS]`t$Msg"
				break
			}
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor Yellow
				$msgToWrite = "[WARNING]`t$Msg"
				break
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite = "[ERROR]`t$Msg"
				break
			}
			"Debug" { 
				if($InDebug -or $InVerbose)
				{
					Write-Debug $MSG
					$msgToWrite = "[DEBUG]`t$Msg"
				}
				break
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose -Msg $MSG
					$msgToWrite = "[VERBOSE]`t$Msg"
				}
				break
			}
		}

		If($WriteLog) 
		{ 
			If(![string]::IsNullOrEmpty($msgToWrite))
			{				
				"[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t$msgToWrite" | Out-File -Append -FilePath $LogFile
			}
		}
		If ($Footer -and $WriteLog) { 
			"=======================================" | Out-File -Append -FilePath $LogFile 
			Write-Host "=======================================" -ForegroundColor Magenta
		}
	}
	catch{
		Throw $(New-Object System.Exception ("Cannot write message"),$_.Exception)
	}
}
Export-ModuleMember -Function Write-LogMessage

# @FUNCTION@ ======================================================================================================================
# Name...........: Join-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Join-ExceptionMessage
{
<#
.SYNOPSIS
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
	param(
		[Exception]$e
	)

	Begin {
	}
	Process {
		$msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
		while ($e.InnerException) {
		  $e = $e.InnerException
		  $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	End {
	}
}
Export-ModuleMember -Function Join-ExceptionMessage

#endregion

#region Helper Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Test-Service
# Description....: Method to query a service status
# Parameters.....: ServiceName
# Return Values..: Service Status
# =================================================================================================================================
Function Test-Service
{
<#
.SYNOPSIS
	Method to query a service status
.DESCRIPTION
	Returns the Status of a Service, Using Get-Service.
.PARAMETER ServiceName
	The Service Name to Check Status for
#>
	param (
		[Parameter(Mandatory=$true)]
		[string]$ServiceName
	)
	Begin {

	}
	Process {
		$svcStatus = "" # Init
		try{
			# Create command to run
			$svcStatus = Get-Service -Name $ServiceName | Select-Object Status
			Write-LogMessage -Type "Debug" -Msg "$ServiceName Service Status is: $($svcStatus.Status)" -LogFile $LOG_FILE_PATH
			return $svcStatus.Status
		}
		catch{
			Throw $(New-Object System.Exception ("Cannot get Service ($ServiceName) status",$_.Exception))
		}
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-Reg
# Description....: Method that will connect to a remote computer Registry using the Parameters it receives
# Parameters.....: Hive, Key, Value, RemoteComputer (Default - local computer)
# Return Values..: Registry Value
# =================================================================================================================================
Function Get-Reg
{
<#
.SYNOPSIS
	Method that will connect to a remote computer Registry using the Parameters it receives

.DESCRIPTION
	Returns the Value Data of the Registry Value Name Queried on a remote machine

.PARAMETER Hive
	The Hive Name (LocalMachine, Users, CurrentUser)
.PARAMETER Key
	The Registry Key Path
.PARAMETER Value
	The Registry Value Name to Query
.PARAMETER RemoteComputer
	The Computer Name that we want to Query (Default Value is Local Computer)
#>
	param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("HKLM:","LocalMachine", "HKU:", "Users", "CurrentUser")]
		[String]$Hive,
		[Parameter(Mandatory=$true)]
		[String]$Key,
		[Parameter(Mandatory=$false)]
		[String]$Value=$null,
		[Parameter(Mandatory=$false)]
		[String]$RemoteComputer="." # If not entered Local Computer is Selected
	)
	Begin {
		$regCommandParameters = ""
		$retOutput = $null
	}
	Process {
		try{
			if($Hive -eq "LocalMachine") { $Hive = "HKLM:" }
			Write-LogMessage -Type "Verbose" -Msg "Opening Key:'$key' on Hive:'$Hive'" -LogFile $LOG_FILE_PATH
			$regPath = Join-Path -Path $Hive -ChildPath $Key
			If(($RemoteComputer -ne ".") -and ($RemoteComputer -ne "localhost"))
			{
				# Connect to Remote Computer Registry
				$regCommandParameters = "-ComputerName $RemoteComputer"
			}
		}
		catch{
			Throw $(New-Object System.Exception ("Get-Reg: Registry Error",$_.Exception))
		}
		if($null -eq $Value) # Enumerate Keys
		{
			If(Test-Path $regPath)
			{
				try{
					# Return Sub Key Names
					$retOutput = (Get-ChildItem -Path $regPath $regCommandParameters | Select-Object Name)
				} catch {
					Throw $(New-Object System.Exception ("Get-Reg: Could not enumerate keys in registry path $regPath",$_.Exception))
				}
			}
			else
			{
				Throw ("Get-Reg: Registry path $regPath does not exist")
			}
		}
		else
		{
			If(Test-Path $regPath)
			{
				$regItems = Get-ItemProperty -Path $regPath
				if($null -ne $regItems)
				{
					try{
						if((Get-ItemProperty -Path $regPath | Get-Member).Name -contains $Value)
						{
							$retOutput = (Get-ItemProperty -Path $regPath -Name $Value | Select-Object $Value).$Value
						}
					} catch {
						Throw $(New-Object System.Exception ("Get-Reg: Could not find value $Value in registry path $regPath",$_.Exception))
					}
				}
				else { Throw ("Get-Reg: No items in registry path $regPath") }
			}
			else
			{
				Throw ("Get-Reg: Registry path $regPath does not exist")
			}
		}

		return $retOutput
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-FileVersion
# Description....: Method to return a file version
# Parameters.....: File Path
# Return Values..: File version
# =================================================================================================================================
Function Get-FileVersion
{
<#
.SYNOPSIS
	Method to return a file version

.DESCRIPTION
	Returns the File version and Build number
	Returns Null if not found

.PARAMETER FilePath
	The path to the file to query
#>
	param ($filePath)
	Begin {

	}
	Process {
		$retFileVersion = $Null
		try{
			If (($null -ne $filePath) -and (Test-Path $filePath))
			{
				$path = Resolve-Path $filePath
				$retFileVersion = ($path | Get-Item | Select-Object VersionInfo).VersionInfo.ProductVersion
			}
			else
			{
				throw "File path is empty"
			}

			return $retFileVersion
		}
		catch{
			Throw $(New-Object System.Exception ("Cannot get File ($filePath) version",$_.Exception))
		}
		finally{

		}
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-CommandExists
# Description....: Checks if a command exists in the script run scope
# Parameters.....: Command Name
# Return Values..: True / False
# =================================================================================================================================
Function Test-CommandExists
{
<#
.SYNOPSIS
	Method to check if a command exists in the script run scope
.DESCRIPTION
	Returns True if a command exists in the script run scope
.PARAMETER Command
	The Command name to check
#>
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Set-DetectedComponents
# Description....: Sets the Detected Components in a Script scope
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Set-DetectedComponents
{
<#
.SYNOPSIS
	Sets the Detected Components in a Script scope
.DESCRIPTION
	Sets the Detected Components in a Script scope
#>
	Write-LogMessage -Type Info -MSG "Detecting installed components" -LogFile $LOG_FILE_PATH
	$_detectedComponents = Find-Components -Component "All"
	# Add  indication if the server is a domain member
	$_detectedComponents | Add-Member -NotePropertyName DomainMember -NotePropertyValue $(Test-InDomain)
	# Make Detected Components available in Script scope
	Set-Variable -Name DetectedComponents -Value $_detectedComponents -Scope Script
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-InstalledRole
# Description....: Gets a server role and test if it is installed on the machine
# Parameters.....: Role Name - the role to check
# Return Values..: $true
#                  $false
# =================================================================================================================================
Function Test-InstalledRole
{
<#
.SYNOPSIS
	Method to check if a server role is installed on the machine
.DESCRIPTION
	Gets a server role and test if it is installed on the machine
.PARAMETER RoleName
	The Role Name to Check Status for
#>
	Param (
		[Parameter(Mandatory=$true)]
		[string]$roleName
	)
	Begin {

	}
	Process{
		try{
			return ((Get-WindowsFeature $roleName).Installed -eq 1)
		}
		catch{
			Throw $(New-Object System.Exception ("Error checking Windows Role/Feature '$roleName'",$_.Exception))
		}
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: New-AccessControlObject
# Description....: Get the relevant access control object for this path.
# Parameters.....: $path - The location path we want to get permissions.
#				   $identity - The identity we want to get the relevant permissions.
#				   $rights - The rights we want to get to the identity on this path.
#							 Please Notice this needs to be string indicate enum name from System.Security.AccessControl.RegistryRights or System.Security.AccessControl.FileSystemRights enums.
# Return Values..: $NUll is couldn't create object, otherwise it return the relevant object.
# =================================================================================================================================
Function New-AccessControlObject{
<#
.SYNOPSIS
	Method to get the relevant access control object for this path.
.DESCRIPTION
	Get the relevant access control object for this path.
.PARAMETER Path
	The location path we want to get permissions.
.PARAMETER Identity
	The user we want to get permissions to.
.PARAMETER Rights
	The rights we want to get to the identity on this path.
	Please Notice this needs to be string indicate enum name from System.Security.AccessControl.RegistryRights or System.Security.AccessControl.FileSystemRights enums.
#>
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]$path,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]$identity,
		[ValidateNotNullOrEmpty()]$rights
	)
	Begin{

	}
	Process{
		$returnVal = $NULL
		Try {
			$item = Get-Item -Path $path

			If ($item -is [System.IO.DirectoryInfo]) {
				$returnVal = New-Object System.Security.AccessControl.FileSystemAccessRule ($identity,$rights,"ContainerInherit,ObjectInherit","None","Allow")
			} ElseIf ($item -is [Microsoft.Win32.RegistryKey]) {
				$returnVal = New-Object System.Security.AccessControl.RegistryAccessRule ($identity,$rights,"ContainerInherit,ObjectInherit","None","Allow")
			} ElseIf ($item -is [System.IO.FileInfo]){
				$returnVal = New-Object System.Security.AccessControl.FileSystemAccessRule ($identity,$rights,"Allow")
			}
		} Catch {
			Throw $(New-Object System.Exception ("Failed to get new Access Control Object",$_.Exception))
		}
		return $returnVal
	}
	End{

   }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-IdentityReference
# Description....: Get Identity Reference
# Parameters.....: $identityReference
# Return Values..: IdentityReference
# =================================================================================================================================
Function Get-IdentityReference
{
<#
.SYNOPSIS
	Method to get the relevant Identity reference
.DESCRIPTION
	Returns the Identity Reference
.PARAMETER IdentityReference
	The current Identity Reference we want to get reference to
#>
	param(
		$identityReference
	)

	Process {
		if ($identityReference -eq 'APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES')
		{
			$identityReference = "ALL APPLICATION PACKAGES"
		}
		if ($identityReference -eq 'APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES')
		{
			$identityReference = "ALL RESTRICTED APPLICATION PACKAGES"
		}

		return $identityReference
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Read-ConfigurationFile
# Description....: Parse Configuration File and get all the steps to execute
# Parameters.....: $ConfigurationFilePath
# Return Values..: Steps to Run Array
# =================================================================================================================================
Function Read-ConfigurationFile
{
<#
.SYNOPSIS
	Parse Configuration File and get all the steps to execute
.DESCRIPTION
	Parse Configuration File and get all the steps to execute
.PARAMETER ConfigurationFilePath
	The Configuration file path to parse
#>
	param(
		[Parameter(Mandatory=$true)]
		[string]$ConfigurationFilePath
	)

	Process {
		try
		{
			[xml]$ConfigurationObject = Get-Content $ConfigurationFilePath
			$ConfigurationSteps=@()
			$StepsNodes = $ConfigurationObject.SelectNodes("//Step")

			foreach ($node in $StepsNodes)
			{
				$name = $node.attributes['Name'].value
				$displayName = $node.attributes['DisplayName'].value
				$scriptName = $node.attributes['ScriptName'].value
				$scriptEnable = $node.attributes['Enable'].value
				$descriptionLink = $node.attributes['Description'].value
				$parametersNode = $node.FirstChild

				$ParamsList=@()  # Will be empty if the step does not contain parameters

				if ($null -ne $parametersNode)
				{
					$ParametersNodeContent = $parametersNode.SelectNodes("//Parameter")
					foreach ($param in $ParametersNodeContent)
					{
						$ParamsList += new-object PSObject -prop @{Name=$($param.attributes['Name'].value);Value=$($param.attributes['Value'].value)}
					}
				}

				$StepObject = new-object PSObject -prop @{Name=$name;DisplayName=$displayName;ScriptName=$scriptName;Parameters=$ParamsList;Enable=$scriptEnable;Description=$descriptionLink}

				$ConfigurationSteps += $StepObject
			}

			return $ConfigurationSteps
		}
		Catch
		{
			Throw $(New-Object System.Exception ("Failed to parse configuration file: $ConfigurationFilePath",$_.Exception))
		}
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-EnabledPolicySetting
# Description....: Verifies a policy condition matches
# Parameters.....: Policy status, Match value and not match criteria
# Return Values..: True / False
# =================================================================================================================================
Function Test-EnabledPolicySetting
{
<#
.SYNOPSIS
	Method to Verifies a policy condition matches
.DESCRIPTION
	Returns True if a policy setting matches the criteria
.PARAMETER PolicyStatus
	The current Policy Status - verify it is enabled
.PARAMETER MatchValue
	The Value to match
.PARAMETER NotMatchCriteria
	The NOT verification criteria
#>
    Param (
		[Parameter(Mandatory=$true)]
		[ValidateSet("enable","disable")]	
		[string]$PolicyStatus, 
		[Parameter(Mandatory=$true)]
		[string]$MatchValue, 
		[Parameter(Mandatory=$true)]
		[ValidateSet("Success","Failure")]	
		[string]$NotMatchCriteria
	)
	$retValue = $true

	if(($PolicyStatus -eq "enable") -and !($MatchValue -match $NotMatchCriteria))
	{
		$retValue = $false
	}

	return $retValue
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Find-Components
# Description....: Detects all CyberArk Components installed on the local server
# Parameters.....: None
# Return Values..: Array of detected components on the local server
# =================================================================================================================================
Function Find-Components
{
<#
.SYNOPSIS
	Method to query a local server for CyberArk components
.DESCRIPTION
	Detects all CyberArk Components installed on the local server
#>
	param(
		[Parameter(Mandatory=$false)]
		[ValidateScript({   
			if($_ -in (@("All")+$DetectionSupportedComponents)) { return $true }
			else{ throw "Use one of these components: $($DetectionSupportedComponents -join ', ')" }
		})]
		[String]$Component = "All"
	)

	Begin {
		$retArrComponents = @()
		# COMPONENTS SERVICE NAMES
		$REGKEY_VAULTSERVICE_NEW = "CyberArk Logic Container"
		$REGKEY_VAULTSERVICE_OLD = "Cyber-Ark Event Notification Engine"
		$REGKEY_CPMSERVICE_NEW = "CyberArk Central Policy Manager Scanner"
		$REGKEY_CPMSERVICE_OLD = "CyberArk Password Manager"
		$REGKEY_PVWASERVICE = "CyberArk Scheduled Tasks"
		$REGKEY_PSMSERVICE = "Cyber-Ark Privileged Session Manager"
		$REGKEY_AIMSERVICE = "CyberArk Application Password Provider"
		$REGKEY_EPMSERVICE = "VfBackgroundWorker"
		$REGKEY_SECURETUNNELSERVICE = "CyberArkPrivilegeCloudSecureTunnel"
	}
	Process {
		if(![string]::IsNullOrEmpty($Component))
		{
			Switch ($Component) {
				"Vault"
				{
					try{
						# Check if Vault is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for Vault..."
						if(($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_VAULTSERVICE_OLD))) -or ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_VAULTSERVICE_NEW))))
						{
							Write-LogMessage -Type "Info" -MSG "Found Vault installation"
							$vaultPath = $componentPath.Replace("LogicContainer\BLServiceApp.exe","").Replace("Event Notification Engine\ENE.exe","").Replace('"',"").Trim()
							$fileVersion = Get-FileVersion "$vaultPath\dbmain.exe"
							return New-Object PSObject -Property @{Name="Vault";Path=$vaultPath;Version=$fileVersion}
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"CPM"
				{
					try{
						# Check if CPM is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for CPM..."
						if(($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE_OLD))) -or ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE_NEW))))
						{
							# Get the CPM Installation Path
							Write-LogMessage -Type "Info" -MSG "Found CPM installation"
							$cpmPath = $componentPath.Replace("Scanner\CACPMScanner.exe","").Replace("PMEngine.exe","").Replace("/SERVICE","").Replace('"',"").Trim()
							$fileVersion = Get-FileVersion "$cpmPath\PMEngine.exe"
							return New-Object PSObject -Property @{Name="CPM";Path=$cpmPath;Version=$fileVersion}
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"PVWA"
				{
					try{
						# Check if PVWA is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for PVWA..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PVWASERVICE)))
						{
							Write-LogMessage -Type "Info" -MSG "Found PVWA installation"
							$pvwaPath = $componentPath.Replace("Services\CyberArkScheduledTasks.exe","").Replace('"',"").Trim()
							$fileVersion = Get-FileVersion "$pvwaPath\Services\CyberArkScheduledTasks.exe"
							return New-Object PSObject -Property @{Name="PVWA";Path=$pvwaPath;Version=$fileVersion}
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"PSM"
				{
					try{
						# Check if PSM is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for PSM..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PSMSERVICE)))
						{
							Write-LogMessage -Type "Info" -MSG "Found PSM installation"
							$PSMPath = $componentPath.Replace("CAPSM.exe","").Replace('"',"").Trim()
							$fileVersion = Get-FileVersion "$PSMPath\CAPSM.exe"
							return New-Object PSObject -Property @{Name="PSM";Path=$PSMPath;Version=$fileVersion}
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"AIM"
				{
					try{
						# Check if AIM is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for AIM..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_AIMSERVICE)))
						{
							Write-LogMessage -Type "Info" -MSG "Found AIM installation"
							$AIMPath = $componentPath.Replace("/mode SERVICE","").Replace("AppProvider.exe","").Replace('"',"").Trim()
							$fileVersion = Get-FileVersion "$AIMPath\AppProvider.exe"
							return New-Object PSObject -Property @{Name="AIM";Path=$AIMPath;Version=$fileVersion}
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"EPM"
				{
					try{
						# Check if EPM Server is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for EPM Server..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_EPMSERVICE)))
						{
							Write-LogMessage -Type "Info" -MSG "Found EPM Server installation"
							$EPMPath = $componentPath.Replace("VfBackgroundWorker.exe","").Replace('"',"").Trim()
							$fileVersion = Get-FileVersion "$EPMPath\VfBackgroundWorker.exe"
							return New-Object PSObject -Property @{Name="EPM";Path=$EPMPath;Version=$fileVersion}
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"SecureTunnel"
				{
					try{
						# Check if Privilege Cloud Secure tunnel is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for Privilege Cloud Secure tunnel..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_SECURETUNNELSERVICE)))
						{
							Write-LogMessage -Type "Info" -MSG "Found Privilege Cloud Secure tunnel installation"
							$tunnelPath = $componentPath.Replace("PrivilegeCloudSecureTunnel.exe","").Replace('"',"").Trim()
							$fileVersion = Get-FileVersion "$tunnelPath\PrivilegeCloudSecureTunnel.exe"
							return New-Object PSObject -Property @{Name="SecureTunnel";Path=$tunnelPath;Version=$fileVersion}
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"All"
				{
					try{
						ForEach($comp in $DetectionSupportedComponents)
						{
							$retArrComponents += Find-Components -Component $comp
						}
						return $retArrComponents
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting components. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
			}
		}
	}
	End {
	}
}
#endregion

#region Exported Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Test-InDomain
# Description....: Returns if the machine is a domain member
# Parameters.....: Machine Name (Optional)
# Return Values..: True / False
# =================================================================================================================================
Function Test-InDomain
{
<#
.SYNOPSIS
	Method to check if the machine is a domain member
.DESCRIPTION
	Returns True if machine is part of a domain
#>
	Param(
		[Parameter(Mandatory=$false)]
		[string]$machineName = "."
	)
	Begin {}
	Process{
		try{
			return $(Get-WMIItem -Class "Win32_ComputerSystem" -Item "PartOfDomain" -RemoteComputer $machineName).PartOfDomain
		}
		catch{
			Write-LogMessage -Type Error -Msg "Failed to check if the machine is a domain member. Error: $(Join-ExceptionMessage $_.Exception)"
			return $false
		}
	}
	End {}
}
Export-ModuleMember -Function Test-InDomain

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-LocalUser
# Description....: Returns if a local user exists on the machine
# Parameters.....: User Name to check
# Return Values..: True / False
# =================================================================================================================================
Function Test-LocalUser
{
<#
.SYNOPSIS
	Method to check if a local user exits on the machine
.DESCRIPTION
	Returns True if the input user name exists on the machine
#>
	Param(
		[Parameter(Mandatory=$true)]
		[string]$userName
	)
	Begin {}
	Process{
		try{
			return ($null -ne $(Get-WMIItem -Class "Win32_UserAccount" -Filter "Name='$userName'" -Item "Name"))
		}
		catch{
			Write-LogMessage -Type Error -Msg "Failed to check if user $userName exists. Error: $(Join-ExceptionMessage $_.Exception)"
			return $null
		}
	}
	End {}
}
Export-ModuleMember -Function Test-LocalUser

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-LocalAdminUser
# Description....: Returns if a local user is the local Administrator user
# Parameters.....: User Name to check
# Return Values..: True / False
# =================================================================================================================================
Function Test-LocalAdminUser
{
	param(
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[Alias("name")]
		[string]$userName,
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[Alias("sid")]
		[string]$userSID
	)
	try{
		if([string]::IsNullOrEmpty($userName) -and [string]::IsNullOrEmpty($userSID)) { Throw "At least one parameter should be used (userName or userSID)" }
		if(![string]::IsNullOrEmpty($userName))
		{
			$userSID = Convert-NameToSID $userName
		}
		
		If($userSID.StartsWith("S-1-5-") -and $userSID.EndsWith("-500"))
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	catch{
		Write-LogMessage -Type Error -Msg "Failed to check if user $userName is the local Admin. Error: $(Join-ExceptionMessage $_.Exception)"
		return $false
	}
}
Export-ModuleMember -Function Test-LocalAdminUser

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-InstalledWindowsRole
# Description....: Check if a Windows role or feature is installed
# Parameters.....: Role / feature, [ref]outStatus
# Return Values..: $true (if installed), $false (if not)
# =================================================================================================================================
Function Test-InstalledWindowsRole
{
<#
.SYNOPSIS
	Method to Verify if a Windows Role or feature is installed on the local machine
.DESCRIPTION
	Check if a Windows role or feature is installed
.PARAMETER Roles
	The Windows Role or Feature Name to verify if installed
#>
	param(
		$Roles,
		[ref]$outStatus
	)

	Begin {

	}
	Process {
		try{
			$outputMsg = ""
			$retValue = $true
			ForEach($item in $Roles)
			{
				if((Test-InstalledRole $item))
				{
					$outputMsg += "Windows Role/Feature '$item' is installed.<BR>"
					$retValue = $false
				}
			}

			if(! $retValue)
			{
				[ref]$outStatus.Value = "$($outputMsg)Consider removing."
				return "Warning"
			}
			else
			{
				[ref]$outStatus.Value = "Only required Windows Role/Feature are installed on the machine."
				return "Good"
			}
			return $true
		}
		catch{
			Write-LogMessage -Type Error -Msg "Failed to verify Windows Role/Feature '$name'. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Failed to verify Windows Roles/Features. Error: $($_.Exception.Message)"
			return "Bad"
		}
	}
	End {

	}
}
Export-ModuleMember -Function Test-InstalledWindowsRole

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-ServiceRunWithLocalUser
# Description....: Check if a service is running with a local user and check if the user has the required user rights to run as service
# Parameters.....: $serviceName - The service name to check.
#                  $userName - The local user name that should run the service
# Return Values..: if succeed $true or $false
# =================================================================================================================================
Function Test-ServiceRunWithLocalUser
{
<#
.SYNOPSIS
	Method to check a service login options and verify that the running user has 'Login as service' rights
.DESCRIPTION
	Check if a service is running with a local user and check if the user has the required user rights to run as service
.PARAMETER ServiceName
	The Service Name to Check Login info for
.PARAMETER UserName
	The User Name to Check 'Login as a Service' for
#>
	param(
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$serviceName,
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$username,
	   [Parameter(Mandatory=$true)]
	   [ref]$outStatus
    )
	Begin{

	}
	Process{
		Try{
			Write-LogMessage -Type Debug -Msg "Checking if '$serviceName' Service uses '$userName' to login with"
			$serviceLogin = (Get-WMIItem -class Win32_Service -Item StartName -Filter "Name='$ServiceName'").StartName
			Write-LogMessage -Type Debug -Msg "Service '$serviceName' is running with '$serviceLogin'"
		}Catch{
			Write-LogMessage -Type Error -Msg "Error Checking Service Login for service '$serviceName'. Error: $(Join-ExceptionMessage $_.Exception)"
		}
		try{
			$myRef = ""
			If($(Test-LocalUser -userName $userName))
			{
				Write-LogMessage -Type Debug -Msg "Checking if $userName has 'Login as Service' rights"
				$isLogonService = Compare-UserRight -userName $username -userRight "SeServiceLogonRight" -outStatus ([ref]$myRef)
			}
			else
			{
				Write-LogMessage -Type Debug -Msg "User $userName does not exist on the machine"
				[ref]$outStatus.Value = "The user $userName does not exist on the machine"
				return "Bad"
			}
		}Catch{
			Write-LogMessage -Type Error -Msg "Error Checking user $userName 'Login as Service' rights. Error: $(Join-ExceptionMessage $_.Exception)"
		}
		try{
			if(($userName.Replace(".\","") -match $serviceLogin.Replace(".\","")) -and $isLogonService)
			{
				[ref]$outStatus.Value = "Service '$serviceName' is running correctly with $serviceLogin.<BR>The user $userName has the 'Login as Service' rights"
				return "Good"
			}
			else
			{
				[ref]$outStatus.Value = "Service '$serviceName' is running with a different user ($serviceLogin) or the user $userName has not been granted the 'Login as Service' rights"
				return "Warning"
			}
		} catch {
			Write-LogMessage -Type Error -Msg "Error matching user '$userName' to '$serviceLogin'. Error: $(Join-ExceptionMessage $_.Exception)"
		}
	}
	End{
   }
}
Export-ModuleMember -Function Test-ServiceRunWithLocalUser

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-CurrentUserLocalAdmin
# Description....: Check if the current user is a Local Admin
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function Test-CurrentUserLocalAdmin
{
<#
.SYNOPSIS
	Method to check a service login options and verify that the running user has 'Login as service' rights
.DESCRIPTION
	Check if a service is running with a local user and check if the user has the required user rights to run as service
.PARAMETER ServiceName
	The Service Name to Check Login info for
.PARAMETER UserName
	The User Name to Check 'Login as a Service' for
#>
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.SecurityIdentifier] "S-1-5-32-544")  # Local Administrators group SID
}
Export-ModuleMember -Function Test-CurrentUserLocalAdmin

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-WMIItem
# Description....: Method Retrieves a specific Item from a remote computer's WMI
# Parameters.....: Class, RemoteComputer (Default - local computer), Item, Query(Default empty WMI SQL Query), Filter (Default empty Filter is Entered)
# Return Values..: WMI Item Value
# =================================================================================================================================
Function Get-WMIItem {
	<#
	.SYNOPSIS
		Method Retrieves a specific Item from a remote computer's WMI
	
	.DESCRIPTION
		Returns the Value Data of a specific WMI query on a remote machine
	
	.PARAMETER Class
		The WMI Class Name
	.PARAMETER Item
		The Item to query
	.PARAMETER Query
		A WMI query to run
	.PARAMETER Filter
		A filter item to filter the results
	.PARAMETER RemoteComputer
		The Computer Name that we want to Query (Default Value is Local Computer)
	#>
		param(
			[Parameter(Mandatory=$true)]
			[String]$Class,
			[Parameter(Mandatory=$false)]
			[String]$RemoteComputer=".", # If not entered Local Computer is Selected
			[Parameter(Mandatory=$true)]
			[String]$Item,
			[Parameter(Mandatory=$false)]
			[String]$Query="", # If not entered an empty WMI SQL Query is Entered
			[Parameter(Mandatory=$false)]
			[String]$Filter="" # If not entered an empty Filter is Entered
		)
	
		Begin {
	
		}
		Process {
			$retValue = ""
			try{
				if ($Query -eq "") # No Specific WMI SQL Query
				{
					# Execute WMI Query, Return only the Requested Items
					$retValue = (Get-WmiObject -Class $Class -ComputerName $RemoteComputer -Filter $Filter -Property $Item | Select-Object $Item)
				}
				else # User Entered a WMI SQL Query
				{
					$retValue = (Get-WmiObject -ComputerName $RemoteComputer -Query $Query | Select-Object $Item)
				}
			}
			catch{
				Throw $(New-Object System.Exception ("WMI Error",$_.Exception))
			}
	
			return $retValue
		}
		End {
	
		}
	}
	Export-ModuleMember -Function Get-WMIItem
	
# @FUNCTION@ ======================================================================================================================
# Name...........: Get-DnsHost
# Description....: Returns the DNS (Full Qualified Domain Name) of the machine
# Parameters.....: None
# Return Values..: DNS Name of the local machine
# =================================================================================================================================
Function Get-DnsHost
{
<#
.SYNOPSIS
	Method to get the DNS Host name of the machine
.DESCRIPTION
	Returns the DNS (Full Qualified Domain Name) of the machine
#>
	Param(
	)
	Begin {}
	Process{
		try{
			return [system.net.dns]::GetHostByName($env:ComputerName) | Format-List hostname | Out-String | ForEach-Object{ "{0}" -f $_.Split(':')[1].Trim()};
		}
		catch{
			Write-LogMessage -Type Error -Msg "Failed to retrieve DNS Host name. Error: $(Join-ExceptionMessage $_.Exception)"
			return $env:ComputerName
		}
	}
	End {}
}
Export-ModuleMember -Function Get-DnsHost

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LocalAdministratorsGroupName
# Description....: Returns the Local Administrators Group Name
# Parameters.....: None
# Return Values..: Local Administrators Group Name
# =================================================================================================================================
Function Get-LocalAdministratorsGroupName
{
<#
.SYNOPSIS
	Method to get the Local Administrators Group Name of the local Machine
.DESCRIPTION
	Returns the Local Administrators Group Name of the local Machine
#>
	Param(
	)
	Begin {}
	Process{
		try{
			# "S-1-5-32-544" is constant value representing Administrators group
			return $(Convert-SIDToName "S-1-5-32-544")
		}
		catch{
			Write-LogMessage -Type Error -Msg "Failed to retrieve local Administrators group name. Error: $(Join-ExceptionMessage $_.Exception)"
			return $null
		}
	}
	End {}
}
Export-ModuleMember -Function Get-LocalAdministratorsGroupName

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LocalSystemGroupName
# Description....: Returns the local SYSTEM account Name
# Parameters.....: None
# Return Values..: local SYSTEM account name
# =================================================================================================================================
Function Get-LocalSystemGroupName
{
<#
.SYNOPSIS
	Method to get the local SYSTEM account Name of the local Machine
.DESCRIPTION
	Returns the Local local SYSTEM account of the local Machine
#>
	Param(
	)
	Begin {}
	Process{
		try{
			# "S-1-5-18" is constant value representing NT-Authority/SYSTEM name
			return $(Convert-SIDToName "S-1-5-18")
		}
		catch{
			Write-LogMessage -Type Error -Msg "Failed to retrieve local SYSTEM account name. Error: $(Join-ExceptionMessage $_.Exception)"
			return $null
		}
	}
	End {}
}
Export-ModuleMember -Function Get-LocalSystemGroupName

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-ServiceInstallPath
# Description....: Get the installation path of a service
# Parameters.....: Service Name
# Return Values..: $true
#                  $false
# =================================================================================================================================
# Save the Services List
$m_ServiceList = $null
Function Get-ServiceInstallPath
{
<#
  .SYNOPSIS
  Get the installation path of a service
  .DESCRIPTION
  The function receive the service name and return the path or returns NULL if not found
  .EXAMPLE
  (Get-ServiceInstallPath $<ServiceName>) -ne $NULL
  .PARAMETER ServiceName
  The service name to query. Just one.
 #>
	param ($ServiceName)
	Begin {

	}
	Process {
		$retInstallPath = $Null
		try{
			if ($null -eq $m_ServiceList)
			{
				Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.PSPath }) -Scope Script
				#$m_ServiceList = Get-Reg -Hive "LocalMachine" -Key System\CurrentControlSet\Services -Value $null
			}
			$regPath =  $m_ServiceList | Where-Object {$_.PSChildName -eq $ServiceName}
			If ($Null -ne $regPath)
			{
				$retInstallPath = $regPath.ImagePath.Substring($regPath.ImagePath.IndexOf('"'),$regPath.ImagePath.LastIndexOf('"')+1)
			}
		}
		catch{
			Throw $(New-Object System.Exception ("Cannot get Service Install path for $ServiceName",$_.Exception))
		}

		return $retInstallPath
	}
	End {

	}
}
Export-ModuleMember -Function Get-ServiceInstallPath

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-SeceditAnalysisResults
# Description....: Parse Secedit Analyze log
# Parameters.....: Path to Log, Reference to output status`
# Return Values..: "Good" / "Warning" / "Bad"
# =================================================================================================================================
Function Get-SeceditAnalysisResults
{
<#
.SYNOPSIS
	Method to Parse Secedit Analyze log
.DESCRIPTION
	Returns the status of the secedit analyze log
.PARAMETER Path
	The Service Name to Check Status for
#>
	param(
	   [ValidateNotNullOrEmpty()]$path,
	   [Parameter(Mandatory=$true)]
	   [ref]$outStatus
	)

	Begin {
		$statusChanged = $false
		$res = "Good"
		$tmpStatus = ""
	}
	Process {
		try{
			# Find 'mismatch' OR 'Not configured' in the file
			$MismatchMatches = Select-String -Path $path -Pattern "(mismatch)"
			$NotConfiguredMatches = Select-String -Path $path -Pattern "(not configured)"
			If($MismatchMatches.Count -gt 0)
			{
				$tmpStatus += "There are $($MismatchMatches.Count) Mismatched configurations see secedit log ($path) for more details.<BR>"
				Write-LogMessage -Type Debug -Msg $($MismatchMatches -join "`n")
				$statusChanged = $true
			}
			If($NotConfiguredMatches.Count -gt 0)
			{
				$tmpStatus += "There are $($NotConfiguredMatches.Count) 'Not configured' configurations see secedit log ($path) for more details."
				Write-LogMessage -Type Debug -Msg $($NotConfiguredMatches -join "`n")
				$statusChanged = $true
			}
			if($statusChanged)
			{
				[ref]$outStatus.Value = $tmpStatus
				$res = "Warning"
			}

			return $res
		}
		catch{
			Write-LogMessage -Type Error -Msg "Failed to Analyse secedit log. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Failed to Analyse secedit log. Error: $($_.Exception.Message)"
			return "Bad"
		}
	}
	End {

	}
}
Export-ModuleMember -Function Get-SeceditAnalysisResults

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-ParsedFileNameByOS
# Description....: Return the file name parsed by OS
# Parameters.....: fileName
# Return Values..: Parsed File name (by OS version)
# =================================================================================================================================
Function Get-ParsedFileNameByOS
{
<#
.SYNOPSIS
	Return the file name parsed by OS
.DESCRIPTION
	Return the file name parsed by OS
.PARAMETER fileName
	The File Name to parse
#>
	param(
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$fileName
	)

	Begin {
		if($fileName -NotMatch "@OS@")
		{
			return $fileName
		}
	}
	Process {
		if($fileName -match "@OS@")
		{
			$osCaption = (Get-WMIItem -Class Win32_OperatingSystem -Item Caption).Caption
			$osCaption -match "(Windows)\s{0,}\w{0,}\s{0,}(\d{1,4})" | Out-Null
			$osVer = $Matches[2]
			return ($fileName -Replace "@OS@", $osVer)
		}
		else
		{
			return $fileName
		}
	}
	End {

	}
}
Export-ModuleMember -Function Get-ParsedFileNameByOS

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-ParsedFileNameByComponent
# Description....: Return the file name parsed by installed components
# Parameters.....: fileName
# Return Values..: Parsed File name (with all installed components)
# =================================================================================================================================
Function Get-ParsedFileNameByComponent
{
<#
.SYNOPSIS
	Return the file name parsed by installed components
.DESCRIPTION
	Return the file name parsed by installed components
.PARAMETER fileName
	The File Name to parse
#>
	param(
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$fileName
	)

	Begin {
		if($fileName -NotMatch "@Component@")
		{
			return $fileName
		}
	}
	Process {
		if($fileName -match "@Component@")
		{
			# Exclude Non-supported components
			$componentsList = $((Get-DetectedComponents).Name | Where-Object { $_ -NotIn $UnsupportedHardeningComponents })
			return ($fileName -Replace "@Component@", $($componentsList -join " "))
		}
		else
		{
			return $fileName
		}
	}
	End {

	}
}
Export-ModuleMember -Function Get-ParsedFileNameByComponent

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-DetectedComponents
# Description....: Gets the Detected Components in a Script scope
# Parameters.....: None
# Return Values..: Detected Components
# =================================================================================================================================
Function Get-DetectedComponents
{
<#
.SYNOPSIS
	Gets the Detected Components in a Script scope
.DESCRIPTION
	Gets the Detected Components in a Script scope
#>
	param(
		# Component name
		[Parameter(Mandatory=$false)]
		[ValidateScript({   
			if($_ -in (@("All")+$DetectionSupportedComponents)) { return $true }
			else{ throw "Use one of these components: $($DetectionSupportedComponents -join ', ')" }
		})]
		[string]$Component = "All"
	)
	$retComponents = $(Get-Variable -Name DetectedComponents -ValueOnly -Scope Script -ErrorAction Ignore)
	If($null -eq $retComponents)
	{
		Set-DetectedComponents
		$retComponents = $(Get-Variable -Name DetectedComponents -ValueOnly -Scope Script)
	}
	# Check if we need to return a specific component
	If($Component -ne "All")
	{
		return ($retComponents | Where-Object { $_.Name -eq $Component })
	}
	else {
		return $retComponents
	}
}
Export-ModuleMember -Function Get-DetectedComponents

# @FUNCTION@ ======================================================================================================================
# Name...........: Set-CurrentComponentFolderPath
# Description....: Sets the current component folder path
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Set-CurrentComponentFolderPath
{
<#
.SYNOPSIS
	Sets the current component folder path
.DESCRIPTION
	Sets the current component folder path
#>
	param(
		[Parameter(Mandatory=$true)]
		$ComponentPath
	)
	Write-LogMessage -Type Verbose -MSG "Setting current component path: $ComponentPath" -LogFile $LOG_FILE_PATH
	Set-Variable -Name CurrentComponentPath -Scope Script -Value $ComponentPath
}
Export-ModuleMember -Function Set-CurrentComponentFolderPath

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-CurrentComponentFolderPath
# Description....: Returns the parsed current component folder path for a relative file
# Parameters.....: Relative File name
# Return Values..: Full path of the relative file name in the current component folder
# =================================================================================================================================
Function Get-CurrentComponentFolderPath
{
<#
.SYNOPSIS
	Returns the parsed current component folder path for a relative file
.DESCRIPTION
	Returns the parsed current component folder path for a relative file
#>
	param(
		[Parameter(Mandatory=$true)]
		$FileName
	)
	$componentPath = $(Get-Variable -Name CurrentComponentPath -Scope Script -ValueOnly)
	If([string]::IsNullOrEmpty($componentPath))
	{
		Throw "Component Path is empty"
	}
	return $(Join-Path -Path $componentPath -ChildPath $FileName)
}
Export-ModuleMember -Function Get-CurrentComponentFolderPath

# @FUNCTION@ ======================================================================================================================
# Name...........: Compare-ServiceStatus
# Description....: Compares the service status to the required status
# Parameters.....: Service Name, Service required status
# Return Values..: $true
#				   $false
# =================================================================================================================================
Function Compare-ServiceStatus
{
<#
.SYNOPSIS
	Returns if the Service status is like to required status
.DESCRIPTION
	Compares the service status to the required status
.PARAMETER ServiceName
	The Service Name to Check Status for
.PARAMETER ServiceStatus
	The Service Status to Check
#>
	param(
		[Parameter(Mandatory=$true)]
		$ServiceName,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Running","Stopped","Paused")]
		$ServiceStatus,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Auto","Manual","Disabled")]
		$ServiceStartMode,
		[Parameter(Mandatory=$true)]
		[ref]$outStatus
	)

	Begin {
		$res = "Good"
		$retValue = ""
	}
	Process {
		Write-LogMessage -Type Debug -Msg "Checking service '$ServiceName' statuses"
		Try{
			If (![string]::IsNullOrEmpty($ServiceStatus))
			{
				$svcStatus = (Get-Service -ServiceName $ServiceName).Status
				Write-LogMessage -Type Debug -Msg "Current Status for service '$ServiceName': $svcStatus"
				If($svcStatus.ToString().ToLower() -ne $ServiceStatus.ToLower())
				{
					$retValue = "Service status for '$ServiceName' is $svcStatus and not $ServiceStatus"
					$res = "Warning"
				}
			}
			elseif(![string]::IsNullOrEmpty($ServiceStartMode))
			{
				$svcStartMode = (Get-WMIItem -class Win32_Service -Item StartMode -Filter "Name='$ServiceName' or DisplayName='$ServiceName'").StartMode
				Write-LogMessage -Type Debug -Msg "Current StartMode for service '$ServiceName': $svcStartMode"
				If($svcStartMode.ToString().ToLower() -ne $ServiceStartMode.ToLower())
				{
					$retValue = "Service start mode for '$ServiceName' is $svcStartMode and not $ServiceStartMode"
					$res = "Warning"
				}
			}
			else
			{
				$retValue = "Wrong parameters used"
				$res = "Bad"
			}

			[ref]$outStatus.Value = $retValue
			return $res
		}
		Catch
		{
			Write-LogMessage -Type Error -Msg "Failed to compare status for service '$ServiceName'. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Failed to compare status for service '$ServiceName'. Error: $($_.Exception.Message)"
			return "Bad"
		}
	}
	End {

	}
}
Export-ModuleMember -Function Compare-ServiceStatus

# @FUNCTION@ ======================================================================================================================
# Name...........: Compare-AuditRulesFromPath
# Description....: Compare audit access rules from the input path
# Parameters.....: $path - Path - Registry or File
#                  $accessRules - Access Control Rules to compare to
# Return Values..: $true
#                  $false
# =================================================================================================================================
Function Compare-AuditRulesFromPath
{
<#
.SYNOPSIS
	Compare audit access rules from the input path
.DESCRIPTION
	Compare the audit access rules of the input path with the input best practice
.PARAMETER Path
	The Audit Path to check (Registry or ACL)
.PARAMETER AccessRules
	The Best practice Access Rules to compare to
#>
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$path,

		[Parameter(Mandatory=$true)]
        $accessRules,

		[Parameter(Mandatory=$true)]
		[ref]$outStatus
    )
	Begin {
		$retValue = "Good"
		$retStatus = ""
		$AuditString = @()
		$MissingAuditRules = @()
	}
	Process {
		Try {
			Write-LogMessage -Type "Debug" -Msg "Comparing audit rules for: $path"

			$pathAudit = Get-Acl $path -Audit
			$auditRules = $pathAudit.GetAuditRules($true,$true,[System.Security.Principal.NTAccount])
			If($auditRules.Count -gt 0)
			{
				ForEach($rule in $auditRules.GetEnumerator())
				{
					$AuditString += "{0}: {1}" -f $rule.IdentityReference, $rule.FileSystemRights
					# Compare ACL Rules
					If(!$accessRules -contains $rule)
					{
						$MissingAuditRules += "{0}: {1}" -f $rule.IdentityReference, $rule.FileSystemRights
					}
				}
				Write-LogMessage -Type "Debug" -Msg "Current rules Audit: $($AuditString -join '`n')"
				
				If($MissingAuditRules.Count -eq 0)
				{
					$retStatus = $AuditString
					$retValue = "Good"
				}
				else
				{
					$retStatus = "Current Audit Access rules: <ul><il>($AuditString -join '<il>')</ul> <BR> Missing Audit Access rules: <ul><il>($MissingAuditRules -join '<il>')</ul>"
					$retValue = "Warning"
				}				
			}
			Else
			{
				$retValue = "Bad"
				$retStatus = "No Audit rules at all on $path"
			}
			
			[ref]$outStatus.Value = $retStatus
			return $retValue
		}
		catch
		{
			Write-LogMessage -Type Error -Msg "Failed to collect audit access rules for: $key. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Failed to collect audit access rules for: $key. Error: $($_.Exception.Message)"
			return "Bad"
		}
	}
	End {

	}
}
Export-ModuleMember -Function Compare-AuditRulesFromPath

# @FUNCTION@ ======================================================================================================================
# Name...........: Compare-RegistryValue
# Description....: Compares registry value to the input values
# Parameters.....: Registry Path, Value Name, Value Data
# Return Values..: $true
#                  $false
# =================================================================================================================================
Function Compare-RegistryValue
{
<#
.SYNOPSIS
	Method to query a service status
.DESCRIPTION
	Compares registry value to the input values
.PARAMETER Path
	The registry Path to query (Hive + Key Path)
.PARAMETER ValueName
	The Registry Value Name to compare to
.PARAMETER ValueData
	The Registry Value Data to compare to
#>
	param(
		[Parameter(Mandatory=$true)]
		[String]$Path,
		[Parameter(Mandatory=$true)]
		[String]$ValueName,
		[Parameter(Mandatory=$true)]
		$ValueData,
		[Parameter(Mandatory=$true)]
		[ref]$outStatus
	)

	Begin {

	}
	Process {
		If (Test-Path $Path)
		{
			try{
				if(Test-Path -Path $Path)
				{
					$_hive = Split-Path -Path $Path -Qualifier
					$_key = Split-Path -Path $Path -NoQualifier
					$retValue = Get-Reg -Hive $_hive -Key $_key -Value $ValueName
					If($null -ne $retValue)
					{
						# Handle a scenario where the Value is not a string (most likely an String Array)
						If($retValue.GetType().Name -eq "String[]")
						{
							$retValue = $retValue -join ','
						}
						If($ValueData.GetType().Name -eq "String[]")
						{
							$ValueData = $ValueData -join ','
						}
						If($ValueData -eq $retValue)
						{
							[ref]$outStatus.Value = "Registry Key: $Path<BR>$ValueName=$ValueData"
							return "Good"
						}
						Else
						{
							[ref]$outStatus.Value = "Registry Key: $Path<BR>Value Name=$ValueName<BR>Should be $ValueData"
							return "Warning"
						}
					}
					Else
					{
						[ref]$outStatus.Value = "Registry Key: $Path<BR>Value Name=$ValueName does not exist"
						return "Warning"
					}
				}
				else
				{
					[ref]$outStatus.Value = "Registry Key: $Path does not exist"
					return "Bad"
				}
			}
			catch{
				Write-LogMessage -Type Error -Msg "Error comparing Registry Value. Error: $(Join-ExceptionMessage $_.Exception)"
				[ref]$outStatus.Value = "Error comparing Registry Value. Error: $($_.Exception.Message)"
				return "Bad"
			}
		}
		else
		{
			Write-LogMessage -Type Error -Msg "Path $Path does not exist"
			[ref]$outStatus.Value = "Missing registry path: $path"
			return "Bad"
		}
	}
	End {

	}
}
Export-ModuleMember -Function Compare-RegistryValue

# @FUNCTION@ ======================================================================================================================
# Name...........: Compare-UserRight
# Description....: Compare user right of a local user in Local security policy
# Parameters.....: $userName - The user name to check
#                  $userRight - The user right to compare
# Return Values..: None
# =================================================================================================================================
Function Compare-UserRight
{
<#
.SYNOPSIS
	Method to compare user right of a specific user
.DESCRIPTION
	Compare user right of a local user in Local security policy
.PARAMETER UserName
	The User Name to Check user settings for
.PARAMETER UserRight
	The User right to compare
#>
	param(
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$userName,
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$userRight,
	   [Parameter(Mandatory=$true)]
	   [ref]$outStatus
    )
		Begin{
			$retValue = ""
		}
    	Process {
		Try{
			Write-LogMessage -Type "Debug" -Msg "Checking ""$userRight"" user rights to user $userName"
			# Get User SID
			$userSIDStr = (Convert-NameToSID -userName $userName)
			if($null -eq $userSIDStr) { throw "User $userName could not be found" }
			# Setting temp file paths
			$tempPath = [System.IO.Path]::GetTempPath()
			$exportPath = Join-Path -Path $tempPath -ChildPath "export.inf"
			if(Test-Path $exportPath) { Remove-Item -Path $exportPath -Force }

			Write-LogMessage -Type Debug -Msg "Export current Local Security Policy to file $exportPath"
			secedit.exe /export /areas SECURITYPOLICY USER_RIGHTS REGKEYS /cfg "$exportPath" | Out-Null

			$currentRightKeyValue = (Select-String $exportPath -Pattern "$userRight").Line
			$currentSidsValue = $currentRightKeyValue.split("=",[System.StringSplitOptions]::RemoveEmptyEntries)[1].Trim()

			if( ($currentSidsValue -NotLike "*$($userSIDStr)*") -and ($currentSidsValue -NotLike "*$($userName)*")) {
				$msg = "User $userName does not have the correct ""$userRight"" user right settings"
				Write-LogMessage -Type "Warning" -Msg $msg
				$retValue = "Warning"
				[ref]$outStatus.Value = $msg
			} else {
				$msg = "User $userName has the correct ""$userRight"" user right settings"
				Write-LogMessage -Type "Info" -Msg $msg
				$retValue = "Good"
				[ref]$outStatus.Value = $msg
			}

			Remove-Item -Path $exportPath -Force

			return $retValue

		}catch{
			Write-LogMessage -Type Error -Msg "Error comparing user rights ""$userRight"" for user $userName. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Error comparing user rights ""$userRight"" for user $userName. Error: $($_.Exception.Message)"
			return "Bad"
		}
	}
	End{

   }
}
Export-ModuleMember -Function Compare-UserRight

# @FUNCTION@ ======================================================================================================================
# Name...........: Compare-PolicyEntry
# Description....: Compare local Group Policy object using the PowerShell module "PolicyFileEditor"
# Parameters.....: $EntryTitle - The descriptive name of the local group policy entry.
#                  $UserDir - Path to the .pol (policy) file
#				   $RegPath - path to the local GPO entry
#				   $RegName - local GPO entry name
#			       $RegData - local GPO entry value
# Return Values..: True in case of success, false otherwise
# =================================================================================================================================
Function Compare-PolicyEntry
{
<#
.SYNOPSIS
	Method to compare local group policy to input GPO data
.DESCRIPTION
	Compare local Group Policy object using the PowerShell module "PolicyFileEditor"
.PARAMETER EntryTitle
	The descriptive name of the local group policy entry.
.PARAMETER UserDir
	Path to the .pol (policy) file
.PARAMETER RegPath
	Path to the local GPO entry
.PARAMETER RegName
	Local GPO entry name
.PARAMETER RegData
	Local GPO entry value
#>
	param(
		[parameter(Mandatory=$true)]
	    [ValidateNotNullOrEmpty()]$EntryTitle,
		[parameter(Mandatory=$true)]
	    [ValidateNotNullOrEmpty()]$UserDir,
		[parameter(Mandatory=$true)]
	    [ValidateNotNullOrEmpty()]$RegPath,
		[parameter(Mandatory=$true)]
	    [ValidateNotNullOrEmpty()]$RegName,
		[parameter(Mandatory=$true)]
	    [ValidateNotNullOrEmpty()]$RegData,
		[Parameter(Mandatory=$true)]
		[ref]$outStatus
	)

	Begin{

	}
	Process{
		try{
			Write-LogMessage -Type "Verbose" -Msg "Starting Compare-PolicyEntry ($EntryTitle,$UserDir,$RegPath,$RegName,$RegData)"
			$retValue = Get-Reg -Hive "LocalMachine" -Key $RegPath -Value $RegName
			if ($RegData -eq $retValue)
			{
				Write-LogMessage -Type "Info" -Msg "Local Group Policy Entry $EntryTitle status matches $RegData"
				[ref]$outStatus.Value = "Local Group Policy Entry $EntryTitle status matches $RegData"
				return "Good"
			}
			else
			{
				Write-LogMessage -Type "Info" -Msg "Local Group Policy Entry $EntryTitle status does not match $RegData"
				[ref]$outStatus.Value = "Local Group Policy Entry $EntryTitle status does not match $RegData"
				return "Warning"
			}
		}catch{
			Write-LogMessage -Type "Error" -Msg "Error comparing local group policy '$EntryTitle'. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Error comparing local group policy '$EntryTitle'. Error: $($_.Exception.Message)"
			return "Bad"
		}
	}
	End{

	}
}
Export-ModuleMember -Function Compare-PolicyEntry

# @FUNCTION@ ======================================================================================================================
# Name...........: Compare-UserPermissions
# Description....: Compare user permissions on the relevant path.
# Parameters.....: $path - The location path we want to check permissions.
#				   $identity - The user we want to check permissions to.
#				   $rights - The rights we want to compare to the identity on this path.
#							 Please Notice this needs to be string indicate enum name from System.Security.AccessControl.RegistryRights or System.Security.AccessControl.FileSystemRights enums.
# Return Values..: True or false if succeeded or not.
# =================================================================================================================================
Function Compare-UserPermissions
{
<#
.SYNOPSIS
	Method to compare User permissions on a path
.DESCRIPTION
	Compare user permissions on the relevant path
.PARAMETER Path
	The location path we want to check permissions.
.PARAMETER Identity
	The user we want to check permissions to.
.PARAMETER Rights
	The rights we want to compare to the identity on this path.
	Please Notice this needs to be string indicate enum name from System.Security.AccessControl.RegistryRights or System.Security.AccessControl.FileSystemRights enums.
#>
	param(
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$path,
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$identity,
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$rights,
	   [parameter(Mandatory=$false)]
	   [ValidateSet("Allow","Deny")]$ACLType = "Allow",
	   [Parameter(Mandatory=$true)]
	   [ref]$outStatus
	)
	Begin{
		$retValue = "Good"
	}
	Process{
		try{

			Write-LogMessage -Type Debug -Msg "Check user permissions: '$rights' on path: '$path' to user\group: '$identity'"
			If(Test-Path $Path)
			{
				$acl = Get-ACL -Path $path
				$aclLog = $acl | Format-List | Out-String
				Write-LogMessage -Type Verbose -MSG "Current permissions on path: '$path': $aclLog"
				if($identity.Contains('\')) { $parsedIdentity = $identity.Split('\')[1] }
				else { $parsedIdentity = $identity }
				$permissions = $acl.Access | Where-Object{$_.IdentityReference -match $parsedIdentity} | Select-Object IdentityReference,FileSystemRights,AccessControlType
                if (($null -ne $permissions) -and ($permissions.FileSystemRights -like "*$rights*") -and ($permissions.AccessControlType -eq $ACLType))

					{
				    Write-LogMessage -Type Debug -Msg "User $identity has the required rights ($rights) to $path"
			        [ref]$outStatus.Value = "$identity has the required rights ($rights) to $path"
				    }

                else{
                     [ref]$outStatus.Value = "$identity does not have required rights ($rights) to $path"
                     $retValue = "Warning"
                    }

             } Else {
				$msg = "The path '$path' does not exist"
				Write-LogMessage -Type Warning -Msg $msg
				[ref]$outStatus.Value = $msg
				$retValue = "Warning"
			}
		} Catch {
			Write-LogMessage -Type Error -Msg "Failed to get user permissions: '$rights' on path: '$path' to user\group: '$identity'. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Failed to get user permissions: '$rights' on path: '$path' to user\group: '$identity'. Error: $($_.Exception.Message)"
			$retValue = "Bad"
		}
		return $retValue
	}
	End{

   }
}
Export-ModuleMember -Function Compare-UserPermissions

# @FUNCTION@ ======================================================================================================================
# Name...........: Compare-UserFlags
# Description....: Compare user object flags to a specific value
# Parameters.....: $userName - The user name to check
#				   $flagName - The user flag we want to check
#				   $flagValue - The flag value we want to compare to
# Return Values..: True or false if succeeded or not.
# =================================================================================================================================
Function Compare-UserFlags
{
<#
.SYNOPSIS
	Method to compare User object flag to a specific value
.DESCRIPTION
	Compare user object flag to a specific value
.PARAMETER userName
	The user name to check.
.PARAMETER flagName
	The user flag we want to check.
.PARAMETER flagValue
	The flag value we want to compare to.
#>
	param(
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$userName,
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$flagName,
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$flagValue,
	   [parameter(Mandatory=$false)]
	   [ValidateSet("SCRIPT","ACCOUNTDISABLE","HOMEDIR_REQUIRED","LOCKOUT","PASSWD_NOTREQD",`
	   "PASSWD_CANT_CHANGE","ENCRYPTED_TEXT_PASSWORD_ALLOWED","TEMP_DUPLICATE_ACCOUNT","NORMAL_ACCOUNT",`
	   "INTERDOMAIN_TRUST_ACCOUNT","WORKSTATION_TRUST_ACCOUNT","SERVER_TRUST_ACCOUNT","DONT_EXPIRE_PASSWD","MNS_LOGON_ACCOUNT",`
	   "SMARTCARD_REQUIRED","TRUSTED_FOR_DELEGATION","NOT_DELEGATED","USE_DES_KEY_ONLY","DONT_REQUIRE_PREAUTH","PASSWORD_EXPIRED","TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION")]
	   $userFlagValue = $null,
	   [Parameter(Mandatory=$true)]
	   [ref]$outStatus
	)
	Begin{
		$retValue = "Good"
		Switch($userFlagValue)
		{
			"SCRIPT" {
				$bUserFlag = "1";
				break
			}
			"ACCOUNTDISABLE"  {
				$bUserFlag = "2";
				break
			}
			"HOMEDIR_REQUIRED" {
				$bUserFlag = "8";
				break
			}
			"LOCKOUT" {
				$bUserFlag = "16";
				break
			}
			"PASSWD_NOTREQD" {
				$bUserFlag = "32";
				break
			}
			"PASSWD_CANT_CHANGE" {
				$bUserFlag = "64";
				break
			}
			"ENCRYPTED_TEXT_PASSWORD_ALLOWED" {
				$bUserFlag = "128";
				break
			}
			"TEMP_DUPLICATE_ACCOUNT" {
				$bUserFlag = "256";
				break
			}
			"NORMAL_ACCOUNT" {
				$bUserFlag = "512";
				break
			}
			"INTERDOMAIN_TRUST_ACCOUNT" {
				$bUserFlag = "2048";
				break
			}
			"WORKSTATION_TRUST_ACCOUNT" {
				$bUserFlag = "4096";
				break
			}
			"SERVER_TRUST_ACCOUNT" {
				$bUserFlag = "8192";
				break
			}
			"DONT_EXPIRE_PASSWD" {
				$bUserFlag = "65536";
				break
			}
			"MNS_LOGON_ACCOUNT" {
				$bUserFlag = "131072";
				break
			}
			"SMARTCARD_REQUIRED" {
				$bUserFlag = "262144";
				break
			}
			"TRUSTED_FOR_DELEGATION" {
				$bUserFlag = "524288";
				break
			}
			"NOT_DELEGATED" {
				$bUserFlag = "1048576";
				break
			}
			"USE_DES_KEY_ONLY" {
				$bUserFlag = "2097152";
				break
			}
			"DONT_REQUIRE_PREAUTH" {
				$bUserFlag = "4194304";
				break
			}
			"PASSWORD_EXPIRED" {
				$bUserFlag = "8388608";
				break
			}
			"TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION" {
				$bUserFlag = "16777216";
				break
			}
		}
	}
	Process{
		try{
			Write-LogMessage -Type Debug -Msg "Check user flag: '$flagName' on user: '$userName' to value: '$flagValue'"
			$user=[ADSI]"WinNT://$ENV:ComputerName/$userName,user"
			if($null -ne $userFlagValue)
			{
				$val = $user.InvokeGet($flagName) -band $bUserFlag
			}
			else
			{
				$val = $user.InvokeGet($flagName)
			}
			Write-LogMessage -Type Debug -Msg "User $userName flags value for flag '$flagName' is $val - needs to be $flagValue"
			if($val -eq $flagValue)
			{
				[ref]$outStatus.Value = "$userName has the required configuration for '$flagName'"
				$retValue = "Good"
			}
			else
			{
				$msg = "$userName has a wrong configuration for '$flagName' - current configuration: $val"
				Write-LogMessage -Type Warning -Msg $msg
				[ref]$outStatus.Value = $msg
				$retValue = "Warning"
			}
		} Catch {
			Write-LogMessage -Type Error -Msg "Failed to get user permissions: '$rights' on path: '$path' to user\group: '$identity'. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Failed to get user permissions: '$rights' on path: '$path' to user\group: '$identity'. Error: $($_.Exception.Message)"
			$retValue = "Bad"
		}
		return $retValue
	}
	End{

   }
}
Export-ModuleMember -Function Compare-UserFlags

# @FUNCTION@ ======================================================================================================================
# Name...........: Compare-AmountOfUserPermissions
# Description....: Compare amount of required user permissions on the relevant path.
# Parameters.....: $path - The location path we want to check permissions.
#				   $amount - The amount of users needed on the path
# Return Values..: True or false if succeeded or not.
# =================================================================================================================================
Function Compare-AmountOfUserPermissions
{
<#
.SYNOPSIS
	Method to compare User permissions on a path
.DESCRIPTION
	Compare user permissions on the relevant path
.PARAMETER Path
	The location path we want to check permissions.
.PARAMETER Amount
	The amount of users that needs to have permissions on the path.
#>
	param(
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$path,
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$amount,
	   [Parameter(Mandatory=$true)]
	   [ref]$outStatus
	)
	Begin{
		$retValue = "Good"
	}
	Process{
		try{
			If(Test-Path $path)
			{
				$aclCount = (Get-ACL -Path $path).Access.Count
				Write-LogMessage -Type Debug -Msg "Path '$path' has $aclCount user/group permissions"

				If($aclCount -ne $amount)
				{
					$msg = "The path '$path' does not have the required amount of permissions (Required: $amount, Current: $aclCount)"
					Write-LogMessage -Type Warning -Msg $msg
					[ref]$outStatus.Value = $msg
					$retValue = "Warning"
				}
			} Else {
				$msg = "The path '$path' does not exist"
				Write-LogMessage -Type Warning -Msg $msg
				[ref]$outStatus.Value = $msg
				$retValue = "Warning"
			}
		} Catch {
			Write-LogMessage -Type Error -Msg "Failed to get user permissions count on path '$path'. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Failed to get user permissions count on path '$path'. Error: $($_.Exception.Message)"
			$retValue = "Bad"
		}
		return $retValue
	}
	End{

   }
}
Export-ModuleMember -Function Compare-AmountOfUserPermissions

# @FUNCTION@ ======================================================================================================================
# Name...........: Compare-AdvancedAuditPolicySubCategory
# Description....: Compare Advanced Audit Policy security settings
# Parameters.....: $subcategory - String containing the entry to set
#                  $success - success enabled/disabled
#                  $failure - failure enabled/disabled
# Return Values..: None
# =================================================================================================================================
Function Compare-AdvancedAuditPolicySubCategory
{
<#
.SYNOPSIS
	Method to Compare Advanced Audit Policy security settings
.DESCRIPTION
	Compare Advanced Audit Policy security settings
.PARAMETER subcategory
	String containing the entry to set
.PARAMETER success
	success enabled/disabled
.PARAMETER failure
	failure enabled/disabled
#>
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]$subcategory,
		[ValidateSet("enable","disable")]
		[ValidateNotNullOrEmpty()]$success="enable",
		[ValidateSet("enable","disable")]
		[ValidateNotNullOrEmpty()]$failure="enable",
		[Parameter(Mandatory=$true)]
		[ref]$outStatus
	)
	Begin{
		$returnVal = "Good"
	}
	Process {
		try {
			Write-LogMessage -Type "Info" -Msg "Checking Advance Audit Policy Sub Category for '$subcategory'"

			$verifySuccess = $false
			$verifyFailure = $false
			$auditLineOutput = ""
			$_subCategory = $subcategory
			# Avoid "Error 0x00000057 occurred"
			If($subcategory -match "(?:^Audit\s)(.*)")
			{
				# Add an exception for "Audit Policy Change"
				If($subcategory -ne "Audit Policy Change")
				{
					# See: http://david-homer.blogspot.com/2016/08/when-using-auditpolexe-you-see-error.html
					$_subCategory = $Matches[1]
				}
			}
			$auditCommandOutput = auditpol /get /subCategory:"$_subCategory" | Where-Object {$_ -match $_subCategory}
			if($null -ne $auditCommandOutput)
			{
				ForEach($item in $auditCommandOutput)
				{
					if($item -ne "")
					{
						$auditLineOutput = $item.Trim()
						Write-LogMessage -Type Debug -Msg "Found Audit Policy: $auditLineOutput"
						$auditPolicy = $item.Trim() -split "($_subCategory\s+)"
						# Assuming $auditPolicy[0] is empty
						if($auditPolicy[1] -eq $_subCategory)
						{
							# $auditPolicy[2] is where the Success, Failure data will be
							$verifySuccess = Test-EnabledPolicySetting -PolicyStatus $success -MatchValue $auditPolicy[2] -NotMatchCriteria "Success"
							$verifyFailure = Test-EnabledPolicySetting -PolicyStatus $failure -MatchValue $auditPolicy[2] -NotMatchCriteria "Failure"
							break
						}
					}
				}
			}
			else {
				Write-LogMessage -Type Error -Msg "There was a problem verifying Advance Audit Policy Sub Category for '$_subCategory'"
				$returnVal = "Warning"
				[ref]$outStatus.Value = "There was a problem verifying Advance Audit Policy Sub Category for '$_subCategory'"
			}
			if($verifySuccess -and $verifyFailure)
			{
				Write-LogMessage -Type Debug -Msg "Advance Audit Policy Sub Category for '$_subCategory' has the correct settings for Success and Failure"
				$returnVal = "Good"
				[ref]$outStatus.Value = "Advance Audit Policy Sub Category for '$_subCategory' has the correct settings for Success and Failure<BR>$auditLineOutput"
			}
		} Catch {
			Write-LogMessage -Type Error -Msg "Could not get Advance Audit Policy Sub Category for '$_subCategory'. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Could not get Advance Audit Policy Sub Category for '$_subCategory'. Error: $($_.Exception.Message)"
			$returnVal = "Bad"
		}
		return $returnVal
	}
	End{

   }
}
Export-ModuleMember -Function Compare-AdvancedAuditPolicySubCategory

# @FUNCTION@ ======================================================================================================================
# Name...........: Compare-EventLogSizeAndRetentionSettings
# Description....:
# Parameters.....:
# Return Values..:
# =================================================================================================================================
Function Compare-EventLogSizeAndRetentionSettings
{
<#
.SYNOPSIS
	Method to check the Event log Size and Retention
.DESCRIPTION
	Returns true if the Event log size and retention are as requested
.PARAMETER LogName
	The Event Log Name to Check
.PARAMETER Size
	The Event Log size to Check
.PARAMETER SaveRetention
	The Event Log retention setting value to Check
#>
	param(
	   [ValidateNotNullOrEmpty()]$LogName,
	   [ValidateNotNullOrEmpty()]$Size,
	   [ValidateNotNullOrEmpty()]$SaveRetention,
	   [Parameter(Mandatory=$true)]
	   [ref]$outStatus
	)

	Begin {

	}
	Process {
		try{
			Write-LogMessage -Type "Info" -Msg "Checking Event Log Size and retention settings for '$LogName'"
			$output = ""
			$EntitySettings = wevtutil gl $LogName | Where-Object { $_ -match "(retention|maxSize)" }
			# Check Retention
			if($EntitySettings[0].Split(":")[1].Trim() -ne $SaveRetention)
			{
				Write-LogMessage -Type "Info" -Msg "Log retention should be set to $SaveRetention"
				$output = "Log retention should be set to $SaveRetention"
			}
			# Check Max Size
			if(([int]($EntitySettings[1].Split(":")[1].Trim())) -lt $Size)
			{
				Write-LogMessage -Type "Info" -Msg "Log Size should be set to $Size"
				if($output -ne "")
				{
					$output+= "<BR>"
				}
				$output+= "Log Size should be set to $Size"
			}

			if($output -ne "")
			{
				[ref]$outStatus.Value = "Size and Retention settings for Log '$LogName' are not correct.<BR>$output"
				return "Warning"
			}
			else
			{
				[ref]$outStatus.Value = "Size and Retention settings for Log '$LogName' are good"
				return "Good"
			}
		}catch{
			Write-LogMessage -Type "Error" -Msg "Error comparing Size and Retention settings for Log '$LogName'. Error: $(Join-ExceptionMessage $_.Exception)"
			[ref]$outStatus.Value = "Error comparing Size and Retention settings for Log '$LogName'. Error: $($_.Exception.Message)"
			return "Bad"
		}
	}
	End {

	}
}
Export-ModuleMember -Function Compare-EventLogSizeAndRetentionSettings

# @FUNCTION@ ======================================================================================================================
# Name...........: Convert-NameToSID
# Description....: Get user SID value
# Parameters.....: $userName - The user name we want his SID value.
# Return Values..: SID string value
# =================================================================================================================================
Function Convert-NameToSID {
<#
.SYNOPSIS
	Method to convert user name to SID
.DESCRIPTION
	Returns the user sid value
.PARAMETER UserName
	The User Name to convert to SID
#>
	param(
	   [parameter(Mandatory=$true)]
	   [ValidateNotNullOrEmpty()]$userName
    )
	Begin {

	}
   	Process {
		Write-LogMessage -Type Debug -Msg "Get SID value for user: $userName"
		$userSIDStr = $null
		Try {
			$NTPrincipal = new-object System.Security.Principal.NTAccount "$userName"
			$userSid = $NTPrincipal.Translate([System.Security.Principal.SecurityIdentifier])
			$userSIDStr = $userSid.Value.ToString()
			Write-LogMessage -Type Debug -Msg "User SID: $userSIDStr"
		} Catch {
			$userSIDStr = $null
			Throw $(New-Object System.Exception ("Failed to get SID for user: $userName",$_.Exception))
		}

		return $userSIDStr
	}
	End{

   }
}
Export-ModuleMember -Function Convert-NameToSID

# @FUNCTION@ ======================================================================================================================
# Name...........: Convert-SIDToName
# Description....: Get the name value of SID identity
# Parameters.....: $sidID - A string indicate the SID id.
# Return Values..: If found we the value name, otherwise $NULL
# =================================================================================================================================
Function Convert-SIDToName{
<#
.SYNOPSIS
	Method to convert SID to Name
.DESCRIPTION
	Returns the user name value
.PARAMETER sidID
	The User/Group SID to convert to Name
#>
   param(
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$sidID
   )
	Begin {

	}
	Process {
		Write-LogMessage -Type Verbose -Msg "Get Name value for SID: $sidID"
		$returnVal = $NULL
		try {
			# Use this SID to take the name of built-in operating system identifiers.
			$objSID = New-Object System.Security.Principal.SecurityIdentifier ($sidID)
			$objGroup = $objSID.Translate([System.Security.Principal.NTAccount])
			$returnVal = $objGroup.value
			Write-LogMessage -Type Verbose -Msg "SID name is: $returnVal"
		} Catch {
			Throw $(New-Object System.Exception ("Failed to get Name from SID: $sidID",$_.Exception))
		}
		return $returnVal
	}
	End{

   }
}
Export-ModuleMember -Function Convert-SIDToName

# @FUNCTION@ ======================================================================================================================
# Name...........: ConvertTo-Bool
# Description....: This method will convert common boolean expressions to real boolean
# Parameters.....: $txt - Text to convert
# Return Values..: Boolean value of the text
# =================================================================================================================================
Function ConvertTo-Bool
{
<#
.SYNOPSIS
	Method to convert common boolean expressions to real boolean
.DESCRIPTION
	This method will convert common boolean expressions to real boolean
.PARAMETER txt
	The text to convert to boolean
#>
	param (
		[parameter(Mandatory=$true)]
 	    [ValidateNotNullOrEmpty()]
		[string]$txt
	)
	$retBool = $false

if ([bool]::TryParse($txt, [ref]$retBool)) {
    # parsed to a boolean
    return $retBool
	} elseif ($txt -match "^yes$|^y$") {
		return $true
	} elseif ($txt -match "^no$|^n$") {
		return $false
	} else {
		Write-LogMessage -Type Error -Msg "The input ""$txt"" is not in the correct format (true/false), defaulting to False"
		return $false
	}
}
Export-ModuleMember -Function ConvertTo-Bool

# @FUNCTION@ ======================================================================================================================
# Name...........: Start-HardeningSteps
# Description....: This method gets a path to a steps config file, parse the file, run the steps,
#						 and return a summary of the execution
# Parameters.....: $configStepsPath - The full path of the steps config file
# Return Values..: execution summary
# =================================================================================================================================
Function Start-HardeningSteps
{
<#
.SYNOPSIS
	Method to parse the hardening steps configuration file
.DESCRIPTION
	This method gets a path to a steps config file, parse the file, run the steps, and return a summary of the execution
.PARAMETER configStepsPath
	The full path of the steps config file
#>
   param(
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$configStepsPath
	)
	Begin{
		$AllStepsArray = @()
		$AllHardeningStepsStatus = @()
	}
	Process {
		try{
			$StepsToRun = Read-ConfigurationFile $configStepsPath

			ForEach ($step in $StepsToRun)
			{
				$refHardeningStepStatus = "" | Select-Object Name, Description, Status, Output

				$refHardeningStepStatus.Name = $step.DisplayName
				$refHardeningStepStatus.Description = $step.Description
				if ($(ConvertTo-Bool $step.Enable) -eq $False)
				{
					Write-LogMessage -Type Debug -Msg "Step $($step.Name) is disabled"
					$refHardeningStepStatus.Status = "Bad"
					$refHardeningStepStatus.Output = "Step is disabled, verification was not performed"
					$AllStepsArray += New-Object PSObject -Property @{Name=$step.Name;CompletedSuccessfully=$false}
				}
				else
				{
					Write-LogMessage -Type Info -Msg "Start Step $($step.DisplayName)" -SubHeader
					try
					{
						$refOutput = ""
						$isSuccess = $true
						$refHardeningStepStatus.Status = . $($step.ScriptName) -Parameters $($step.Parameters) -refOutput ([ref]$refOutput)
						$refHardeningStepStatus.Output = $refOutput.Value
						If($refHardeningStepStatus.Status -ne "Good")
						{
							$isSuccess = $false
						}
						$refHardeningStepStatus.Output = $refOutput.Value
						$AllStepsArray += New-Object PSObject -Property @{Name=$step.Name;CompletedSuccessfully=$isSuccess}
					}
					catch
					{
						Write-LogMessage -Type Error -Msg "Error running step $($step.Name).  Error: $(Join-ExceptionMessage $_.Exception)"
						$refHardeningStepStatus.Status = "Bad"
						$refHardeningStepStatus.Output = "Error running step.  Error: $(Join-ExceptionMessage $_.Exception)"
						$AllStepsArray += New-Object PSObject -Property @{Name=$step.Name;CompletedSuccessfully=$false}
					}

					Write-LogMessage -Type Info -Msg "Finished Step $($step.DisplayName)"
				}
				# Add to steps array
				#Write-LogMessage -Type Debug -Msg "$($refHardeningStepStatus.Name) ($($refHardeningStepStatus.Status)): $($refHardeningStepStatus.Output)"
				Write-LogMessage -Type Debug -Msg "$($refHardeningStepStatus.Name) ($($refHardeningStepStatus.Status))"
				$AllHardeningStepsStatus += $refHardeningStepStatus
			}

			Write-LogMessage -Type Info -Msg "Hardening Steps summary for '$configStepsPath'" -Header
			Write-LogMessage -Type Info -Msg "Step Name, Completed Successfully?" -SubHeader
			ForEach ($step in $AllStepsArray)
			{
				Write-LogMessage -Type Info -Msg "$($step.Name), $($step.CompletedSuccessfully)"
			}
			Write-LogMessage -Type Info -Msg "" -Footer
		}
		catch{
			Write-LogMessage -Type Error -Msg "Error running Hardening Steps. Error: $(Join-ExceptionMessage $_.Exception)"
		}
		return $AllHardeningStepsStatus
	}
	End{
   }
}
Export-ModuleMember -Function Start-HardeningSteps

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-CredFileRestrictions
# Description....: Checks the restrictions of the credential files that are used by the CyberArk components
# Parameters.....: None
# Return Values..: VerificationsFlag value
# =================================================================================================================================
Function Test-CredFileVerificationType
{

<#
.SYNOPSIS
	Check what restrictions have been placed on the component credential files
.DESCRIPTION
	This check what (if any) restrictions have been put on to the credential file when it was created, this credential file is utilized by the components to communicate back to the vault
#>

    param (
   		[Parameter(Mandatory=$true)]
        [String] $CredentialFilePath,
		[Parameter(Mandatory=$true)]
		[ref]$outStatus
    )

	Begin {
            $retValue = "Good"
            $typeOfVerification = ""
            $verificationsFlag = ""
            $vaultUser = ""
	}
	Process {
        if(Test-Path $CredentialFilePath)
        {
            try{
                $verificationsFlag = $(get-content $CredentialFilePath | Select-String 'VerificationsFlag') -replace 'VerificationsFlag=',''
                $vaultUser = $(get-content $CredentialFilePath | Select-String 'Username') -replace 'Username=',''
                $credFileType = $(get-content $CredentialFilePath | Select-String 'CredFileType') -replace 'CredFileType=',''
				
				# Check Credential File Type
				$typeOfCredFile = @{"Password" = "No"; "EnhancedPasswordMachine" = "Machine"; "EnhancedPasswordUser" = "User"}
				$credTypeMsg = "Using {0} OS Protected Storage" -f $typeOfCredFile.Get_Item($CredFileType)
				
				# Check Cred File Verifications
				$typeOfVerification = @{0 = "No" ; 1 = "Client Type" ; 2 = "Execution Path" ; 4 = "IP" ; 8 = "OS User" ; 32 = "Hostname"}
				If($verificationsFlag -gt 16)
				{
					$verificationMsg = $($typeOfVerification.Keys | Where-Object { $_ -band $verificationsFlag } | ForEach-Object { $typeOfVerification.Get_Item($_) }) -join ', '
					If($verificationMsg.Contains(','))
					{
						# Organize the text a bit in case of list
						$verificationMsg = $verificationMsg.Remove($verificationMsg.LastIndexOf(','),$verificationMsg.Length-$verificationMsg.LastIndexOf(','))+$verificationMsg.Substring($verificationMsg.LastIndexOf(',')).Replace(','," and")
					}
					$retValue = "Good"
				} Else {
				   $verificationMsg = $typeOfVerification.Get_Item(0)
				   $retValue = "Warning"
				}
				
				$retMsg = "$verificationMsg restriction(s) set on the '$(Split-path $CredentialFilePath -leaf)' credential file for the vault user '$vaultUser'."
				$retMsg += $credTypeMsg

				[ref]$outStatus.Value = $retMsg
            } catch {
				Write-LogMessage -Type Error -Msg "Error comparing Registry Value. Error: $(Join-ExceptionMessage $_.Exception)"
				[ref]$outStatus.Value = "Error comparing Registry Value. Error: $($_.Exception.Message)"
				$retValue = "Bad"
			}
		}
        Else {
			[ref]$outStatus.Value = "Credential file not found"
			$retValue = "Warning"
		}

		return $retValue
   } End {
   }
}
Export-ModuleMember -Function Test-CredFileVerificationType
#endregion