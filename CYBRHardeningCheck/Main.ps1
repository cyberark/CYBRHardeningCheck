###########################################################################
#
# SCRIPT NAME: CyberArk Hardening HealthCheck
#
###########################################################################
<#
.SYNOPSIS
            The main script of CyberArk Hardening Health Check

.DESCRIPTION
            This script will detect the installed component on the local machine and verify the hardening on the machine
			compared to CyberArk best practice and hardening recommendation
			Supported components are: Vault, CPM, PVWA, PSM, AIM, EPM Server
#>
[CmdletBinding()]
param
(
)

# Get Script Location
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

# Script Version
$ScriptVersion = "2.8.1"

# Set Log file path
$global:LOG_FILE_PATH = "$ScriptLocation\Hardening_HealthCheck.log"

# Set Bin Folder
$global:MODULE_BIN_PATH = "$ScriptLocation\bin"

# Set Date Time Pattern
[string]$global:g_DateTimePattern = "$([System.Globalization.CultureInfo]::CurrentCulture.DateTimeFormat.ShortDatePattern) $([System.Globalization.CultureInfo]::CurrentCulture.DateTimeFormat.LongTimePattern)"

# Set Hardening Configuration Steps XML
$CPM_HARDENING_CONFIG = "$ScriptLocation\CPM\CPM_Hardening_Config.xml"
$PVWA_HARDENING_CONFIG = "$ScriptLocation\PVWA\PVWA_Hardening_Config.xml"
$PSM_HARDENING_CONFIG = "$ScriptLocation\PSM\PSM_Hardening_Config.xml"
$VAULT_HARDENING_CONFIG = "$ScriptLocation\Vault\Vault_Hardening_Config.xml"

# Set modules paths
$MODULE_COMMON_UTIL = "$MODULE_BIN_PATH\CommonUtil.psm1"
$MODULE_GENERAL_STEPS = "$MODULE_BIN_PATH\GeneralHardeningSteps.psm1"
$MODULE_CPM_STEPS = "$ScriptLocation\CPM\CPMHardeningSteps.psm1"
$MODULE_PVWA_STEPS = "$ScriptLocation\PVWA\PVWAHardeningSteps.psm1"
$MODULE_PSM_STEPS = "$ScriptLocation\PSM\PSMHardeningSteps.psm1"
$MODULE_VAULT_STEPS = "$ScriptLocation\Vault\VaultHardeningSteps.psm1"

# Output file template
$REPORT_TEMPLATE_PATH = "$ScriptLocation\Hardening_HealthCheck_Report.html"

#region Helper Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Import-ScriptModule
# Description....: Load the relevant modules into the script
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Import-ScriptModule
{
<#
.SYNOPSIS
	Load hardening modules
.DESCRIPTION
	Load all relevant hardening modules for the script
#>
	param(
	)

	Begin {
	}
	Process {
		$commonUtilInfo = Import-Module $MODULE_COMMON_UTIL -Force -DisableNameChecking -PassThru -ErrorAction Stop
		$generalInfo = Import-Module $MODULE_GENERAL_STEPS -Force -DisableNameChecking -PassThru -ErrorAction Stop
	}
	End {
		return $commonUtilInfo,$generalInfo
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Remove-ScriptModule
# Description....: UnLoad the relevant modules into the script
# Parameters.....: Module Info
# Return Values..: None
# =================================================================================================================================
Function Remove-ScriptModule
{
<#
.SYNOPSIS
	UnLoad hardening modules
.DESCRIPTION
	UnLoad all relevant hardening modules for the script
#>
	param(
		$moduleInfo
	)

	Begin {
	}
	Process {
		ForEach ($info in $moduleInfo)
		{
			Remove-Module -ModuleInfo $info -ErrorAction Stop | out-Null
		}
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Write-HTMLHardeningStatusTable
# Description....: Write the Hardening status rows to the HTML report output table
# Parameters.....: Hardening Status
# Return Values..: None
# =================================================================================================================================
Function Write-HTMLHardeningStatusTable
{
<#
.SYNOPSIS
	Write a new Hardening status row to the HTML report output table
.DESCRIPTION
	Write a new Hardening status row to the HTML report output table
.PARAMETER

#>
	param(
		$hardeningStatus
	)

	Begin {
		If($null -eq $hardeningStatus)
		{
			Throw $(New-Object System.Exception ("Hardening Status object is NULL",$_.Exception))
		}
	}
	Process {
		$retText = ""
		# Get the Unique sorted list of hardening steps
		$sortedHardeningStatus = $hardeningStatus | Sort-Object -Property Name -Unique
		# Concatenate the status of duplicated items
		ForEach($item in $sortedHardeningStatus)
		{
			# Check for duplicates
			If(($hardeningStatus.Name -match $item.Name).Count -gt 1)
			{
				Write-LogMessage -Type Verbose -Msg "Handling '$($item.Name)' duplication..."
				$tempDupStatus = $hardeningStatus | Where-Object { $_.Name -eq $item.Name }
				$tempOutput = $tempDupStatus | ForEach-Object {
					"<details><summary><b>{0}</b> step was completed with status '{1}'. See more details</summary><p>{2}</p></details><BR>" -f `
					$_.Component, $_.Status, $_.Output
				}
				#$tempComponent = "<B>[$($tempDupStatus.Component -join "]</B><B>[")]</B>"
				Write-LogMessage -Type Verbose -Msg ("Component:{0}`nName:{1}`nStatus:{2}`n" -f $item.Component, $item.Name, $item.Status)
				#$item.Name = $tempComponent+$Item.Name
				$item.Name = $Item.Name
				$Item.Output = $tempOutput
				Write-LogMessage -Type Verbose -Msg "New output: $($Item.Output)"
			}
			Else
			{
				$Item.Output = "<details><summary><b>{0}</b> step was completed with status '{1}'. See more details</summary><p>{2}</p></details><BR>" -f `
					$Item.Component, $Item.Status, $Item.Output
			}
		}

		Write-LogMessage -type Verbose -Msg "Printing $($sortedHardeningStatus.count) hardening steps"
		ForEach ($status in $sortedHardeningStatus)
		{
			$docLink = ""
			If(-not [string]::IsNullOrEmpty($status.Description))
			{
				$docLink = "<a href=$($status.Description)>Link to documentation</a>"
			}
			$retText += "<tr style='border:1px solid black;'>	<td>$($status.Name)</td> 	<td><div class=$($status.Status) /></td>	<td>$($status.Output)</td>	<td>$docLink</td></tr>"
		}
		return $retText
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Write-HTMLComponentsTable
# Description....: Write components table to the HTML report output table
# Parameters.....: Components data
# Return Values..: None
# =================================================================================================================================
Function Write-HTMLComponentsTable
{
<#
.SYNOPSIS
	Write components table to the HTML report output table
.DESCRIPTION
	Write components table to the HTML report output table
.PARAMETER

#>
	param(
		$componentsData
	)

	Begin {

	}
	Process {
		$retText = "<table class=""table.responsiveContent"" width=""100%"" cellspacing=""0"" cellpadding=""0"" align=""left"" style=""font-size: 14px; font-style: normal; font-weight: normal; color: #666; line-height: 1.5em; font-family: sans-serif;""><tbody>"
		if($null -ne $componentsData)
		{
			ForEach ($item in $componentsData)
			{
				$retText += "<tr>	<td>$($item.Name)</td>	<td>$($item.Version)</td></tr>"
			}
		}
		$retText += "</tbody></table>"
		return $retText
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: New-HTMLReportOutput
# Description....: Creates the HTML Report
# Parameters.....: Machine name, Components, Hardening Status
# Return Values..: Export File path
# =================================================================================================================================
Function New-HTMLReportOutput
{
<#
.SYNOPSIS
	Creates the HTML Report
.DESCRIPTION
	Creates the HTML Report, Returns the newly created file path
.PARAMETER Machine name
	The Machine Name to add to the file
.PARAMETER Components
	Array of installed components and their version
.PARAMETER HardeningStatus
	Array of Hardening steps and their status
#>
	param(
		[string]$machineName,
		$components,
		$hardeningStatus
	)

	Begin {
		$reportDateTime = $(Get-Date -Format $g_DateTimePattern)
		$htmlFileContent = Get-Content $REPORT_TEMPLATE_PATH
		$exportFileName = "Hardening_HealthCheck_Report_$($reportDateTime.Replace("/","-").Replace(":","-").Replace(" ","_")).html"
		$exportFilePath = Join-Path -Path $(Split-Path $REPORT_TEMPLATE_PATH -Parent) -ChildPath $exportFileName
	}
	Process {
		If(Test-InDomain)
		{
			$machineName += " <B>(In Domain)</B>"
		}
		$htmlFileContent = $htmlFileContent.Replace("@@@MachineName@@@",$machineName)
		$htmlFileContent = $htmlFileContent.Replace("@@@tblComponents@@@", $(Write-HTMLComponentsTable $components))
		$htmlFileContent = $htmlFileContent.Replace("@@@tblHardening@@@", $(Write-HTMLHardeningStatusTable $hardeningStatus))
		$htmlFileContent = $htmlFileContent.Replace("@@@DateTime@@@",$reportDateTime)
		# Export the data to the file
		$htmlFileContent | Out-File $exportFilePath
	}
	End {
		return $exportFilePath
	}
}
#endregion

#---------------
# Check if Powershell is running in Constrained Language Mode
If($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage")
{
	Write-LogMessage -Type Error -Msg "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Write-LogMessage -Type Info -Msg "Script ended"
	return
}

# Load all relevant modules
$moduleInfos = Import-ScriptModule

Write-LogMessage -Type Info -MSG "Starting script (v$ScriptVersion)" -Header -LogFile $LOG_FILE_PATH
if($InDebug) { Write-LogMessage -Type Info -MSG "Running in Debug Mode" -LogFile $LOG_FILE_PATH }
if($InVerbose) { Write-LogMessage -Type Info -MSG "Running in Verbose Mode" -LogFile $LOG_FILE_PATH }
Write-LogMessage -Type Debug -MSG "Running PowerShell version $($PSVersionTable.PSVersion.Major) compatible of versions $($PSVersionTable.PSCompatibleVersions -join ", ")" -LogFile $LOG_FILE_PATH
# Verify the Powershell version is compatible
If (!($PSVersionTable.PSCompatibleVersions -join ", ") -like "*3*")
{
	Write-LogMessage -Type Error -Msg "The Powershell version installed on this machine is not compatible with the required version for this script.`
	Installed PowerShell version $($PSVersionTable.PSVersion.Major) is compatible with versions $($PSVersionTable.PSCompatibleVersions -join ", ").`
	Please install at least PowerShell version 3."
	Write-LogMessage -Type Info -Msg "Script ended"
	return
}

#region Prepare Hardening modules dictionary
$dicComponentHardening = @{
	"Vault" = @{"Module" = $MODULE_VAULT_STEPS; "Configuration" = $VAULT_HARDENING_CONFIG};
	"CPM" = @{"Module" = $MODULE_CPM_STEPS; "Configuration" = $CPM_HARDENING_CONFIG};
	"PVWA" = @{"Module" = $MODULE_PVWA_STEPS; "Configuration" = $PVWA_HARDENING_CONFIG};
	"PSM" = @{"Module" = $MODULE_PSM_STEPS; "Configuration" = $PSM_HARDENING_CONFIG};
	"AIM" = @{"Module" = ""; "Configuration" = ""};
	"EPM" = @{"Module" = ""; "Configuration" = ""};
}
#endregion

Write-LogMessage -Type Info -MSG "Getting Machine Name" -LogFile $LOG_FILE_PATH
$machineName = Get-DnsHost
Write-LogMessage -Type Debug -Msg "Machine Name: $machineName"

# Set the detected components varialble
Set-DetectedComponents

$hardeningStepsStatus = @()
ForEach ($comp in $(Get-DetectedComponents))
{
	Write-LogMessage -Type Info -MSG "Running Hardening Validations for component $($comp.Name)" -LogFile $LOG_FILE_PATH
	If(![string]::IsNullOrEmpty($dicComponentHardening[$comp.Name].Module))
	{
		$moduleInfo = Import-Module $($dicComponentHardening[$comp.Name].Module) -PassThru
		Set-CurrentComponentFolderPath -ComponentPath $(Join-Path -Path $ScriptLocation -ChildPath $comp.Name)
		$compHardeningStepsStatus = Start-HardeningSteps $($dicComponentHardening[$comp.Name].Configuration)
		$compHardeningStepsStatus | Add-Member -NotePropertyName "Component" -NotePropertyValue $comp.Name
		$hardeningStepsStatus += $compHardeningStepsStatus
		Remove-ScriptModule $moduleInfo		
	}
	Else
	{
		throw [System.NotImplementedException]::New('This Hardening Component check is not implemented.')
	}
}

# Export the Report when Finished
$outputFile = New-HTMLReportOutput -machineName $machineName -components $detectedComponents -hardeningStatus $hardeningStepsStatus

Write-LogMessage -Type Info -MSG "Hardening Health Check Report located in: $outputFile" -LogFile $LOG_FILE_PATH
. $outputFile

Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH

# UnLoad loaded modules
Remove-ScriptModule $moduleInfos

