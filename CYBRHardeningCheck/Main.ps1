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
$ScriptVersion = "2.9"

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
$TUNNEL_HARDENING_CONFIG = "$ScriptLocation\SecureTunnel\SecureTunnel_Hardening_Config.xml"

# Set modules paths
$MODULE_COMMON_UTIL = "$MODULE_BIN_PATH\CommonUtil.psm1"
$MODULE_GENERAL_STEPS = "$MODULE_BIN_PATH\GeneralHardeningSteps.psm1"
$MODULE_CPM_STEPS = "$ScriptLocation\CPM\CPMHardeningSteps.psm1"
$MODULE_PVWA_STEPS = "$ScriptLocation\PVWA\PVWAHardeningSteps.psm1"
$MODULE_PSM_STEPS = "$ScriptLocation\PSM\PSMHardeningSteps.psm1"
$MODULE_VAULT_STEPS = "$ScriptLocation\Vault\VaultHardeningSteps.psm1"
$MODULE_TUNNEL_STEPS = "$ScriptLocation\SecureTunnel\SecureTunnelHardeningSteps.psm1"

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

Function Get-HardeningStatus
{
<#
.SYNOPSIS
	Gets the Hardening status row to the HTML report output table
.DESCRIPTION
	Write a new Hardening status row to the HTML report output table
.PARAMETER HardeningStatus
	The hardening status object to build the report from
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
		$summary = "" | Select-Object "Errors", "hardeningPercentage"
		$summary.errors = 0
		$summary.hardeningPercentage = 0.0
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
				$tempOutput += $($tempDupStatus | ForEach-Object {
					Get-SummaryOutput -Component $_.Component -Status $_.Status -Details $_.Output
				})
				Write-LogMessage -Type Verbose -Msg ("Component:{0}`nName:{1}`nStatus:{2}`n" -f $item.Component, $item.Name, $item.Status)
				$item.Name = $Item.Name
				$Item.Output = $tempOutput
				Write-LogMessage -Type Verbose -Msg "New output: $($Item.Output)"
			}
			Else
			{
				$Item.Output = $(Get-SummaryOutput -Component $Item.Component -Status $Item.Status -Details $Item.Output)
			}
			# Count Errors
			If($item.Status -ne "Good")
			{
				$summary.errors++
			}
		}
		$summary.hardeningPercentage = ($summary.errors / $sortedHardeningStatus.count)

		# return the Hardening setup and the Summary
		return @( $sortedHardeningStatus, $summary )
	}
	End{}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: EndScript
# Description....: End the Script with a Footer line and Remove all used modules
# Parameters.....: Module Info
# Return Values..: None
# =================================================================================================================================
Function EndScript
{
<#
.SYNOPSIS
	End the Script with a Footer line and Remove all used modules
.DESCRIPTION
	End the Script with a Footer line and Remove all used modules
#>
	param(
		$moduleInfos
	)

	Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH

	# UnLoad loaded modules
	Remove-ScriptModule $moduleInfos	
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-SummaryOutput
# Description....: Returns the relevant summary message output based on the parameters
# Parameters.....: Component, hardening status, more details
# Return Values..: None
# =================================================================================================================================
Function Get-SummaryOutput
{
<#
.SYNOPSIS
	Write a new Hardening status row to the HTML report output table
.DESCRIPTION
	Write a new Hardening status row to the HTML report output table
.PARAMETER Component
	The Component that was tested
.PARAMETER Status
	The hardening status of the test
.PARAMETER Details
	The additional details on the test
#>
param(
	$Component, $status, $details
)
	$outputSummary =  $(
@"
	<li> 
		<div class="{1}">{0}<span class="status">{1}</span>
			<span class="info">{2}</span>
		</div>
	</li>	
"@ -f $Component, $Status, $Details
	)
	return $outputSummary
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
.PARAMETER HardeningStatus
	The hardening status object to build the report from
#>
	param(
		$hardeningStatus
	)
	$retText = ""
	Write-LogMessage -type Verbose -Msg "Printing $($hardeningStatus.count) hardening steps"
	ForEach ($status in $hardeningStatus)
	{
		$docLink = ""
		If(-not [string]::IsNullOrEmpty($status.Description))
		{
			$docLink = "<a href=$($status.Description)>Link to documentation</a>"
		}
		$retText += 
@"
		<tr>
			<td>
			<details>
				<summary class="$($status.Status)">$($status.Name)</summary>
				<ul>
					$($status.Output)
				</ul>
			</details>
			</td>	
			<td>$docLink</td>
		</tr>
"@
	}
	return $retText
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
.PARAMETER componentsData
	The list of discovered components

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
		else {
			Write-LogMessage -type verbose -Msg "No components found"
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
		$componentsList = @()
		$componentsList += $Components
		$htmlFileContent = $htmlFileContent.Replace("@@@MachineName@@@",$machineName)
		$htmlFileContent = $htmlFileContent.Replace("@@@ComponentsNum@@@", $($componentsList.Count))
		$hardeningTable,$summary = $(Get-HardeningStatus $hardeningStatus)
		$htmlFileContent = $htmlFileContent.Replace("@@@HardeningStatus@@@", $($summary.hardeningPercentage.tostring("#%")))
		$htmlFileContent = $htmlFileContent.Replace("@@@ErrorsNum@@@", $($summary.Errors))
		$htmlFileContent = $htmlFileContent.Replace("@@@tblComponents@@@", $(Write-HTMLComponentsTable $components))
		$htmlFileContent = $htmlFileContent.Replace("@@@tblHardening@@@", $(Write-HTMLHardeningStatusTable $hardeningTable))
		$htmlFileContent = $htmlFileContent.Replace("@@@DateTime@@@",$reportDateTime)
		# Export the data to the file
		$htmlFileContent | Out-File $exportFilePath -Encoding utf8
	}
	End {
		return $exportFilePath
	}
}

function Out-HardeningFolderPath {
	param (
		[Parameter(Mandatory=$true)]
		[ValidateScript({ Test-Path $_ })]
		[string]$Path
	)
	$fileContent = Get-Content $Path
	$stringToReplace = "@@@Hardening_Scripts_Folder@@@"
	$allFolders = $(Get-ChildItem -Path "$ENV:SystemDrive\*" -Include "InstallationAutomation" -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "CPM|PVWA|PSM|AIM" })
	Write-LogMessage -Type Debug -Msg "Found $($allFolders.count) fodlers named 'InstallationAutomation'"
	If($allFolders.Count -gt 1)
	{
		# Assuming that all found folders relate to CyberArk
		$outString = "<ul>"
		Foreach($folder in $allFolders)
		{
			$outString += "<li>$($folder.FullName)</li>"
		}
		$outString += "</ul>"
	}
	elseif($allFolders -eq 1)
	{
		$outString = "'$($allFolders.FullName)'"
	}
	else {
		$outString = "Did not find CyberArk Hardening scripts folder on this machine."
	}
	# Replace the data
	$fileContent = $fileContent.Replace($stringToReplace,$outString)
	# Export the data to the file
	$fileContent | Out-File $path -Encoding utf8
}
#endregion

#---------------
# Load all relevant modules
$moduleInfos = Import-ScriptModule

# Check if Powershell is running in Constrained Language Mode
If($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage")
{
	Write-LogMessage -Type Error -Msg "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	EndScript
	return
}

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
	EndScript
	return
}

# Check that you are running with Admin privileges (So that we can access all paths that are hardened)
If($(Test-CurrentUserLocalAdmin) -eq $false)
{
	Write-LogMessage -Type Error -Msg "In order to get all information, plesae run the script again on an Administrator Powershell session (Run as Admin)"
	EndScript
	return
}

# Check if relevant files are blocked
If($null -ne $(Get-ChildItem -Path $ScriptLocation -Include ('*.ps1','*.psm1','*.dll') -Recurse | Get-Item -Stream “Zone.Identifier” -ErrorAction SilentlyContinue))
{
	Write-LogMessage -Type Error -Msg "Some files are marked as blocked"
	$command = "Get-ChildItem -Path $ScriptLocation -Recurse | Unblock-File"
	Write-LogMessage -Type Info -Msg "To solve this you can run the following command: $command"
	EndScript
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
	"SecureTunnel" = @{"Module" = $MODULE_TUNNEL_STEPS; "Configuration" = $TUNNEL_HARDENING_CONFIG};
}
#endregion

Write-LogMessage -Type Info -MSG "Getting Machine Name" -LogFile $LOG_FILE_PATH
$machineName = Get-DnsHost
Write-LogMessage -Type Debug -Msg "Machine Name: $machineName"


$hardeningStepsStatus = @()
ForEach ($comp in $(Get-DetectedComponents))
{
	try {
		Write-LogMessage -Type Info -MSG "Running Hardening Validations for component $($comp.Name)" -LogFile $LOG_FILE_PATH
		If(![string]::IsNullOrEmpty($dicComponentHardening[$comp.Name].Module))
		{
			$moduleInfo = Import-Module $($dicComponentHardening[$comp.Name].Module) -PassThru
			Set-CurrentComponentFolderPath -ComponentPath $(Join-Path -Path $ScriptLocation -ChildPath $comp.Name)
			$compHardeningStepsStatus = Start-HardeningSteps $($dicComponentHardening[$comp.Name].Configuration)
			$compHardeningStepsStatus | Add-Member -NotePropertyName "Component" -NotePropertyValue $comp.Name
			$hardeningStepsStatus += $compHardeningStepsStatus
			Remove-Module $moduleInfo		
		}
		Else
		{
			throw [System.NotImplementedException]::new('This Hardening Component check is not implemented.')
		}
	}
	catch {
		Write-LogMessage -type Error -Msg "Error running hardening validations for component $($comp.Name). Error: $(Join-ExceptionMessage $_.Exception)" -LogFile $LOG_FILE_PATH
	}
}

# Export the Report when Finished
$outputFile = New-HTMLReportOutput -machineName $machineName -components $(Get-DetectedComponents) -hardeningStatus $hardeningStepsStatus
# Add the Hardening Scripts folder to the report
Out-HardeningFolderPath -Path $outputFile

Write-LogMessage -Type Info -MSG "Hardening Health Check Report located in: $outputFile" -LogFile $LOG_FILE_PATH
. $outputFile

EndScript
