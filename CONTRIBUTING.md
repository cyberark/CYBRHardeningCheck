# Contributing to CyberArk Hardening Check
👍🎉 First off, thanks for taking the time to contribute! 🎉👍

The following is a set of guidelines for contributing to the CyberArk Hardening Check tool. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

This repository is maintained by good people that take the time to make this tool better with hardening best practices and not by official CyberArk R&D. 

For general contribution and community guidelines, please see the [community repo](https://github.com/cyberark/community).

## Table of Contents

- [Development](#development)
- [Testing](#testing)
- [Releases](#releases)
- [Contributing](#contributing)
	- [General Workflow](#general-workflow)
	- [Reporting Bugs](#reporting-bugs)

## Development

This tool is built using Powershell.
You should be familiar with PowerShell before contibuting to this project.

### Common functions

In the Bin folder, there are two main powershell modules: CommonUtil, GeneralHardeningSteps
> Note: a powershell module is constructed by two main files:
> - The Metadata file of the module (using a \*.psd1 extension)
> - The module file (using a \*.psm1 extension)

The CommonUtil holds all the shared functions that perform the check on the machine, it holds the "bear-metal" functions to keep this tool going
The GeneralHardeningSteps holds all hardening steps that are common to all components, any hardening step that is component specific should be in the relevant [*Component Hardening*](#component-hardening) folder.

Doing major changes in one of those module files (\*.psm1) should be accompanied with an increase in the module version in the metadata file (\*.psd1)

### Component Hardening

The script architecture is structured in a way that each component has its own folder
In the folder there are all relvant files for the component hardening.
Two main files are the Hardening steps script (saved as \*.psm1) and the hardening configuration (saved as \*.xml)

### Available hardening tests and functions
#### CommonUtil.psm1
- Write-LogMessage
- Join-ExceptionMessage
- Get-WMIItem
- Test-InDomain
- Test-LocalUser
- Test-InstalledWindowsRole
- Test-ServiceRunWithLocalUser
- Get-DnsHost
- Get-LocalAdministrators
- Get-LocalSystem
- Get-ServiceInstallPath
- Get-SeceditAnalysisResults
- Get-ParsedFileNameByOS
- Get-DetectedComponents
- Compare-ServiceStatus
- Compare-AuditRulesFromPath
- Compare-RegistryValue
- Compare-UserRight
- Compare-PolicyEntry
- Compare-UserPermissions
- Compare-UserFlags
- Compare-AmountOfUserPermissions
- Compare-AdvancedAuditPolicySubCategory
- Compare-EventLogSizeAndRetentionSettings
- Convert-NameToSID
- Convert-SIDToName
- ConvertTo-Bool
- Start-HardeningSteps
- Test-CredFileVerificationType
	
#### GeneralHardeningSteps.psm1
- ImportingINFConfiguration
- ValidateServerRoles
- DisableScreenSaver
- AdvancedAuditPolicyConfiguration
- RemoteDesktopServices
- EventLogSizeAndRetention
- RegistryAudits
- RegistryPermissions
- FileSystemPermissions
- FileSystemAudit
- DisableServices
#### VaultHardeningSteps.psm1
- Vault_NICHardening
- Vault_StaticIP
- Vault_WindowsFirewall
- Vault_DomainJoined
- Vault_LogicContainerServiceLocalUser
- Vault_FirewallNonStandardRules
- Vault_ServerCertificate

#### CPMHardeningSteps.psm1
- CPM_Password_Manager_Services_LocalUser
- CPM_EnableFIPSCryptography
- CPM_DisableDEPForExecutables
- CPM_CredFileHardening

#### PVWAHardeningSteps.psm1
- PVWA_IIS_Registry_Shares
- PVWA_IIS_WebDAV
- PVWA_Cryptography_Settings
- PVWA_IIS_MimeTypes
- PVWA_AnonymousAuthentication
- PVWA_DirectoryBrowsing
- PVWA_IIS_SSL_TLS_Settings
- PVWA_IIS_Cypher_Suites
- PVWA_Scheduled_Task_Service_LocalUser
- PVWA_NonSystemDrive
- PVWA_IIS_Hardening
- PVWA_AdditionalAppPool
- PVWA_CredFileHardening

#### PSMHardeningSteps.psm1
- ConfigureUsersForPSMSessions
- PSMForWebApplications
- EnableUsersToPrintPSMSessions
- SupportWebApplications
- ClearRemoteDesktopUsers
- RunApplocker
- ConfigureOutOfDomainPSMServer
- DisableTheScreenSaverForThePSMLocalUsers
- HidePSMDrives
- BlockIETools
- HardenRDS
- HardenPSMUsersAccess
- HardenSMBServices
- PSM_CredFileHardening

#### SecureTunnelHardeningSteps.psm1
- SecureTunnel_Permissions


### Adding a new hardening check

Before adding a new hardening check, think if it is a component specific hardening or a general best practive hardening check.
If it is a specific one, create it in the relevant component hardening file with the naming convention of *<ComponentName>_<Hardening Check>*
If it is a general one, create it in the GeneralHardeningSteps file with the naming convention of *<Hardening check name in Camel Case - no spaces>*

## Testing

You will be responsible testing your own code, please make sure to adhere to the functions naming convention and add the relevant documentation link if available.

## Contributing 

### General Workflow

1. [Fork the project](https://help.github.com/en/github/getting-started-with-github/fork-a-repo)
2. [Clone your fork](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository)
3. Make local changes to your fork by editing or creating new files
3. [Commit your changes](https://help.github.com/en/github/managing-files-in-a-repository/adding-a-file-to-a-repository-using-the-command-line)
4. [Push your local changes to the remote server](https://help.github.com/en/github/using-git/pushing-commits-to-a-remote-repository)
5. [Create new Pull Request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request-from-a-fork)

From here your pull request will be reviewed and once you've responded to all feedback it will be merged into the project. 

Congratulations, you're a contributor! 🎉🎉🎉

### Reporting Bugs
This section guides you through submitting a bug report or an issue with one of the script published in this repository. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

When you are creating a bug report, please include as many details as possible and make sure you run the script with Debug and Verbose logging (In all PowerShell scripts just add '-Debug -Verbose' at the end of the script command).

**Note**: If you find a Closed issue that seems like it is the same thing that you're experiencing, open a new issue and include a link to the original issue in the body of your new one.

**Before Submitting A Bug Report**
Run the script with Verbose logging.
Perform a cursory search to see if the problem has already been reported. If it has and the issue is still open, add a comment to the existing issue instead of opening a new one.
