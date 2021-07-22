[![release][]][github-site]
[![license][]][license-link]
[![downloads][]][github-site]

[release]:https://img.shields.io/github/v/release/cyberark/CYBRHardeningCheck?color=brightgreen
[github-site]:https://github.com/cyberark/CYBRHardeningCheck/releases/latest
[license]:https://img.shields.io/github/license/cyberark/CYBRHardeningCheck.svg
[license-link]:https://github.com/cyberark/CYBRHardeningCheck/blob/main/LICENSE
[downloads]:https://img.shields.io/github/downloads/cyberark/CYBRHardeningCheck/total?color=brightgreen


# CyberArk Hardening Health Check
One of the most important recommendations for any application, and especially for security applications is to harden the server.
CyberArk provides recommendations and automation scripts to harden its servers to make sure best security.
>This tool provides a simple way to report on whether the recommendations were implemented fully or partly.
>This tool does not replace running the hardening procedures from CyberArk and cannot be taken as a guarantee for making sure the server is fully secured - it is always good to run your own security check up tools.
Note that these settings are security best practices and the tool is “AS IS without warranty” for you to use and build on.

## General
CyberArk provides automatic hardening to the Vault and component servers (CPM, PVWA and PSM) through automated scripts and procedures.
Hardening is not an easy task and it covers a great deal of configurations and settings that one needs to apply in order to be compliant to the hardening best practice. 

- How can you verify that you actually did all the required steps? 
- How do you know that the hardening script finished successfully and applied all recommendations? (besides inspecting the log files)
- How can an organization verify if they are compliant if they applied their own hardening best practices?

Wouldn't it be nice if we could ask the server - are you hardened?

Well, the answer is here - CyberArk Hardening Health Check.

## What is this tool?
This tool is based on the Automated Hardening scripts that are provided by CyberArk and will allow you, as a CyberArk customer, to verify if a server is hardened based on CyberArk best practices.
The tool is based on the same hardening XML that comes with the automated hardening scripts and allows to disable some of the checks as well.
What this means is that if you disabled a specific hardening step, you can disable the same one in the hardening health check to prevent false positives.
The tool also provides links to documentation to most of the hardening checks and relevant information in a report where the hardening is not complete or missing.
<Example Report Image>

## Usage
The package ZIP includes a few folders, a Powershell script (Main.ps1) and a HTML template for the report.
Download the ZIP and extract it on a CyberArk component server you wish to check
Open Powershell (as an Administrator) and run the Main.ps1 script
```powershell
PS> .\Main.ps1
```

For troubleshooting or getting more information about the checks done, you can run the script using Verbose logging
```powershell
PS> .\Main.ps1 -Debug -Verbose
```

The tool creates a log file by default that contains all steps taken by the script (when using Verbose logging you will get a lot more info in the log file)
Other relevant information will be referenced in the log and the report.

## Available Hardening tests
### Cross-Component hardening checks
|Hardening check      				| Description               
|--------      						| -------               
|ImportingINFConfiguration			|Importing an INF File to the Local Machine
|ValidateServerRoles				|This function checks for unnecessary roles
|EnableScreenSaver					|Checks if the screen saver is disabled
|AdvancedAuditPolicyConfiguration	|Advanced Audit Policy Configuration
|RemoteDesktopServices				|Check Remote Desktop Services settings
|EventLogSizeAndRetention			|Check Event Log and Retention settings
|RegistryAudits						|Check Registry Audits access control	
|RegistryPermissions				|Check Registry permissions
|FileSystemPermissions				|Validates unnecessary permissions on %SystemRoot%\System32\Config and %SystemRoot%\System32\Config\RegBack.
|FileSystemAudit					|Check audit access rules on %SystemRoot%\System32\Config and %SystemRoot%\System32\Config\RegBack.
|DisableServices					|Check that the following services are disabled:  "Routing and Remote Access", "Smart Card", "Smart Card Removal Policy", "SNMP Trap", "Special Administration Console Helper","Windows Error Reporting Service", "WinHTTP Web Proxy Auto-Discovery Service"


### Vault specific hardening checks
|Hardening check      				| Description               
|--------      						| -------               
|Vault_NICHardening					|Network Interface Configuration Hardening
|Vault_StaticIP						|Check that the Vault has Static IP
|Vault_WindowsFirewall				|Check that the Vault has the Firewall active
|Vault_DomainJoined					|Check that the Vault was not joined to a Domain
|Vault_LogicContainerServiceLocalUser|Vault Logic Container Service LocalUser
|Vault_FirewallNonStandardRules|Vault Firewall Rule
|Vault_ServerCertificate|Vault Server Certificate

### CPM specific hardening checks
|Hardening check      				| Description               
|--------      						| -------               
|CPM_Password_Manager_Services_LocalUser|CPM Password Manager Services LocalUser
|CPM_EnableFIPSCryptography|CPM Enable FIPS Cryptography
|CPM_DisableDEPForExecutables|CPM Disable DEP For Executables
|CPM_CredFileHardening|Credential File Hardening

### PVWA specific hardening checks
|Hardening check      				| Description               
|--------      						| -------               
|PVWA_IIS_Registry_Shares|PVWA IIS Registry Shares
|PVWA_IIS_WebDAV|PVWA IIS WebDAV
|PVWA_Cryptography_Settings|PVWA Cryptography Mode Settings
|PVWA_IIS_MimeTypes|PVWA IIS MimeTypes
|PVWA_AnonymousAuthentication|PVWA IIS Anonymous Authentication
|PVWA_DirectoryBrowsing|PVWA IIS Directory Browsing
|PVWA_IIS_SSL_TLS_Settings|PVWA IIS SSL TLS Settings
|PVWA_IIS_Cypher_Suites|PVWA IIS Cypher Suites
|PVWA_Scheduled_Task_Service_LocalUser|PVWA Scheduled Task Service LocalUser
|PVWA_NonSystemDrive|PVWA not installed on System drive
|PVWA_IIS_Hardening|PVWA IIS Hardening
|PVWA_AdditionalAppPool|PVWA Application Pool configuration
|PVWA_CredFileHardening|Credential File Hardening

### PSM specific hardening checks
|Hardening check      				| Description               
|-------   						| ------
|ConfigureUsersForPSMSessions|Configure users for PSM sessions
|PSMForWebApplications|PSM for web applications
|EnableUsersToPrintPSMSessions|Enable users to print PSM sessions
|SupportWebApplications|Support Web Applications on PSM
|ClearRemoteDesktopUsers|Clear Remote Desktop Users group from PSM Server
|RunApplocker|Check up AppLocker Rules
|ConfigureOutOfDomainPSMServer|Configure Out Of Domain PSM Server
|DisableTheScreenSaverForThePSMLocalUsers|Disable ScreenSaver for PSM Local users
|HidePSMDrives|Hide PSM Drives
|BlockIETools|Block IE Developer Tools and Context menu
|HardenRDS|Harden Remote Desktop Services
|HardenPSMUsersAccess|Harden PSM Users Access
|HardenSMBServices|Harden SMB and XB Services
|PSM_CredFileHardening|Credential File Hardening

### Privilege Cloud Secure Tunnel specific hardening checks
|Hardening check      				| Description               
|-------   						| ------
|SecureTunnel_Permissions|Check Secure Tunnel folder hardening


## Contributing
Please see our [`CONTRIBUTING`](CONTRIBUTING.md) for more details.

## Licensing

Copyright (c) 2020 CyberArk Software Ltd. All rights reserverd

This repository is licensed under GNU GENERAL PUBLIC LICENSE Version 3 - see [`LICENSE`](LICENSE) for more details.
