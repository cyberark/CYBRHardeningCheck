$Script:GitHubAPIURL = "https://api.github.com/repos"

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-ScriptLatestVersion
# Description....: Compare the current version and the online (GitHub) version
# Parameters.....: The online file URL, current Version, a pattern to look for the script version number in the online file
# Return Values..: True if the online version is the latest, False otherwise
# =================================================================================================================================
Function Test-ScriptLatestVersion
{
<# 
.SYNOPSIS 
	Compare the current version and the online (GitHub) version
.DESCRIPTION
	Compare the current version and the online (GitHub) version.
    Can compare version number based on Major, Major-Minor and Major-Minor-Patch version numbers
    Returns True if the online version is the latest, False otherwise
.PARAMETER fileURL
    The online file URL (in GitHub) to download and inspect
.PARAMETER currentVersion
    The current version number to compare to
.PARAMETER versionPattern
    A pattern of the script version number to search for in the online file
#>
    param(
        [Parameter(Mandatory=$true)]
        [string]$fileURL,
        [Parameter(Mandatory=$true)]
        [string]$currentVersion,
        [Parameter(Mandatory=$false)]
        [string]$versionPattern = "ScriptVersion"
    )
    $getScriptContent = ""
    $isLatestVersion = $false
    try{
        $getScriptContent = (Invoke-WebRequest -UseBasicParsing -Uri $scriptURL).Content
        If($($getScriptContent -match "$versionPattern\s{0,1}=\s{0,1}\""([\d\.]{1,10})\"""))
	    {
            $gitHubScriptVersion = $Matches[1]
            Write-LogMessage -Type Info -MSG "Current Version: $currentVersion; GitHub Version: $gitHubScriptVersion"
            # Get a Major-Minor number format
            $gitHubMajorMinor = [double]($gitHubScriptVersion.Split(".")[0..1] -join '.')
            $currentMajorMinor = [double]($currentVersion.Split(".")[0..1] -join '.')
            # Check if we have a Major-Minor-Patch version number or only Major-Minor
            If($gitHubScriptVersion.Split(".").count -gt 2)
            {
                $gitHubPatch = [int]($gitHubScriptVersion.Split(".")[2])
                $currentPatch = [int]($currentVersion.Split(".")[2])
            }
            # Check the Major-Minor version
            If($gitHubMajorMinor -ge $currentMajorMinor)
            {
                If($gitHubMajorMinor -eq $currentMajorMinor)
                {
                    # Check the patch version
                    $isLatestVersion = $($gitHubPatch -gt $currentPatch)
                }
                else {
                    $isLatestVersion = $true
                }
            }
        }
        else {
            Throw "Test-ScriptVersion: Couldn't match Script Version pattern ($versionPattern)"
        }
	}
	catch
	{
		Throw $(New-Object System.Exception ("Test-ScriptVersion: Couldn't download and check for latest version",$_.Exception))
	}
    return $isLatestVersion
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Copy-GitHubContent
# Description....: Copies all file and folder structure from a specified GitHub repository folder
# Parameters.....: The output folder path, the GitHub item URL to download from
# Return Values..: NONE
# =================================================================================================================================
Function Copy-GitHubContent
{
    <# 
.SYNOPSIS 
	Copies all file and folder structure from a specified GitHub repository folder
.DESCRIPTION
	Copies all file and folder structure from a specified GitHub repository folder
    Will create the content from a GitHub URL in the output folder
    Can handle files and folders recursevely
.PARAMETER outputFolderPath
    The folder path to create the files and folders in
.PARAMETER gitHubItemURL
    The GitHub item URL to download from
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$outputFolderPath,
        [Parameter(Mandatory=$true)]
        [string]$gitHubItemURL
    )
    try{
        $gitHubFolderObject = (Invoke-RestMethod -Method Get -Uri $gitHubItemURL)
        foreach ($item in $gitHubFolderObject) {
            if($item.type -eq "dir")
            {
                # Create the relevant folder
                $itemDir = Join-Path -Path $outputFolderPath -ChildPath $item.name
                if(! (Test-Path -path $itemDir))
                {
                    New-Item -ItemType Directory -Path $itemDir
                }		
                # Get all relevant files from the folder
                Copy-GitHubContent -outputFolderPath $itemDir -gitHubItemURL $item.url
            }
            elseif ($item.type -eq "file") {
                $getFileContent = (Invoke-WebRequest -UseBasicParsing -Uri ($item.download_url)).Content
                $getFileContent | Out-File -FilePath $(Join-Path -Path $outputFolderPath -ChildPath $item.name)
            }
        }
    }
    catch{
        Throw $(New-Object System.Exception ("Copy-GitHubContent: Couldn't download files and folders from GitHub URL ($gitHubItemURL)",$_.Exception))
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-GitHubLatestVersion
# Description....: Tests if the script is running the latest version from GitHub
# Parameters.....: NONE
# Return Values..: True / False
# =================================================================================================================================
Function Test-GitHubLatestVersion
{
<# 
.SYNOPSIS 
	Tests if the script is running the latest version from GitHub
.DESCRIPTION
	Tests if the script is running the latest version from GitHub
    Can support a mode of test only and Test and download new version
    Can support searching the entire repository or a specific folder or a specific branch (default main)
    If not exclusively selected to test only, the function will update the script if a new version is found
.PARAMETER repositoryName
    The repository name
.PARAMETER scriptVersionFileName
    The file name to search the script version in
.PARAMETER currentVersion
    The current version of the script
.PARAMETER sourceFolderPath
    The source folder of the script
    Used to download and replace the new updated script to
.PARAMETER repositoryFolderPath
    The repository Folder path
.PARAMETER branch
    The branch to search for
    Default main
.PARAMETER TestOnly
    Switch parameter to perform only test
    If not exclusively selected, the function will update the script if a new version is found
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$repositoryName,
    [Parameter(Mandatory=$true)]
    [string]$scriptVersionFileName,
    [Parameter(Mandatory=$true)]
    [string]$currentVersion,
    [Parameter(Mandatory=$true)]
    [string]$sourceFolderPath,
    [Parameter(Mandatory=$false)]
    [string]$repositoryFolderPath,
    [Parameter(Mandatory=$false)]
    [string]$branch = "main",
    [Parameter(Mandatory=$false)]
    [switch]$TestOnly
)
    if([string]::IsNullOrEmpty($repositoryFolderPath))
    {
        $apiURL = "$GitHubAPIURL/$repositoryName/contents"
    }
    else {
        $apiURL = "$GitHubAPIURL/$repositoryName/contents/$repositoryFolderPath`?ref=$branch"
    }
	
	$retLatestVersion = $true
	try{
		$folderContents = $(Invoke-RestMethod -Method Get -Uri $apiURL)
		$scriptURL = $($folderContents | Where-Object { $_.Type -eq "file" -and $_.Name -eq $scriptVersionFileName }).download_url
        $downloadLatestVersion = Test-ScriptLatestVersion -fileURL $scriptURL -currentVersion $currentVersion
	}
	catch
	{
		Throw $(New-Object System.Exception ("Test-GitHubLatestVersion: Couldn't check for latest version",$_.Exception))
	}
	
    try{
        # Check if we need to download the gitHub version
        If($downloadLatestVersion -and (! $TestOnly))
        {
            $retLatestVersion = $false
            Write-LogMessage -Type Info -MSG "Found new version, Updating..."
            # Create a new tmp folder to download all files to
            $tmpFolder = Join-Path -path $sourceFolderPath -ChildPath "tmp"
            if(! (Test-Path -path $tmpFolder))
            {
                New-Item -ItemType Directory -Path $tmpFolder
            }
            try{
                # Download the entire folder (files and directories) to the tmp folder
                Copy-GitHubContent -outputFolderPath $tmpFolder -gitHubItemURL $apiURL
                # Replace the current folder content
                #Copy-Item -Recurse -Path $tmpFolder -Destination $ScriptLocation -Force
                # Remove tmp folder
                Remove-Item -Recurse -Path $tmpFolder -Force
            }
            catch
	        {
                Write-LogMessage -Type Error -MSG "There was an error downloading GitHub content. Error: $(Join-ExceptionMessage $_.Exception)"
                # Revert to current version in case of error
                $retLatestVersion = $true
            }
        }
        Else
        {
            Write-LogMessage -Type Info -MSG  "Current version ($currentVersion) is the latest!"
        }
    }
    catch
	{
		Throw $(New-Object System.Exception ("Test-GitHubLatestVersion: Couldn't download latest version",$_.Exception))
	}
	
	return $retLatestVersion
}
Export-ModuleMember -Function Test-GitHubLatestVersion