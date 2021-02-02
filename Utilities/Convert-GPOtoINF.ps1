###########################################################################
#
# NAME: Convert-GPOtoINF
#
# AUTHOR:  Assaf Miron
#
# DESCRIPTION: 
# This utility will extract the Security template INF and Audit CSV 
# from a exported ZIP GPO file
# This utility will also include custom ADM registry settings to check
# This can be used to verify a component Security policy in domain
#
###########################################################################
[CmdletBinding()]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter the GPO Zip file path to extract INF and Audit from")]
	[Alias("gpo")]
	[ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid} )]
	[String]$GPOZipFilePath,
	
	[Parameter(Mandatory=$false,HelpMessage="Please enter the GPO Zip file path to extract INF and Audit from")]
	[Alias("folder")]
	[String]$OutputFolder
)

# File paths
$AuditPath = "{0}\GPO\Machine\microsoft\windows nt\Audit\audit.csv"
$INFPath = "{0}\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
$RegPolPath = "{0}\GPO\Machine\registry.pol"

# Output file names
$FileObject = (Get-Item -path $GPOZipFilePath)
$SecurityTemplateINF = ("{0} - GPO Security Tempalte.inf" -f $FileObject.BaseName)
$AdvAuditCSV = ("{0} - GPO Advanced Audit.csv" -f $FileObject.BaseName)

If([string]::IsNullOrEmpty($OutputFolder))
{
	$OutputFolder = $FileObject.Directory
}

# Extract the ZIP to the output folder
$zipOutputFolder = Join-Path -Path $OutputFolder -ChildPath "ZIPTemp"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($GPOZipFilePath, $zipOutputFolder)
# Get the path for DomainSysvol folder - the main folder of the GPO
$domainSysvolPath = (Get-ChildItem -Path $zipOutputFolder -Directory -Recurse -Filter "DomainSysvol").FullName

# Get the Audit file
Copy-Item -Path ($AuditPath -f $domainSysvolPath) -Destination (Join-Path -Path $OutputFolder -ChildPath $AdvAuditCSV)
# Get the INF file
Copy-Item -Path ($INFPath -f $domainSysvolPath) -Destination (Join-Path -Path $OutputFolder -ChildPath $SecurityTemplateINF)
If(Test-Path ($RegPolPath -f $domainSysvolPath))
{	
	# Get additional GPO Registry settings (from registry.pol)
	$additionalRegSettings = Get-RegPolDetails -path ($RegPolPath -f $domainSysvolPath)
}

# Add the additional registry settings (if exist) to the main INF
If($null -ne $additionalRegSettings)
{
	$SecEditInf = Get-IniContent -filePath (Join-Path -Path $OutputFolder -ChildPath $SecurityTemplateINF)
	ForEach($setting in $additionalRegSettings)
	{
		$regValue = $setting.Split('=')
		If(!$SecEditInf["Registry Values"].ContainsKey($regValue[0]))
		{
			$SecEditInf["Registry Values"].Add($regValue[0],$regValue[1])
		}
	}
	Out-IniFile -InputObject $SecEditInf -FilePath (Join-Path -Path $OutputFolder -ChildPath $SecurityTemplateINF)
}

# Delete the temp ZIP folder path
Remove-Item $zipOutputFolder -Force

Function Get-RegPolDetails
{
	param(
		[Parameter(Mandatory=$true)]
		[ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid} )]
		[Alias("path")]
		[string]$regpolicyFilePath
	)
	
	$retRegPolicies = @()
	$policyString = ""
	$regPol = Get-Content -Path $regpolicyFilePath -RAW
	for($i=0;$i -lt $regpol.Length; $i++)
	{
		if($regpol[$i] -eq "[")
		{
			$policyString = ""
			$i++;
			for(;$regpol[$i] -ne "]";$i++)
			{
				if($regpol[$i] -match '[\w\\;\.\*\:\d]')
				{
					$policyString += $regPol[$i]
				}
			}
			$splitString = $policyString.Split(';')
			$retRegPolicies += ("MACHINE\{0}={1},{2}" -f $splitString)
		}
	}
	
	return $retRegPolicies
}

Function Get-IniContent ($filePath)
{
    $ini = [ordered]@{}
    switch -regex -file $FilePath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value
        }
        "(.+?)\s*=(.*)" # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
		default
		{
			$name = "NOKEY" + $_.Split(',')[0]
			$ini[$section][$name] = $_
		}
    }
    return $ini
}

Function Out-IniFile($InputObject, $FilePath)
{
	If(-not (Test-Path $FilePath))
	{
		$outFile = New-Item -ItemType file -Path $Filepath
	}
	Else
	{
		$outFile = $FilePath
	}
    foreach ($i in $InputObject.keys)
    {
        if (!($($InputObject[$i].GetType().Name) -eq "Hashtable"))
        {
            #No Sections
            Add-Content -Path $outFile -Value "$i=$($InputObject[$i])"
        } else {
            #Sections
            Add-Content -Path $outFile -Value "[$i]"
            Foreach ($j in ($InputObject[$i].keys | Sort-Object))
            {
                if ($j -match "^Comment[\d]+") {
                    Add-Content -Path $outFile -Value "$($InputObject[$i][$j])"
                } elseif ($j -match "^NOKEY+") {
                    Add-Content -Path $outFile -Value "$($InputObject[$i][$j])"
                } else {
                    Add-Content -Path $outFile -Value "$j=$($InputObject[$i][$j])"
                }

            }
            Add-Content -Path $outFile -Value ""
        }
    }
}