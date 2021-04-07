###########################################################################
#
# NAME: Merge-INF
#
# AUTHOR:  Assaf Miron
#
# DESCRIPTION: 
# This utility will merge two INF files to one bsaed on prioirity
# In case an INF setting is the same, it is copied as is
# In case an INF setting is the different between files, 
# the priority is given to the selected file
# This utility can come in handy in conjunction with the Convert-GPOtoINF utility
#
###########################################################################
[CmdletBinding(DefaultParametersetName="INF")]
param
(
    [Parameter(ParameterSetName='INF',Mandatory=$false)][switch]$INF,
    [Parameter(ParameterSetName='CSV',Mandatory=$false)][switch]$CSV,

	[Parameter(Mandatory=$true)]
    [Parameter(ParameterSetName='INF',HelpMessage="The base INF file, this file settings will be prioritized")]
    [Parameter(ParameterSetName='CSV',HelpMessage="The base CSV file, this file settings will be prioritized")]
	[ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid} )]
	[String]$BaseFile,

    [Parameter(Mandatory=$true)]
    [Parameter(ParameterSetName='INF',HelpMessage="The INF file to compare to and merge from")]
    [Parameter(ParameterSetName='CSV',HelpMessage="The CSV file to compare to and merge from")]
	[ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid} )]
	[String]$SecondaryFile,
	
	[Parameter(Mandatory=$true,HelpMessage="The output merged file")]
	[Alias("output")]
	[String]$OutputFile
)

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
	If(Test-Path $FilePath)
	{
		Remove-Item $FilePath -Force
	}
	
	$outFile = New-Item -ItemType file -Path $Filepath
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

function New-CloneObject {
    param($DeepCopyObject)
    $memStream = new-object IO.MemoryStream
    $formatter = new-object Runtime.Serialization.Formatters.Binary.BinaryFormatter
    $formatter.Serialize($memStream,$DeepCopyObject)
    $memStream.Position=0
    $formatter.Deserialize($memStream)
}

switch($PsCmdlet.ParameterSetName)
{
    "INF" { $INF = $true; break }
    "CSV" { $CSV = $true; break }
    Default { $INF = $true; break }
}

If($INF)
{
    $objBaseFile = Get-IniContent -FilePath $BaseFile
    $objSecondaryFile = Get-IniContent -filePath $SecondaryFile
}
elseif($CSV)
{
    $objBaseFile = Import-CSV $BaseFile
    $objSecondaryFile = Import-CSV $SecondaryFile
}

$outObject = New-CloneObject $objSecondaryFile
if($INF)
{
    foreach ($section in $objBaseFile.keys) {
        foreach ($item in $objBaseFile[$section].Keys) {
            # Prioritize base object value over secondary
            # If an object does not exist, it will be created
            $outObject[$section][$item] = $objBaseFile[$section][$item]
        }
    }
    Out-IniFile -InputObject $outObject -FilePath $OutputFile
}
elseif($CSV)
{
    # Add all lines from 
    foreach ($line in $objBaseFile) {
        If($outObject.SubCategory -Contains $line.SubCategory)
        {
            # Prioritize base object value over secondary
            $outObject[$($outObject.Subcategory.indexof($line.SubCategory))] = $line
        }
        else {
            # Add missing lines
            $outObject += $line
        }
    }
 
    $outObject | Export-Csv -Path $OutputFile -NoTypeInformation -NoClobber -Encoding ASCII -Force
}