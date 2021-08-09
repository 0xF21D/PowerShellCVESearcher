# CVESearcher.psm1
# by Robert Hollingshead (robert@roberthollingshead.net)

# This module provides functions to assist in the searching of CVEs published in the National Vulnerability Database
# You can find the latest version and updates on github: https://github.com/0xF21D/PowerShellCVESearcher

# Helper function to determine the basepath of the CVE JSON files. 
Function Get-CVESearcherPath
{
    $CVEPath = '/.CVE/'
    $BasePath = $env:HOME + $CVEPath
    Return $BasePath
}

# Function to programmatically build the list of NVD JSON metadata files. 
Function Get-CVEMetaList
{
    param($StartYear,$EndYear)
    process{

        # If a starting year is specified use it instead of 2002.
        If($StartYear) {
            [int]$FirstYear = $StartYear
        } else {
            [int]$FirstYear = 2002
        }

        # If an ending year is specified use it instead of the current year.
        If($EndYear) {
            [int]$LastYear = $EndYear    
        } else {
            [int]$LastYear = get-date -format yyyy
        }

        
        # Build the list of metadata files. 
        [int]$CurrentYear = $FirstYear

        $MetaList = @()

        While ($CurrentYear -le $LastYear) {
            $MetaList += @("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$($CurrentYear)")
            $CurrentYear++
        }
        
        Return $MetaList
    }
}

# Update the CVE cache. 
Function Update-CVECache {
    process {

        # Determine the path of the files and the file list. 
        $BasePath = Get-CVESearcherPath
        $MetaList = Get-CVEMetaList

        # Check if the path exists.Make it if it does not. 
        if (!(Test-Path -Path $BasePath)) {
        mkdir $BasePath
        }

        #Create path to the metadata xml file.
        $MetaDataFile = $BasePath + 'meta.xml'

        #See if the metadata xml file exists. If it does, load it. 
        #If it doesn't, create a new metadata object based on the meta list.
        If ((Test-Path -Path $MetaDataFile) -eq $False) {
        
            [array]$MetaData = $null

            ForEach ($Meta in $MetaList) {
                $MetaItem = [PSCustomObject]@{
                    baseURL = $Meta
                    baseFileName = ($Meta.Split('/'))[-1]
                    lastModifiedDate = [DateTime]((get-date).AddDays(-1))
                    hash = $null
                    rawContent = $null
                }
            
                $MetaData += $MetaItem
            }
        }
        else {
            [array]$MetaData = Import-Clixml -Path $MetaDataFile
        }
        
        # For each item in the metalist, download the metadata file from NVD and compare hashes.
        # If the hashes don't match, then download and extract the updated json file. This also
        # works if there's no local file (no hash to compre.)
        ForEach ($MetaItem in $MetaData) {
        
            $URL = $MetaItem.baseURL + '.meta'

            Write-Host -Message "Downloading CVE JSON Source File: $($URL)"

            $MetaItem.rawContent = (Invoke-WebRequest -Uri $URL).Content.Split(':')
        
            If ($MetaItem.hash -ne $MetaItem.rawContent[8]) {
                try {
                    $URL = $MetaItem.baseURL + '.json.zip'
                    $ZIPPath = $BasePath + $MetaItem.baseFileName + '.json.zip'

                    Invoke-WebRequest -Uri $URL -OutFile $ZIPPath
                    $MetaItem.hash = $MetaItem.rawContent[8]
                    Expand-Archive -LiteralPath $ZIPPath -DestinationPath $BasePath -Force
                    Remove-Item -Path $ZIPPath -Force
        
                }
                catch {
                    Write-Host -Message "Failed to Download CVE JSON Source File: $($URL)"
                }
            }
        
            $Progress++

        }
        
        #Save the new metadata XML file.
        $MetaData | Export-Clixml -Path $MetaDataFile -Force
    }
    
}

# Function to search the CVE list.
Function Search-CVEList {
    param([Parameter(Mandatory=$true)]$CPE,[Parameter(Mandatory=$false)]$MinScore=0,[Parameter(Mandatory=$false)]$MaxScore=10,$StartYear,$EndYear)
    process{

        [array]$IntermediateList = $null
        
        # If a range of years are specific call the Get-CVEMetalist function appropriately to return a list of files. 
        # This needs to be improved upon as I don't think it really needs to be written this way. 
        If($StartYear -and $EndYear) {
            $MetaList = Get-CVEMetaList -StartYear $StartYear -EndYear $EndYear
        } else {
            If($StartYear) {
                $MetaList = Get-CVEMetaList -StartYear $StartYear
            } else {
                If($EndYear) {
                    $MetaList = Get-CVEMetaList -EndYear $EndYear
                } else {
                    $MetaList = Get-CVEMetaList 
                }
            }
        }    

        # Look through each file to extract applicable CVEs. 
        ForEach ($MetaItem in $MetaList) {
            If ($CPE.count -eq 1) {
                $Feed[0].CVE_Items = $Feed[0].CVE_Items | Where-Object {$_.configurations.nodes.cpe_match.cpe23URI -match $CPE}
            } else {
                ForEach ($CPETerm in $CPE) {
                    $Feed[0].CVE_Items = $Feed[0].CVE_Items| Where-Object {$_.configurations.nodes.cpe_match.cpe23URI -match $CPETerm}
                }
            }

            $IntermediateList = $IntermediateList + $Feed[0].CVE_Items
        }

        # If a minimum or maximum base score is specified, here is where narrow the search. 
        # We need to be mindful of older cvssV2 based CVEs. 
        ForEach ($ListItem in $IntermediateList) {
            If ($ListItem.impact.baseMetricV3.cvssV3.baseScore -and $ListItem.impact.baseMetricV3.cvssV3.baseScore -ge $MinScore -and $ListItem.impact.baseMetricV3.cvssV3.baseScore -le $MaxScore) {
                $FinalList = $FinalList + $ListItem
            } else {
                If ($ListItem.impact.baseMetricV2.cvssV2.baseScore -ge $MinScore -and $ListItem.impact.baseMetricV2.cvssV2.baseScore -le $MaxScore) {
                    $FinalList = $FinalList + $ListItem
                }
            }
        }

        Return $FinalList
    }
}

# Parses the object returned by the Search-CVEList function to return an easier to use
# object containing basic CVE Details. Is aware of v2 and v3 cvss versions. 
Function Get-BasicCVEDetails {
    param([Parameter(ValueFromPipeline)]$RawCVEList)
    process {

        [PSCustomObject]$ApplicableCVE = $null

        # Step through each item in the list we were provided. 

        ForEach($CVEItem in $RawCVEList) { 
            [array]$CPEObject = $CVEItem.configurations.nodes.cpe_match.cpe23Uri[0] -split (':')
                
            #Determine if we can use V3 Metrics or if we need to fall back to V2.
            #Set appropriate values. 
            If ($CVEItem.impact.baseMetricV3.cvssV3.baseScore) {
                $MetricsVersion = 3
                $Score = $CVEItem.impact.baseMetricV3.cvssV3.baseScore
                $Severity = $CVEItem.impact.baseMetricV3.cvssV3.baseSeverity
                $Vector = $CVEItem.impact.baseMetricV3.cvssV3.attackVector
                $Complexity = $CVEItem.impact.baseMetricV3.cvssV3.attackComplexity
                $Interaction = $CVEItem.impact.baseMetricV3.cvssV3.userInteraction
                $Privileges = $CVEItem.impact.baseMetricV3.cvssV3.privilegesRequired
            }
            else {
                $MetricsVersion = 2
                $Score = $CVEItem.impact.baseMetricV2.cvssV2.baseScore
                $Vector = $CVEItem.impact.baseMetricV2.cvssV2.attackVector
                $Complexity = $CVEItem.impact.baseMetricV2.cvssV2.attackComplexity
            }

            # Create custom object and fill it with CVE details. Add it to the new list. 
            $ApplicableCVE = $ApplicableCVE + [PSCustomObject]@{
                ID = $CVEItem.cve.CVE_data_meta.ID
                CPE = $CVEItem.configurations.nodes.cpe_match.cpe23Uri
                CPE_Version = $CPEObject[1]
                Vendor = $CPEObject[3]
                Published = [Datetime]$CVEItem.publishedDate
                Modified = [Datetime]$CVEItem.lastModifiedDate
                MetricsVersion = $MetricsVersion
                Score = $Score
                Severity = $Severity
                Vector = $Vector
                Complexity = $Complexity
                Interaction = $Interaction
                Privileges = $Privileges
                Description = ($CVEItem.cve.description.description_data | Where-Object {$_.lang -eq 'en'}).value
            }
        }

        Return $ApplicableCVE
    }
}

# Update the CVE Cache when loaded. 
Update-CVECache