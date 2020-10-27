#Parse the CVE's from the NVD JSON Data feed based on a custom list of CPEs. 

$MinimumScore = 7
$BasePath = 'D:\OneDrive - Occurative\Documents\CVE\'
$MetaList = @('https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019',
'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020'
)

Function Update-JSONFiles {
    param ($BasePath,$MetaList)
    process {
        #Create path to the metadata xml file.
        $MetaDataFile = $BasePath + 'meta.xml'

        #See if the metadata xml file exists. If it does, load it. 
        #If it doesn't, create a new metadata object array based on the meta list.
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
        

        $MaxCount=$MetaList.Count
        $Progress=0

        # For each item in the metalist, download the metadata file from NVD and compare hashes.
        # If the hashes don't match, then download and extract the updated json file. This also
        # works if there's no local file (no hash to compre.)
        ForEach ($MetaItem in $MetaData) {
        
            $URL = $MetaItem.baseURL + '.meta'

            Write-Progress -Activity "Updating JSON Files..." -Status "$($URL)" -PercentComplete ((($Progress)/$MaxCount)*100)

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
                    Write-Host "Fail $($URL)"
                }
            }
        
            $Progress++

        }
        
        #Save the new metadata XML file.
        $MetaData | Export-Clixml -Path $MetaDataFile -Force
    }
    
}

#Update the JSON Files in the MetaList
Update-JSONFiles -BasePath $BasePath -MetaList $MetaList

$Progress = 0
$MaxCount=$MetaList.Count

[array]$ApplicableCVE = $null

ForEach ($MetaItem in $MetaList) {

    $MetaItem = $BasePath + ($MetaItem.Split('/'))[-1] + '.json'
    $Content = Get-Content -Raw -Path $MetaItem
    $Feed = ConvertFrom-Json -InputObject $Content

    Write-Host $MetaItem

    ForEach ($CVE in $Feed[0].CVE_Items) {
        
        ForEach ($CPE in $CVE.configurations.nodes.cpe_match) {
            If ($CPE.cpe23Uri -imatch 'okta' -and $CPE.vulnerable -eq $True -and ($CVE.impact.baseMetricV3.cvssV3.baseScore -ge $MinimumScore -or $CVE.impact.baseMetricV3.cvssV3.baseScore -ge $MinimumScore)) {
                
                [array]$CPEObject = $CPE.cpe23Uri -split (':')
    
                #Determine if we can use V3 Metrics or if we need to fall back to V2. 
                If ($CVE.impact.baseMetricV3.cvssV3.baseScore) {
                    $MetricsVersion = 3
                    $Score = $CVE.impact.baseMetricV3.cvssV3.baseScore
                    $Severity = $CVE.impact.baseMetricV3.cvssV3.baseSeverity
                    $Vector = $CVE.impact.baseMetricV3.cvssV3.attackVector
                    $Complexity = $CVE.impact.baseMetricV3.cvssV3.attackComplexity
                    $Interaction = $CVE.impact.baseMetricV3.cvssV3.userInteraction
                    $Privileges = $CVE.impact.baseMetricV3.cvssV3.privilegesRequired
                }
                else {
                    $MetricsVersion = 2
                    $Score = $CVE.impact.baseMetricV2.cvssV2.baseScore
                    $Severity = $null
                    $Vector = $CVE.impact.baseMetricV2.cvssV2.attackVector
                    $Complexity = $CVE.impact.baseMetricV2.cvssV2.attackComplexity
                    $Interaction = $null
                    $Privileges = $null
                }
    
                $CVEItem = [PSCustomObject]@{
                    ID = $CVE.cve.CVE_data_meta.ID
                    CPE = $CPE.cpe23Uri
                    Vendor = $CPEObject[3]
                    CI = $CPEObject[4]
                    CI_Version = $CPEObject[5]
                    CI_Release = $CPEObject[6]
                    Published = [Datetime]$CVE.publishedDate
                    Modified = [Datetime]$CVE.lastModifiedDate
                    Score = $Score
                    Severity = $Severity
                    Vector = $Vector
                    Complexity = $Complexity
                    Interaction = $Interaction
                    Privileges = $Privileges
                    Description = ($CVE.cve.description.description_data | Where-Object {$_.lang -eq 'en'}).value
                }
                $ApplicableCVE += $CVEItem
            }
    
        }    
    }

    $Progress++
}
