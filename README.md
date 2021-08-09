# PowerShellCVESearcher
Tool to cache and search the NVD CVE database. 

It stores a local copy of the available JSON files in $home/.cve

## To Use ##
import-module ./CVESearcher.psm1

When loading the module, it will immediately update the local cache of JSON files. The cache is stored in $home/.CVE 

The first time the module is loaded will take a bit longer because each JSON file must be downloaded and unpacked. As of 2021 there are 19 files to download dating back to the year 2002. Subsequent loads of the module will only refresh those files that have changed since the last load. 

## Functions ##

### Update-CVECache ###
Contacts the NVD website and caches new copies of metadata files if the hash differs from the local copy. This function also creates the cache folder and populates it if the path does not exit. It only downloads changed files to prevent excessive load on the NVD server.

This function is called when the module is loaded. 

### Search-CVEList ###
Returns a subset of the CVEs found in a specified set of NVD json files based on specific CPE keywords. 

#### Parameters ####

* CPE = This is a mandatory parameter. Can be passed a single keyword (slow) or an array of keywoards. Example: -CPE @('microsoft','windows','10','1909')
* MinScore = The minimum score of CVEs to return. Default is 0
* MaxScore = The maximum score of CVEs to return. Default is 10. 
* StartYear = The first year to search. 
* EndYear = The last year to search.

### Get-BasicCVEDetails ###
Parses the object returned by Search-CVEList and returns a more suitable object that can be used for reporting. 

example: Search-CVEList -CPE @('microsoft','windows','xp') -MinScore 9 | Get-BasicCVEDetails | select ID,Score,Severity,Description

## Other Functions ##

### Get-CVESearcherPath ###
This returns the local path to the cached CVE data.

### Get-CVEMetaList ###
Returns a list of the CVE meatadata files. The list can be modified with parameters. 

#### Parameters ####
* StartYear = The first year on the list to be returned. Default is 2002
* EndYear = The last year on the list to be returned. Default is current year. 
