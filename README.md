<p align="center">
<img width="264" height="61" src="https://i.imgur.com/SGnNoju.png">
<br />
<i>Multi-API Malware Search &amp; Download Utility.</i>
</p>

## About The Project
This utility wraps [Malshare](https://www.malshare.com), [Hybrid
Analysis'](https://www.hybrid-analysis.com) and 
[Virus Total](https://www.virustotal.com) public APIs to enable researchers to 
query for information about malware samples.  

**You must have an API key(s) to use this utility. Some features only work if
you have a premium API- key(I.E: downloading samples from VT)**. 

### Supported functionality
* Searching hashes.
* Download samples (*depends on your API access*).
* Daily feed lists.
* List API info.

## Getting API Keys
* [Malshare Registration]()
    * Free 1k API calls a day.

* [Hybrid Analysis Registration]()
    * Free API calls, but must be vetted for premium access for API sample 
      downloads.
* [VirusTotal Registration]()
    * Free API calls for searching and listing files. Premium access required
      for downloads. Free accounts are heavily throttled (4 requests a second)

## Installation

### System Configuration
API keys must be exported as environment variables or availble via your .bashrc.
The following variable names are parsed by ```libquery.py``` for provider access:

* Malshare: ```MALSHARE_TOKEN```
* Virus Total (vt): ```VT_TOKEN```
* Hybrid-Analysis (hba): ```HBA_TOKEN```

### Dependencies
* Python requests
```
pip install -r requirements.txt
```

### Using Docker
0. Specify API keys within environment variables. For example: ``` export MALSHARE_TOKEN="TOKEN_GOES_HERE" ```

1. ``` docker build . -t mquery```
2. ``` docker run mquery --action info```

## Example Queries

* Searching for hashes not specifying a provider:
```
./mquery --action search --hash $HASH_VAL 
```

* Downloading a file specifying the provider:
```
./mquery --action download --hash $HASH_VAL --provider malshare
```

* Get API info from VirusTotal API:
```
./mquery --action info --provider vt
```

* Get API info from all APIs.
```bash
./mquery.py --action info
[================[ >MQuery< ]==================]

[+] Malshare API token identified.
[+] Hybrid-Analysis API token identified.
[+] VirusTotal API token identified.

[================[ API Info ]===================]

[Malshare API Requests]
    [+] Limit: 1000
    [+] Remaining: 993

[Hybrid Analysis Requests]
    [+] Limits: M:200:H2000
    [+] Used: M2:H2

[*] Virustotal does not support an info endpoint at this time.
```

## Adding Additional Endpoints
The ``` ./src/libs ```  folder contains classes for each API provider. 
```libquery.py``` acts as an middleware wrapper to abstract the differences in 
the underlying provider API calls. 

0. To add a new API, copy one of the existing classes and update the request 
endpoints as appropriate.
1. Copy template groupings from ```libquery.py``` to meet your API.
2. Create a  "loader function" to populate the variables created in step 1.
3. Update ```__api_status__(self)``` to execute your loader when a
```libquery``` object is called.
