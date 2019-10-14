import os
import json
import argparse
import sys
import time
try:
    import requests
except importerror as err:
    print("[!] error, missing %s" % (err))
    sys.exit()

class HBAPI():
    '''
    API wrapper for https://www.hybrid-analysis.com API.
    Docs: https://www.hybrid-analysis.com/docs/api/v2
    '''

    def __init__(self, api_key):
        self.api_key = api_key

        self.http_headers = { "accept" : "application/json", 
            "User-Agent" : "Falcon Sandbox", # user-agent specified in documentation
            "Type" : "application/x-www-form-urlencoded",
            "Content-Type" : "application/x-www-form-urlencoded",
            "api-key" : self.api_key } 

        self.base_url = "https://www.hybrid-analysis.com/api/v2/"

    def get_api_info(self):
        '''
        Name: get_limit
        Purpose: get limit of API provider
        Parameters: N/A
        '''
        req = requests.get(self.base_url+"key/current", headers=self.http_headers)
        if req.status_code == 200:
            api_headers = json.loads(req.headers.get("Api-Limits"))
            return("\n\t[Hybrid Analysis Requests]\n\t\t[+] Limits: M:%s:H%s\n\t\t" \
                    "[+] Used: M%s:H%s" % (api_headers.get("limits").get("minute"),
                    api_headers.get("limits").get("hour"),
                    api_headers.get("used").get("minute"),
                    api_headers.get("used").get("hour")))

        elif req.status_code == 429:
            return "[!] Error, too many requests being made against Hybrid Analysis." 

        else:
            return("\n[!] Error, Hyrbrid API request for API limits went \
                    horribly wrong. %s" % str(req.text))

    def latest_submissions(self):
        '''
        Name: latest_submissions
        Purpose: get latest hash contents.
        Parameters: N/A
        Return: string.
        '''
        self.http_headers = {
                             "accept" : "application/json", # user-agent specified in documentation
                             "User-Agent" : "Falcon Sandbox", 
                             "api-key" : self.api_key } 
        req = requests.get(self.base_url+"feed/latest", headers=self.http_headers)
        if req.status_code == 200:
            print(json.dumps(req.json(), indent=5))
        elif req.status_code == 429:
            return "[!] Error, too many requests being made against Hybrid Analysis." 
        else:
            return("\n[!] Error, Hyrbrid API request for latest submissions went \
                    horribly wrong. %s" % str(req.text))

    def hash_search(self, hash_val):
        '''
        Name: search_hash_sample
        purpose: search for infor about a particular hash
        Parameters: [hash_val] string value to specify hash to search for.
        return: string
        '''
        body = "hash=%20"+hash_val
        req = requests.post(self.base_url+"search/hash", 
                            headers=self.http_headers,
                            data=body)
        if req.status_code == 200:
            return(json.dumps(req.json(),indent=4))
        else:
            return("[!] Error attempting grabbing hash from Hybrid-Analysis!")

    def download_sample(self, hash_value, file_name=None):
        '''
        Name: download_sample
        Purpose: Download a hash from an API provider and writes sample 
                 byte stream to a file of the hash name or user provided name.
        Param:
            [hash_value] string value indicatin hash (sha{128,256,512}/md5) to 
            search for.

            [file_name] string value specifying the file name to download on 
            the CLI. Otherwise the file name is the hash.
        Return:
            [boolean] True if file downloaded successfully. 
                      False if error occurs.
        '''
        req = requests.get(self.download_endpoint+hash_value)

        if req.status_code == 200:
            if file_name is None:
                with open(hash_value, "wb+") as fout:
                    fout.write(req.content)
                print("[+] Successfully downloaded sample %s." % (hash_value))
                return True
            else: # Specified filename on CLI
                with open(file_name, "wb+") as fout:
                    fout.write(req.content)
                print("[+] Successfully downloaded sample %s." % (file_name))
                return True

        else:
            print("[!] Failed to identify hash %s.\n\t[ERROR] %s" 
                    % (hash_value, req.status_code))
            return False
