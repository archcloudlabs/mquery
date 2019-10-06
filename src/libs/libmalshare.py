import os
import json
import argparse
import sys
try:
    import requests
except importerror as err:
    print("[!] error, missing %s" % (err))
    sys.exit()

class MalshareAPI():
    '''
    Malshare API wrapper for https://www.malshare.com API
    '''

    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = ("https://malshare.com/api.php?api_key=%s&action=" % (self.api_key))
        self.get_api_limit = "getlimit"
        self.hash_search_endpoint = (self.base_url + "search&query=")
        self.download_endpoint = (self.base_url + "getfile&hash=") 
        self.get_lists = "getlist"
        self.get_info_of_sample = "details&hash="

    def get_api_info(self):
        '''
        Name: get_limit
        purpose: get limit of api
        parameters: n/a
        '''
        req = requests.get(self.base_url+self.get_api_limit)
        if req.status_code == 200:
            return("\n\t[Malshare API Requests]\n\t\t[+] Limit: %s\n\t\t[+] Remaining:%s " % \
                    (req.json().get("LIMIT"), req.json().get("REMAINING")) )
        else:
            return("\n[!] Error, Malshare API request for API limits went \
                    horribly wrong. %s" % str(req.text))

    def latest_submissions(self):
        '''
        Name: latest_submissions
        purpose: get latest hash contents.
        return: JSON content.
        '''
        req = requests.get(self.base_url+self.get_lists)
        if req.status_code == 200:
            #import pdb; pdb.set_trace()
            for hashes in req.json():
                info_req = requests.get(self.base_url+self.get_info_of_sample+hashes.get("md5"))
                if info_req.status_code == 200:
                    print(json.dumps(info_req.json(), indent=5))
        elif req.status_code == 429:
            return "[!] Error, too many requests being made against Malshare API"
        else:
            return("\n[!] Error, Hyrbrid API request for latest submissions went \
                    horribly wrong. %s" % str(req.text))

    def hash_search(self, hash_val):
        '''
        Name: search_hash_sample
        purpose: search for infor about a particular hash
        Parameters: 
            [hash_val] string value to specify hash to search for.
        '''
        req = requests.get(self.hash_search_endpoint+hash_val)
        if req.status_code == 200:
            try:
                print(json.dumps(req.json(),indent=4))
            except json.decoder.JSONDecodeError as err:
                # If something is searched out and doesn't return JSON or 
                # malformed, print the plain text.
                print(req.text)
        elif req.status_code == 429:
            return "[!] Error, too many requests being made against Malshare." 
        else:
            return "[!] Error, hash not identified."
    

    def download_sample(self, hash_value, file_name=None):
        '''
        Name: download_sample
        Purpose: Download a hash from malware provider and writes sample 
                 byte stream to a file of the hash name or user provided name.
        Param:
            [hash_value] string value indicatin hash (sha{128,256,512}/md5) to 
            search for.
            [file_name] specify the file name to download on the CLI. Otherwise
            this is the hash.
        Return:
            [boolean] True if file downloaded successfully. 
                      False if error occurs.
        '''
        req = requests.get(self.download_endpoint+hash_value)

        if req.status_code == 200:
            if file_name is None:
                with open(hash_value, "wb+") as fout:
                    fout.write(req.content)
                return True
            else: # Specified filename on CLI
                with open(file_name, "wb+") as fout:
                    fout.write(req.content)
                return True
        else:
            print("[!] Failed to identify hash %s.\n\t[ERROR] %s" 
                    % (hash_value, req.status_code))
            return False
