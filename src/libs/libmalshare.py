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
        self.download_endpoint = (self.base_url + "getfile&hash=%s" % (self.api_key))
        self.get_lists = ("getlist%s" % (self.api_key))

    def get_api_info(self):
        '''
        Name: get_limit
        purpose: get limit of api
        parameters: n/a
        '''
        req = requests.get(self.base_url+self.get_api_limit)
        if req.status_code == 200:
            print("\nMalshare API Requests:\n\tLimit: %s\n\tRemaining:%s " % \
                    (req.json().get("LIMIT"), req.json().get("REMAINING")) )
        else:
            print("\n[!] Error, Malshare API request for API limits went \
                    horribly wrong. %s" % str(req.text))

    def latest_submissions(self):
        '''
        Name: latest_submissions
        purpose: get latest hash contents.
        return: JSON content.
        '''
        req = requests.get(self.url+self.get_lists)
        return(req.json())

    def hash_search(self, hash_val):
        '''
        Name: search_hash_sample
        purpose: search for infor about a particular hash
        Parameters: 
            [hash_val] string value to specify hash to search for.
        '''
        req = requests.get(self.hash_search_endpoint+hash_val)
        if req.status_code == 200:
            print(json.dumps(req.json(),indent=4))
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
        #download_endpoint = ("/api.php?api_key=%s&action=getfile&hash=%s" 
        #        % (self.api_key, hash_value))

        req = requests.get(self.download_endpoint+hash_value)

        if req.status_code == 200:
            if file_name is None:
                with open(hash_value, "wb+") as fout:
                    fout.write(req.content)
                print("[+] Successfully downloaded sample %s." % (hash_value))
            else: # Specified filename on CLI
                with open(file_name, "wb+") as fout:
                    fout.write(req.content)
                print("[+] Successfully downloaded sample %s." % (file_name))
                return True

        else:
            print("[!] Failed to identify hash %s.\n\t[ERROR] %s" 
                    % (hash_value, req.status_code))
            return False
