import os
import json
import argparse
import sys
try:
    import requests
except ImportError as err:
    print("[!] error, missing %s" % (err))
    sys.exit()

class CaesarAPI():
    '''
    API wrapper for 
    Docs: https://avcaesar.malware.lu/docs/api
    '''

    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://avcaesar.malware.lu/api/v1/"

    def get_api_info(self):
        '''
        Name: get_limit
        Purpose: get limit of API provider
        Parameters: N/A
        '''
        req = requests.get(self.base_url+"/user/quota", 
                cookies=dict(apikey=self.api_key))

        if req.status_code == 200:
            return("\n\t[ AV Caesar ]\n\t\t[+] Analysis %s/%s" \
                    "\n\t\t[+] Download: %s/%s\n\t\t[+] Info: %s/%s" %
                    (req.json().get('analysis').get('current'),
                     req.json().get('analysis').get('limit'),
                     req.json().get('download').get('current'),
                     req.json().get('download').get('limit'),
                     req.json().get('info').get('current'),
                     req.json().get('info').get('limit')
                        ))

        else:
            return("\n[!] Error, A/V Caesar API request for API limits went \
                    horribly wrong. %s" % str(req.text))

    def latest_submissions(self):
        '''
        Name: latest_submissions
        Purpose: get latest hash contents.
        Parameters: N/A
        Return: string.
        '''
        return("\t[*] AV Caesar does not support latest submissions.")

    def hash_search(self, hash_val):
        '''
        Name: search_hash_sample
        purpose: search for infor about a particular hash
        Parameters: [hash_val] string value to specify hash to search for.
        return: string
        '''
        req = requests.get(self.base_url+"/sample/"+hash_val,
                cookies=dict(apikey=self.api_key))

        if req.status_code == 200:
            try:
                return("\t[AV Caesar]\n"+json.dumps(req.json(),indent=4))
            except json.decoder.JSONDecodeError as err:
                # If something is searched out and doesn't return JSON or 
                # malformed, print the plain text.
                if len(req.text) == 0:
                    return "[!] Error, HTTP request succeeded, but no content"\
                            " is available."
                else:
                    return(req.text)
        elif req.status_code == 429:
            return "[!] Error, too many requests being made against AV Caesar." 
        else:
            return "[AV Caesar] Hash not found."
    

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
        req = requests.get(self.base_url+"/sample/"+hash_value+"/download",
                cookies=dict(apikey=self.api_key))

        if req.status_code == 200:
            try:
                with open(hash_value, "wb+") as fout:
                    fout.write(req.content)
                return True
            except IOError as err:
                print("[!] Error writing to file.")
        else:
            print("[!] Failed to identify hash %s.\n\t[ERROR] %s" 
                    % (hash_value, req.status_code))
            return False
