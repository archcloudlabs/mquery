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
    Hybrid-Analysis API wrapper for https://www.hybrid-analysis.com

    curl -X POST "https://www.hybrid-analysis.com/api/v2/search/hash?_timestamp=1570381751779" -H  "accept: application/json" 
    -H  "user-agent: Falcon Sandbox" -H  "api-key: hn27tpzx8c923858eggtitwz9e2bbedffujt7zg477777a3dlytippc35f229939" 
        -H  "Content-Type: application/x-www-form-urlencoded" -d "hash=%205f76ee20fb8094332a172b4f57df119637ce74144a939cb67e65cb7f3b04d590%20"


    '''

    def __init__(self, api_key):
        self.api_key = api_key

        self.http_headers = {
                             "accept" : "application/json", # user-agent specified in documentation
                             "User-Agent" : "Falcon Sandbox", 
                             "Type" : "application/x-www-form-urlencoded",
                             "Content-Type" : "application/x-www-form-urlencoded",
                             "api-key" : self.api_key } 

        self.base_url = "https://www.hybrid-analysis.com/api/v2/"
        self.daily_feed = "https://www.hybrid-analysis.com/feed?json"
        #self.search_url = "search/hash?_timestamp=1570381751779"
        self.search_url = "search/hash?_timestamp=%s" % self.get_timestamp()
        self.api_limit = "key/current?_%s" % self.get_timestamp()

        #self.get_api_limit = ("getlimit" % (self.api_key))
        #self.hash_search = (self.base_url + "search&query=" % (self.api_key))
        #self.download_endpoint = (self.base_url + "getfile&hash=" % (self.api_key))
        #self.get_lists = ("getlist" % (self.api_key))

    def get_timestamp(self):
        '''
        '''
        return str(time.time()).replace(".","")

    def get_api_info(self):
        '''
        Name: get_api_info
        purpose: get limit of api
        parameters: n/a
        '''

        req = requests.get(self.base_url+self.api_limit, headers=self.http_headers)
        if req.status_code == 200:
            api_headers = json.loads(req.headers.get("Api-Limits"))
            print("\n\t[Hybrid Analysis Requests]\n\t\t[+] Limits: M:%s:H%s\n\t\t" \
                    "[+] Used: M%s:H%s" % (api_headers.get("limits").get("minute"),
                    api_headers.get("limits").get("hour"),
                    api_headers.get("used").get("minute"),
                    api_headers.get("used").get("hour")))

        else:
            print("\n[!] Error, Hyrbrid API request for API limits went \
                    horribly wrong. %s" % str(req.text))

    def latest_submissions(self):
        '''
        Name: latest_submissions
        purpose: get latest hash contents.
        return: JSON content.
        '''
        import pdb; pdb.set_trace()
        req = requests.get(self.daily_feed)
        if req.status_code == 200:
            return(req.json())

    def hash_search(self, hash_val):
        '''
        Name: search_hash_sample
        purpose: search for infor about a particular hash
        Parameters: 
            [hash_val] string value to specify hash to search for.
        '''
        req = requests.get(self.hash_search+hash_val)

        if req.status_code == 200:
            print(json.dumps(req.json(),indent=4))
        else:
            print("[!] Error attempting grabbing hash!")

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
if __name__ == "__main__":
    hb = HBAPI()
    hb.latest_submissions()
