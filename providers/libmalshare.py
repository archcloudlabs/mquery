import json
import sys
import time
try:
    import requests
except ImportError as err:
    print("[!] error, missing %s" % (err))
    sys.exit()

class MalshareAPI():
    '''
    API wrapper for https://www.malshare.com API.
    Docs:
    '''

    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = ("https://malshare.com/api.php?api_key=%s&action=" % \
                (self.api_key))
        self.hash_search_endpoint = (self.base_url + "details&hash=")
        #self.data_search_endpoint = (self.base_url + "search&query=")
        self.download_endpoint = (self.base_url + "getfile&hash=")

    def get_api_info(self):
        '''
        Name: get_api_info
        Purpose: get info about API usage from provider
        Parameters: N/A
        '''
        try:
            req = requests.get(self.base_url+"getlimit")
        except requests.exceptions.RequestException as err:
            return "[!] Error, could not get API info from Malshare!\n\t%s" % (err)
        if req.status_code == 200:
            return("\n\t[ Malshare ]\n\t\t[+] Limit: %s \n\t\t[+] Remaining: %s "
                   %  (req.json().get("LIMIT"), req.json().get("REMAINING")))
        return "\n\t[!] Error, Malshare API request for API limits went " \
                "horribly wrong. %s" % str(req.text)

    def latest_submissions(self):
        '''
        Name: latest_submissions
        Purpose: get latest hash contents.
        Parameters: N/A
        Return: string.
        '''
        try:
            req = requests.get(self.base_url+"getlist") # Get the latest submissions
        except requests.exceptions.RequestException as err:
            return "[!] Error, could not get latest submissions from Malshare!\n\t%s" % (err)

        if req.status_code == 200:
            for hashes in req.json():
                    # Get data about the latest submissions
                info_req = requests.get(self.base_url+"details&hash="+ \
                        hashes.get("md5"))
                if info_req.status_code == 200:
                    print(json.dumps(info_req.json(), indent=4))
                    # TODO: for each hash that comes back concat into a large
                    # list and return all at once.
            return True # Avoid 'None' from being printed.
        if req.status_code == 429:
            return "\t[!] Error, too many requests being made against Malshare API"
        return "\n\t[Malshare] Error, trying to get latest submissions." \
                "Something went horribly wrong. %s" % str(req.text)

    def hash_search(self, hash_val):
        '''
        Name: hash_search 
        Purpose: search for information about a particular hash
        Parameters: [hash_val] string value to specify hash to search for.
        return: string
        '''
        try:
            req = requests.get(self.hash_search_endpoint+hash_val)
        except requests.exceptions.RequestException as err:
            return "[!] Error, could not search for hash with Malshare!\n\t%s" % (err)

        if req.status_code == 200:
            try:
                return "[Malshare]\n" + json.dumps(req.json(), indent=4)
            except json.decoder.JSONDecodeError:
                # If something is searched out and doesn't return JSON or
                # malformed, print the plain text.
                if len(req.text) == 0:
                    return "\t[!] Error, HTTP request succeeded, but no content" \
                            "is available."
                return req.text
        elif req.status_code == 429:
            return "[!] Error, too many requests being made against Malshare."
        else:
            return "\t[Malshare] Hash not identified."

    def download_sample(self, hash_value, directory):
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
        try:
            req = requests.get(self.download_endpoint+hash_value)
        except requests.exceptions.RequestException as err:
            return "[!] Error, could not downloda sample with Malshare!\n\t%s" % (err)

        if req.status_code == 200:
            try:
                with open(directory + hash_value, "wb+") as fout:
                    fout.write(req.content)
                return True
            except IOError as err:
                print("\t[!] Error writing to file.\n\t%s" % (err))
        else:
            print("\t[!] Error %s, failed to identify hash %s." %
                  (req.status_code, hash_value))
            return False

    def daily_download(self):
        '''
        Name: daily_download
        Purpose: Download daily provided hashes from provider
        Param: N/A
        Return: string indicating success/errors when performing a bulk daily 
                download
        '''
        try:
            req = requests.get(self.base_url+"getlist") # Get the latest submissions
        except requests.exceptions.RequestException as err:
            return "[!] Error, could not get latest submissions from Malshare!\n\t%s" % (err)

        if req.status_code == 200:
            for sample in req.json():
                if self.download_sample(sample.get('md5')):
                    print("[Malshare] Downloaded %s @%s" % (sample.get('md5'), time.asctime()))
            return "[Malshare] Successfully finished downloaded samples @%s" % time.asctime()
        if req.status_code == 429:
            return "\t[!] Error, too many requests being made against Malshare API"
        return "\n\t[Malshare] Error, trying to get latest submissions." \
                    "Something went horribly wrong. %s" % str(req.text)
