import json
import time
import sys
try:
    import requests
except ImportError as err:
    print("[!] error, missing %s" % (err))
    sys.exit()


class VTAPI():
    '''
    API wrapper for https://www.virustotal.com API.
    Docs: https://developers.virustotal.com
    '''

    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = ("https://www.virustotal.com/vtapi/v2/file/")
        self.params = {'apikey' : self.api_key}

    def get_api_info(self):
        '''
        Name: get_limit
        Purpose: get limit of API provider
        Parameters: N/A
        '''
        return "\t[*] Virustotal does not support an info endpoint at this time."

    def latest_submissions(self):
        '''
        Name: latest_submissions
        Purpose: get latest hash contents.
        Parameters: N/A
        Return: string.
        '''
        print("\t[*] This is a premium feature, and requires a private API key.")
        self.params['package'] = "11:00"
        req = requests.get(self.base_url+"feed", params=self.params, stream=True,
                           allow_redirects=True)

        if req.status_code == 200:
            fname = time.asctime().replace(' ', '-').replace(':', '-')
            try:
                with open(fname, 'wb') as file_writer:
                    for chunk in req.iter_content(chunk_size=65536):
                        file_writer.write(chunk)
            except IOError as err:
                return "[!] Error wrting file, %s" % str(err)
            return "[+] Wrote daily pull to %s" % (fname)

        elif req.status_code == 429:
            return "[!] Error, too many requests being made against Virus Total API"

        elif req.status_code == 403:
            return "\n\t[!] Error, you do not have appropriate permissions " \
                    "to make this Virus Total API request."

    def hash_search(self, hash_val):
        '''
        Name: search_hash_sample
        purpose: search for infor about a particular hash
        Parameters: [hash_val] string value to specify hash to search for.
        return: string
        '''

        req = requests.get(self.base_url+ "report", params=self.params)
        self.params['resource'] = hash_val
        self.params['allinfo'] = False  # premium API feature
        req = requests.get(self.base_url+ "report", params=self.params)
        if req.status_code == 200:
            try:
                return "[VirusTotal]\n" + json.dumps(req.json(), indent=4)
            except json.decoder.JSONDecodeError:
                if len(req.text) == 0:
                    return "[!] Error, HTTP request succeeded, but no content" \
                            " is available."
                else:
                    return req.text
        elif req.status_code == 429:
            return "\t[!] Error, too many requests being made against VirusTotal."

        elif req.status_code == 403:
            return "\n\t[!] Error, you do not have appropriate permissions " \
                    "to make this Virus Total API request."
        else:
            return "\t[VirusTotal] Error, hash not found."

    def download_sample(self, hash_value):
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
        print("\t[*] This is a premium feature, and requires a private API key.")
        self.params['hash'] = hash_value
        req = requests.get(self.base_url+ "download", params=self.params)

        if req.status_code == 200:
            try:
                with open(hash_value, "wb+") as fout:
                    fout.write(req.content)
                return True
            except IOError as err:
                print("\t[!] Error writing to file.\n\tMsg: %s" % (err))
                return False
        elif req.status_code == 403:
            print("\n\t[!] Error, you do not have appropriate permissions " \
                    "to make this Virus Total API request.")
            return False
        else:
            print("\t[!] Failed to identify hash %s.\n\t[ERROR] %s" \
                    % (hash_value, req.status_code))
            return False
