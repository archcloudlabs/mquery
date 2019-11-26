"""
AVCaesar API class wrapper
"""
import json
import sys
import logging
try:
    import requests
except ImportError as err:
    print("[!] error, missing %s" % (err))
    sys.exit()

class CaesarAPI():
    '''
    API wrapper for AV Caesar
    Docs: https://avcaesar.malware.lu/docs/api
    '''

    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://avcaesar.malware.lu/api/v1/"
        logging.getLogger().setLevel(logging.INFO)

    def get_api_info(self):
        '''
        Name: get_api_info
        Purpose: get info about API usage from provider
        Parameters: N/A
        '''
        try:
            req = requests.get(self.base_url+"/user/quota", cookies=dict(apikey=self.api_key))
        except requests.exceptions.RequestException as req_err:
            return "[!] Error getting API info from AV Caesar!\n\t %s" % str(req_err)


        if req.status_code == 200:
            return("\n\t[ AV Caesar ]\n\t\t[+] Analysis %s/%s" \
                   "\n\t\t[+] Download: %s/%s\n\t\t[+] Info: %s/%s" %
                   (req.json().get('analysis').get('current'),
                    req.json().get('analysis').get('limit'),
                    req.json().get('download').get('current'),
                    req.json().get('download').get('limit'),
                    req.json().get('info').get('current'),
                    req.json().get('info').get('limit')))

        return "\n[!] Error, A/V Caesar API request for API limits went "\
                    "horribly wrong. %s" % str(req.text)

    def latest_submissions(self):
        '''
        Name: latest_submissions
        Purpose: get latest hash contents.
        Parameters: N/A
        Return: string.
        '''

        logging.info("[*] libavcaesar does not provide a latest-submissions feed.")
        return "\t[*] AV Caesar does not support latest submissions."

    def hash_search(self, hash_val):
        '''
        Name: hash_search
        Purpose: search for information about a particular hash.
        Parameters: [hash_val] string value to specify hash to search for.
        return: string
        '''
        try:
            req = requests.get(self.base_url+"/sample/"+hash_val, cookies=dict(apikey=self.api_key))

        except requests.exceptions.RequestException as req_err:
            return "[!] Error searching for hash from AV Caesar!\n\t %s" % str(req_err)


        if req.status_code == 200:
            logging.debug("Downloading hash %s", str(hash_val))
            try:
                logging.info("Identified hash %s", str(hash_val))
                return "\t[AV Caesar]\n"+json.dumps(req.json(), indent=4)
            except json.decoder.JSONDecodeError:
                # If something is searched out and doesn't return JSON or
                # malformed, print the plain text.
                if len(req.text) == 0:
                    return "[!] Error, HTTP request succeeded, but no content"\
                            " is available."
                return req.text
        elif req.status_code == 429:
            return "\t[!] Error, too many requests being made against AV Caesar."
        else:
            return "\t[AV Caesar] Hash not found."

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
            req = requests.get(self.base_url+"/sample/"+hash_value+"/download",
                               cookies=dict(apikey=self.api_key))
        except requests.exceptions.RequestException as req_err:
            return "[!] Error downloading sample from AV Caesar!\n\t %s" % str(req_err)

        if req.status_code == 200:
            try:
                with open(directory + hash_value, "wb+") as fout:
                    fout.write(req.content)
                return True
            except IOError as err:
                print("\t[!] Error writing to file.\n\t%s" % str(err))
        else:
            print("\t[!] Failed to identify hash %s.\n\t[ERROR] %s"
                  % (hash_value, req.status_code))
            return False
