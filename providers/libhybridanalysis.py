import time
import json
import sys
try:
    import requests
except ImportError as err:
    print("[!] error, missing %s" % (err))
    sys.exit()

class HBAPI():
    '''
    API wrapper for https://www.hybrid-analysis.com API.
    Docs: https://www.hybrid-analysis.com/docs/api/v2
    '''

    def __init__(self, api_key):
        self.api_key = api_key

        self.http_headers = {"accept" : "application/json",
                             # user-agent specified in documentation
                             "User-Agent" : "Falcon Sandbox",
                             "Type" : "application/x-www-form-urlencoded",
                             "Content-Type" : "application/x-www-form-urlencoded",
                             "api-key" : self.api_key}

        self.base_url = "https://www.hybrid-analysis.com/api/v2/"

    def get_api_info(self):
        '''
        Name: get_api_limit
        Purpose: get info about API usage from provider
        Parameters: N/A
        '''
        try:
            req = requests.get(self.base_url+"key/current",
                               headers=self.http_headers)
        except requests.exceptions.RequestException as err:
            return "\n\t[!] Error, Hyrbrid API request for API limits went " \
                    "horribly wrong.\n\tError: %s" % str(err)

        if req.status_code == 200:
            api_headers = json.loads(req.headers.get("Api-Limits"))
            return("\n\t[Hybrid Analysis Requests]\n\t\t[+] Limits: "
                   "M:%s:H%s\n\t\t[+] Used: M%s:H%s\n" %
                   (api_headers.get("limits").get("minute"),
                    api_headers.get("limits").get("hour"),
                    api_headers.get("used").get("minute"),
                    api_headers.get("used").get("hour")))

        if req.status_code == 429:
            return "\n\t[!] Error, too many requests being made against " \
                    "Hybrid Analysis."

        return "\n\t[!] Error, Hyrbrid API request for API limits went " \
                "horribly wrong. %s\n" % str(req.text)


    def latest_submissions(self):
        '''
        Name: latest_submissions
        Purpose: get latest hash contents.
        Parameters: N/A
        Return: string.
        '''
        # user-agent specified in documentation
        self.http_headers = {"accept" : "application/json",
                             "User-Agent" : "Falcon Sandbox", "api-key" : self.api_key}

        try:
            req = requests.get(self.base_url+"feed/latest", headers=self.http_headers)
        except requests.exceptions.RequestException as err:
            return "[!] Error getting latest submissions from Hybria Analysis!\n\t%s" % (err)

        if req.status_code == 200:
            return "\t[Hybrid Analysis]\n" + json.dumps(req.json(), indent=4)
        if req.status_code == 429:
            return "\n\t[!] Error, too many requests being made against Hybrid Analysis."
        return "\n\t[!] Error, Hyrbrid API request for latest submissions went " \
                "horribly wrong. %s" % str(req.text)

    def hash_search(self, hash_val):
        '''
        Name: hash_search
        Purpose: search for information about a particular hash
        Parameters: [hash_val] string value to specify hash to search for.
        return: string
        '''
        #body = "hash=" + hash_val + str(time.time()).replace(".","")
        body = "hash=" + hash_val 

        try:
            req = requests.post(self.base_url+"search/hash?_timestamp=" + str(time.time()).replace(".", ""),
                                headers=self.http_headers,
                                data=body)
        except requests.exceptions.RequestException as err:
            return "[!] Error searching for hash with Hybrid Analysis!\n\t%s" % (err)

        if req.status_code == 200 and len(req.json()) > 0:
            return "[Hybrid-Analysis]\n"+json.dumps(req.json(), indent=4)
        return "\t[Hybrid-Analysis] Hash not found!"

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

        if len(hash_value) != 64:
            print("[HBA Download Error] Hybrid Analysis requires a sha256 hash"\
                    "to download.")
        try:
            req = requests.get(self.base_url + "overview/" + hash_value + \
                    "/sample", headers=self.http_headers)
        except requests.exceptions.RequestException as err:
            print("[!] Error downloading sample with Hybrid Analysis %s" % (err))

        if req.status_code == 200:
            if file_name is None:
                try:
                    with open(hash_value, "wb+") as fout:
                        fout.write(req.content)
                    print("\t[+] Successfully downloaded sample %s." % (hash_value))
                    return True
                except IOError as err:
                    print("\t[!] I/O Error downloading sample %s.\n\t%s" \
                            % (hash_value, err))
                    return False
            else: # Specified filename on CLI
                with open(file_name, "wb+") as fout:
                    fout.write(req.content)
                print("\t[+] Successfully downloaded sample %s." % (file_name))
                return True

        else:
            print("\t[!] Failed to identify hash %s.\n\t\t[ERROR] %s"
                  % (hash_value, req.json().get('message')))
            return False

    def daily_download(self):
        '''
        Name: daily_download
        Purpose: get latest hash contents.
        Parameters: N/A
        Return: string.
        '''
        # user-agent specified in documentation
        self.http_headers = {"accept" : "application/json",
                             "User-Agent" : "Falcon Sandbox", "api-key" : self.api_key}

        try:
            req = requests.get(self.base_url+"feed/latest", headers=self.http_headers)
        except requests.exceptions.RequestException as err:
            return "[!] Error getting latest submissions from Hybria Analysis!\n\t%s" % (err)

        if req.status_code == 200:
            for sample in req.json().get('data'):
                if self.download_sample(sample.get('sha256')):
                    print("\t[Hybrid Analysis] Downloaded %s @%s" % \
                            (sample.get('sha256'), time.asctime()))
            return "\t[Hybird Analysis] Successfully finished downloaded samples @%s" \
                        % time.asctime()
        if req.status_code == 429:
            return "\n\t[!] Error, too many requests being made against Hybrid Analysis."
        return "\n\t[!] Error, Hyrbrid API request for latest submissions went " \
                "horribly wrong. %s" % str(req.text)
