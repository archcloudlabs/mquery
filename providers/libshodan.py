"""
Shodan API class wrapper
"""
import json
import sys
import logging
import os

try:
    import requests
except ImportError as import_err:
    print("[!] error, missing %s" % import_err)
    sys.exit()


class ShodanAPI(object):
    """
    ShodanAPI wrapper for https://developer.shodan.io/api
    """
    def __init__(self, api_key):
        self.api_key = ""
        self.base_url = "https://api.shodan.io/"

        logging.getLogger().setLevel(logging.INFO)

    def get_api_info(self):
        """
        Name: get_api_info
        Purpose: get info about API usage from provider
        Parameters: N/A
        """
        try:
            req = requests.get(self.base_url+"api-info?key=%s" % self.api_key)
        except requests.exceptions.RequestException as req_err:
            return "[!] Error, could not get API info from ShodanAPI!\n\t%s" % req_err
        if req.status_code == 200:
            return req.text
        else:
            return "\n\t[!] Error, Shodan API request for API limits went " \
               "horribly wrong. Response code: %s" % str(req.status_code)

    def ip_search(self, ioc_val):
        """
        Name:  
        Purpose: search for information about a particular ioc
        Parameters: [ioc_val] string value to specify hash to search for.
        return: string
        """
        try:
            req = requests.get(self.search_endpoint+ioc_val)
        except requests.exceptions.RequestException as req_err:
            return "[!] Error, could not search for ioc with Malshare!\n\t%s" % req_err

        if req.status_code == 200:
            try:
                logging.info("Identified ioc %s" % ioc_val)
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

if __name__ == "__main__":
    import os
    token = os.getenv("SHODAN_TOKEN")
    sObj = ShodanAPI(token)
    print(sObj.get_api_info())
