'''
Greynoise API class wrapper
'''
import json
import sys
import time
import logging
try:
    import requests
except ImportError as err:
    print("[!] error, missing %s" % (err))
    sys.exit()

class GreynoiseAPI():
    '''
    API wrapper for http://docs.greynoise.io/?python#ip-context
    Docs: 
    '''
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {'Accept': 'application/json', 'key' : self.api_key}
        self.base_url = ("https://api.greynoise.io/v2/noise/context/")

        logging.getLogger().setLevel(logging.INFO)

    def search(self, ioc_obj):
        '''
        Name: search
        Purpose: Search for information about a particular hash/ip
        Parameters: [ioc_obj] string value to specify hash/ip/etc.. to search for.
        return: string
        '''
        try:
            req = requests.get(self.base_url+ioc_obj, headers=self.headers)
            data = req.json()
            return("%s:%s:%s"% (data.get('ip'), data.get('metadata'), data.get('tags')))

        except requests.exceptions.RequestException as err:
            return "[!] Error, could not search for IoC with Greynoise!\n\t%s" % (err)

        if req.status_code == 200:
            try:
                logging.info("Identified IoC %s" % ioc_obj)
                return "[Greynoise]\n" + json.dumps(req.json(), indent=4)
            except json.decoder.JSONDecodeError:
                if len(req.text) == 0:
                    return "\t[!] Error, HTTP request succeeded, but no content" \
                            "is available."
                return req.text
        elif req.status_code == 429:
            return "[!] Error, too many requests being made against Greynoise."
        else:
            return "\t[Greynoise] IoC not identified."
