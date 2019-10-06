try:
    import os
    import json
    from libs.libmalshare import MalshareAPI
    from libs.libhybridanalysis import HBAPI
except ImportError as err:
    print("[!] Error, could not import %s. Quitting!" % str(err))
    os._exit(1)

class MalQuery():
    '''
    MalQuery is a middle-ware helper class to parse user-args and leverage
    different underlying Malware download site APIs.
    '''

    def __init__(self, provider, action, hashval):
        '''
        '''
        self.provider = provider
        self.action = action
        self.hash = hashval

        
        # Malshare groupings
        self.malshare_api_key = self.__get_env_var__("MALSHARE_TOKEN")
        self.has_malshare_api = None
        self.malshare_obj = None

        # Hybrid-Analysis groupings
        self.hba_api_key = self.__get_env_var__("HBA_TOKEN")
        self.has_hba_api = None
        self.hba_obj = None

        # Libquery Meta
        self.__provider_objects__ = [] # List of class objects to iterate 
                                       # through for API operations.

        self.__api_status__() # Check what API tokens are available and update 
                              # objects 

        self.parse_action(self.action)

    def __api_status__(self):
        '''
        Name: __api_status__
        Purpose: Check if 
        '''
        if self.provider == "all":

            if self.malshare_api_key is not None:
                self.has_malshare_api = True
                self.malshare_obj = MalshareAPI(self.malshare_api_key)
                self.__provider_objects__.append(self.malshare_obj)
                print("\t[+] Malshare API token identified.")

            if self.hba_api_key is not None:
                self.has_hba_api = True
                self.hba_obj = HBAPI(self.hba_api_key)
                self.__provider_objects__.append(self.hba_obj)
                print("\t[+] Hybrid-Analysis API token identified.")

        elif self.provider == "hba":
            if self.hba_api_key is not None:
                self.has_hba_api = True
                self.hba_obj = HBAPI(self.hba_api_key)
                self.__provider_objects__.append(self.hba_obj)
                print("\t[+] Hybrid-Analysis API token identified.")

        elif self.provider == "malshare":
            if self.malshare_api_key is not None:
                self.has_malshare_api = True
                self.malshare_obj = MalshareAPI(self.malshare_api_key)
                self.__provider_objects__.append(self.malshare_obj)
                print("\t[+] Malshare API token identified.")


    def __get_env_var__(self, env_name):
        '''
        Name: get_env_var
        purpose: get environment variable for malshare api key.
        return: string value.
        '''
        if os.environ.get(env_name) is None:
            print("[!] %s environment variable not specified." % str(env_name))
        else:
            return os.environ.get(env_name)

    def parse_action(self, action):
        '''
        '''
        if action == "download":
            for provider in self.__provider_objects__:
                fname = provider + "_" + self.filename
                if self.sample_download(provider, self.hash, fname) == True:
                    print("[+] %s found and downloaded via %s" % (self.hash, fname))
                else:
                    print("[!] %s not found at %s" % (self.hash, fname))
                break # No need to download same sample from different provider.

        elif action == "search":
            print("[================ Search ===================]")
            for provider in self.__provider_objects__:
                provider.hash_search(self.hash)

        elif action == "api_info":
            print("[================ API Info ===================]")
            for provider in self.__provider_objects__:
                provider.get_api_info()

        elif action == "list":
            print("[================ 24hr File List ===================]")
            for provider in self.__provider_objects__:
                provider.latest_submissions()

    def sample_download(self, provider, hash_value, file_name):
        '''
        '''
        #if provider.lower() == "malshare" and self.has_malshare_api is not None:
        #    self.malshare_obj.download_sample(hash_value, file_name)
        return provider.download_sample(hash_value, file_name) 
