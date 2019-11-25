try:
    import os
    from providers.libmalshare import MalshareAPI
    from providers.libhybridanalysis import HBAPI
    from providers.libvirustotal import VTAPI
    from providers.libavcaesar import CaesarAPI
except ImportError as err:
    print("[!] Error, could not import %s. Quitting!" % str(err))
    os._exit(1)

class MalQuery():
    '''
    MalQuery is a middle-ware helper class to parse user-args and leverage
    different underlying Malware download site APIs.
    '''

    def __init__(self, provider, action, hashval, directory="."):

        self.provider = provider # CLI Provided API provider
        self.action = action # CLI provided action
        self.hash = hashval # Hash to search
        self.dir = directory # Directory to save samples to

        if self.dir[-1::] not in ["/", ""] and self.action == "download":
            print("[*] Full filepath not specified. Downloaded files will " \
                    "precede with %sFILE_HASH_HERE" % str(self.dir))

        # TEMPLATE API
        # self.custom_api_key = self.__get_env_var__("CUSTOM_TOKEN")
        # self.has_custom_api = None # Boolean object indicating API exists.
        # self.custom_obj = None

        # Malshare groupings
        self.malshare_api_key = self.__get_env_var__("MALSHARE_TOKEN")
        self.has_malshare_api = None # Boolean object indicating API exists.
        self.malshare_obj = None

        # Hybrid-Analysis groupings
        self.hba_api_key = self.__get_env_var__("HBA_TOKEN")
        self.has_hba_api = None # Boolean object indicating API exists.
        self.hba_obj = None

        # VT groupings
        self.vt_api_key = self.__get_env_var__("VT_TOKEN")
        self.has_vt_api = None # Boolean object indicating API exists.
        self.vt_obj = None

        # Caesar groupings
        self.caesar_api_key = self.__get_env_var__("CAESAR_TOKEN")
        self.has_caesar_api = None # Boolean object indicating API exists.
        self.caesar_obj = None

        # Libquery Meta
        self.__provider_objects__ = [] # List of class objects to iterate
                                       # through for API operations.

        self.__api_status__() # Check what API tokens are available and update
                              # objects

        self.parse_action(self.action) # Parse CLI action and call underlying
                                       # API objects.
    def __api_status__(self):
        '''
        Name: __api_status__
        Purpose: Check if API keys exist.
        '''
        if self.provider == "all":
            self.__load_malshare_api__()
            self.__load_hba_api__()
            self.__load_vt_api__()
            self.__load_caesar_api__()

        elif self.provider == "hba":
            self.__load_hba_api__()

        elif self.provider == "malshare":
            self.__load_malshare_api__()

        elif self.provider == "virustotal":
            self.__load_vt_api__()

        elif self.provider == "caesar":
            self.__load_caesar_api__()

    def __load_caesar_api__(self):
        '''
        Name: __load_caesar_api
        Purpose: load AV Caesar API objects
        Return: N/A
        '''
        if self.caesar_api_key is not None:
            self.has_caesar_api = True
            self.caesar_obj = CaesarAPI(self.caesar_api_key)
            self.__provider_objects__.append(self.caesar_obj)
            print("\t[+] Caesar API token identified.")

    def __load_vt_api__(self):
        '''
        Name: __load_vt_api
        Purpose: load Virus Total API objects
        Return: N/A
        '''
        if self.vt_api_key is not None:
            self.has_vt_api = True
            self.vt_obj = VTAPI(self.vt_api_key)
            self.__provider_objects__.append(self.vt_obj)
            print("\t[+] VirusTotal API token identified.")

    def __load_malshare_api__(self):
        '''
        Name: __load_malshare_api__
        Purpose: load Malshare API objects
        Return: N/A
        '''
        if self.malshare_api_key is not None:
            self.has_malshare_api = True
            self.malshare_obj = MalshareAPI(self.malshare_api_key)
            self.__provider_objects__.append(self.malshare_obj)
            print("\t[+] Malshare API token identified.")

    def __load_hba_api__(self):
        '''
        Name: __load_hba_api__
        Purpose: load Hybrid-Analysis API objects
        Return: N/A
        '''
        if self.hba_api_key is not None:
            self.has_hba_api = True
            self.hba_obj = HBAPI(self.hba_api_key)
            self.__provider_objects__.append(self.hba_obj)
            print("\t[+] Hybrid-Analysis API token identified.")

    def __get_env_var__(self, env_name):
        '''
        Name: get_env_var
        purpose: get environment variable for malshare api key.
        return: string value.
        '''
        if os.environ.get(env_name) is None or len(os.environ.get(env_name)) == 0:
            print("\t[!] %s environment variable was not specified." % str(env_name))
        else:
            return os.environ.get(env_name)

    def parse_action(self, action):
        '''
        Name: parse_action
        Purpose: Parse CLI action for downloading/searchhing/list
        '''
        if len(self.__provider_objects__) == 0:
            print("\t[!] No API providers found! Quitting!")
            return 1
        if action == "download":
            for provider in self.__provider_objects__:
                if provider.download_sample(self.hash, self.dir) == True:
                    print("\n[================[ Download ]==================]")
                    print("\t[+] %s found and downloaded via %s" % (self.hash,
                            provider.__module__.split('.')[1].replace("lib", "")))

                    return 0# No need to download same sample from different provider.
                else:
                    print("\t[!] Hash %s not found at %s" % (self.hash,
                            provider.__module__.split('.')[1].replace("lib", "")))

        elif action == "search":
            print("\n[================[ Search ]===================]")
            for provider in self.__provider_objects__:
                print(provider.hash_search(self.hash))
            print("\n[===============================================]")
            return 0

        elif action == "info":
            print("\n[================[ API Info ]===================]")
            for provider in self.__provider_objects__:
                print(provider.get_api_info())
            print("\n[===============================================]")
            return 0

        elif action == "list":
            print("\n[===============[ 24hr File List ]==============]")
            for provider in self.__provider_objects__:
                print(provider.latest_submissions())
            print("\n[===============================================]")
            return 0

        elif action == "daily-download":
            print("\n[===============[ Daily Download ]==============]")
            for provider in self.__provider_objects__:
                try:
                    print(provider.daily_download(self.dir))
                    print("\n[===============================================]")
                except AttributeError as attr_err:
                    print("\n\t[daily-download error] %s" % str(attr_err))
                    pass
            return 0
