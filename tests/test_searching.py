#!/usr/bin/python3
try:
    import sys
    import os
    import unittest
    from providers.libmalshare import MalshareAPI
    from providers.libhybridanalysis import HBAPI
    from providers.libavcaesar import CaesarAPI
    from providers.libvirustotal import VTAPI
except ImportError as err:
    print("[!] Error, could not import %s" % str(err))
    sys.exit(1)

class TestHashSearch(unittest.TestCase):
    '''
    Test hash search functionality
    '''

    def test_hashsearch_malshare(self):
        '''
        evaluate malshare hash searching with a known hash
        '''
        mapi = MalshareAPI(os.getenv("MALSHARE_TOKEN"))
        response = mapi.hash_search("5a34cb996293fde2cb7a4ac89587393a")
        assert "Error" not in response

    def test_hashsearch_avcaesar(self):
        '''
        evaluate av caesar hash searching with a known hash
        '''
        capi = CaesarAPI(os.getenv("CAESAR_TOKEN"))
        response = capi.hash_search("5a34cb996293fde2cb7a4ac89587393a")
        assert "Error" not in response

    def test_hashsearch_libhyrbirdanalysis(self):
        '''
        evaluate hybrid analysis hash searching with a known hash
        '''
        hapi = HBAPI(os.getenv("HBA_TOKEN"))
        response = hapi.hash_search("5a34cb996293fde2cb7a4ac89587393a")
        assert "Error" not in response

    def test_hashsearch_virustotal(self):
        '''
        evaluate hybrid analysis hash searching with a known hash
        '''
        vtapi = VTAPI(os.getenv("VT_TOKEN"))
        response = vtapi.hash_search("5a34cb996293fde2cb7a4ac89587393a")
        assert "Error" not in response

if __name__ == "__main__":
    unittest.main()
