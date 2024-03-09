#!/usr/bin/python3
try:
    import sys
    import os
    import unittest
    from providers.libmalshare import MalshareAPI
    from providers.libhybridanalysis import HBAPI
except ImportError as err:
    print("[!] Error, could not import %s" % str(err))
    sys.exit(1)

class TestAPIGetInfo(unittest.TestCase):
    '''
    Test hash search functionality
    '''

    def test_hashsearch_malshare(self):
        '''
        Evaluate malshare hash searching with a known hash
        '''
        mapi = MalshareAPI(os.getenv("MALSHARE_TOKEN"))
        response = mapi.get_api_info()
        assert "Error" not in response

    def test_hashsearch_libhyrbirdanalysis(self):
        '''
        Evaluate hybrid analysis hash searching with a known hash
        '''
        hapi = HBAPI(os.getenv("HBA_TOKEN"))
        response = hapi.get_api_info()
        assert "Error" not in response

    # VirusTotal does not have a test for API info.

if __name__ == "__main__":
    unittest.main()
