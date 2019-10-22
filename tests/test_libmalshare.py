#!/usr/bin/python3
try:
    import sys
    import os
    sys.path.append(os.path.abspath('..'))
    import requests
    import unittest
    from unittest import mock
    from nose.tools import assert_true
    from providers.libmalshare import MalshareAPI
except ImportError as err:
    print("[!] Error, could not import %s" % str(err))
    sys.exit(1)

class TestLibMalshare(unittest.TestCase):

    @mock.patch('requests.get')
    def test_get_api_info(self, mock_get_api_info):
        mock_get_api_info.return_value.status_code = 200
        mock_get_api_info.return_value.json.return_value = { "LIMIT": 200, 
                "REMAINING":200}

        mapi = MalshareAPI("MOCK_API_KEY")
        response_text = mapi.get_api_info()
        assert("Error" not in response_text)

    @mock.patch('requests.get')
    def test_hash_search(self, mock_get_api_info):
        mock_get_api_info.return_value.status_code = 200
        mock_get_api_info.return_value.json.return_value = {
                'MD5': 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
                'SHA1': 'YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY',
                'SHA256': 'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ',
                'SSDEEP': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'F_TYPE': 'PE32',
                'SOURCES': ['http://www.example.com/']}
        mapi = MalshareAPI("MOCK_API_KEY")
        response_text = mapi.hash_search("HASH_EXAMPLE")
        assert("Error" not in response_text)

    @mock.patch('requests.get')
    def test_download_sample(self, mock_get_api_info):
        mock_get_api_info.return_value.status_code = 200
        mock_get_api_info.return_value.content = "0x90\\0x92".encode()

        mapi = MalshareAPI("MOCK_API_KEY")
        response = mapi.download_sample("HASH_EXAMPLE")
        assert(response == True)


if __name__ == "__main__":
    unittest.main()
