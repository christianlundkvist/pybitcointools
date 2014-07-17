import pybitcointools as bc
import sys
import unittest

class TestStealth(unittest.TestCase):

    def setUp(self):
        
        self.addr = 'vJmtjxSDxNPXL4RNapp9ARdqKz3uJyf1EDGjr1Fgqs9c8mYsVH82h8wvnA4i5rtJ57mr3kor1EVJrd4e5upACJd588xe52yXtzumxj'
        self.scan_pub = '025e58a31122b38c86abc119b9379fe247410aee87a533f9c07b189aef6c3c1f52'
        self.scan_priv = '3e49e7257cb31db997edb1cf8299af0f37e2663e2260e4b8033e49d39a6d02f2'
        self.spend_pub = '03616562c98e7d7b74be409a787cec3a912122f3fb331a9bee9b0b73ce7b9f50af'
        self.spend_priv = 'aa3db0cfb3edc94de4d10f873f8190843f2a17484f6021a95a7742302c744748'
        self.ephem_pub = '03403d306ec35238384c7e340393335f9bc9bb4a2e574eb4e419452c4ea19f14b0'
        self.ephem_priv = '9e63abaf8dcd5ea3919e6de0b6c544e00bf51bf92496113a01d6e369944dc091'
        self.pay_pub = '02726112ad39cb6bf848b1b1ef30b88e35286bf99f746c2be575f96c0e02a9357c'
        self.pay_priv = '4e422fb1e5e1db6c1f6ab32a7706d368ceb385e7fab098e633c5c5949c3b97cd'
        
    def test_address_data(self):

        # Basic address
        data = bc.stealth_address_to_data(self.addr)
        self.assertEqual(data['scan_pubkey'], self.scan_pub)
        self.assertEqual(data['spend_pubkeys'][0], self.spend_pub)
        self.assertEqual(data['num_signatures'], 1)
        self.assertEqual(data['prefix_num_bits'], 0)

        sc_pub, sp_pub = bc.basic_stealth_address_to_pubkeys(self.addr)
        self.assertEqual(sc_pub, self.scan_pub)
        self.assertEqual(sp_pub, self.spend_pub)

        stealth_addr = bc.stealth_data_to_address(data)
        self.assertEqual(stealth_addr, self.addr)

        stealth_addr2 = bc.pubkeys_to_basic_stealth_address(sc_pub, sp_pub)
        self.assertEqual(stealth_addr2, self.addr)

        # More complex address
        
        
if __name__ == '__main__':
    unittest.main()
