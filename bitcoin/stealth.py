import main
import transaction as tx

# Shared secrets and uncovering pay keys

def shared_secret_sender(scan_pubkey, ephem_privkey):
    shared_point = main.multiply(scan_pubkey,ephem_privkey)
    shared_secret = main.sha256(main.encode_pubkey(shared_point,'bin_compressed'))
    return shared_secret
    
def shared_secret_receiver(ephem_pubkey, scan_privkey):
    shared_point = main.multiply(ephem_pubkey,scan_privkey)
    shared_secret = main.sha256(main.encode_pubkey(shared_point,'bin_compressed'))
    return shared_secret

def uncover_pay_pubkey_sender(scan_pubkey, spend_pubkey, ephem_privkey):
    shared_secret = shared_secret_sender(scan_pubkey, ephem_privkey)
    return main.add_pubkeys(spend_pubkey, main.privtopub(shared_secret))
    
def uncover_pay_pubkey_receiver(scan_privkey, spend_pubkey, ephem_pubkey):
    shared_secret = shared_secret_receiver(ephem_pubkey, scan_privkey)
    return main.add_pubkeys(spend_pubkey, main.privtopub(shared_secret))

def uncover_pay_privkey(scan_privkey, spend_privkey, ephem_pubkey):
    shared_secret = shared_secret_receiver(ephem_pubkey, scan_privkey)
    return main.add_privkeys(spend_priv,shared_secret)    

# Address encoding
    
def stealth_data_to_address(stealth_data, magic_byte=42):
    # magic_byte = 42 for mainnet, 43 for testnet.
    scan_pubkey = main.encode_pubkey(stealth_data['scan_pubkey'],'hex_compressed')
    spend_pubkeys = [main.encode_pubkey(sp,'hex_compressed') for sp in stealth_data['spend_pubkeys'] ]
    num_sigs = stealth_data['num_signatures']
    prefix_num_bits = stealth_data['prefix_num_bits']
    
    if prefix_num_bits > 0:
        prefix_bitfield = stealth_data['prefix_bitfield']
    
    if len(spend_pubkeys) == 0:
        # Reuse scan_pubkey as spend_pubkey
        opt = 1
    else:
        opt = 0
    
    serialized = '{0:02x}{1:066x}{2:02x}'.format(opt, int(scan_pubkey,16), len(spend_pubkeys))
    
    spend_pubkeys_string = ''
    for sp in spend_pubkeys:
        spend_pubkeys_string += '{0:066x}'.format(int(sp,16))
    
    serialized += spend_pubkeys_string
    serialized += '{0:02x}{1:02x}'.format(num_sigs, prefix_num_bits)
    
    if prefix_num_bits != 0:
        # num_bytes = prefix_num_bits/8, round up
        num_bytes = (prefix_num_bits+7)/8
        format_str = '{0:0' + str(2*num_bytes) + 'x}'
        bitfield_hex = format_str.format(prefix_bitfield)
        bitfield_little_endian = bitfield_hex.decode('hex')[::-1].encode('hex')
        serialized += bitfield_little_endian
    
    return main.hex_to_b58check(serialized, magic_byte)

def stealth_address_to_data(addr):    
    hex_data = main.b58check_to_hex(addr)
    data = {}
    data['scan_pubkey'] = hex_data[2:68]
    
    num_spendkeys = int(hex_data[68:70],16)
    spend_pubkeys = []
    for ii in range(num_spendkeys):
        spend_pubkeys.append(hex_data[70+66*ii:70+66*(ii+1)])
    
    last_spendkey_idx = 70+66*num_spendkeys
    data['spend_pubkeys'] = spend_pubkeys
    data['num_signatures'] = int(hex_data[last_spendkey_idx:last_spendkey_idx+2],16)
    prefix_num_bits = int(hex_data[last_spendkey_idx+2:last_spendkey_idx+4],16)
    data['prefix_num_bits'] = prefix_num_bits
    data['prefix_bitfield'] = 0
    if prefix_num_bits > 0:
        prefix_num_bytes = (prefix_num_bits+7)/8
        bitfield_little_endian = hex_data[last_spendkey_idx+4:last_spendkey_idx+4+2*prefix_num_bytes]
        bitfield_hex = bitfield_little_endian.decode('hex')[::-1].encode('hex')
        data['prefix_bitfield'] = int(bitfield_hex,16)

    return data

# Convenience functions for basic stealth addresses,
# i.e. one scan key, one spend key, no prefix
def pubkeys_to_basic_stealth_address(scan_pubkey, spend_pubkey, magic_byte=42):
    hex_scankey = main.encode_pubkey(scan_pubkey, 'hex_compressed')
    hex_spendkey = main.encode_pubkey(spend_pubkey, 'hex_compressed')
    hex_data = '00{0:066x}01{1:066x}0100'.format(int(hex_scankey,16), int(hex_spendkey,16))
    addr = main.hex_to_b58check(hex_data, magic_byte)
    
    return addr
    
def basic_stealth_address_to_pubkeys(stealth_address):
    hex_data = main.b58check_to_hex(stealth_address)
    if len(hex_data) != 140:
        raise Exception('Stealth address is not of basic type (one scan key, one spend key, no prefix)')
    
    scan_pubkey = hex_data[2:68]
    spend_pubkey = hex_data[70:136]
    
    return scan_pubkey, spend_pubkey

# Sending stealth payments

def mk_stealth_script(ephem_pubkey, nonce):
    op_return = '6a'
    msg_size = '26'
    version = '06'
    return op_return + msg_size + version + '{0:08x}'.format(nonce) + main.encode_pubkey(ephem_pubkey, 'hex_compressed')

def nonce_matches_prefix(nonce, prefix_num_bits, prefix_bitfield, ephem_pubkey):
    if prefix_num_bits == 0:
        return True
    else:
        prefix_num_bytes = (prefix_num_bits+7)/8
        prefix_bitstring = ('{0:0' + str(8*prefix_num_bytes) + 'b}').format(prefix_bitfield)
        pubkey_hex = main.encode_pubkey(ephem_pubkey, 'hex_compressed')
        nonce_hex = '{0:08x}'.format(nonce)
        input_bin = (nonce_hex + pubkey_hex).decode('hex')
        hashresult = int(main.dbl_sha256(input_bin)[:8],16)
        hash_bitstring = '{0:032b}'.format(hashresult)
        return hash_bitstring[:prefix_num_bits] == prefix_bitstring[:prefix_num_bits]

def random_nonce_matching_prefix(prefix_num_bits, prefix_bitfield, ephem_pubkey):

    if (prefix_num_bits > 12):
        raise Exception("Currently max 12 prefix bits supported for performance reasons.")

    if (prefix_bitfield >= 2**32):
        raise Exception("prefix_bitfield needs to be 4 bytes or less.")
        
    if prefix_num_bits == 0:
        random_nonce = int(main.random_key()[:8],16)
    else:
        match_found = False
        while(not match_found):
            random_nonce = int(main.random_key()[:8],16)
            match_found = nonce_matches_prefix(random_nonce, prefix_num_bits, prefix_bitfield, ephem_pubkey)
            
    return random_nonce
    
def mk_stealth_tx_outputs(stealth_addr, value, ephem_privkey, nonce, network='btc'):
    if network == 'btc':
        if stealth_addr[0] != 'v':
            raise Exception('Invalid mainnet stealth address: ' + stealth_addr)
        
        magic_byte_addr = 0
        magic_byte_p2sh = 5 
        
    elif network == 'testnet':
        if stealth_addr[0] != 'w':
            raise Exception('Invalid testnet stealth address: ' + stealth_addr)
    
        magic_byte_addr = 111
        magic_byte_p2sh = 192
        
    ephem_pubkey = main.privkey_to_pubkey(ephem_privkey)
    stealth_data = stealth_address_to_data(stealth_addr)
    scan_pubkey = stealth_data['scan_pubkey']
    spend_pubkeys = stealth_data['spend_pubkeys']
    prefix_num_bits = stealth_data['prefix_num_bits']
    if prefix_num_bits > 0:
        prefix_bifield = stealth_data['prefix_bitfield']
        if not nonce_matches_prefix(nonce, prefix_num_bits, prefix_bitfield, ephem_pubkey):
            raise Exception('Nonce does not match prefix bitfield when attempting stealth tx.')

    output0 = {'script' : mk_stealth_script(ephem_pubkey, nonce),
               'value' : 0}
        
    if len(spend_pubkeys) == 1:
        # Single address
        pay_pubkey = uncover_pay_pubkey_sender(scan_pubkey, spend_pubkeys[0], ephem_privkey)
        pay_addr = main.pubkey_to_address(pay_pubkey, magic_byte_addr)
        output1 = {'address' : pay_addr,
                   'value' : value}
    elif len(spend_pubkeys) > 1:
        # Multisig
        pay_pubs = []
        for sp in spend_pubkeys:
            pay_pubs.append(uncover_pay_pubkey_sender(scan_pubkey, sp, ephem_privkey))
        num_sigs = stealth_data['num_signatures']
        multisig_script = tx.mk_multisig_script(pay_pubs, num_sigs, len(pay_pubs))
        p2sh_addr = tx.p2sh_scriptaddr(multisig_script, magic_byte_p2sh)
        output1 = {'address' : p2sh_addr,
                   'value' : value}
    else:
        # No spend_pubkeys, use scan_pubkey to spend
        pay_pubkey = uncover_pay_pubkey_sender(scan_pubkey, scan_pubkey, ephem_privkey)
        pay_addr = main.pubkey_to_address(pay_pubkey, magic_byte_addr)
        output1 = {'address' : pay_addr,
                   'value' : value}
                   
    return [output0, output1]

# Receiving stealth payments

def ephem_pubkey_from_tx_script(stealth_tx_script):
    if len(stealth_tx_script) != 80:
        raise Exception('Wrong format for stealth tx output')
    
    return stealth_tx_script[14:]
