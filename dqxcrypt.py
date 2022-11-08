from collections import namedtuple
import io
import struct
import sys
from frida_agent import FridaAgent
from managed_package_data_client import ManagedPackageDataClient

CryFile = namedtuple('CryFile', ['magic', 'version', 'unknown', 'data'])
def read_cry_file(filepath: str) -> CryFile:
    with open(filepath, 'rb') as f:
        (magic, data_size, version, unk0) = struct.unpack('<IIII', f.read(16))
        data = f.read(data_size)
        return CryFile(magic, version, unk0, data)

def write_cry_file(cryfile: CryFile) -> bytes:
    out = io.BytesIO()
    out.write(struct.pack('<IIII', cryfile.magic, len(cryfile.data), cryfile.version, cryfile.unknown))
    out.write(cryfile.data)
    return out.getvalue()



def print_usage():
    print("""DQX CRY [en|de]cryptor
    
Usage:
    * dqxcrypt.py decrypt <path to encrypted .cry file> <path to ManagedPackageDataClient.win32.pkg> 
    * dqxcrypt.py encrypt <path to unencrypted .etp file> <encryption key string> 
    """)

def do_encrypt(agent, filepath, encryption_key):
    with open(filepath, 'rb') as f:
        data = f.read()
        encrypted_data = agent.blowfish_encrypt(encryption_key, data)
        return write_cry_file(CryFile(0x9595243, 16, 0, encrypted_data))

def do_decrypt(agent, filepath, managed_package_data_client_path, crib=b'EVTX'):
    # Read the encrypted data + key file
    cryfile = read_cry_file(filepath)
    mpdc = ManagedPackageDataClient()
    mpdc.read_from('ManagedPackageDataClient.win32.pkg')

    # Print key ranges & groups for debugging.
    group_type = ['smldt_msg_pkg_%s.*.etp', 'eventText%sClient.*.etp', 'subPackage%02dClient.*.etp']
    for i in range(mpdc.group_count):
        print(f"Key Group {i} - used for {group_type[i]} files")
        print('  Ranges:')
        for (ri, range_obj) in enumerate(mpdc.group_ranges[i]):  
            print(f'    Range[{ri}]: {range_obj}')

        print('  Keys:')
        for (ki, key) in enumerate(mpdc.group_keys[i]):  
            print(f'    Key[{ki}]: {key}')

        print('')

    # Try decrypting with all of the keys in the file until we find our crib text.
    for key_group in mpdc.group_keys:
        for key in key_group:
            decrypted_data = agent.blowfish_decrypt(key, cryfile.data)
            if decrypted_data[:len(crib)] == crib:
                return (key, decrypted_data)

    return (None, None)


def main():

    # Terrible CLI parsing, but it works, so meh.
    if len(sys.argv) < 2:
        print_usage()
        exit(1)
    elif sys.argv[1] == 'encrypt' and len(sys.argv) < 4:
        print_usage()
        exit(1)
    elif sys.argv[1] == 'decrypt' and len(sys.argv) < 4:
        print_usage()
        exit(1)

    print('Attaching to game client...')
    
    # Attach to the game
    agent = FridaAgent()
    agent.attach_game()

    if sys.argv[1] == 'encrypt':
        filepath = sys.argv[2]
        encryption_key = sys.argv[3]
        
        print(f'Encrypting {filepath} with key {encryption_key}')
        data = do_encrypt(agent, filepath, encryption_key)

        # Write file if we managed to decrypt it.
        if data != None:
            output_filepath = filepath + '.enc'
            print(f'Encrypted with key "{encryption_key}". Writing to: {output_filepath}')
            with open(output_filepath, 'wb') as f:
                f.write(data)
        else:
            print(f'Failed to encrypt file with key {encryption_key}')

    elif sys.argv[1] == 'decrypt':
        filepath = sys.argv[2]
        managed_package_data_client_path = sys.argv[3]

        print(f'Decrypting {filepath} with keys from {managed_package_data_client_path}.')
        (key, data) = do_decrypt(agent, filepath, managed_package_data_client_path)

        # Write file if we managed to decrypt it.
        if key != None:
            output_filepath = filepath + '.dec'
            print(f'Decrypted with key "{key}". Writing to: {output_filepath}')
            with open(output_filepath, 'wb') as f:
                f.write(data)
        else:
            print('Failed to decrypt file with the keys in ManagedPackageDataClient.win32.pkg')


    # Detach from game
    agent.detach_game()

if __name__ == '__main__':
    main()