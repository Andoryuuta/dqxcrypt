from collections import namedtuple
import struct
import frida
import sys
import os
from pprint import pprint
from hexdump import hexdump

CryFile = namedtuple('CryFile', ['magic', 'version', 'unknown', 'data'])
def read_cry_file(filepath: str) -> CryFile:
    with open(filepath, 'rb') as f:
        (magic, data_size, version, unk0) = struct.unpack('<IIII', f.read(16))
        data = f.read(data_size)
        return CryFile(magic, version, unk0, data)

def get_agent_script():
    with open('./dqx-blowfish-frida-agent/_agent.js', 'rt', encoding='utf-8') as f:
        return f.read()

def main():
    session = frida.attach("DQXGame.exe")
    script = session.create_script(get_agent_script())
    script.load()

    cryfile = read_cry_file(r'C:\Users\Ando\Desktop\dqx_dat_dump\out\data00000000.win32.dat0\800718ca783ff612_rps\smldt_msg_pkg_COMMANDWINDOW.win32.etp.cry')
    
    original_encrypted_data = [x for x in cryfile.data]
    decrypted_data = script.exports.blowfish_decrypt("9)R6F3ZRr)FuijVY", original_encrypted_data)
    reencrypted_data = list(script.exports.blowfish_encrypt("9)R6F3ZRr)FuijVY", [x for x in decrypted_data]))

    print("origin vs enc->dec->enc:")
    print(original_encrypted_data[:16])
    print(reencrypted_data[:16])

    script.unload()
    sys.stdin.read()

if __name__ == '__main__':
    main()