import { MSVCVector } from './msvc.js'

const baseAddr = Process.enumerateModules()[0].base;
var procVceBlockEncryptBlowfishCtor = new NativeFunction(baseAddr.add(ptr(0x2BEFF3)), 'pointer', ['pointer'], 'thiscall');

// A terrible global object to keep references to all allocated memory
// this _should_ be cleared once we are done with our allocs, however,
// due to the limited usage of this library, we just allow the memory to
// leak until to the process we are injected into restarts.
let pinned_allocs = new Map();
function customAlloc(size: number): NativePointer {
    let mem = Memory.alloc(size);
    pinned_allocs.set(mem, mem);
    return mem;
}

function customDealloc(ptr: NativePointer): void {
    pinned_allocs.delete(ptr);
}

rpc.exports = {
    blowfishDecrypt: function(key: string, data_arr: Array<number>): ArrayBuffer {
        let data = new Uint8Array(data_arr).buffer as ArrayBuffer;

        let blowfishObjMemory = customAlloc(12);
        let blowfishObj = procVceBlockEncryptBlowfishCtor(blowfishObjMemory);
        let vtable = blowfishObj.readPointer();

        /* Load the vtable functions...
        0x00 + j_vce__BlockEncryptBlowfish__dtor
        0x04 + vce__BlockEncryptBlowfish__Initialize // bool Initialize(unsigned char *key,int keybitlength);
        0x08 + vce__BlockEncryptBlowfish__Reinitialize // bool Reinitialize();
        0x0C + vce__BlockEncryptBlowfish__Encrypt // bool Encrypt(const void *src,size_t srcsize,std::vector<unsigned char> &dest);
        0x10 + vce__BlockEncryptBlowfish__Decrypt // bool Decrypt(const std::vector<unsigned char> &src,std::vector<unsigned char> &dest);
        */

        let vf_vce_initalize = new NativeFunction(vtable.add(0x04).readPointer(), 'bool', ['pointer', 'pointer', 'int', 'int'], 'thiscall');
        let vf_vce_reinitalize = new NativeFunction(vtable.add(0x08).readPointer(), 'bool', [], 'thiscall');
        let vf_vce_encrypt = new NativeFunction(vtable.add(0x0C).readPointer(), 'bool', ['pointer', 'pointer', 'int', 'pointer'], 'thiscall');
        let vf_vce_decrypt = new NativeFunction(vtable.add(0x10).readPointer(), 'bool', ['pointer', 'pointer', 'pointer'], 'thiscall');

        let keyMem = customAlloc(key.length);
        keyMem.writeAnsiString(key);

        let result = vf_vce_initalize(blowfishObj, keyMem, 8*key.length, 0);

        let src = new MSVCVector(customAlloc, customDealloc);
        src.setData(data);

        let dst = new MSVCVector(customAlloc, customDealloc);
        dst.resize(data.byteLength);
        
        let result2 = vf_vce_decrypt(blowfishObj, src.ptr(), dst.ptr());

        // Recalculate this in case the encryption changed the size somehow (padding, etc)
        let outputSize = dst.size();
        return dst.get_start().readByteArray(outputSize)!;
    },
    blowfishEncrypt: function(key: string, data_arr: Array<number>): ArrayBuffer {
        let data = new Uint8Array(data_arr).buffer as ArrayBuffer;

        let blowfishObjMemory = customAlloc(12);
        let blowfishObj = procVceBlockEncryptBlowfishCtor(blowfishObjMemory);
        let vtable = blowfishObj.readPointer();

        /* Load the vtable functions...
        0x00 + j_vce__BlockEncryptBlowfish__dtor
        0x04 + vce__BlockEncryptBlowfish__Initialize // bool Initialize(unsigned char *key,int keybitlength);
        0x08 + vce__BlockEncryptBlowfish__Reinitialize // bool Reinitialize();
        0x0C + vce__BlockEncryptBlowfish__Encrypt // bool Encrypt(const void *src,size_t srcsize,std::vector<unsigned char> &dest);
        0x10 + vce__BlockEncryptBlowfish__Decrypt // bool Decrypt(const std::vector<unsigned char> &src,std::vector<unsigned char> &dest);
        */

        let vf_vce_initalize = new NativeFunction(vtable.add(0x04).readPointer(), 'bool', ['pointer', 'pointer', 'int', 'int'], 'thiscall');
        let vf_vce_reinitalize = new NativeFunction(vtable.add(0x08).readPointer(), 'bool', [], 'thiscall');
        let vf_vce_encrypt = new NativeFunction(vtable.add(0x0C).readPointer(), 'bool', ['pointer', 'pointer', 'int', 'pointer'], 'thiscall');
        let vf_vce_decrypt = new NativeFunction(vtable.add(0x10).readPointer(), 'bool', ['pointer', 'pointer', 'pointer'], 'thiscall');

        let keyMem = customAlloc(key.length);
        keyMem.writeAnsiString(key);

        let result = vf_vce_initalize(blowfishObj, keyMem, 8*key.length, 0);

        let srcMem = customAlloc(data.byteLength);
        srcMem.writeByteArray(data);

        let dst = new MSVCVector(customAlloc, customDealloc);
        dst.resize(8* (((data.byteLength+7)>>3)+4));

        let result2 = vf_vce_encrypt(blowfishObj, srcMem, data.byteLength, dst.ptr());

        // Recalculate this in case the encryption changed the size somehow (padding, etc)
        let outputSize = dst.size();
        return dst.get_start().readByteArray(outputSize)!;
    }
}