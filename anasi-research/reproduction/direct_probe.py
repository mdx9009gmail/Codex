"""Binary-only inversion using native helpers located by Ghidra. No source/IR input."""
import ctypes as C, mmap, struct, pathlib, subprocess, json, hashlib
binary=pathlib.Path(__import__('sys').argv[1])
raw=binary.read_bytes()
mem=mmap.mmap(-1,0x500000,prot=7)
base=C.addressof(C.c_char.from_buffer(mem))
phoff=struct.unpack_from('<Q',raw,32)[0]
ents,num=struct.unpack_from('<HH',raw,54)
for i in range(num):
    typ,flags,off,va,pa,fs,ms,align=struct.unpack_from('<IIQQQQQQ',raw,phoff+i*ents)
    if typ==1: mem[va:va+fs]=raw[off:off+fs]
U=C.c_uint32; P=C.c_void_p
def fn(off,*types): return C.CFUNCTYPE(U,*types)(base+off)
def buf(x): return (C.c_ubyte*len(x))(*x)
def layer(off,x,*args):
    b=buf(x); fn(off,P,*([U]*len(args)))(b,*args); return list(b)
def independent_inverse(off,y,*args):
    tables=[{} for _ in y]
    for v in range(256):
        out=layer(off,[v]*24,*args)
        for i,z in enumerate(out): tables[i][z]=v
    assert all(len(t)==256 for t in tables)
    return [tables[i][v] for i,v in enumerate(y)]

print(fn(int(__import__('sys').argv[2],16),U,U)(123,456),flush=True)


