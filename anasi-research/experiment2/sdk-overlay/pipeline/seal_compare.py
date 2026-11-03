"""Explicit, fail-closed adapter for fixed byte-array equality (1..55 bytes).

Replaces the public reversible target with SHA-256(target). This is an opt-in
cryptographic change: equality is preserved subject to SHA-256 collisions.
It does not hide known passwords, prevent guessing, or prevent binary patching.
"""
import argparse
import hashlib
import json
import pathlib
import re

K = '''428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2'''

def runtime(n, digest):
    return r'''
static uint32_t sdk_rotr(uint32_t x, unsigned n) { return (x>>n)|(x<<(32-n)); }
static void sdk_sha256_fixed(const unsigned char *p, unsigned char out[32]) {
    static const uint32_t k[64] = {K_VALUES};
    uint32_t w[64] = {0};
    for (unsigned i=0;i<INPUT_SIZE;++i) w[i/4] |= (uint32_t)p[i] << (24-8*(i%4));
    w[INPUT_SIZE/4] |= 0x80u << (24-8*(INPUT_SIZE%4)); w[15]=INPUT_SIZE*8;
    for(unsigned i=16;i<64;++i) {
        uint32_t x=w[i-15], y=w[i-2];
        w[i]=w[i-16]+(sdk_rotr(x,7)^sdk_rotr(x,18)^(x>>3))+w[i-7]+(sdk_rotr(y,17)^sdk_rotr(y,19)^(y>>10));
    }
    uint32_t a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a,
             e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;
    for(unsigned i=0;i<64;++i) {
        uint32_t t1=h+(sdk_rotr(e,6)^sdk_rotr(e,11)^sdk_rotr(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t t2=(sdk_rotr(a,2)^sdk_rotr(a,13)^sdk_rotr(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    uint32_t s[8]={a+0x6a09e667u,b+0xbb67ae85u,c+0x3c6ef372u,d+0xa54ff53au,
                  e+0x510e527fu,f+0x9b05688cu,g+0x1f83d9abu,h+0x5be0cd19u};
    for(unsigned i=0;i<32;++i) out[i]=(unsigned char)(s[i/4]>>(24-8*(i%4)));
}
static int sdk_sealed_equal(const unsigned char *p) {
    static const unsigned char digest[32]={DIGEST_VALUES};
    unsigned char actual[32]; sdk_sha256_fixed(p,actual);
    unsigned difference=0;
    for(unsigned i=0;i<32;++i) difference |= actual[i]^digest[i];
    return difference==0;
}
'''.replace('K_VALUES', ','.join('0x'+v+'u' for v in K.split())).replace('INPUT_SIZE',str(n)).replace('DIGEST_VALUES',','.join(str(v) for v in digest))

def seal(source, target, call):
    pattern=r'static const unsigned char '+re.escape(target)+r'\s*\[[^\]]+\]\s*=\s*\{([^}]+)\}\s*;'
    matches=list(re.finditer(pattern,source))
    if len(matches)!=1: raise ValueError('expected exactly one byte-array target')
    m=matches[0]
    tokens=[s.strip() for s in m[1].split(',') if s.strip()]
    if not all(re.fullmatch(r'0x[0-9a-fA-F]{1,2}|[0-9]{1,3}',s) for s in tokens):
        raise ValueError('unsupported target initializer')
    data=bytes(int(s,0) for s in tokens)
    if not 1<=len(data)<=55: raise ValueError('single-block SHA-256 supports 1..55 bytes')
    if source.count(call)!=1: raise ValueError('expected exactly one explicit comparison call')
    cp=re.fullmatch(r'\w+\((\w+),\s*'+re.escape(target)+r'\)',call)
    if not cp: raise ValueError('comparison must be function(buffer, target)')
    digest=hashlib.sha256(data).digest()
    result=source[:m.start()]+runtime(len(data),digest)+source[m.end():]
    result=result.replace(call,'sdk_sealed_equal('+cp[1]+')')
    if re.search(r'\b'+re.escape(target)+r'\b',result): raise ValueError('unhandled target references')
    # Supplied CTF source carries the answer in a comment; omit this from derived source.
    result=re.sub(r'(?m)^\s*// ctf input:.*\n','',result)
    return result,{'scheme':'SHA-256 fixed-length target sealing','bytes':len(data),'target_digest':digest.hex(),'source_sha256':hashlib.sha256(source.encode()).hexdigest()}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',required=True);p.add_argument('--output',required=True)
    p.add_argument('--target',required=True);p.add_argument('--call',required=True)
    a=p.parse_args()
    output,manifest=seal(pathlib.Path(a.source).read_text(),a.target,a.call)
    pathlib.Path(a.output).write_text(output)
    pathlib.Path(a.output+'.seal.json').write_text(json.dumps(manifest,indent=2))
