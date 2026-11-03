import ctypes,hashlib,importlib.util,json,pathlib,random,subprocess,time
R=pathlib.Path(__file__).resolve().parent
B=R/'build'
spec=importlib.util.spec_from_file_location('seal',R/'sdk/pipeline/seal_compare.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
rng=random.Random(20261103)
def cc(src,out,*flags):
    subprocess.run(['clang++','-O2',*flags,str(src),'-o',str(out)],check=True)
sha_cases=0
for n in (1,3,24,55):
    src=B/'sha_test.cpp';lib=B/('sha_test_'+str(n)+'.so')
    src.write_text('#include <stdint.h>\n'+m.runtime(n,bytes(32))+'\nextern "C" void test(const unsigned char *p,unsigned char *o){sdk_sha256_fixed(p,o);}\n')
    cc(src,lib,'-shared','-fPIC')
    fn=ctypes.CDLL(str(lib)).test
    fn.argtypes=[ctypes.c_void_p,ctypes.c_void_p]
    for data in [bytes(n),bytes([255])*n,bytes(range(n))]+[rng.randbytes(n) for _ in range(64)]:
        out=ctypes.create_string_buffer(32);fn(data,out)
        assert out.raw==hashlib.sha256(data).digest()
        sha_cases+=1
source=(R/'ctf.original.cpp').read_text()
for invalid in [source.replace('compare_output(transformed, kExpected)','compare_output(transformed, other)'),source+'\nint extra = kExpected[0];',source.replace('kExpected[kOutputBytes]', 'missing[kOutputBytes]')]:
    try:m.seal(invalid,'kExpected','compare_output(transformed, kExpected)')
    except ValueError:pass
    else:raise AssertionError('adapter accepted unsupported source')
for name in ('original','sealed'):
    cc(R/('ctf.'+name+'.cpp'),B/('native.'+name))
key='rotate_the_keys_while_we'
cases=[[],[''],[key],['A'*23],['A'*25],['A'*100],[key,'extra']]
cases += [[key[:i]+'X'+key[i+1:]] for i in range(24)]
cases += [[''.join(rng.choice('abcdef0123456789_') for _ in range(24))] for _ in range(96)]
bins=[B/'native.original',B/'native.sealed',R/'ctf.protected.bin']
times=[]
for args in cases:
    values=[]
    for b in bins:
        start=time.monotonic();p=subprocess.run([str(b),*args],capture_output=True,timeout=10)
        if b==bins[-1]:times.append(time.monotonic()-start)
        values.append((p.returncode,p.stdout.replace(str(b).encode(),b'<exe>'),p.stderr))
    assert values[0]==values[1]==values[2],(args,values)
raw=bins[-1].read_bytes()
target=bytes.fromhex('5ee26d23277871ca7b60e0406d09cf48219a52a7743c2e62')
assert key.encode() not in raw
assert target not in raw
tamper=[]
for label,offset in [('elf_padding',9),('digest',len(raw)-10),('magic',len(raw)-1)]:
    modified=bytearray(raw);modified[offset]^=1
    path=B/('tampered.'+label);path.write_bytes(modified);path.chmod(0o755)
    p=subprocess.run([str(path),key],capture_output=True,timeout=10)
    assert p.returncode==174,(label,p.returncode,p.stdout)
    tamper.append({'case':label,'exit':p.returncode})
gate=json.loads((B/'work/native_call_gate.json').read_text())
report={'sha256_reference_cases':sha_cases,'adapter_rejection_cases':3,'differential_cases':len(cases),'binaries_compared':3,'failures':0,'protected_seconds_min':min(times),'protected_seconds_max':max(times),'protected_seconds_mean':sum(times)/len(times),'plaintext_answer_absent':True,'original_target_bytes_absent':True,'tamper_tests':tamper,'native_gate_function_count':len(gate['covered']),'binary_sha256':hashlib.sha256(raw).hexdigest()}
(R/'validation.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
