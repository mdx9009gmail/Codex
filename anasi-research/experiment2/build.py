import hashlib,json,pathlib,re,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parent
SDK=ROOT/'sdk'
BUILD=ROOT/'build'
BUILD.mkdir(exist_ok=True)
def run(args,log,cwd=None):
    start=time.monotonic()
    with (BUILD/log).open('w') as f:
        subprocess.run([str(x) for x in args],stdout=f,stderr=subprocess.STDOUT,check=True,cwd=cwd)
    print(log,round(time.monotonic()-start,2),'seconds',flush=True)
run([sys.executable,SDK/'pipeline/seal_compare.py','--source',ROOT/'ctf.original.cpp','--output',ROOT/'ctf.sealed.cpp','--target','kExpected','--call','compare_output(transformed, kExpected)'],'seal.log')
run(['clang++','-S','-emit-llvm','-O1','-fno-inline',ROOT/'ctf.sealed.cpp','-o',BUILD/'discovery.ll'],'frontend.log')
ir=(BUILD/'discovery.ll').read_text()
names=[n for n in re.findall(r'^define\b[^@\n]*@([^ (]+)\(',ir,re.M) if n=='verify_password' or 'sdk_sealed_equal' in n]
assert len(names)==2,names
(BUILD/'functions.txt').write_text('\n'.join(names)+'\n')
run([sys.executable,'pipeline/protect.py','--native','--dist','/usr','--source',ROOT/'ctf.sealed.cpp','--output',ROOT/'ctf.protected.bin','--workdir',BUILD/'work','--functions','@'+str(BUILD/'functions.txt'),'--cflag=-xc++','--cflag=-std=c++17','--cflag=-fno-unroll-loops','--cflag=-fno-vectorize','--cflag=-fno-slp-vectorize','--guard-seed','20261103','--guards','anti-emu,integrity,deny-attach,opaque,seal','--native-call-gate','verify_password'],'protect.log',SDK)
b=ROOT/'ctf.protected.bin'
(ROOT/'binary-manifest.json').write_text(json.dumps({'file':b.name,'bytes':b.stat().st_size,'sha256':hashlib.sha256(b.read_bytes()).hexdigest()},indent=2))
print((ROOT/'binary-manifest.json').read_text())
