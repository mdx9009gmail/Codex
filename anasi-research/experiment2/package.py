import hashlib,json,pathlib,shutil,zipfile
R=pathlib.Path(__file__).resolve().parent
D=R.parent/'experiment2-delivery/anasi-research/experiment2'
D.mkdir(parents=True,exist_ok=True)
top=['REPORT.txt','binary-manifest.json','validation.json','build.py','validate.py','package.py','ctf.original.cpp','ctf.sealed.cpp','ctf.sealed.cpp.seal.json','ctf.protected.bin']
evidence=['build/protect.log','build/frontend.log','build/seal.log','build/gate-tests.log','build/functions.txt','build/work/native_call_gate.json','build/work/module_plan.json','build/work/profile.json','build/work/transformed.ll']
files=[R/x for x in top+evidence]
files += [p for p in (R/'sdk').rglob('*') if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts and p.suffix!='.pyc']
with zipfile.ZipFile(D/'experiment2-full.zip','w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for p in files:z.write(p,'experiment2/'+p.relative_to(R).as_posix())
for name in top:shutil.copy2(R/name,D/name)
for name in ['pipeline/seal_compare.py','pipeline/guard_file_seal.c']:
    dest=D/'sdk-overlay'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(R/'sdk'/name,dest)
with zipfile.ZipFile(R/'experiment2-report.zip','w',zipfile.ZIP_DEFLATED) as z:
    for name in ['REPORT.txt','binary-manifest.json','validation.json','build.py','validate.py']:z.write(R/name,name)
manifest={p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [D/'experiment2-full.zip',D/'ctf.protected.bin']}
(D/'delivery-manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps(manifest,indent=2))
