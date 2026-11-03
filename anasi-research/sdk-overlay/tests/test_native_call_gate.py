"""Executable gate tests: optimized IR, recursion, threads and direct entry."""
import ctypes, pathlib, subprocess, sys, tempfile, unittest
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'pipeline'))
from native_call_gate import apply

class GateTests(unittest.TestCase):
    def test_runtime(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            (p/'x.c').write_text('int leaf(int x){return x*3+1;} int root(int x){return x>0?leaf(x)+root(x-1):leaf(0);}')
            subprocess.run(['clang','-O1','-fPIC','-fno-inline','-S','-emit-llvm',str(p/'x.c'),'-o',str(p/'x.ll')],check=True)
            text,report=apply((p/'x.ll').read_text(),['root'])
            self.assertEqual(report['native_descendants'],['leaf'])
            (p/'gate.ll').write_text(text)
            subprocess.run(['clang','-O3','-shared','-fPIC',str(p/'gate.ll'),'-o',str(p/'gate.so')],check=True)
            lib=ctypes.CDLL(str(p/'gate.so'))
            with ThreadPoolExecutor(4) as pool:
                got=list(pool.map(lib.root,range(40)))
            self.assertEqual(got,[(n+1)+3*n*(n+1)//2 for n in range(40)])
            # A legitimate return must clear this thread's context.
            code='import ctypes; l=ctypes.CDLL('+repr(str(p/'gate.so'))+'); l.root(3); l.leaf(1)'
            result=subprocess.run([sys.executable,'-c',code],capture_output=True)
            self.assertEqual(result.returncode,-4)
            with self.assertRaises(ValueError): apply(text,['root'])
            with self.assertRaises(ValueError): apply((p/'x.ll').read_text(),['missing'])
    def test_indirect_rejected(self):
        ir='define i32 @root(ptr %f) {\nentry:\n %r = call i32 %f()\n ret i32 %r\n}\n'
        with self.assertRaises(ValueError): apply(ir,['root'])

if __name__=='__main__': unittest.main()


