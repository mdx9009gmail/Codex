"""Opt-in call-context gate for native descendants of a protected entry.

This is a direct-call barrier, not cryptographic secrecy or anti-patching.
Only ordinary, direct-call LLVM IR is supported. Exception/nonlocal exits
are unsupported; roots must not escape through longjmp or thread exit.
"""
import re
from guards_ir import parse_module_functions, call_graph

def apply(text, roots):
    if '__sdk_ncg_' in text:
        raise ValueError('native-call-gate: reserved symbol already present')
    funcs = parse_module_functions(text)
    byname = {f[0]: f for f in funcs}
    if not roots or set(roots) - byname.keys():
        raise ValueError('native-call-gate: roots must name defined functions')
    reached, pending = set(), list(roots)
    while pending:
        name = pending.pop()
        if name in reached: continue
        reached.add(name)
        pending.extend(call_graph(funcs, name) & byname.keys() - reached)
    for name in reached:
        _, start, end, lines = byname[name]
        body = '\n'.join(lines[start:end])
        if re.search(r'\b(invoke|callbr|musttail|setjmp|longjmp)\b', body):
            raise ValueError('native-call-gate: unsupported nonlocal control flow: '+name)
        if re.search(r'\bcall\b[^\n@]*%[\w.]+\s*\(', body):
            raise ValueError('native-call-gate: indirect call requires explicit audit: '+name)
    attrs = {int(k):v for k,v in re.findall(r'^attributes #(\d+) = \{(.*)\}', text, re.M)}
    next_attr = max(attrs, default=-1) + 1
    new_attrs = []
    lines = text.split('\n')
    for name, start, end, _ in reversed(funcs):
        if name not in reached: continue
        # Remove inferred pure-function attributes invalidated by the gate.
        group = re.search(r'#(\d+)', lines[start])
        if group:
            value = attrs[int(group[1])]
            value = re.sub(r'\bmemory\([^)]*\)|\b(readnone|readonly|writeonly|speculatable|nosync)\b', '', value)
            lines[start] = lines[start].replace(group[0], '#'+str(next_attr))
            new_attrs.append('attributes #'+str(next_attr)+' = {'+value+'}')
            next_attr += 1
        for i in range(end-1, start, -1):
            if name in roots and re.match(r'\s*ret\b', lines[i]):
                lines.insert(i, '  call void @__sdk_ncg_leave()')
        pos = start + 1
        while pos < len(lines) and (not lines[pos].strip() or lines[pos].lstrip().startswith(';')): pos += 1
        if re.match(r'^[\w.$-]+:', lines[pos]): pos += 1
        lines.insert(pos, '  call void @__sdk_ncg_'+('enter' if name in roots else 'check')+'()')
    helpers = '''
@__sdk_ncg_depth = internal thread_local global i64 0, align 8
@__sdk_ncg_cookie = internal thread_local global i64 0, align 8
define internal void @__sdk_ncg_enter() noinline {
entry:
  %d = load volatile i64, ptr @__sdk_ncg_depth
  %n = add i64 %d, 1
  store volatile i64 %n, ptr @__sdk_ncg_depth
  store volatile i64 5398780445451579969, ptr @__sdk_ncg_cookie
  ret void
}
define internal void @__sdk_ncg_leave() noinline {
entry:
  %d = load volatile i64, ptr @__sdk_ncg_depth
  %n = sub i64 %d, 1
  store volatile i64 %n, ptr @__sdk_ncg_depth
  %active = icmp ne i64 %n, 0
  %cookie = select i1 %active, i64 5398780445451579969, i64 0
  store volatile i64 %cookie, ptr @__sdk_ncg_cookie
  ret void
}
define internal void @__sdk_ncg_check() noinline {
entry:
  %d = load volatile i64, ptr @__sdk_ncg_depth
  %depth_ok = icmp ne i64 %d, 0
  %cookie = load volatile i64, ptr @__sdk_ncg_cookie
  %cookie_ok = icmp eq i64 %cookie, 5398780445451579969
  %ok = and i1 %depth_ok, %cookie_ok
  br i1 %ok, label %pass, label %fail
fail:
  call void @llvm.trap()
  unreachable
pass:
  ret void
}
'''
    if not re.search(r'declare void @llvm.trap\(', text): helpers += '\ndeclare void @llvm.trap()\n'
    return '\n'.join(lines)+helpers+'\n'+'\n'.join(new_attrs)+'\n', {'roots':sorted(roots),'covered':sorted(reached),'native_descendants':sorted(reached-set(roots)), 'limitations':['No protection against patching or emulating the gate','No longjmp/exception/nonlocal exits','Indirect calls rejected in covered graph']}

