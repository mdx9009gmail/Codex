# Native-call gate: evidence, usage and limits

The first experiment recovered the CTF input by loading the protected ELF into another process and directly calling its unprotected native transformation helpers. The neural verifier and output comparator were protected, but their native callees were reusable independently.

This optional SDK extension follows direct calls from nominated entry functions and adds a thread-local execution-context check to their module-defined descendants. Entry functions establish a depth and a fixed context marker; ordinary returns restore the depth and clear the marker at depth zero. Descendants trap unless both fields are valid. The marker prevents accidentally accepting unrelated TLS data when the ELF is manually mapped into a foreign process. It is public and is not a cryptographic secret.

## Apply the repository overlay

Copy `sdk-overlay/pipeline/protect.py`, `sdk-overlay/pipeline/native_call_gate.py`, and `sdk-overlay/tests/test_native_call_gate.py` over the corresponding paths in the original SDK. All other SDK files, including weights and `pipeline/guards_ir.py`, remain required and unchanged. The preceding Git commit records the original protect.py for review.

Add `--native-call-gate verify_password` to the original successful protection command. The example used `--native --dist /usr --functions @functions.txt --cflag=-xc++ --cflag=-std=c++17`, with `functions.txt` selecting `verify_password` and the compiler-mangled output comparator. Keep the existing guard settings. `work/native_call_gate.json` records actual coverage. Run `python3 tests/test_native_call_gate.py` on Linux with Clang.

## Validation on this sample

* 95 input cases compared native, original protected and hardened programs: no return-code/stdout/stderr mismatches (executable names in usage text normalized).
* Cases include the recovered valid input, all 24 single-position mutations, 64 deterministic random inputs, length boundaries and argument errors.
* Optimized native gate tests cover recursive roots, concurrent threads, direct entry after a legitimate return, duplicate application, missing roots and unsupported indirect calls.
* A relocated direct-call probe of the same avalanche helper returns `803275274` in the baseline (offset 0x1b40), and terminates with SIGILL in the hardened binary (new offset 0x1b80). Addresses were updated, so this is not an offset-only failure.
* Hardened ELF SHA-256: `559a6caf4559867627bc2d3fe97085873483995b83dce126f823aa1b01102d3a`.

## Security and compatibility limits

This blocks the demonstrated unmodified direct-entry path. It does not make native algorithms secret, encrypt constants, prevent static reconstruction, or prove the entire recovery strategy impossible. An adversary controlling the process can patch the check, set its TLS state, or emulate the expected context. Replaying the entire inverse after adapting to these countermeasures is not claimed here. The original secret remains valid because functional behavior is preserved.

Use ordinary synchronous call/return code. Indirect calls, invoke/callbr/musttail and named setjmp/longjmp in the covered graph are rejected. External libraries can still hide nonlocal exits; inspect such paths before enabling the option. Exceptions, cancellation, asynchronous signal-handler reentry and fibers are not supported. Roots are explicitly callable trust boundaries; reentering them establishes a valid context. This prototype gate should not be treated as an authorization boundary.

The original all-function neural plan exceeded 4,096 action classes (11,987 requested); this extension does not remove that capacity limit. The experiment had prior source-comment exposure and is not a blind benchmark. Full compilable C reconstruction remains outside the completed hardening deliverable.

