# ANASI CTF experiment

Status: round 1 binary analysis in progress; no SDK hardening changes yet.

Original SDK archive: anasi-nn-main.zip, supplied by the owner. Baseline built without editing SDK code. Full-function composition failed: 11,987 action classes exceed the SDK's hard-coded 4,096 limit. The user approved selecting the password verifier and output comparator instead; the remaining transformation code is native.

Baseline: Linux x86-64 PIE, stripped; 3,173,633 bytes; SHA-256 `62dc5a207e66955599fab6126ec29523da38db14bed02940f7cbd4495eb90a5d`. SDK self-tests passed. Wrong-input execution returns `Access denied.` Positive-case equivalence has not yet been verified.

The isolated Desktop/test directory contains only the baseline binary. Analysis outputs live outside that directory. The analyst had seen the first 45 source lines, including a CTF-input comment, during an earlier file-access check. This is not a blind experiment. Any recovered input must be supported by binary evidence and an acceptance test.

Deliverables pending: binary-derived recovery, reconstructed C, evidence-driven SDK changes, functional differential tests, hardened binary, final report. No claim of key recovery or security improvement is made at this stage.
