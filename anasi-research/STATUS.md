# ANASI hardening delivery

Evidence-driven native-call context gate implemented and validated. See [report and usage](README.md), [SDK overlay](sdk-overlay/), and [validation](results/validation.json).

95 three-way differential cases passed. An updated-address direct helper call succeeds in the baseline and traps in the hardened binary. This is a narrow barrier, not resistance to patching, state forgery or complete static reconstruction. Full compilable C reconstruction is not completed. The original experiment was not blind because an earlier source-access check exposed a CTF input comment.
