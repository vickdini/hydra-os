# Untestable code (Group 26: Linux file layer)

Every file of the brief is compiled into this crate and tested; all are above 70 %
(see the final report). What is left uncovered on purpose:

| File | Function | Lines | Why |
|---|---|---|---|
| `src/compat/linux/efivars.rs` | `impl VarServices for Runtime` (`get`, `set`, `next`) | 71-81 | The UEFI runtime services themselves (`GetVariable`, `SetVariable`, `GetNextVariableName`): they call into the firmware through the system table, which a host process has none of. The logic around them (buffer growth, name retries, status to errno, files, unlink) runs against `fake::firmware`. |

The few other uncovered lines in each file are defensive branches (a lock poisoned by a
concurrent change, a FUSE reply racing an abort, a 64-step walk limit) that need two
threads interleaving at one exact point; they are not listed as hardware-only.
