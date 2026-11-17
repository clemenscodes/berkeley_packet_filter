# The command

The command is the number the kernel reads as the first argument of the `bpf` system call. It names
which operation the call performs, and the attribute carries the fields of that operation.

| Command | Number |
|---|---|
| map creation | 0 |
| map update | 2 |
| map deletion | 3 |
| program load | 5 |
| object pin | 6 |
| object lookup | 7 |
| program attachment | 8 |
| program detachment | 9 |

The command is internal to the crate. A caller names an operation by the function it calls, and the
function picks the command the kernel reads.
