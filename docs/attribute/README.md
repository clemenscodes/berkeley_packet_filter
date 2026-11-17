# The attribute

The attribute is the single argument the kernel reads for every command of `bpf`. It is a zeroed
buffer of 128 bytes, little endian, and the call passes the whole size of it. Every command writes
its own fields at the offsets the kernel reads, and the fields a command leaves out stay zero.

These are the offsets, proven byte for byte by the tests of the module.

| Command | Fields at their offsets |
|---|---|
| map creation | map type one for a hash at 0, key size at 4, value size at 8, entry limit at 12 |
| map update | map descriptor at 0, address of the key at 8, address of the value at 16, flags zero at 24 |
| map deletion | map descriptor at 0, address of the key at 8 |
| program load | program type fifteen at 0, count of instructions at 4, address of the instructions at 8, address of the license at 16, log level one at 24, log size at 28, address of the log at 32, expected attach type six at 68 |
| object pin | address of the path at 0, descriptor at 8 |
| object lookup | address of the path at 0 |
| program attachment | target descriptor at 0, program descriptor at 4, attach type six at 8, flags at 12 |
| program detachment | the same as the attachment, with the flags zero |

A caller never composes an attribute itself. Every function of the crate composes the attribute of
its command, points its addresses at the buffers the caller handed in, and passes it to the call.
