# The call

The call is the one system call of the crate. It takes a command and the bytes of an attribute,
invokes `bpf` through `libc::syscall` and `libc::SYS_bpf`, and answers the descriptor the kernel
returns. This is the single function that holds `unsafe`, for the system call and for the adoption of
the descriptor into an `OwnedFd`, and the crate denies `unsafe_code` everywhere else.

A nonnegative answer of the kernel is a descriptor, and the call adopts it into an `OwnedFd` that
closes it when it is dropped. A negative answer is a failure, and the call reads the errno through
`io::Error::last_os_error`.

Not every command answers a descriptor. A map creation, a program load and an object lookup answer a
new descriptor, which the caller owns. A map update, a map deletion, an object pin, a program
attachment and a program detachment answer zero, the acknowledgement of the kernel. The call adopts
that zero like any answer and the outcome releases it with `mem::forget`, so the descriptor zero,
which the crate never owns, is never closed.
