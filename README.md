# berkeley_packet_filter

berkeley_packet_filter is a small library that makes the `bpf` system call itself, with no libbpf
and no compiler, and exposes a safe and sound API over it. It knows the commands of `bpf`, the
layouts of their attributes and nothing else. It holds no product logic, no locks, no cgroups and no
GPUs, so any program that needs the raw calls of `bpf` reads and writes maps, loads a device program
and attaches it through this one crate.

`unsafe` stands in exactly one private function, the system call itself. The crate sets
`unsafe_code = "deny"` and allows the lint on that one function alone, so no second `unsafe` slips in.
Its only dependency is `libc`, for `libc::syscall` and `libc::SYS_bpf`.

## The API

Every function composes its attribute itself and points it at the buffers it receives, so a caller
never handles a raw pointer and every buffer lives for the whole call. A descriptor the kernel
answers comes back as `std::os::fd::OwnedFd`, which closes it when it is dropped, and every failure
comes back as `std::io::Error` from `io::Error::last_os_error`, so a caller reads the errno.

```rust
pub fn create_hash_map(key_size: u32, value_size: u32, entry_limit: u32) -> io::Result<OwnedFd>;
pub fn update_element(map: BorrowedFd<'_>, key: &[u8], value: &[u8]) -> io::Result<()>;
pub fn delete_element(map: BorrowedFd<'_>, key: &[u8]) -> io::Result<()>;
pub fn load_device_program(instructions: &[u8], license: &CStr) -> io::Result<OwnedFd>;
pub fn pin_object(object: BorrowedFd<'_>, path: &Path) -> io::Result<()>;
pub fn open_object(path: &Path) -> io::Result<OwnedFd>;
pub fn attach_device_program(cgroup: BorrowedFd<'_>, program: BorrowedFd<'_>, multiple: bool) -> io::Result<()>;
pub fn detach_device_program(cgroup: BorrowedFd<'_>, program: BorrowedFd<'_>) -> io::Result<()>;
```

`update_element` and `delete_element` read the key and the value from slices, and the kernel reads
exactly the sizes the map was created with, so a caller passes slices of the sizes of the map.
`load_device_program` loads a program of the type `BPF_PROG_TYPE_CGROUP_DEVICE` with the expected
attach type `BPF_CGROUP_DEVICE`, refuses a length of the instructions that is no multiple of eight
with `InvalidInput`, and where the load fails it appends the text of the verifier log to the error.
`pin_object` and `open_object` refuse a path that holds a zero byte with `InvalidInput`.
`attach_device_program` passes the flag of multi where `multiple` is true, and `detach_device_program`
always passes the flags zero, because the kernel refuses a detach with the flags of multi.

## How it is built and tested

The crate builds and tests through its flake with crane.

```
nix build .#berkeleyPacketFilter
nix develop -c cargo nextest run
```

The tests run without root and never touch a real cgroup. They prove the layouts of the attributes
byte for byte, the refusals of `InvalidInput`, and that an unprivileged creation of a map and a load
of an empty program answer an error of the kernel instead of a panic.

## The chapters of the book

- The attribute, the zeroed buffer of 128 bytes every command reads.
- The command, the number of every command of `bpf`.
- The call, the one system call and the descriptor it answers.
