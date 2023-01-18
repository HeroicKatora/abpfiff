A library to interact with BPF kernel state.

Just simple, pure idiomatic Rust-based bindings to manage user-space state
necessary for interacting with the kernel system. Some little helpers are added
but not beyond the minimalism (avoids generics or extra dependencies).

The name is bacronym for:

> A BPF InterFace Foundation

## Goals

In decreasing order of priority.

* Safer than direct system calls
* Pure Rust code, no C dependency
* Minimal dependencies for OS interaction
* Efficient

Non-Goals:
* Replacement for `libbpf`
* A C interface, to be re-evaluated later
* An `async` style of implementation. It should be possible to achieve all
  functionality with synchronous code. However, optional concurrency may be
  introduced with `async` where efficient.
* Binary analysis and manipulation of BPF programs

## Implementation

Note that the implementation does _not_ need link directly against any `libc`
functions. Rather, it defines an expected interface in terms of free C
functions (`sys::SysVTable`). The caller can fill it with functions loaded
statically or dynamically from a linker but also with another equivalent
implementation. Unfortunately, the data type definitions will have to be
compatible with the platform `libc` in both cases, but it is a start to avoid
the hell of `LD_PRELOAD` as a stupid, global mechanism for overwriting them.

## Motivation

Depending on `libbpf` is quite heavy when only a fraction of it is needed. In
particular, connecting together networking functionality does not depend on
writing BPF. Also, the library is riddled with C-isms:

* unknown or highly implicit thread-safety
* synchronous resources opened and closed in rapid succession just to hide that
  resource management complexity from the caller. No really, a new netlink
  socket is created, configured, loop polled and closed for literally each
  `libbpf_netlink_send_recv` that's hidden in _a lot_ of operations.
* Code that looks like so:

  ```c
  static int libbpf_netlink_send_recv(...) {
      /* ... */
      req->nh.nlmsg_seq = time(NULL);
  ```

  They are fucking with us, no?
