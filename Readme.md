## Goals

In decreasing order of priority.

* Safer than direct system calls.
* Pure Rust code, no C dependency.
* Minimal dependencies for OS interaction.
* Efficient.

## Implementation

Note that the implementation will _not_ link directly against any `libc`
functions. Rather, it defines an expected interface in terms of free C
functions (`sys::SysVTable`). The caller can fill it with functions loaded
statically or dynamically from a linker but also with another equivalent
implementation. Unfortunately, the data type definitions will have to be
compatible with the platform `libc` in both cases, but it is a start to avoid
the hell of `LD_PRELOAD` as a stupid, global mechanism for overwriting them.

## Motivation

Depending on `libbpf` is quite heavy when only a fraction of it is needed.
Also, the library is riddled with C-isms:

* unknown or suboptimal thread-safety
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

  They are fucking with me, no?
