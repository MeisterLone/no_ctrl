# no_ctrl v0.1

# WIP - not useful right now!

A kernel exploit for PS5 firmware <=10.40 via stack use-after-free in the fsc2h_ctrl syscall.

## Overview

This PoC demonstrates a race condition in `fsc2h_ctrl` where Thread 3's stack can be freed while suspended during `CMD_RESOLVE`, allowing memory corruption when the thread resumes.

## Technique

1. **Thread 1** occupies slot 0 with `CMD_WAIT`
2. **Thread 3** calls `CMD_RESOLVE`, storing its stack pointer
3. **Thread 3** gets suspended via `thr_suspend_ucontext` 
4. **Thread 2** frees the stack with second `CMD_WAIT`
5. **Main thread** sprays allocations to reclaim freed stack
6. **Thread 3** resumes ..> uses corrupted stack ..> crash/control

## Status

- [x] 4-thread race condition implemented
- [x] Stack UAF achieved
- [x] RIP control at predictable offset
- [ ] Full ROP chain for privilege escalation

## eta when?
This is a PoC demonstrator, I dont want to get sued.

# Notes
This is a payload for v1.2 [Y2JB](https://github.com/Gezine/Y2JB)
It will just crash in its current state, nothing useful. However at this point it does demonstrate UAF and RIP control around ~20% of runs.

A successful run of this currently ends with this output, followed by a crash. Unsuccessfuly runs crash during the timing ROP or spray region.
```
[7] resume t3
    resume: 0x0000000000000000
    waiting for t3 to return...``
```



## Credits
  *   Original CVE by [theflow0](https://hackerone.com/reports/2900606)
  *   Lots of inspiration from Lapse
  *   Y2JB Stage 0 by [Gezine](https://github.com/Gezine/Y2JB)
  *   [zecoxao](https://github.com/zecoxao)

## Disclaimer
Educational & research only. 
