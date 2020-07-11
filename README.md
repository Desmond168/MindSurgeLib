# MindSurge (MS) by nagisa 
Abusing [Control Flow Guard](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard) APIs to write arbitrary data to a remote process. 

## Table of Contents
* [Overview](#overview)
* [MS1 Limitations](#limitations)
* [SetProcessValidCallTargets Limitations](#api)
* [MS1 Forensic Footprint](#sysfootprint) <br>
* [MS1 RemoteLoadDll Quick Guide](#quickguide) <br>
* [MS1 Step by step](#steps) <br>
* [To do list](#todolist) <br>
* [Useful links](#links) <br>

<a name="overview" />

## Overview

MindSurge V1.0 (MS1) is a mixture of a standard process injection technique using CreateRemoteThread to execute LoadLibraryA in a target process to load an implant DLL from disk. Popular with PSPs, WriteProcessMemory API is not used, instead MS1 turns to Control Flow Guard (CFG) SetProcessValidCallTargets API to write the name of the DLL module in the CFG bitmap.

MS1 operation is described step by step in this write-up.

<a name="limitations" />

## Limitations

- Works only on "CFG-aware" systems: Windows 8.1 and Windows 10 (Desktop and Server).
- Works only on processes with CFG mitigation policy enabled.

__MS1 Limitations__:
- 64-bit process are not supported.
- The DLL module must exist on disk, and must be reachable by LoadLibraryA (e.g. exist in the same directory as the current directory of the target process).


<a name="api" />

## SetProcessValidCallTargets Limitations

MSDN: [SetProcessValidCallTargets](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessvalidcalltargets) and [CFG_CALL_TARGET_INFO](https://docs.microsoft.com/en-us/windows/win32/memory/-cfg-call-target-info)

<br>

> **SetProcessValidCallTargets function**<br><br>Provides Control Flow Guard (CFG) with a list of valid indirect call targets and specifies whether they should be marked valid or not. The valid call target information is provided as a list of offsets relative to a virtual memory range (start and size of the range). The call targets specified should be 16-byte aligned and in ascending order.

<br>

```
typedef struct _CFG_CALL_TARGET_INFO {
  ULONG_PTR Offset;
  ULONG_PTR Flags;
} CFG_CALL_TARGET_INFO, *PCFG_CALL_TARGET_INFO;

BOOL SetProcessValidCallTargets(
  HANDLE                hProcess,
  PVOID                 VirtualAddress,
  SIZE_T                RegionSize,
  ULONG                 NumberOfOffsets,
  PCFG_CALL_TARGET_INFO OffsetInformation
);
```

<br>

__NOTE__: Supported Flags are CFG_CALL_TARGET_VALID (set state to {0, 1}) or "CFG_CALL_TARGET_INVALID" (set state to {0, 0}), for more information about CFG_CALL_TARGET_x flags check _winnt.h_ header file.

VirtualAllocEx allows to set the states for the allocated memory region by default to {1, 1} for executable pages (PAGE_EXECUTABLE), or all to invalid, but it's not advisable since {1, 1} is unattainable for now. Therefore the only value that cannot be directly attained is {1, 0}.

The conversion from ASCII character to bitmap state limits the number of characters available, for example, ASCII (lowercase/uppercase) letters from the alphabet to have a file name are constrained to:

Letter | Binary
-------|-------
p	| 01110000
q | 01110001
s	| 01110011
t | 01110100
u | 01110101
w | 01110111
P	| 01010000
Q | 01010001
S | 01010011
T | 01010100
U | 01010101
W | 01010111


The character "." (00101110) is unusable for file extensions. Conveniently the description of [LoadLibraryA from MSDN](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) states:

> lpLibFileName <br>...<br>If the string specifies a module name without a path and the file name extension is omitted, the function appends the default library extension .dll to the module name. To prevent the function from appending .dll to the module name, include a trailing point character (.) in the module name string.

MS1 expects a DLL file name without extension.  MS1 **conversion algorithm fails and returns an error if a {1, 0} is found while parsing the bits of the string.**


<a name="sysfootprint" />

## MS1 Forensic Footprint

* A DLL implant module **must exist on disk** to be loaded by MS primary technique. MS1 **DOES NOT** delete the DLL after use.
    * Suggested action: delete DLL implant module.
* An allocated memory region to which MS1 does not write any data is created in the target process.
    * Use MS1 cleanup function RemoteCleanup() after the DLL is loaded.
* On a successful write operation, the name of the DLL will continue to exist on the bitmap until the allocated memory is freed.
    * Use MS1 cleanup function RemoteCleanup() after the DLL is loaded.

<a name="quickguide" />

---

## MS1 CRemoteLoadDll Quick Guide

See [MindSurgeDemo](https://github.com/ionagisa/MindSurgeDemo).

---

<a name="steps" />

## MS1 Step by step

**1.** [Verification of the target process CFG mitigation policy with GetProcessMitigationPolicy API](https://github.com/ionagisa/MindSurgeLib/blob/44a1b9fb8e1688b30e78e0eaed064544044b7853/src/ICRemoteLoadDll.cpp#L195) <br>
**2.** [Get the CFG bitmap base address](https://github.com/ionagisa/MindSurgeLib/blob/44a1b9fb8e1688b30e78e0eaed064544044b7853/src/ICRemoteLoadDll.cpp#L229) <br>
**3.** ["Parallel" memory allocation in the target process.](https://github.com/ionagisa/MindSurgeLib/blob/44a1b9fb8e1688b30e78e0eaed064544044b7853/src/ICRemoteLoadDll.cpp#L264) <br>
Conforming to the [limitations described](https://github.com/ionagisa/MindSurge/blob/master/README.md#api), MS1 allocates a memory region to - in parallel - allocate enough states in the bitmap. <br>
**4.** [DLL name to CFG bitmap states conversion](https://github.com/ionagisa/MindSurgeLib/blob/44a1b9fb8e1688b30e78e0eaed064544044b7853/src/ICRemoteLoadDll.cpp#L367) Conforming to the [limitations described](https://github.com/ionagisa/MindSurge/blob/master/README.md#api) <br>
**5.** [Write DLL name in the bitmap](https://github.com/ionagisa/MindSurgeLib/blob/44a1b9fb8e1688b30e78e0eaed064544044b7853/src/ICRemoteLoadDll.cpp#L424) <br>
**6.** [CreateRemoteThread on LoadLibrary](https://github.com/ionagisa/MindSurgeLib/blob/44a1b9fb8e1688b30e78e0eaed064544044b7853/src/ICRemoteLoadDll.cpp#L160) <br>

---
<a name="todolist" />

## TODO
* Handle 64-bit targets.
* Document source code.

---

<a name="links" />

## Useful links

[Control Flow Guard](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard) by MSDN.<br>
[Windows Process Injection in 2019](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf) by Amit Klein, Itzik Kotler (Safebreach Labs)<br>
[Control Flow Guard Teleportation](https://github.com/86hh/PagedOut2/blob/master/CFGTeleport.pdf) by hh86<br>
[Exploring Control Flow Guard in Windows 10](https://documents.trendmicro.com/assets/wp/exploring-control-flow-guard-in-windows10.pdf) by Jack Tang (Trend Micro Threat Solution Team)<br>
[Bypass-Control-Flow-Guard-Comprehensively](https://www.blackhat.com/docs/us-15/materials/us-15-Zhang-Bypass-Control-Flow-Guard-Comprehensively-wp.pdf) by Zhang Yunhai<br>
