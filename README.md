## Highcall-Library

Designed for avoiding detection from behavior analytics, sandboxes, anti-cheats, anti-viruses used in windows, avoiding common detection routines. 

Supported systems are Windows 7, Windows 8, Windows 8.1, Windows 10. Highcall is capable of running both in native x86/64 and as x86_64 in a wow64 process. Some procedures, in a wow64 environment while highcall is used, are going to use a gate to call the x86_64 version of a system call, instead of the windows wow64's version of it. This avoids the old trick of hooking the callgate procedure.

* External/Internal Process 
  * List, find and open processes.
  * Enumerate Ldr/No PE/No Ldr modules.
  * Manipulate virtual memory
  * Kill/Suspend/Resume any process
  * Configure access tokens
  * Static module reading
  * Code pattern searching
* Internal Process
  * Locate export addresses without LdrGetProcedureAddress
  * Relocate/Restore functions
  * Hook functions with relocation fixes
  * Handy safe reading functions
  * String helpers (such as ignore case comparison, validation, tokenizing)
  * Error setting (compatible with WINAPI) includes notes
* New features
  * injecting from 32 bit to 64, 32 to 32, 64 to 32 and 64 to 64.
  * debugger detection
  * memory scanning detection (cheat engine, etc.)
  * many ports to be able to do 32 to 64 and 64 to 32 things.
