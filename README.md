## Highcall-Library

Designed to avoid generic methods used in windows, avoiding common detection routines, while being a helpful library to work with in general. Residing in usermode, it communicates with the kernel through system calls, without leaving a trace.

Supported systems are Windows 7, Windows 8, Windows 8.1, Windows 10.

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
