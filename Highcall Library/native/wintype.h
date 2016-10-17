/*
	Use this file to #include only common Windows types (HWND, HDC, etc) without functions. This is great for use in a header file
	where all you need are the common types. It also means you can avoid those annoying Win32 macros like CopyFile().
	Ideally you would just #include windef.h, but it will have compilation errors without the _X86_ and _AMD64_ #defines. Thus, we
	also add them here.
*/

#ifndef __windows_types_h_
#define __windows_types_h_

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_) && defined(_M_IX86)
#define _X86_
#endif

#if !defined(_68K_) && !defined(_MPPC_) && !defined(_X86_) && !defined(_IA64_) && !defined(_AMD64_) && defined(_M_AMD64)
#define _AMD64_
#endif

#include <windef.h>

#endif