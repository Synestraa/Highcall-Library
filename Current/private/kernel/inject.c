#include <highcall.h>
#include "../sys/syscall.h"
#include "../distorm/include/distorm.h"

typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOLEAN(WINAPI *PDLL_MAIN)(HMODULE, SIZE_T, LPVOID);
typedef NTSTATUS(NTAPI *pLdrLoadDll) (PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef VOID(NTAPI *pHcInitUnicodeString) (PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI *pLdrGetProcedureAddress) (HMODULE, PANSI_STRING, ULONG, LPVOID*);
typedef VOID(NTAPI *pRtlInitAnsiString) (PANSI_STRING, LPCSTR);

typedef struct {
	ULONG ImageBase;
	ULONG NtHeaders;
	ULONG BaseRelocation;
	ULONG ImportDirectory;
	ULONG fnLoadLibraryA;
	ULONG fnGetProcAddress;
} MANUAL_MAP, *PMANUAL_MAP;

typedef struct {
	LPVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLdrLoadDll fnLdrLoadDll;
	pHcInitUnicodeString fnHcInitUnicodeString;
	pLdrGetProcedureAddress fnLdrGetProcedureAddress;
	pRtlInitAnsiString fnRtlInitAnsiString;
	pGetProcAddress fnGetProcAddress;
	pLoadLibraryA fnLoadLibraryA;
} MMAP_INITIALIZER32, *PMMAP_INITIALIZER32;

BYTE apc_stub_x86[] = "\xFC\x8B\x74\x24\x04\x55\x89\xE5\xE8\x89\x00\x00\x00\x60\x89\xE5"
						"\x31\xD2\x64\x8B\x52\x30\x8B\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F"
						"\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF"
						"\x0D\x01\xC7\xE2\xF0\x52\x57\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B"
						"\x40\x78\x85\xC0\x74\x4A\x01\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01"
						"\xD3\xE3\x3C\x49\x8B\x34\x8B\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF"
						"\x0D\x01\xC7\x38\xE0\x75\xF4\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58"
						"\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04"
						"\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58"
						"\x5F\x5A\x8B\x12\xEB\x86\x5B\x80\x7E\x10\x00\x75\x3B\xC6\x46\x10"
						"\x01\x68\xA6\x95\xBD\x9D\xFF\xD3\x3C\x06\x7C\x1A\x31\xC9\x64\x8B"
						"\x41\x18\x39\x88\xA8\x01\x00\x00\x75\x0C\x8D\x93\xCF\x00\x00\x00"
						"\x89\x90\xA8\x01\x00\x00\x31\xC9\x51\x51\xFF\x76\x08\xFF\x36\x51"
						"\x51\x68\x38\x68\x0D\x16\xFF\xD3\xC9\xC2\x0C\x00\x00\x00\x00\x00"
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
						"\x00\x00\x00\x00";

BYTE apc_stub_x64[] = "\xFC\x80\x79\x10\x00\x0F\x85\x13\x01\x00\x00\xC6\x41\x10\x01\x48"
						"\x83\xEC\x78\xE8\xC8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48"
						"\x31\xD2\x65\x48\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52\x20\x48"
						"\x8B\x72\x50\x48\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0\xAC\x3C"
						"\x61\x7C\x02\x2C\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED\x52\x41"
						"\x51\x48\x8B\x52\x20\x8B\x42\x3C\x48\x01\xD0\x66\x81\x78\x18\x0B"
						"\x02\x75\x72\x8B\x80\x88\x00\x00\x00\x48\x85\xC0\x74\x67\x48\x01"
						"\xD0\x50\x8B\x48\x18\x44\x8B\x40\x20\x49\x01\xD0\xE3\x56\x48\xFF"
						"\xC9\x41\x8B\x34\x88\x48\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41"
						"\xC1\xC9\x0D\x41\x01\xC1\x38\xE0\x75\xF1\x4C\x03\x4C\x24\x08\x45"
						"\x39\xD1\x75\xD8\x58\x44\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C"
						"\x48\x44\x8B\x40\x1C\x49\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x41"
						"\x58\x41\x58\x5E\x59\x5A\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20"
						"\x41\x52\xFF\xE0\x58\x41\x59\x5A\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF"
						"\x5D\x48\x31\xD2\x65\x48\x8B\x42\x30\x48\x39\x90\xC8\x02\x00\x00"
						"\x75\x0E\x48\x8D\x95\x07\x01\x00\x00\x48\x89\x90\xC8\x02\x00\x00"
						"\x4C\x8B\x01\x4C\x8B\x49\x08\x48\x31\xC9\x48\x31\xD2\x51\x51\x41"
						"\xBA\x38\x68\x0D\x16\xFF\xD5\x48\x81\xC4\xA8\x00\x00\x00\xC3\x00"
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
						"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
						"\x00\x00\x00";

CONST BYTE payload64[] =
{
	0x55,
	0x8B, 0xEC,
	0x83, 0xEC, 0x38,
	0x8B, 0x45, 0x08,
	0x89, 0x45, 0xFC,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x08,
	0x89, 0x55, 0xF8,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x04,
	0x8B, 0x55, 0xFC,
	0x8B, 0x02,
	0x2B, 0x41, 0x34,
	0x89, 0x45, 0xD0,
	0x8B, 0x4D, 0xF8,
	0x83, 0x39, 0x00,
	0x0F, 0x84, 0x87, 0x00, 0x00, 0x00,
	0x8B, 0x55, 0xF8,
	0x83, 0x7A, 0x04, 0x08,
	0x72, 0x6D,
	0x8B, 0x45, 0xF8,
	0x8B, 0x48, 0x04,
	0x83, 0xE9, 0x08,
	0xD1, 0xE9,
	0x89, 0x4D, 0xD4,
	0x8B, 0x55, 0xF8,
	0x83, 0xC2, 0x08,
	0x89, 0x55, 0xDC,
	0xC7, 0x45, 0xEC, 0x00, 0x00, 0x00, 0x00,
	0xEB, 0x09,
	0x8B, 0x45, 0xEC,
	0x83, 0xC0, 0x01,
	0x89, 0x45, 0xEC,
	0x8B, 0x4D, 0xEC,
	0x3B, 0x4D, 0xD4,
	0x73, 0x3C,
	0x8B, 0x55, 0xEC,
	0x8B, 0x45, 0xDC,
	0x0F, 0xB7, 0x0C, 0x50,
	0x85, 0xC9,
	0x74, 0x2C,
	0x8B, 0x55, 0xEC,
	0x8B, 0x45, 0xDC,
	0x0F, 0xB7, 0x0C, 0x50,
	0x81, 0xE1, 0xFF, 0x0F, 0x00, 0x00,
	0x8B, 0x55, 0xF8,
	0x8B, 0x02,
	0x03, 0xC1,
	0x8B, 0x4D, 0xFC,
	0x03, 0x01,
	0x89, 0x45, 0xD8,
	0x8B, 0x55, 0xD8,
	0x8B, 0x02,
	0x03, 0x45, 0xD0,
	0x8B, 0x4D, 0xD8,
	0x89, 0x01,
	0xEB, 0xB3,
	0x8B, 0x55, 0xF8,
	0x8B, 0x45, 0xF8,
	0x03, 0x42, 0x04,
	0x89, 0x45, 0xF8,
	0xE9, 0x6D, 0xFF, 0xFF, 0xFF,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x0C,
	0x89, 0x55, 0xF0,
	0x8B, 0x45, 0xF0,
	0x83, 0x38, 0x00,
	0x0F, 0x84, 0xE4, 0x00, 0x00, 0x00,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x10,
	0x89, 0x55, 0xF4,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x50, 0x10,
	0x89, 0x55, 0xE4,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x50, 0x0C,
	0x52,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x10,
	0xFF, 0xD2,
	0x89, 0x45, 0xE0,
	0x83, 0x7D, 0xE0, 0x00,
	0x75, 0x07,
	0x33, 0xC0,
	0xE9, 0xD9, 0x00, 0x00, 0x00,
	0x8B, 0x45, 0xF4,
	0x83, 0x38, 0x00,
	0x0F, 0x84, 0x8B, 0x00, 0x00, 0x00,
	0x8B, 0x4D, 0xF4,
	0x8B, 0x11,
	0x81, 0xE2, 0x00, 0x00, 0x00, 0x80,
	0x74, 0x32,
	0x8B, 0x45, 0xF4,
	0x8B, 0x08,
	0x81, 0xE1, 0xFF, 0xFF, 0x00, 0x00,
	0x51,
	0x8B, 0x55, 0xE0,
	0x52,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x14,
	0xFF, 0xD1,
	0x89, 0x45, 0xE8,
	0x83, 0x7D, 0xE8, 0x00,
	0x75, 0x07,
	0x33, 0xC0,
	0xE9, 0x98, 0x00, 0x00, 0x00,
	0x8B, 0x55, 0xE4,
	0x8B, 0x45, 0xE8,
	0x89, 0x02,
	0xEB, 0x35,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF4,
	0x03, 0x10,
	0x89, 0x55, 0xCC,
	0x8B, 0x4D, 0xCC,
	0x83, 0xC1, 0x02,
	0x51,
	0x8B, 0x55, 0xE0,
	0x52,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x14,
	0xFF, 0xD1,
	0x89, 0x45, 0xE8,
	0x83, 0x7D, 0xE8, 0x00,
	0x75, 0x04,
	0x33, 0xC0,
	0xEB, 0x61,
	0x8B, 0x55, 0xE4,
	0x8B, 0x45, 0xE8,
	0x89, 0x02,
	0x8B, 0x4D, 0xF4,
	0x83, 0xC1, 0x04,
	0x89, 0x4D, 0xF4,
	0x8B, 0x55, 0xE4,
	0x83, 0xC2, 0x04,
	0x89, 0x55, 0xE4,
	0xE9, 0x69, 0xFF, 0xFF, 0xFF,
	0x8B, 0x45, 0xF0,
	0x83, 0xC0, 0x14,
	0x89, 0x45, 0xF0,
	0xE9, 0x10, 0xFF, 0xFF, 0xFF,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x04,
	0x83, 0x7A, 0x28, 0x00,
	0x74, 0x23,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x04,
	0x8B, 0x55, 0xFC,
	0x8B, 0x02,
	0x03, 0x41, 0x28,
	0x89, 0x45, 0xC8,
	0x6A, 0x00,
	0x6A, 0x01,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x52,
	0xFF, 0x55, 0xC8,
	0x0F, 0xB6, 0xC0,
	0xEB, 0x05,
	0xB8, 0x01, 0x00, 0x00, 0x00,
	0x8B, 0xE5,
	0x5D,
	0xC2, 0x04, 0x00

};

CONST BYTE payload32[] = 
{
	0x55,
	0x8B, 0xEC,
	0x83, 0xEC, 0x38,
	0x8B, 0x45, 0x08,
	0x89, 0x45, 0xFC,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x08,
	0x89, 0x55, 0xF8,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x04,
	0x8B, 0x55, 0xFC,
	0x8B, 0x02,
	0x2B, 0x41, 0x34,
	0x89, 0x45, 0xD0,
	0x8B, 0x4D, 0xF8,
	0x83, 0x39, 0x00,
	0x0F, 0x84, 0x87, 0x00, 0x00, 0x00,
	0x8B, 0x55, 0xF8,
	0x83, 0x7A, 0x04, 0x08,
	0x72, 0x6D,
	0x8B, 0x45, 0xF8,
	0x8B, 0x48, 0x04,
	0x83, 0xE9, 0x08,
	0xD1, 0xE9,
	0x89, 0x4D, 0xD4,
	0x8B, 0x55, 0xF8,
	0x83, 0xC2, 0x08,
	0x89, 0x55, 0xDC,
	0xC7, 0x45, 0xEC, 0x00, 0x00, 0x00, 0x00,
	0xEB, 0x09,
	0x8B, 0x45, 0xEC,
	0x83, 0xC0, 0x01,
	0x89, 0x45, 0xEC,
	0x8B, 0x4D, 0xEC,
	0x3B, 0x4D, 0xD4,
	0x73, 0x3C,
	0x8B, 0x55, 0xEC,
	0x8B, 0x45, 0xDC,
	0x0F, 0xB7, 0x0C, 0x50,
	0x85, 0xC9,
	0x74, 0x2C,
	0x8B, 0x55, 0xEC,
	0x8B, 0x45, 0xDC,
	0x0F, 0xB7, 0x0C, 0x50,
	0x81, 0xE1, 0xFF, 0x0F, 0x00, 0x00,
	0x8B, 0x55, 0xF8,
	0x8B, 0x02,
	0x03, 0xC1,
	0x8B, 0x4D, 0xFC,
	0x03, 0x01,
	0x89, 0x45, 0xD8,
	0x8B, 0x55, 0xD8,
	0x8B, 0x02,
	0x03, 0x45, 0xD0,
	0x8B, 0x4D, 0xD8,
	0x89, 0x01,
	0xEB, 0xB3,
	0x8B, 0x55, 0xF8,
	0x8B, 0x45, 0xF8,
	0x03, 0x42, 0x04,
	0x89, 0x45, 0xF8,
	0xE9, 0x6D, 0xFF, 0xFF, 0xFF,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x0C,
	0x89, 0x55, 0xF0,
	0x8B, 0x45, 0xF0,
	0x83, 0x38, 0x00,
	0x0F, 0x84, 0xE4, 0x00, 0x00, 0x00,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x10,
	0x89, 0x55, 0xF4,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x50, 0x10,
	0x89, 0x55, 0xE4,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF0,
	0x03, 0x50, 0x0C,
	0x52,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x10,
	0xFF, 0xD2,
	0x89, 0x45, 0xE0,
	0x83, 0x7D, 0xE0, 0x00,
	0x75, 0x07,
	0x33, 0xC0,
	0xE9, 0xD9, 0x00, 0x00, 0x00,
	0x8B, 0x45, 0xF4,
	0x83, 0x38, 0x00,
	0x0F, 0x84, 0x8B, 0x00, 0x00, 0x00,
	0x8B, 0x4D, 0xF4,
	0x8B, 0x11,
	0x81, 0xE2, 0x00, 0x00, 0x00, 0x80,
	0x74, 0x32,
	0x8B, 0x45, 0xF4,
	0x8B, 0x08,
	0x81, 0xE1, 0xFF, 0xFF, 0x00, 0x00,
	0x51,
	0x8B, 0x55, 0xE0,
	0x52,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x14,
	0xFF, 0xD1,
	0x89, 0x45, 0xE8,
	0x83, 0x7D, 0xE8, 0x00,
	0x75, 0x07,
	0x33, 0xC0,
	0xE9, 0x98, 0x00, 0x00, 0x00,
	0x8B, 0x55, 0xE4,
	0x8B, 0x45, 0xE8,
	0x89, 0x02,
	0xEB, 0x35,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x8B, 0x45, 0xF4,
	0x03, 0x10,
	0x89, 0x55, 0xCC,
	0x8B, 0x4D, 0xCC,
	0x83, 0xC1, 0x02,
	0x51,
	0x8B, 0x55, 0xE0,
	0x52,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x14,
	0xFF, 0xD1,
	0x89, 0x45, 0xE8,
	0x83, 0x7D, 0xE8, 0x00,
	0x75, 0x04,
	0x33, 0xC0,
	0xEB, 0x61,
	0x8B, 0x55, 0xE4,
	0x8B, 0x45, 0xE8,
	0x89, 0x02,
	0x8B, 0x4D, 0xF4,
	0x83, 0xC1, 0x04,
	0x89, 0x4D, 0xF4,
	0x8B, 0x55, 0xE4,
	0x83, 0xC2, 0x04,
	0x89, 0x55, 0xE4,
	0xE9, 0x69, 0xFF, 0xFF, 0xFF,
	0x8B, 0x45, 0xF0,
	0x83, 0xC0, 0x14,
	0x89, 0x45, 0xF0,
	0xE9, 0x10, 0xFF, 0xFF, 0xFF,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x51, 0x04,
	0x83, 0x7A, 0x28, 0x00,
	0x74, 0x23,
	0x8B, 0x45, 0xFC,
	0x8B, 0x48, 0x04,
	0x8B, 0x55, 0xFC,
	0x8B, 0x02,
	0x03, 0x41, 0x28,
	0x89, 0x45, 0xC8,
	0x6A, 0x00,
	0x6A, 0x01,
	0x8B, 0x4D, 0xFC,
	0x8B, 0x11,
	0x52,
	0xFF, 0x55, 0xC8,
	0x0F, 0xB6, 0xC0,
	0xEB, 0x05,
	0xB8, 0x01, 0x00, 0x00, 0x00,
	0x8B, 0xE5,
	0x5D,
	0xC2, 0x04, 0x00
};

#pragma region Internal Manual Map Code

// turn off incremental linking -- should force this to *not* use a jump table
#pragma comment(linker, "/incremental:no")

// turn off optimizations
//#pragma optimize( "", off )

// turn off pesky runtime checks that add an extra call to _RTC_CheckEsp to the end of our function
#pragma runtime_checks( "", off)

// put both functions in the same section.  as long as there are only two, they should be in order
#pragma code_seg( ".text$A" )

static __inline size_t __mbstowcs(register wchar_t *pwcs, register const char *s, int n)
{
	register int i = n;

	while (--i >= 0)
	{
		if (!(*pwcs++ = *s++))
		{
			return n - i - 1;
		}
	}
	return n - i;
}

static __inline size_t __str_size(register const char *s)
{
	size_t ret = 0;
	for (; *(s++); ret++);

	return ret;
}

__declspec(noinline)
static
SIZE_T HCAPI MmInternalResolve(PMMAP_INITIALIZER32 Init)
{
	HMODULE hModule;
	ULONG_PTR Index, Function, Count, Delta;
	PULONG_PTR FunctionPointer;
	PDWORD ImportList;
	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;
	PIMAGE_NT_HEADERS32 NtHeaders;
	pRtlInitAnsiString fnRtlInitAnsiString;
	pHcInitUnicodeString fnHcInitUnicodeString;
	pLdrGetProcedureAddress fnLdrGetProcedureAddress;
	pLdrLoadDll fnLdrLoadDll;
	PDLL_MAIN EntryPoint;

	NtHeaders = (PIMAGE_NT_HEADERS32) Init->NtHeaders;
	pIBR = Init->BaseRelocation;
	Delta = (ULONG_PTR) ((LPBYTE) Init->ImageBase - NtHeaders->OptionalHeader.ImageBase);
	fnLdrLoadDll = (pLdrLoadDll) Init->fnLdrLoadDll;
	fnLdrGetProcedureAddress = (pLdrGetProcedureAddress) Init->fnLdrGetProcedureAddress;
	fnRtlInitAnsiString = (pRtlInitAnsiString) Init->fnRtlInitAnsiString;
	fnHcInitUnicodeString = (pHcInitUnicodeString) Init->fnHcInitUnicodeString;

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			Count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(DWORD);
			ImportList = (PDWORD)(pIBR + 1);

			for (Index = 0; Index < Count; Index++)
			{
				if (ImportList[Index])
				{
					FunctionPointer = (PULONG_PTR) Init->ImageBase + pIBR->VirtualAddress + (ImportList[Index] & 0xFFFF);
					*FunctionPointer += Delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	pIID = Init->ImportDirectory;

	while (pIID->Characteristics)
	{
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)Init->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)Init->ImageBase + pIID->FirstThunk);

		hModule = Init->fnLoadLibraryA((LPCSTR)Init->ImageBase + pIID->Name);
		if (!hModule)
		{
			return FALSE;
		}

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				Function = (SIZE_T)Init->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			else
			{
				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)Init->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function = (SIZE_T)Init->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)Init->ImageBase + NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)Init->ImageBase, DLL_PROCESS_ATTACH, NULL);
	}

	return TRUE;
}

static void __stdcall MmInternalResolve_End()
{

}

#pragma code_seg()
#pragma runtime_checks ("", restore)
//#pragma optimize ("", restore)

#pragma endregion

static
BOOLEAN
HCAPI
HcParameterVerifyInjectModuleManual(PVOID Buffer)
{
	PIMAGE_NT_HEADERS pHeaderNt = HcImageGetNtHeader(Buffer);

	return pHeaderNt && (pHeaderNt->FileHeader.Characteristics & IMAGE_FILE_DLL);
}

DECL_EXTERN_API(VOID, InjectExecuteCode, CONST IN HANDLE hProcess, LPBYTE lpShellcode, LPVOID lpArgs)
{
	DWORD Threads[200];
	DWORD dwThreadCount = 200;
	HcInternalZero(Threads, 200);

	if (HcThreadGetAllThreadIds(HcProcessGetId(hProcess), Threads, &dwThreadCount))
	{
		for (DWORD i = 0; i < dwThreadCount; i++)
		{
			if (Threads[i] == 0)
				break;

			HANDLE hThread = HcThreadOpen(Threads[i], THREAD_SET_CONTEXT);
			if (hThread)
			{
				if (HcThreadSuspend(hThread))
				{
					HcQueueApcThread(hThread, (PIO_APC_ROUTINE) lpShellcode, lpArgs, NULL, 0);
					HcThreadResume(hThread);
				}
				HcObjectClose(&hThread);
			}
		}
	}
}

DECL_EXTERN_API(BOOLEAN, InjectManualMap32W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath)
{
	MANUAL_MAP ManualInject;
	PIMAGE_DOS_HEADER pHeaderDos;
	PIMAGE_NT_HEADERS32 pHeaderNt;
	PIMAGE_SECTION_HEADER pHeaderSection;
	HANDLE hThread = NULL, hFile;
	PVOID ImageBuffer, LoaderBuffer = NULL, FileBuffer = NULL;
	DWORD ExitCode = 0, SectionIndex;
	SIZE_T BytesWritten = 0;
	DWORD dwFileSize;
	BOOLEAN bSuspended = FALSE;
	BOOLEAN bReturnValue = FALSE;
	HMODULE hRemoteKernel32;
	ULONG_PTR dwRvaLoadLibraryA;
	ULONG_PTR dwRvaGetProcAddress;

	ZERO(&ManualInject);

	/* Check if we attempted to inject too early. */
	if (!HcProcessReadyEx(hProcess))
	{
		return FALSE;
	}

	if (hProcess != NtCurrentProcess())
	{
		if (HcProcessSuspendEx(hProcess))
		{
			bSuspended = TRUE;
		}
	}

	/* Read the file */
	hFile = HcFileOpenW(szcPath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		goto done;
	}

	dwFileSize = HcFileSize(hFile);
	if (!dwFileSize)
	{
		goto done;
	}

	/* Allocate for the file information */
	FileBuffer = HcAlloc(dwFileSize);
	if (!FileBuffer)
	{
		goto done;
	}

	if (HcFileRead(hFile, FileBuffer, dwFileSize) != dwFileSize)
	{
		HcObjectClose(&hFile);
		goto done;
	}
	HcObjectClose(&hFile);

	if (!HcParameterVerifyInjectModuleManual(FileBuffer))
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		goto done;
	}


	pHeaderDos = HcImageGetDosHeader(FileBuffer);
	pHeaderNt = HcImageGetNtHeader32((ULONG_PTR) FileBuffer);

	/* Allocate for the code/data of the dll */
	ImageBuffer = HcVirtualAllocEx(hProcess,
		NULL,
		pHeaderNt->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!ImageBuffer)
	{
		goto done;
	}

	/* Write the code/data to the target executable */
	if (!HcProcessWriteMemory(hProcess,
		ImageBuffer,
		FileBuffer,
		pHeaderNt->OptionalHeader.SizeOfHeaders,
		&BytesWritten))
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		goto done;
	}

	pHeaderSection = IMAGE_FIRST_SECTION(pHeaderNt);

	/* Write sections of the dll to the process, not guaranteed to succeed, so no check. */
	for (SectionIndex = 0; SectionIndex < pHeaderNt->FileHeader.NumberOfSections; SectionIndex++)
	{
		HcProcessWriteMemory(hProcess,
			(LPBYTE)ImageBuffer + pHeaderSection[SectionIndex].VirtualAddress,
			(LPBYTE)FileBuffer + pHeaderSection[SectionIndex].PointerToRawData,
			pHeaderSection[SectionIndex].SizeOfRawData,
			&BytesWritten);
	}

	/* Allocate code for our function */
	LoaderBuffer = HcVirtualAllocEx(hProcess,
		NULL,
		4096 + dwFileSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (!LoaderBuffer)
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		goto done;
	}

	
	hRemoteKernel32 = (HMODULE) HcModuleRemoteHandle32W(hProcess, L"kernel32.dll");

	if (!hRemoteKernel32)
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		goto done;
	}

	dwRvaLoadLibraryA = HcProcessGetExportAddress32A(hProcess, hRemoteKernel32, "LoadLibraryA") - (ULONG_PTR) hRemoteKernel32;
	dwRvaGetProcAddress = HcProcessGetExportAddress32A(hProcess, hRemoteKernel32, "GetProcAddress") - (ULONG_PTR) hRemoteKernel32;

	ManualInject.ImageBase =		POINTER_32BIT(ImageBuffer);
	ManualInject.NtHeaders =		POINTER_32BIT((LPBYTE) ImageBuffer + pHeaderDos->e_lfanew);
	ManualInject.BaseRelocation =	POINTER_32BIT((LPBYTE) ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory =	POINTER_32BIT((LPBYTE) ImageBuffer + pHeaderNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA =	POINTER_32BIT((LPBYTE) hRemoteKernel32 + dwRvaLoadLibraryA);
	ManualInject.fnGetProcAddress = POINTER_32BIT((LPBYTE) hRemoteKernel32 + dwRvaGetProcAddress);

	/* Set the manual map information */
	if (!HcProcessWriteMemory(hProcess,
		LoaderBuffer,
		&ManualInject,
		sizeof(MANUAL_MAP),
		&BytesWritten))
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		goto done;
	}

	/* Set the code which will resolve imports, relocations  */
	if (!HcProcessWriteMemory(hProcess,
		(LPBYTE) LoaderBuffer + sizeof(MANUAL_MAP),
		(LPVOID) payload32,
		sizeof(payload32),
		&BytesWritten))
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);

		goto done;
	}

	//HcInjectExecuteCode(hProcess, (LPBYTE) LoaderBuffer + sizeof(MANUAL_MAP), LoaderBuffer);
	/* Execute the code in a new thread  */
	hThread = HcProcessCreateThread(hProcess,
		(LPTHREAD_START_ROUTINE) ((LPBYTE) LoaderBuffer + sizeof(MANUAL_MAP)),
		LoaderBuffer,
		0);

	if (!hThread)
	{
		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);
		goto done;
	}

	HcThreadResume(hThread);

	/* Wait for the thread to finish */
	HcObjectWait(hThread, 5000);

	/* Did the thread exit? */
	HcThreadExitCode(hThread, &ExitCode);
	if (!ExitCode)
	{
		/* We're out, something went wrong. */
		HcErrorSetDosError(ExitCode);

		HcVirtualFreeEx(hProcess, ImageBuffer, 0, MEM_RELEASE);

		goto done;
	}

	bReturnValue = TRUE;

done:
	if (bSuspended)
	{
		HcProcessResumeEx(hProcess);
	}

	if (hThread != NULL && hThread != INVALID_HANDLE)
	{
		HcObjectClose(&hThread);
	}

	if (LoaderBuffer)
	{
		HcVirtualFreeEx(hProcess, LoaderBuffer, 0, MEM_RELEASE);
	}

	if (FileBuffer)
	{
		HcFree(FileBuffer);
	}

	return bReturnValue;
}

DECL_EXTERN_API(ULONG, InjectRemoteThreadLdr32W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath)
{
	UNICODE_STRING32 InternalPath;
	ULONG PathSize = 0;
	LPBYTE InternalShellcodeCopy = NULL;
	PUNICODE_STRING32 exPath;
	WCHAR szFullPath[MAX_PATH];
	LPVOID pfnLdrLoadDll;
	HMODULE hNtdll;
	HANDLE hThread = NULL;
	ULONG ExitCode = 0;
	ULONG hReturn = 0;
	LPBYTE exShellcode;
	HMODULE* exModule;
	LPBYTE exPayload = NULL;
	LPWSTR exszPath;

	CONST UCHAR x86_shellcode_ldr[] =
	{
		0x68, 0, 0, 0, 0,           // push ModuleHandle            offset +1 
		0x68, 0, 0, 0, 0,           // push ModuleFileName          offset +6
		0x6A, 0,                    // push Flags  
		0x6A, 0,                    // push PathToFile
		0xE8, 0, 0, 0, 0,           // call LdrLoadDll              offset +15
		0xC2, 0x04, 0x00            // ret 4
	};

	if (!HcPathGetFullPathNameW(szcPath, szFullPath))
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		goto done;
	}

	hNtdll = HcModuleHandleAdvancedExW(hProcess, L"ntdll.dll", TRUE);
	if (!hNtdll)
	{
		goto done;
	}

	pfnLdrLoadDll = (LPVOID) HcProcessGetExportAddress32W(hProcess, hNtdll, L"LdrLoadDll");
	if (!pfnLdrLoadDll)
	{
		goto done;
	}

	PathSize = HcStringSizeW(szFullPath);
	if (!PathSize)
	{
		goto done;
	}

	exPayload = (LPBYTE) HcVirtualAllocEx(hProcess,
		NULL, 
		sizeof(x86_shellcode_ldr) + sizeof(*exPath) + PathSize + sizeof(ULONG), 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_EXECUTE_READWRITE);

	if (!exPayload)
	{
		goto done;
	}

	exShellcode = exPayload;
	exPath = (PUNICODE_STRING32) (exPayload + sizeof(x86_shellcode_ldr));
	exszPath = (LPWSTR) ((LPBYTE) exPath) + sizeof(*exPath);
	exModule = (HMODULE*) ((LPBYTE) exszPath) + PathSize;

	InternalPath.Length = (USHORT) PathSize;
	InternalPath.MaximumLength = (USHORT) PathSize + sizeof(UNICODE_NULL);
	InternalPath.Buffer = (ULONG) (ULONG_PTR) exszPath;

	if (!HcProcessWriteMemory(hProcess, exPath, &InternalPath, sizeof(InternalPath), NULL))
	{
		goto done;
	}

	if (!HcProcessWriteMemory(hProcess, exszPath, (LPVOID) szFullPath, PathSize, NULL))
	{
		goto done;
	}

	InternalShellcodeCopy = (LPBYTE) HcAlloc(sizeof(x86_shellcode_ldr));
	if (!InternalShellcodeCopy)
	{
		goto done;
	}

	HcInternalCopy(InternalShellcodeCopy, x86_shellcode_ldr, sizeof(x86_shellcode_ldr));

	*(ULONG*) (InternalShellcodeCopy + 1) = (ULONG) (ULONG_PTR) exModule;
	*(ULONG*) (InternalShellcodeCopy + 6) = (ULONG) (ULONG_PTR) exPath;
	*(ULONG*) (InternalShellcodeCopy + 15) = (ULONG) ((ULONG_PTR) pfnLdrLoadDll - (ULONG_PTR) exShellcode - 19);

	if (!HcProcessWriteMemory(hProcess, exShellcode, InternalShellcodeCopy, sizeof(x86_shellcode_ldr), NULL))
	{
		goto done;
	}

	hThread = HcProcessCreateThread(hProcess, (LPTHREAD_START_ROUTINE) exShellcode, NULL, 0);
	if (!hThread)
	{
		goto done;
	}

	HcThreadResume(hThread);
	HcObjectWait(hThread, INFINITE);

	if (!HcProcessReadMemory(hProcess, exModule, &hReturn, sizeof(ULONG), NULL))
	{
		HcErrorSetNtStatus(STATUS_FAIL_CHECK);
	}

done:
	if (hThread != NULL)
	{
		HcObjectClose(&hThread);
	}

	if (exPayload != NULL)
	{
		HcVirtualFreeEx(hProcess, exPayload, 0, MEM_RELEASE);
	}

	if (InternalShellcodeCopy != NULL)
	{
		HcFree(InternalShellcodeCopy);
	}

	return hReturn;
}

DECL_EXTERN_API(ULONG64, InjectRemoteThreadLdr64W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath)
{
	UNICODE_STRING64 InternalPath;
	ULONG PathSize = 0;
	LPBYTE InternalShellcodeCopy = NULL;
	WCHAR szFullPath[MAX_PATH];
	DWORD64 pfnLdrLoadDll;
	DWORD64 hNtdll;
	HANDLE hThread = NULL;
	ULONG ExitCode = 0;
	ULONG64 hReturn = 0;
	DWORD64 exPathUnicode;
	DWORD64 exszPath;
	DWORD64 exShellcode;
	DWORD64 expModule;
	DWORD64 exPayload = 0;

	CONST UCHAR x86_64_shellcode_ldr[] =
	{
		0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
		0x48, 0x31, 0xC9,                       // xor rcx, rcx
		0x48, 0x31, 0xD2,                       // xor rdx, rdx
		0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12
		0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +22
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32
		0xFF, 0xD0,                             // call rax
		0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
		0xC3                                    // ret
	};

	if (!HcPathGetFullPathNameW(szcPath, szFullPath))
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		goto done;
	}

	/* we do not want to check if we can access it since we might be injecting a dll in system32 and we might be 32bit */
	/*
	hDll = HcFileOpenW(szFullPath, OPEN_EXISTING, GENERIC_READ);
	if (hDll == INVALID_HANDLE)
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER_1);
		goto done;
	}

	HcObjectClose(&hDll);
	*/

	hNtdll = HcModuleRemoteHandle64W(hProcess, L"ntdll.dll");
	if (!hNtdll)
	{
		goto done;
	}

	pfnLdrLoadDll = HcProcessGetExportAddress64W(hProcess, (ULONG64) hNtdll, L"LdrLoadDll");
	if (!pfnLdrLoadDll)
	{
		goto done;
	}

	PathSize = HcStringSizeW(szFullPath);
	if (!PathSize)
	{
		goto done;
	}

	exPayload = HcVirtualAlloc64Ex(hProcess, 0, 
		sizeof(x86_64_shellcode_ldr) + sizeof(UNICODE_STRING64) + PathSize + sizeof(ULONG64), 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_EXECUTE_READWRITE);

	if (!exPayload)
	{
		goto done;
	}

	exShellcode = exPayload;
	exPathUnicode = exShellcode + sizeof(x86_64_shellcode_ldr);
	exszPath = exPathUnicode + sizeof(UNICODE_STRING64);
	expModule = exszPath + PathSize;

	InternalPath.Length = (USHORT) PathSize;
	InternalPath.MaximumLength = (USHORT) PathSize + sizeof(UNICODE_NULL);
	InternalPath.Buffer = exszPath;

	if (!HcProcessWriteMemory64(hProcess, (PVOID64) exPathUnicode, &InternalPath, sizeof(InternalPath), NULL))
	{
		goto done;
	}

	if (!HcProcessWriteMemory64(hProcess, (PVOID64) exszPath, (LPVOID) szFullPath, PathSize, NULL))
	{
		goto done;
	}

	InternalShellcodeCopy = (LPBYTE) HcAlloc(sizeof(x86_64_shellcode_ldr));
	if (!InternalShellcodeCopy)
	{
		goto done;
	}

	HcInternalCopy(InternalShellcodeCopy, x86_64_shellcode_ldr, sizeof(x86_64_shellcode_ldr));

	*(ULONG64*) (InternalShellcodeCopy + 12) = exPathUnicode;
	*(ULONG64*) (InternalShellcodeCopy + 22) = expModule;
	*(ULONG64*) (InternalShellcodeCopy + 32) = pfnLdrLoadDll;

	if (!HcProcessWriteMemory64(hProcess, (PVOID64) exShellcode, InternalShellcodeCopy, sizeof(x86_64_shellcode_ldr), NULL))
	{
		goto done;
	}

	hThread = HcProcessCreateThread64(hProcess, exShellcode, 0, 0);
	if (!hThread)
	{
		goto done;
	}

	HcThreadResume(hThread);
	HcObjectWait(hThread, INFINITE);

	if (!HcProcessReadMemory64(hProcess, (PVOID64) expModule, &hReturn, sizeof(ULONG64), NULL))
	{
		HcErrorSetNtStatus(STATUS_FAIL_CHECK);
	}

done:
	if (hThread != NULL)
	{
		HcObjectClose(&hThread);
	}

	if (exPayload != 0)
	{
		/* cannot free 64bit memory from 32bit */
#ifdef _WIN64
		HcVirtualFreeEx(hProcess, (LPVOID) exPayload, 0, MEM_RELEASE);
#endif
	}

	if (InternalShellcodeCopy != NULL)
	{
		HcFree(InternalShellcodeCopy);
	}

	return hReturn;
}

DECL_EXTERN_API(BOOLEAN, InjectRemoteThreadW, CONST IN HANDLE hProcess, IN LPCWSTR szcPath)
{
#ifdef _WIN64
	return HcInjectRemoteThread64W(hProcess, szcPath);
#else
	return HcInjectRemoteThread32W(hProcess, szcPath);
#endif
}

DECL_EXTERN_API(BOOLEAN, InjectRemoteThread64W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath)
{
	ULONG64 PathToDll;
	ULONG64 lpToLoadLibrary = 0;
	ULONG64 hKernel32;
	SIZE_T PathSize;
	LPWSTR szFullPath = NULL;
	HANDLE hThread = NULL;
	DWORD ExitCode = 0;
	BOOLEAN bReturnValue = FALSE;
	BOOLEAN bSuspended = FALSE;

	if (HcProcessSuspendEx(hProcess))
	{
		bSuspended = TRUE;
	}

	if (HcStringIsBad(szcPath))
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		goto done;
	}

	hKernel32 = HcModuleRemoteHandle64W(hProcess, L"kernel32.dll");
	if (!hKernel32)
	{
		goto done;
	}

	lpToLoadLibrary = HcProcessGetExportAddress64W(hProcess, hKernel32, L"LoadLibraryW");
	if (!lpToLoadLibrary)
	{
		HcErrorSetNtStatus(STATUS_INVALID_ADDRESS);
		goto done;
	}

	szFullPath = HcStringAllocW(MAX_PATH);
	if (!szFullPath)
	{
		HcErrorSetNtStatus(STATUS_NO_MEMORY);
		goto done;
	}

	if (!HcPathGetFullPathNameW(szcPath, szFullPath))
	{
		//
		// return INVALID_FILE;
		//
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		goto done;
	}

	/* we do not want to check if we can access it since we might be injecting a dll in system32 and we might be 32bit */
	/*
	hFile = HcFileOpenW(szFullPath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER_1);
		goto done;
	}

	HcObjectClose(&hFile);
	*/

	PathSize = HcStringSizeW(szFullPath);
	if (!PathSize)
	{
		goto done;
	}

	PathToDll = HcVirtualAlloc64Ex(hProcess, 0,
		PathSize + sizeof(WCHAR), 
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!PathToDll)
	{
		goto done;
	}

	if (!HcProcessWriteMemory64(hProcess,
		(PVOID64) PathToDll,
		szFullPath,
		PathSize + sizeof(WCHAR),
		NULL))
	{
		goto done;
	}

	hThread = HcProcessCreateThread64(hProcess, (DWORD64) lpToLoadLibrary, (DWORD64) PathToDll, 0);
	if (hThread == INVALID_HANDLE)
	{
		goto done;
	}

	/* Wait for the thread to finish */
	HcObjectWait(hThread, INFINITE);
	HcThreadExitCode(hThread, &ExitCode);

	if (!ExitCode)
	{
		/* We've injected successfully, but DLL_MAIN failed. */
		HcErrorSetNtStatus(STATUS_FAIL_CHECK);
	}

done:
	if (hThread != NULL)
	{
		HcClose(hThread);
	}

	if (szFullPath != NULL)
	{
		HcFree(szFullPath);
	}

	/* We can't free the allocated memory if we're in 32bit. */
#ifdef _WIN64
	if (lpToLoadLibrary != 0)
	{
		HcVirtualFreeEx(hProcess, (LPVOID) lpToLoadLibrary, 0, MEM_RELEASE);
	}
#endif
	
	if (bSuspended)
	{
		HcProcessResumeEx(hProcess);
	}

	return bReturnValue;
}

DECL_EXTERN_API(BOOLEAN, InjectRemoteThread32W, CONST IN HANDLE hProcess, IN LPCWSTR szcPath)
{
	LPBYTE PathToDll;
	ULONG_PTR lpToLoadLibrary = 0;
	HMODULE hKernel32;
	SIZE_T PathSize;
	LPWSTR szFullPath = NULL;
	HANDLE hThread = NULL;
	DWORD ExitCode = 0;
	BOOLEAN bReturnValue = FALSE;
	BOOLEAN bSuspended = FALSE;

	if (HcProcessSuspendEx(hProcess))
	{
		bSuspended = TRUE;
	}

	if (HcStringIsBad(szcPath))
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		goto done;
	}

	hKernel32 = HcModuleHandleAdvancedExW(hProcess, L"kernel32.dll", TRUE);
	if (!hKernel32)
	{
		goto done;
	}

	lpToLoadLibrary = HcProcessGetExportAddress32W(hProcess, hKernel32, L"LoadLibraryW");
	if (!lpToLoadLibrary)
	{
		HcErrorSetNtStatus(STATUS_INVALID_ADDRESS);
		goto done;
	}

	szFullPath = HcStringAllocW(MAX_PATH);
	if (!szFullPath)
	{
		HcErrorSetNtStatus(STATUS_NO_MEMORY);
		goto done;
	}

	if (!HcPathGetFullPathNameW(szcPath, szFullPath))
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER);
		goto done;
	}

	/* we do not want to check if we can access it since we might be injecting a dll in system32 and we might be 32bit */
	/*
	hFile = HcFileOpenW(szFullPath, OPEN_EXISTING, GENERIC_READ);
	if (hFile == INVALID_HANDLE)
	{
		HcErrorSetNtStatus(STATUS_INVALID_PARAMETER_1);
		goto done;
	}

	HcObjectClose(&hFile);
	*/

	PathSize = HcStringSizeW(szFullPath);
	if (!PathSize)
	{
		goto done;
	}

	PathToDll = HcVirtualAllocEx(hProcess,
		0,
		PathSize + sizeof(WCHAR),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (!PathToDll)
	{
		goto done;
	}

	if (!HcProcessWriteMemory(hProcess,
		PathToDll,
		szFullPath,
		PathSize + sizeof(WCHAR),
		NULL))
	{
		goto done;
	}

	hThread = HcProcessCreateThread(hProcess, (LPTHREAD_START_ROUTINE) lpToLoadLibrary, (LPVOID) PathToDll, 0);
	if (hThread == INVALID_HANDLE)
	{
		goto done;
	}

	/* Wait for the thread to finish */
	HcObjectWait(hThread, INFINITE);
	HcThreadExitCode(hThread, &ExitCode);

	if (!ExitCode)
	{
		/* We've injected successfully, but DLL_MAIN failed. */
		HcErrorSetNtStatus(STATUS_FAIL_CHECK);
	}

	/* Done.*/

done:
	if (hThread != NULL)
	{
		HcClose(hThread);
	}

	if (szFullPath != NULL)
	{
		HcFree(szFullPath);
	}

	if (lpToLoadLibrary != 0)
	{
		HcVirtualFreeEx(hProcess, (LPVOID) lpToLoadLibrary, 0, MEM_RELEASE);
	}

	if (bSuspended)
	{
		HcProcessResumeEx(hProcess);
	}

	return bReturnValue;
}