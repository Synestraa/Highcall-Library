#include <highcall.h>
#pragma comment(lib, "highcall.lib")

#include <stdio.h>
#include <stdlib.h>
#include <conio.h>

#define _CRTDBG_MAP_ALLOC  
#include <stdlib.h>  
#include <crtdbg.h>  

int main()
{
	NTSTATUS StartupStatus = HcInitialize();
	LPWSTR lpUniqueId = HcUniqueHardwareId();
	if (!NT_SUCCESS(StartupStatus))
	{
		printf("Failed startup. Reason: 0x%x\n", StartupStatus);
		goto done;
	}
	else
	{
		printf("Startup successful, Administrator [%s], Hardware Id [%ws]\n",  (HcGlobal.IsElevated ? "TRUE" : "FALSE"), lpUniqueId);
	}

	PROCESS_INFORMATION_W procs[200];
	ULONG Count = 0;

	HcProcessGetAllByNameW(L"svchost.exe", procs, &Count);

	PEB peb;
	if (!HcProcessGetPeb(NtCurrentProcess(), &peb))
	{
		printf("Failed retrieving PEB from self process, reason: 0x%x\n", HcErrorGetLastStatus());
	}
	else
	{
		printf("PEB.BeingDebugged [%d], PEB.ImageBaseAddress [%p], PEB.IsProtectedProcess [%d]\n", (ULONG) peb.BeingDebugged, peb.ImageBaseAddress, peb.IsProtectedProcess);
	}

	printf("Setting debugger trap.\n");

	if (HcScanCheckDebuggerBasic(TRUE) == STATUS_DEBUGGER_ATTACHED)
	{
		printf("Pressing a key will make the program continue, because you are using a debugger, it will likely crash if you try to step the program.\n"); 
		_getch();
	}

	NTSTATUS TrapStatus = HcScanApplyDebuggerMines();
	if (!NT_SUCCESS(TrapStatus))
	{
		printf("Failed setting debugger trap. 0x%x\n", TrapStatus);
	}
	else
	{
		printf("Debugger trap set.\n");
	}

	printf("Scanning for debugger.\n");
	
	NTSTATUS ScanStatus = HcScanCheckDebuggerBasic(TRUE);
	if (ScanStatus == STATUS_FAIL_CHECK)
	{
		printf("Procedure failed with last status: 0x%x\n", HcErrorGetLastStatus());
	}
	else if (ScanStatus == STATUS_DEBUGGER_ATTACHED)
	{
		printf("Debugger detected.\n");
	}
	else
	{
		printf("No debugger detected! Hurray.\n");
	}

	while (true)
	{
		printf("Please enter the name of a x86_64 process with it's extension. Example: svchost.exe\n");

		PROCESS_INFORMATION_W process;
		HcInternalSet(&process, 0, sizeof(process));

		char* processName = HcStringAllocA(256);
		gets_s(processName, 255);

		processName[256] = 0;

		wchar_t* convertedProcessName = HcStringConvertAtoW(processName);

		printf("You entered %s, wchar_t*: %ws\n", processName, convertedProcessName);

		if (!HcProcessGetByNameW(convertedProcessName, &process))
		{
			printf("Failed locating %ws\n", convertedProcessName);
		}
		else
		{
			printf("Found %ws [%d]\n", convertedProcessName, process.Id);

			HANDLE hProcess = HcProcessOpen(process.Id, PROCESS_ALL_ACCESS);
			if (!hProcess)
			{
				printf("Could not open %ws\n", convertedProcessName);
			}
			else
			{
				printf("Opened %ws [%p]\n", convertedProcessName, hProcess);

				PEB64 peb64;
				if (!HcProcessGetPeb64(hProcess, &peb64))
				{
					printf("Failed retrieving PEB64 from %ws, reason: 0x%x\n", convertedProcessName, HcErrorGetLastStatus());
				}
				else
				{
					printf("PEB64.BeingDebugged [%d], PEB64.ImageBaseAddress [0x%llx], PEB64.IsProtectedProcess [%d]\n", (ULONG) peb64.BeingDebugged, peb64.ImageBaseAddress, peb.IsProtectedProcess);
				}
			}
		}

		HcFree(processName);
		HcFree(convertedProcessName);
	}
done:
	_CrtDumpMemoryLeaks();
	_getch();
	return 0;
}