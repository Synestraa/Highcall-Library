#include <highcall.h>
#include <windows.h>

#include <stdio.h>
#include <conio.h>

#pragma comment(lib, "highcall.lib")
#pragma comment(lib, "user32.lib")

/*
--	If true is returned, it stops the iteration
--	If false is returned, it goes to the next untill there is no more modules to loop
*/
BOOLEAN CALLBACK ModuleCallback(PHC_MODULE_INFORMATIONW hcInfo, LPARAM lPARAM)
{
	wprintf(L"\t\t%s\n", hcInfo->Name);
#ifdef _WIN64
	wprintf(L"\t\tBase Address:%llx\n", hcInfo->Base);
	wprintf(L"\t\tSize of Module:%llx\n", hcInfo->Size);
#else
	wprintf(L"\t\tBase Address:%x\n", hcInfo->Base);
	wprintf(L"\t\tSize of Module:%x\n", hcInfo->Size);
#endif
	wprintf(L"\t\tPath:%s\n", hcInfo->Path);

	wprintf(L"\n");

	/* We just want to loop all of them, so keep going regardless */
	return FALSE;
}

/*
	If true is returned, it stops the iteration
	If false is returned, it goes to the next untill there is no more processes to loop
*/
BOOLEAN CALLBACK ProcessCallback(PHC_PROCESS_INFORMATION_EXW hpcInfo, LPARAM lParam)
{
	wprintf(L"\nProcess %s\n", hpcInfo->Name);
	wprintf(L"\tAccessible? %s\n", hpcInfo->CanAccess ? L"true" : L"false");
	
	if (!hpcInfo->CanAccess)
	{
		wprintf(L"--------------");
		return FALSE;
	} 

	/* We need a handle first */
	HANDLE ProcessHandle;
	ProcessHandle = HcProcessOpen(hpcInfo->Id, PROCESS_ALL_ACCESS);

	if (!ProcessHandle)
	{
		return FALSE;
	}

	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION BasicInformation;
	
	/* include hcsyscall.h */

	/* Ask the kernel for the basic information of this process */
	Status = HcQueryInformationProcess(ProcessHandle,
		ProcessBasicInformation,
		&BasicInformation,	
		sizeof(BasicInformation),
		NULL);

	if (!NT_SUCCESS(Status) || BasicInformation.PebBaseAddress == NULL)
	{
		wprintf(L"\tPEB Address not found, the process may be running on a different architecture.\n");
		return FALSE;
	}
	else
	{
#ifdef _WIN64
		wprintf(L"\tPEB Address: %llx\n", (SIZE_T)BasicInformation.PebBaseAddress);
#else
		wprintf(L"\tPEB Address: %x\n", (SIZE_T)BasicInformation.PebBaseAddress);
#endif // _WIN64
	}

	/* Enumerate modules */
	wprintf(L"\tModules:");

	/* Enumerate modules */
	HcProcessEnumModulesW(ProcessHandle, ModuleCallback, NULL);

	HcObjectClose(ProcessHandle);

	return TRUE;
}

/*
If true is returned, it stops the iteration
If false is returned, it goes to the next untill there is no more processes to loop
*/
BOOLEAN CALLBACK HiddenModuleCallback(PHC_PROCESS_INFORMATION_EXW hpcInfo, LPARAM lParam)
{
	wprintf(L"\nProcess %s\n", hpcInfo->Name);
	wprintf(L"\tAccessible? %s\n", hpcInfo->CanAccess ? L"Yes" : L"No");

	if (!hpcInfo->CanAccess)
	{
		wprintf(L"--------------");
		return FALSE;
	}

	/* Enumerate modules */
	wprintf(L"\tModules:");

	/* We need a handle first */
	HANDLE ProcessHandle;
	ProcessHandle = HcProcessOpen(hpcInfo->Id, PROCESS_ALL_ACCESS);

	if (!ProcessHandle)
	{
		return FALSE;
	}

	/* Enumerate hidden modules */
	HcProcessEnumMappedImagesW(ProcessHandle, ModuleCallback, NULL);

	HcObjectClose(ProcessHandle);

	return TRUE;
}

void Thread_Test()
{
	printf("Yep, my Id is: %x\n", GetCurrentThreadId());
}

typedef int (WINAPI *tMessageBoxA) (HWND,LPCSTR,LPCSTR,UINT);
tMessageBoxA oMessageBoxA = NULL;

int WINAPI Hooked_MessageBoxA(
	_In_opt_ HWND    hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_     UINT    uType
) {
	printf("New message captain: %s\n", lpText);
	return -100;
}

typedef HANDLE (WINAPI *tOpenProcess) (
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL  bInheritHandle,
	_In_ DWORD dwProcessId
);

tOpenProcess oOpenProcess = NULL;

int ***pointer;

int wmain(int argc, wchar_t *argv[])
{
	printf("highcall.h\n");

	HIGHCALL_STATUS Status;

	/* Start Highcall. */
	Status = HcInitialize();

	/* Check if we failed. */
	if (!HIGHCALL_ADVANCE(Status))
	{
		char errornote[260];
		HcErrorGetNoteA(errornote);

		printf("Could not start Highcall, Status: %x, Note: %s\n", Status, errornote);
		_getch();
		return -1;
	}

	printf("Highcall initialized.\n\n\n");

	printf("hchook.h pt.1\n");
	SIZE_T openProcessLocation = HcModuleProcedureAddressA(HcModuleHandleA("kernelbase.dll"), "OpenProcess");
	if (!openProcessLocation)
	{
		printf("Could not find open process!\n");
		_getch();
		return -1;
	}

	/* Assume that openprocess is around 50 bytes or so. */
	oOpenProcess = (tOpenProcess)HcHookRecreateCode((PBYTE)openProcessLocation, 50);

	/* Try opening a handle with the recreated function we've got. */
	HANDLE hand = oOpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (hand)
	{
		printf("We recreated OpenProcess and got a handle: %p\n\n\n", hand);
	}
	else
	{
		printf("We recreated OpenProcess and couldn't get a handle.\n\n\n");
	}

	printf("hcprocess.h\n");

	/* Starting arbitrary thread. */
	printf("Mr. Arbitrary Thread, are you there? ");

	HANDLE hThread = HcProcessCreateThread(NtCurrentProcess, (LPTHREAD_START_ROUTINE)Thread_Test, NULL, 0);

	/* Wait for it to finish */
	HcObjectWait(hThread, INFINITE);

	printf("Acquiring debug privilege: ");

	/* Get debug privilege for protected processes. */
	if (HcProcessSetPrivilegeW(NtCurrentProcess, SE_DEBUG_NAME, TRUE))
	{
		printf("success.\n\n\n");
	}
	else
	{
		printf("failed.\n\n\n");
	}

	printf("hchook.h pt.2\n");

	/* Hook example time.
	-- We're just gonna hook MessageBoxA, try intercepting it, then use the original from the copied bytes
	-- And finally restore it.
	*/

	SIZE_T MessageBoxAddress = HcModuleProcedureAddressA(HcGlobal.HandleUser32, "MessageBoxA");

	/* Set the address page to something inacessible. */
	DWORD oldProtect;
	if (!HcVirtualProtect((LPVOID)MessageBoxAddress, 100, PAGE_NOACCESS, &oldProtect))
	{
		printf("Failed setting the NOACCESS protection.\n");
		return -1;
	}

	/* Test the address to see if its valid, not necessary but for showcase. */
	if (HcInternalValidate((LPCVOID)MessageBoxAddress))
	{
		printf("MBA is accessible, something went wrong.\n");
		return -1;
	}
	else
	{
		printf("MBA is inacessible.\n");

		/* Restore it.*/
		if (!HcVirtualProtect((LPVOID)MessageBoxAddress, 1, oldProtect, &oldProtect))
		{
			printf("Failed restoring the NOACCESS protection.\n");
			return -1;
		}
	}

	DetourContext HookMessageBox;
	HookMessageBox.lpSource = (LPVOID)MessageBoxAddress;
	HookMessageBox.lpDestination = Hooked_MessageBoxA;
	//HookMessageBox.pbOriginal = (PBYTE)HcAlloc(0x100);

	HStatus HookStatus;
	if ((HookStatus = HcHookDetour(&HookMessageBox)) != HOOK_NO_ERR)
	{
		printf("Failed hooking messagebox. Error: %x\n\n", HookStatus);
		_getch();
		return -1;
	}

	oMessageBoxA = (tMessageBoxA)HookMessageBox.pbReconstructed;

	/* If we return -100, it means that our hook successfully took control over what happens. */
	if (MessageBoxA(0, "Example Hooked Message", 0, 0) == -100)
	{
		printf("Intercepted the message.\n");
	}
	else
	{
		printf("Seems like we couldnt intercept it captain.\n");
	}

	printf("hcprocess.h pt.2\n");

	printf("Dissecting explorer.exe\n");

	/*
		arg1 - NULL
			Search for processes with any name
		arg2 - BOOL function
			function to call on each process callback
		arg3 - LPARAM
			any parameter to pass to the callback
	*/


	HcProcessQueryByNameExW(L"explorer.exe", ProcessCallback, NULL);

	/* Enumerate hidden modules */
	HcProcessQueryByNameExW(L"explorer.exe", HiddenModuleCallback, NULL);

	printf("\n\n");

	getchar();
	return 0;
}