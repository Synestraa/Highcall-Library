#include "highcall.h"

#include "../../public/imports.h"

#include "../../private/sys/syscall.h"
#include "../../private/sys/version_table_86.h"
#include "../../private/sys/version_table_86_64.h"
#include "../../private/sys/version_table_wow64.h"

HcGlobalEnv HcGlobal;

//
// csrss.exe
//

#define BASESRV_SERVERDLL_INDEX     1
#define BASESRV_FIRST_API_NUMBER    0

//
// no context
//

UNICODE_STRING Restricted = RTL_CONSTANT_STRING(L"Restricted");

static NTSTATUS INITIALIZATION_ROUTINE InitializeModules(VOID)
{
	PPEB pPeb = NtCurrentPeb();
	if (pPeb == NULL)
	{
		return STATUS_FAIL_CHECK;
	}

	if (pPeb->LoaderData == NULL)
	{
		return STATUS_SUCCESS; /* We don't care if there's  nothing, we're loaded into a very early process. */
	}

	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = NULL;
	PLIST_ENTRY pListHead = &(pPeb->LoaderData->InMemoryOrderModuleList), pListEntry = NULL;

	/* Loop through entry list till we find a match for the module's name
	the comparison is strict to the entire name, case sensitive. */
	for (pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink)
	{
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;
		if (pLdrDataTableEntry->FullModuleName.Buffer == NULL || pLdrDataTableEntry->FullModuleName.Length == 0)
		{
			continue;
		}

		if (HcStringCompareW(L"ntdll.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			HcGlobal.HandleNtdll = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
		else if (HcStringCompareW(L"user32.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			HcGlobal.HandleUser32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
		else if (HcStringCompareW(L"kernel32.dll", pLdrDataTableEntry->FullModuleName.Buffer))
		{
			HcGlobal.HandleKernel32 = (HMODULE)pLdrDataTableEntry->InInitializationOrderLinks.Flink;
		}
	}

	return STATUS_SUCCESS;
}

static NTSTATUS INITIALIZATION_ROUTINE InitializeVersion(VOID)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG majorVersion;
	ULONG minorVersion;
	ULONG buildNumber;
	PPEB Peb;

	HcGlobal.IsWow64 = HcIsWow64();
	Peb = NtCurrentPeb();

	majorVersion = Peb->OSMajorVersion;
	minorVersion = Peb->OSMinorVersion;
	buildNumber = Peb->OSBuildNumber;

	/* Windows 7 */
	if (majorVersion == 6 && minorVersion == 1)
	{
		HcGlobal.WindowsVersion = WINDOWS_7_1;
	}
	/* Windows 8.0 */
	else if (majorVersion == 6 && minorVersion == 2)
	{
		HcGlobal.WindowsVersion = WINDOWS_8;
	}
	/* Windows 8.1 */
	else if (majorVersion == 6 && minorVersion == 3)
	{
		HcGlobal.WindowsVersion = WINDOWS_8_1;
	}
	/* Windows 10 */
	else if (majorVersion == 10 && minorVersion == 0)
	{
		if (buildNumber > 16299)
		{
			HcGlobal.WindowsVersion = WINDOWS_10_1803;
		}
		else if (buildNumber == 16299)
		{
			HcGlobal.WindowsVersion = WINDOWS_10_1709;
		}
		else if (buildNumber >= 15063)
		{
			HcGlobal.WindowsVersion = WINDOWS_10_1703;
		}
		else if (buildNumber >= 14393)
		{
			HcGlobal.WindowsVersion = WINDOWS_10_1607;
		}
		else if (buildNumber >= 10586)
		{
			HcGlobal.WindowsVersion = WINDOWS_10_1511;
		}
		else if (buildNumber >= 10240)
		{
			HcGlobal.WindowsVersion = WINDOWS_10_1507;
		}
		else
		{
			HcGlobal.WindowsVersion = WINDOWS_NOT_SUPPORTED;
		}
	}
	else
	{
		/* We dont support anything else (yet). */
		HcGlobal.WindowsVersion = WINDOWS_NOT_SUPPORTED;
		Status = STATUS_INVALID_OWNER;
	}

	return Status;
}


static NTSTATUS InitializeSyscall(VOID)
{
	/* Initializes every used systemcall in the current environment without communicating with the kernel to query the indicies.
	*/
	//return HcSysInitializeNativeSystem() ? STATUS_SUCCESS : STATUS_FAIL_CHECK;
	ULONG v = HcGlobal.WindowsVersion;
	if (v == WINDOWS_NOT_DEFINED || v == WINDOWS_NOT_SUPPORTED)
	{
		return STATUS_FATAL_APP_EXIT;
	}

#ifdef _WIN64
	sciAcceptConnectPort = sciTable_86_64_NtAcceptConnectPort[v];
	sciAccessCheck = sciTable_86_64_NtAccessCheck[v];
	sciAccessCheckAndAuditAlarm = sciTable_86_64_NtAccessCheckAndAuditAlarm[v];
	sciAccessCheckByType = sciTable_86_64_NtAccessCheckByType[v];
	sciAccessCheckByTypeAndAuditAlarm = sciTable_86_64_NtAccessCheckByTypeAndAuditAlarm[v];
	sciAccessCheckByTypeResultList = sciTable_86_64_NtAccessCheckByTypeResultList[v];
	sciAccessCheckByTypeResultListAndAuditAlarm = sciTable_86_64_NtAccessCheckByTypeResultListAndAuditAlarm[v];
	sciAccessCheckByTypeResultListAndAuditAlarmByHandle = sciTable_86_64_NtAccessCheckByTypeResultListAndAuditAlarmByHandle[v];
	sciAddAtom = sciTable_86_64_NtAddAtom[v];
	sciAddBootEntry = sciTable_86_64_NtAddBootEntry[v];
	sciAddDriverEntry = sciTable_86_64_NtAddDriverEntry[v];
	sciAdjustGroupsToken = sciTable_86_64_NtAdjustGroupsToken[v];
	sciAdjustPrivilegesToken = sciTable_86_64_NtAdjustPrivilegesToken[v];
	sciAlertResumeThread = sciTable_86_64_NtAlertResumeThread[v];
	sciAlertThread = sciTable_86_64_NtAlertThread[v];
	sciAllocateLocallyUniqueId = sciTable_86_64_NtAllocateLocallyUniqueId[v];
	sciAllocateReserveObject = sciTable_86_64_NtAllocateReserveObject[v];
	sciAllocateUserPhysicalPages = sciTable_86_64_NtAllocateUserPhysicalPages[v];
	sciAllocateUuids = sciTable_86_64_NtAllocateUuids[v];
	sciAllocateVirtualMemory = sciTable_86_64_NtAllocateVirtualMemory[v];
	sciAlpcAcceptConnectPort = sciTable_86_64_NtAlpcAcceptConnectPort[v];
	sciAlpcCancelMessage = sciTable_86_64_NtAlpcCancelMessage[v];
	sciAlpcConnectPort = sciTable_86_64_NtAlpcConnectPort[v];
	sciAlpcCreatePort = sciTable_86_64_NtAlpcCreatePort[v];
	sciAlpcCreatePortSection = sciTable_86_64_NtAlpcCreatePortSection[v];
	sciAlpcCreateResourceReserve = sciTable_86_64_NtAlpcCreateResourceReserve[v];
	sciAlpcCreateSectionView = sciTable_86_64_NtAlpcCreateSectionView[v];
	sciAlpcCreateSecurityContext = sciTable_86_64_NtAlpcCreateSecurityContext[v];
	sciAlpcDeletePortSection = sciTable_86_64_NtAlpcDeletePortSection[v];
	sciAlpcDeleteResourceReserve = sciTable_86_64_NtAlpcDeleteResourceReserve[v];
	sciAlpcDeleteSectionView = sciTable_86_64_NtAlpcDeleteSectionView[v];
	sciAlpcDeleteSecurityContext = sciTable_86_64_NtAlpcDeleteSecurityContext[v];
	sciAlpcDisconnectPort = sciTable_86_64_NtAlpcDisconnectPort[v];
	sciAlpcImpersonateClientOfPort = sciTable_86_64_NtAlpcImpersonateClientOfPort[v];
	sciAlpcOpenSenderProcess = sciTable_86_64_NtAlpcOpenSenderProcess[v];
	sciAlpcOpenSenderThread = sciTable_86_64_NtAlpcOpenSenderThread[v];
	sciAlpcQueryInformation = sciTable_86_64_NtAlpcQueryInformation[v];
	sciAlpcQueryInformationMessage = sciTable_86_64_NtAlpcQueryInformationMessage[v];
	sciAlpcRevokeSecurityContext = sciTable_86_64_NtAlpcRevokeSecurityContext[v];
	sciAlpcSendWaitReceivePort = sciTable_86_64_NtAlpcSendWaitReceivePort[v];
	sciAlpcSetInformation = sciTable_86_64_NtAlpcSetInformation[v];
	sciApphelpCacheControl = sciTable_86_64_NtApphelpCacheControl[v];
	sciAreMappedFilesTheSame = sciTable_86_64_NtAreMappedFilesTheSame[v];
	sciAssignProcessToJobObject = sciTable_86_64_NtAssignProcessToJobObject[v];
	sciCallbackReturn = sciTable_86_64_NtCallbackReturn[v];
	sciCancelIoFile = sciTable_86_64_NtCancelIoFile[v];
	sciCancelIoFileEx = sciTable_86_64_NtCancelIoFileEx[v];
	sciCancelSynchronousIoFile = sciTable_86_64_NtCancelSynchronousIoFile[v];
	sciCancelTimer = sciTable_86_64_NtCancelTimer[v];
	sciClearEvent = sciTable_86_64_NtClearEvent[v];
	sciClose = sciTable_86_64_NtClose[v];
	sciCloseObjectAuditAlarm = sciTable_86_64_NtCloseObjectAuditAlarm[v];
	sciCommitComplete = sciTable_86_64_NtCommitComplete[v];
	sciCommitEnlistment = sciTable_86_64_NtCommitEnlistment[v];
	sciCommitTransaction = sciTable_86_64_NtCommitTransaction[v];
	sciCompactKeys = sciTable_86_64_NtCompactKeys[v];
	sciCompareTokens = sciTable_86_64_NtCompareTokens[v];
	sciCompleteConnectPort = sciTable_86_64_NtCompleteConnectPort[v];
	sciCompressKey = sciTable_86_64_NtCompressKey[v];
	sciConnectPort = sciTable_86_64_NtConnectPort[v];
	sciContinue = sciTable_86_64_NtContinue[v];
	sciCreateDebugObject = sciTable_86_64_NtCreateDebugObject[v];
	sciCreateDirectoryObject = sciTable_86_64_NtCreateDirectoryObject[v];
	sciCreateEnlistment = sciTable_86_64_NtCreateEnlistment[v];
	sciCreateEvent = sciTable_86_64_NtCreateEvent[v];
	sciCreateEventPair = sciTable_86_64_NtCreateEventPair[v];
	sciCreateFile = sciTable_86_64_NtCreateFile[v];
	sciCreateIoCompletion = sciTable_86_64_NtCreateIoCompletion[v];
	sciCreateJobObject = sciTable_86_64_NtCreateJobObject[v];
	sciCreateJobSet = sciTable_86_64_NtCreateJobSet[v];
	sciCreateKey = sciTable_86_64_NtCreateKey[v];
	sciCreateKeyTransacted = sciTable_86_64_NtCreateKeyTransacted[v];
	sciCreateKeyedEvent = sciTable_86_64_NtCreateKeyedEvent[v];
	sciCreateMailslotFile = sciTable_86_64_NtCreateMailslotFile[v];
	sciCreateMutant = sciTable_86_64_NtCreateMutant[v];
	sciCreateNamedPipeFile = sciTable_86_64_NtCreateNamedPipeFile[v];
	sciCreatePagingFile = sciTable_86_64_NtCreatePagingFile[v];
	sciCreatePort = sciTable_86_64_NtCreatePort[v];
	sciCreatePrivateNamespace = sciTable_86_64_NtCreatePrivateNamespace[v];
	sciCreateProcess = sciTable_86_64_NtCreateProcess[v];
	sciCreateProcessEx = sciTable_86_64_NtCreateProcessEx[v];
	sciCreateProfile = sciTable_86_64_NtCreateProfile[v];
	sciCreateProfileEx = sciTable_86_64_NtCreateProfileEx[v];
	sciCreateResourceManager = sciTable_86_64_NtCreateResourceManager[v];
	sciCreateSection = sciTable_86_64_NtCreateSection[v];
	sciCreateSemaphore = sciTable_86_64_NtCreateSemaphore[v];
	sciCreateSymbolicLinkObject = sciTable_86_64_NtCreateSymbolicLinkObject[v];
	sciCreateThread = sciTable_86_64_NtCreateThread[v];
	sciCreateThreadEx = sciTable_86_64_NtCreateThreadEx[v];
	sciCreateTimer = sciTable_86_64_NtCreateTimer[v];
	sciCreateToken = sciTable_86_64_NtCreateToken[v];
	sciCreateTransaction = sciTable_86_64_NtCreateTransaction[v];
	sciCreateTransactionManager = sciTable_86_64_NtCreateTransactionManager[v];
	sciCreateUserProcess = sciTable_86_64_NtCreateUserProcess[v];
	sciCreateWaitablePort = sciTable_86_64_NtCreateWaitablePort[v];
	sciCreateWorkerFactory = sciTable_86_64_NtCreateWorkerFactory[v];
	sciDebugActiveProcess = sciTable_86_64_NtDebugActiveProcess[v];
	sciDebugContinue = sciTable_86_64_NtDebugContinue[v];
	sciDelayExecution = sciTable_86_64_NtDelayExecution[v];
	sciDeleteAtom = sciTable_86_64_NtDeleteAtom[v];
	sciDeleteBootEntry = sciTable_86_64_NtDeleteBootEntry[v];
	sciDeleteDriverEntry = sciTable_86_64_NtDeleteDriverEntry[v];
	sciDeleteFile = sciTable_86_64_NtDeleteFile[v];
	sciDeleteKey = sciTable_86_64_NtDeleteKey[v];
	sciDeleteObjectAuditAlarm = sciTable_86_64_NtDeleteObjectAuditAlarm[v];
	sciDeletePrivateNamespace = sciTable_86_64_NtDeletePrivateNamespace[v];
	sciDeleteValueKey = sciTable_86_64_NtDeleteValueKey[v];
	sciDeviceIoControlFile = sciTable_86_64_NtDeviceIoControlFile[v];
	sciDisableLastKnownGood = sciTable_86_64_NtDisableLastKnownGood[v];
	sciDisplayString = sciTable_86_64_NtDisplayString[v];
	sciDrawText = sciTable_86_64_NtDrawText[v];
	sciDuplicateObject = sciTable_86_64_NtDuplicateObject[v];
	sciDuplicateToken = sciTable_86_64_NtDuplicateToken[v];
	sciEnableLastKnownGood = sciTable_86_64_NtEnableLastKnownGood[v];
	sciEnumerateBootEntries = sciTable_86_64_NtEnumerateBootEntries[v];
	sciEnumerateDriverEntries = sciTable_86_64_NtEnumerateDriverEntries[v];
	sciEnumerateKey = sciTable_86_64_NtEnumerateKey[v];
	sciEnumerateSystemEnvironmentValuesEx = sciTable_86_64_NtEnumerateSystemEnvironmentValuesEx[v];
	sciEnumerateTransactionObject = sciTable_86_64_NtEnumerateTransactionObject[v];
	sciEnumerateValueKey = sciTable_86_64_NtEnumerateValueKey[v];
	sciExtendSection = sciTable_86_64_NtExtendSection[v];
	sciFilterToken = sciTable_86_64_NtFilterToken[v];
	sciFindAtom = sciTable_86_64_NtFindAtom[v];
	sciFlushBuffersFile = sciTable_86_64_NtFlushBuffersFile[v];
	sciFlushInstallUILanguage = sciTable_86_64_NtFlushInstallUILanguage[v];
	sciFlushInstructionCache = sciTable_86_64_NtFlushInstructionCache[v];
	sciFlushKey = sciTable_86_64_NtFlushKey[v];
	sciFlushProcessWriteBuffers = sciTable_86_64_NtFlushProcessWriteBuffers[v];
	sciFlushVirtualMemory = sciTable_86_64_NtFlushVirtualMemory[v];
	sciFlushWriteBuffer = sciTable_86_64_NtFlushWriteBuffer[v];
	sciFreeUserPhysicalPages = sciTable_86_64_NtFreeUserPhysicalPages[v];
	sciFreeVirtualMemory = sciTable_86_64_NtFreeVirtualMemory[v];
	sciFreezeRegistry = sciTable_86_64_NtFreezeRegistry[v];
	sciFreezeTransactions = sciTable_86_64_NtFreezeTransactions[v];
	sciFsControlFile = sciTable_86_64_NtFsControlFile[v];
	sciGetContextThread = sciTable_86_64_NtGetContextThread[v];
	sciGetCurrentProcessorNumber = sciTable_86_64_NtGetCurrentProcessorNumber[v];
	sciGetDevicePowerState = sciTable_86_64_NtGetDevicePowerState[v];
	sciGetMUIRegistryInfo = sciTable_86_64_NtGetMUIRegistryInfo[v];
	sciGetNextProcess = sciTable_86_64_NtGetNextProcess[v];
	sciGetNextThread = sciTable_86_64_NtGetNextThread[v];
	sciGetNlsSectionPtr = sciTable_86_64_NtGetNlsSectionPtr[v];
	sciGetNotificationResourceManager = sciTable_86_64_NtGetNotificationResourceManager[v];
	sciGetWriteWatch = sciTable_86_64_NtGetWriteWatch[v];
	sciImpersonateAnonymousToken = sciTable_86_64_NtImpersonateAnonymousToken[v];
	sciImpersonateClientOfPort = sciTable_86_64_NtImpersonateClientOfPort[v];
	sciImpersonateThread = sciTable_86_64_NtImpersonateThread[v];
	sciInitializeNlsFiles = sciTable_86_64_NtInitializeNlsFiles[v];
	sciInitializeRegistry = sciTable_86_64_NtInitializeRegistry[v];
	sciInitiatePowerAction = sciTable_86_64_NtInitiatePowerAction[v];
	sciIsProcessInJob = sciTable_86_64_NtIsProcessInJob[v];
	sciIsSystemResumeAutomatic = sciTable_86_64_NtIsSystemResumeAutomatic[v];
	sciIsUILanguageComitted = sciTable_86_64_NtIsUILanguageComitted[v];
	sciListenPort = sciTable_86_64_NtListenPort[v];
	sciLoadDriver = sciTable_86_64_NtLoadDriver[v];
	sciLoadKey = sciTable_86_64_NtLoadKey[v];
	sciLoadKey2 = sciTable_86_64_NtLoadKey2[v];
	sciLoadKeyEx = sciTable_86_64_NtLoadKeyEx[v];
	sciLockFile = sciTable_86_64_NtLockFile[v];
	sciLockProductActivationKeys = sciTable_86_64_NtLockProductActivationKeys[v];
	sciLockRegistryKey = sciTable_86_64_NtLockRegistryKey[v];
	sciLockVirtualMemory = sciTable_86_64_NtLockVirtualMemory[v];
	sciMakePermanentObject = sciTable_86_64_NtMakePermanentObject[v];
	sciMakeTemporaryObject = sciTable_86_64_NtMakeTemporaryObject[v];
	sciMapCMFModule = sciTable_86_64_NtMapCMFModule[v];
	sciMapUserPhysicalPages = sciTable_86_64_NtMapUserPhysicalPages[v];
	sciMapUserPhysicalPagesScatter = sciTable_86_64_NtMapUserPhysicalPagesScatter[v];
	sciMapViewOfSection = sciTable_86_64_NtMapViewOfSection[v];
	sciModifyBootEntry = sciTable_86_64_NtModifyBootEntry[v];
	sciModifyDriverEntry = sciTable_86_64_NtModifyDriverEntry[v];
	sciNotifyChangeDirectoryFile = sciTable_86_64_NtNotifyChangeDirectoryFile[v];
	sciNotifyChangeKey = sciTable_86_64_NtNotifyChangeKey[v];
	sciNotifyChangeMultipleKeys = sciTable_86_64_NtNotifyChangeMultipleKeys[v];
	sciNotifyChangeSession = sciTable_86_64_NtNotifyChangeSession[v];
	sciOpenDirectoryObject = sciTable_86_64_NtOpenDirectoryObject[v];
	sciOpenEnlistment = sciTable_86_64_NtOpenEnlistment[v];
	sciOpenEvent = sciTable_86_64_NtOpenEvent[v];
	sciOpenEventPair = sciTable_86_64_NtOpenEventPair[v];
	sciOpenFile = sciTable_86_64_NtOpenFile[v];
	sciOpenIoCompletion = sciTable_86_64_NtOpenIoCompletion[v];
	sciOpenJobObject = sciTable_86_64_NtOpenJobObject[v];
	sciOpenKey = sciTable_86_64_NtOpenKey[v];
	sciOpenKeyEx = sciTable_86_64_NtOpenKeyEx[v];
	sciOpenKeyTransacted = sciTable_86_64_NtOpenKeyTransacted[v];
	sciOpenKeyTransactedEx = sciTable_86_64_NtOpenKeyTransactedEx[v];
	sciOpenKeyedEvent = sciTable_86_64_NtOpenKeyedEvent[v];
	sciOpenMutant = sciTable_86_64_NtOpenMutant[v];
	sciOpenObjectAuditAlarm = sciTable_86_64_NtOpenObjectAuditAlarm[v];
	sciOpenPrivateNamespace = sciTable_86_64_NtOpenPrivateNamespace[v];
	sciOpenProcess = sciTable_86_64_NtOpenProcess[v];
	sciOpenProcessToken = sciTable_86_64_NtOpenProcessToken[v];
	sciOpenProcessTokenEx = sciTable_86_64_NtOpenProcessTokenEx[v];
	sciOpenResourceManager = sciTable_86_64_NtOpenResourceManager[v];
	sciOpenSection = sciTable_86_64_NtOpenSection[v];
	sciOpenSemaphore = sciTable_86_64_NtOpenSemaphore[v];
	sciOpenSession = sciTable_86_64_NtOpenSession[v];
	sciOpenSymbolicLinkObject = sciTable_86_64_NtOpenSymbolicLinkObject[v];
	sciOpenThread = sciTable_86_64_NtOpenThread[v];
	sciOpenThreadToken = sciTable_86_64_NtOpenThreadToken[v];
	sciOpenThreadTokenEx = sciTable_86_64_NtOpenThreadTokenEx[v];
	sciOpenTimer = sciTable_86_64_NtOpenTimer[v];
	sciOpenTransaction = sciTable_86_64_NtOpenTransaction[v];
	sciOpenTransactionManager = sciTable_86_64_NtOpenTransactionManager[v];
	sciPlugPlayControl = sciTable_86_64_NtPlugPlayControl[v];
	sciPowerInformation = sciTable_86_64_NtPowerInformation[v];
	sciPrePrepareComplete = sciTable_86_64_NtPrePrepareComplete[v];
	sciPrePrepareEnlistment = sciTable_86_64_NtPrePrepareEnlistment[v];
	sciPrepareComplete = sciTable_86_64_NtPrepareComplete[v];
	sciPrepareEnlistment = sciTable_86_64_NtPrepareEnlistment[v];
	sciPrivilegeCheck = sciTable_86_64_NtPrivilegeCheck[v];
	sciPrivilegeObjectAuditAlarm = sciTable_86_64_NtPrivilegeObjectAuditAlarm[v];
	sciPrivilegedServiceAuditAlarm = sciTable_86_64_NtPrivilegedServiceAuditAlarm[v];
	sciPropagationComplete = sciTable_86_64_NtPropagationComplete[v];
	sciPropagationFailed = sciTable_86_64_NtPropagationFailed[v];
	sciProtectVirtualMemory = sciTable_86_64_NtProtectVirtualMemory[v];
	sciPulseEvent = sciTable_86_64_NtPulseEvent[v];
	sciQueryAttributesFile = sciTable_86_64_NtQueryAttributesFile[v];
	sciQueryBootEntryOrder = sciTable_86_64_NtQueryBootEntryOrder[v];
	sciQueryBootOptions = sciTable_86_64_NtQueryBootOptions[v];
	sciQueryDebugFilterState = sciTable_86_64_NtQueryDebugFilterState[v];
	sciQueryDefaultLocale = sciTable_86_64_NtQueryDefaultLocale[v];
	sciQueryDefaultUILanguage = sciTable_86_64_NtQueryDefaultUILanguage[v];
	sciQueryDirectoryFile = sciTable_86_64_NtQueryDirectoryFile[v];
	sciQueryDirectoryObject = sciTable_86_64_NtQueryDirectoryObject[v];
	sciQueryDriverEntryOrder = sciTable_86_64_NtQueryDriverEntryOrder[v];
	sciQueryEaFile = sciTable_86_64_NtQueryEaFile[v];
	sciQueryEvent = sciTable_86_64_NtQueryEvent[v];
	sciQueryFullAttributesFile = sciTable_86_64_NtQueryFullAttributesFile[v];
	sciQueryInformationAtom = sciTable_86_64_NtQueryInformationAtom[v];
	sciQueryInformationEnlistment = sciTable_86_64_NtQueryInformationEnlistment[v];
	sciQueryInformationFile = sciTable_86_64_NtQueryInformationFile[v];
	sciQueryInformationJobObject = sciTable_86_64_NtQueryInformationJobObject[v];
	sciQueryInformationPort = sciTable_86_64_NtQueryInformationPort[v];
	sciQueryInformationProcess = sciTable_86_64_NtQueryInformationProcess[v];
	sciQueryInformationResourceManager = sciTable_86_64_NtQueryInformationResourceManager[v];
	sciQueryInformationThread = sciTable_86_64_NtQueryInformationThread[v];
	sciQueryInformationToken = sciTable_86_64_NtQueryInformationToken[v];
	sciQueryInformationTransaction = sciTable_86_64_NtQueryInformationTransaction[v];
	sciQueryInformationTransactionManager = sciTable_86_64_NtQueryInformationTransactionManager[v];
	sciQueryInformationWorkerFactory = sciTable_86_64_NtQueryInformationWorkerFactory[v];
	sciQueryInstallUILanguage = sciTable_86_64_NtQueryInstallUILanguage[v];
	sciQueryIntervalProfile = sciTable_86_64_NtQueryIntervalProfile[v];
	sciQueryIoCompletion = sciTable_86_64_NtQueryIoCompletion[v];
	sciQueryKey = sciTable_86_64_NtQueryKey[v];
	sciQueryLicenseValue = sciTable_86_64_NtQueryLicenseValue[v];
	sciQueryMultipleValueKey = sciTable_86_64_NtQueryMultipleValueKey[v];
	sciQueryMutant = sciTable_86_64_NtQueryMutant[v];
	sciQueryObject = sciTable_86_64_NtQueryObject[v];
	sciQueryOpenSubKeys = sciTable_86_64_NtQueryOpenSubKeys[v];
	sciQueryOpenSubKeysEx = sciTable_86_64_NtQueryOpenSubKeysEx[v];
	sciQueryPerformanceCounter = sciTable_86_64_NtQueryPerformanceCounter[v];
	sciQueryPortInformationProcess = sciTable_86_64_NtQueryPortInformationProcess[v];
	sciQueryQuotaInformationFile = sciTable_86_64_NtQueryQuotaInformationFile[v];
	sciQuerySection = sciTable_86_64_NtQuerySection[v];
	sciQuerySecurityAttributesToken = sciTable_86_64_NtQuerySecurityAttributesToken[v];
	sciQuerySecurityObject = sciTable_86_64_NtQuerySecurityObject[v];
	sciQuerySemaphore = sciTable_86_64_NtQuerySemaphore[v];
	sciQuerySymbolicLinkObject = sciTable_86_64_NtQuerySymbolicLinkObject[v];
	sciQuerySystemEnvironmentValue = sciTable_86_64_NtQuerySystemEnvironmentValue[v];
	sciQuerySystemEnvironmentValueEx = sciTable_86_64_NtQuerySystemEnvironmentValueEx[v];
	sciQuerySystemInformation = sciTable_86_64_NtQuerySystemInformation[v];
	sciQuerySystemInformationEx = sciTable_86_64_NtQuerySystemInformationEx[v];
	sciQuerySystemTime = sciTable_86_64_NtQuerySystemTime[v];
	sciQueryTimer = sciTable_86_64_NtQueryTimer[v];
	sciQueryTimerResolution = sciTable_86_64_NtQueryTimerResolution[v];
	sciQueryValueKey = sciTable_86_64_NtQueryValueKey[v];
	sciQueryVirtualMemory = sciTable_86_64_NtQueryVirtualMemory[v];
	sciQueryVolumeInformationFile = sciTable_86_64_NtQueryVolumeInformationFile[v];
	sciQueueApcThread = sciTable_86_64_NtQueueApcThread[v];
	sciQueueApcThreadEx = sciTable_86_64_NtQueueApcThreadEx[v];
	sciRaiseException = sciTable_86_64_NtRaiseException[v];
	sciRaiseHardError = sciTable_86_64_NtRaiseHardError[v];
	sciReadFile = sciTable_86_64_NtReadFile[v];
	sciReadFileScatter = sciTable_86_64_NtReadFileScatter[v];
	sciReadOnlyEnlistment = sciTable_86_64_NtReadOnlyEnlistment[v];
	sciReadRequestData = sciTable_86_64_NtReadRequestData[v];
	sciReadVirtualMemory = sciTable_86_64_NtReadVirtualMemory[v];
	sciRecoverEnlistment = sciTable_86_64_NtRecoverEnlistment[v];
	sciRecoverResourceManager = sciTable_86_64_NtRecoverResourceManager[v];
	sciRecoverTransactionManager = sciTable_86_64_NtRecoverTransactionManager[v];
	sciRegisterProtocolAddressInformation = sciTable_86_64_NtRegisterProtocolAddressInformation[v];
	sciRegisterThreadTerminatePort = sciTable_86_64_NtRegisterThreadTerminatePort[v];
	sciReleaseKeyedEvent = sciTable_86_64_NtReleaseKeyedEvent[v];
	sciReleaseMutant = sciTable_86_64_NtReleaseMutant[v];
	sciReleaseSemaphore = sciTable_86_64_NtReleaseSemaphore[v];
	sciReleaseWorkerFactoryWorker = sciTable_86_64_NtReleaseWorkerFactoryWorker[v];
	sciRemoveIoCompletion = sciTable_86_64_NtRemoveIoCompletion[v];
	sciRemoveIoCompletionEx = sciTable_86_64_NtRemoveIoCompletionEx[v];
	sciRemoveProcessDebug = sciTable_86_64_NtRemoveProcessDebug[v];
	sciRenameKey = sciTable_86_64_NtRenameKey[v];
	sciRenameTransactionManager = sciTable_86_64_NtRenameTransactionManager[v];
	sciReplaceKey = sciTable_86_64_NtReplaceKey[v];
	sciReplacePartitionUnit = sciTable_86_64_NtReplacePartitionUnit[v];
	sciReplyPort = sciTable_86_64_NtReplyPort[v];
	sciReplyWaitReceivePort = sciTable_86_64_NtReplyWaitReceivePort[v];
	sciReplyWaitReceivePortEx = sciTable_86_64_NtReplyWaitReceivePortEx[v];
	sciReplyWaitReplyPort = sciTable_86_64_NtReplyWaitReplyPort[v];
	sciRequestPort = sciTable_86_64_NtRequestPort[v];
	sciRequestWaitReplyPort = sciTable_86_64_NtRequestWaitReplyPort[v];
	sciResetEvent = sciTable_86_64_NtResetEvent[v];
	sciResetWriteWatch = sciTable_86_64_NtResetWriteWatch[v];
	sciRestoreKey = sciTable_86_64_NtRestoreKey[v];
	sciResumeProcess = sciTable_86_64_NtResumeProcess[v];
	sciResumeThread = sciTable_86_64_NtResumeThread[v];
	sciRollbackComplete = sciTable_86_64_NtRollbackComplete[v];
	sciRollbackEnlistment = sciTable_86_64_NtRollbackEnlistment[v];
	sciRollbackTransaction = sciTable_86_64_NtRollbackTransaction[v];
	sciRollforwardTransactionManager = sciTable_86_64_NtRollforwardTransactionManager[v];
	sciSaveKey = sciTable_86_64_NtSaveKey[v];
	sciSaveKeyEx = sciTable_86_64_NtSaveKeyEx[v];
	sciSaveMergedKeys = sciTable_86_64_NtSaveMergedKeys[v];
	sciSecureConnectPort = sciTable_86_64_NtSecureConnectPort[v];
	sciSerializeBoot = sciTable_86_64_NtSerializeBoot[v];
	sciSetBootEntryOrder = sciTable_86_64_NtSetBootEntryOrder[v];
	sciSetBootOptions = sciTable_86_64_NtSetBootOptions[v];
	sciSetContextThread = sciTable_86_64_NtSetContextThread[v];
	sciSetDebugFilterState = sciTable_86_64_NtSetDebugFilterState[v];
	sciSetDefaultHardErrorPort = sciTable_86_64_NtSetDefaultHardErrorPort[v];
	sciSetDefaultLocale = sciTable_86_64_NtSetDefaultLocale[v];
	sciSetDefaultUILanguage = sciTable_86_64_NtSetDefaultUILanguage[v];
	sciSetDriverEntryOrder = sciTable_86_64_NtSetDriverEntryOrder[v];
	sciSetEaFile = sciTable_86_64_NtSetEaFile[v];
	sciSetEvent = sciTable_86_64_NtSetEvent[v];
	sciSetEventBoostPriority = sciTable_86_64_NtSetEventBoostPriority[v];
	sciSetHighEventPair = sciTable_86_64_NtSetHighEventPair[v];
	sciSetHighWaitLowEventPair = sciTable_86_64_NtSetHighWaitLowEventPair[v];
	sciSetInformationDebugObject = sciTable_86_64_NtSetInformationDebugObject[v];
	sciSetInformationEnlistment = sciTable_86_64_NtSetInformationEnlistment[v];
	sciSetInformationFile = sciTable_86_64_NtSetInformationFile[v];
	sciSetInformationJobObject = sciTable_86_64_NtSetInformationJobObject[v];
	sciSetInformationKey = sciTable_86_64_NtSetInformationKey[v];
	sciSetInformationObject = sciTable_86_64_NtSetInformationObject[v];
	sciSetInformationProcess = sciTable_86_64_NtSetInformationProcess[v];
	sciSetInformationResourceManager = sciTable_86_64_NtSetInformationResourceManager[v];
	sciSetInformationThread = sciTable_86_64_NtSetInformationThread[v];
	sciSetInformationToken = sciTable_86_64_NtSetInformationToken[v];
	sciSetInformationTransaction = sciTable_86_64_NtSetInformationTransaction[v];
	sciSetInformationTransactionManager = sciTable_86_64_NtSetInformationTransactionManager[v];
	sciSetInformationWorkerFactory = sciTable_86_64_NtSetInformationWorkerFactory[v];
	sciSetIntervalProfile = sciTable_86_64_NtSetIntervalProfile[v];
	sciSetIoCompletion = sciTable_86_64_NtSetIoCompletion[v];
	sciSetIoCompletionEx = sciTable_86_64_NtSetIoCompletionEx[v];
	sciSetLdtEntries = sciTable_86_64_NtSetLdtEntries[v];
	sciSetLowEventPair = sciTable_86_64_NtSetLowEventPair[v];
	sciSetLowWaitHighEventPair = sciTable_86_64_NtSetLowWaitHighEventPair[v];
	sciSetQuotaInformationFile = sciTable_86_64_NtSetQuotaInformationFile[v];
	sciSetSecurityObject = sciTable_86_64_NtSetSecurityObject[v];
	sciSetSystemEnvironmentValue = sciTable_86_64_NtSetSystemEnvironmentValue[v];
	sciSetSystemEnvironmentValueEx = sciTable_86_64_NtSetSystemEnvironmentValueEx[v];
	sciSetSystemInformation = sciTable_86_64_NtSetSystemInformation[v];
	sciSetSystemPowerState = sciTable_86_64_NtSetSystemPowerState[v];
	sciSetSystemTime = sciTable_86_64_NtSetSystemTime[v];
	sciSetThreadExecutionState = sciTable_86_64_NtSetThreadExecutionState[v];
	sciSetTimer = sciTable_86_64_NtSetTimer[v];
	sciSetTimerEx = sciTable_86_64_NtSetTimerEx[v];
	sciSetTimerResolution = sciTable_86_64_NtSetTimerResolution[v];
	sciSetUuidSeed = sciTable_86_64_NtSetUuidSeed[v];
	sciSetValueKey = sciTable_86_64_NtSetValueKey[v];
	sciSetVolumeInformationFile = sciTable_86_64_NtSetVolumeInformationFile[v];
	sciShutdownSystem = sciTable_86_64_NtShutdownSystem[v];
	sciShutdownWorkerFactory = sciTable_86_64_NtShutdownWorkerFactory[v];
	sciSignalAndWaitForSingleObject = sciTable_86_64_NtSignalAndWaitForSingleObject[v];
	sciSinglePhaseReject = sciTable_86_64_NtSinglePhaseReject[v];
	sciStartProfile = sciTable_86_64_NtStartProfile[v];
	sciStopProfile = sciTable_86_64_NtStopProfile[v];
	sciSuspendProcess = sciTable_86_64_NtSuspendProcess[v];
	sciSuspendThread = sciTable_86_64_NtSuspendThread[v];
	sciSystemDebugControl = sciTable_86_64_NtSystemDebugControl[v];
	sciTerminateJobObject = sciTable_86_64_NtTerminateJobObject[v];
	sciTerminateProcess = sciTable_86_64_NtTerminateProcess[v];
	sciTerminateThread = sciTable_86_64_NtTerminateThread[v];
	sciTestAlert = sciTable_86_64_NtTestAlert[v];
	sciThawRegistry = sciTable_86_64_NtThawRegistry[v];
	sciThawTransactions = sciTable_86_64_NtThawTransactions[v];
	sciTraceControl = sciTable_86_64_NtTraceControl[v];
	sciTraceEvent = sciTable_86_64_NtTraceEvent[v];
	sciTranslateFilePath = sciTable_86_64_NtTranslateFilePath[v];
	sciUmsThreadYield = sciTable_86_64_NtUmsThreadYield[v];
	sciUnloadDriver = sciTable_86_64_NtUnloadDriver[v];
	sciUnloadKey = sciTable_86_64_NtUnloadKey[v];
	sciUnloadKey2 = sciTable_86_64_NtUnloadKey2[v];
	sciUnloadKeyEx = sciTable_86_64_NtUnloadKeyEx[v];
	sciUnlockFile = sciTable_86_64_NtUnlockFile[v];
	sciUnlockVirtualMemory = sciTable_86_64_NtUnlockVirtualMemory[v];
	sciUnmapViewOfSection = sciTable_86_64_NtUnmapViewOfSection[v];
	sciVdmControl = sciTable_86_64_NtVdmControl[v];
	sciWaitForDebugEvent = sciTable_86_64_NtWaitForDebugEvent[v];
	sciWaitForKeyedEvent = sciTable_86_64_NtWaitForKeyedEvent[v];
	sciWaitForMultipleObjects = sciTable_86_64_NtWaitForMultipleObjects[v];
	sciWaitForMultipleObjects32 = sciTable_86_64_NtWaitForMultipleObjects32[v];
	sciWaitForSingleObject = sciTable_86_64_NtWaitForSingleObject[v];
	sciWaitForWorkViaWorkerFactory = sciTable_86_64_NtWaitForWorkViaWorkerFactory[v];
	sciWaitHighEventPair = sciTable_86_64_NtWaitHighEventPair[v];
	sciWaitLowEventPair = sciTable_86_64_NtWaitLowEventPair[v];
	sciWorkerFactoryWorkerReady = sciTable_86_64_NtWorkerFactoryWorkerReady[v];
	sciWriteFile = sciTable_86_64_NtWriteFile[v];
	sciWriteFileGather = sciTable_86_64_NtWriteFileGather[v];
	sciWriteRequestData = sciTable_86_64_NtWriteRequestData[v];
	sciWriteVirtualMemory = sciTable_86_64_NtWriteVirtualMemory[v];
	sciYieldExecution = sciTable_86_64_NtYieldExecution[v];
#else
	if (HcGlobal.IsWow64)
	{
		/*
		sciAcceptConnectPort = sciTable_wow64_NtAcceptConnectPort[v];
		sciAccessCheck = sciTable_wow64_NtAccessCheck[v];
		sciAccessCheckAndAuditAlarm = sciTable_wow64_NtAccessCheckAndAuditAlarm[v];
		sciAccessCheckByType = sciTable_wow64_NtAccessCheckByType[v];
		sciAccessCheckByTypeAndAuditAlarm = sciTable_wow64_NtAccessCheckByTypeAndAuditAlarm[v];
		sciAccessCheckByTypeResultList = sciTable_wow64_NtAccessCheckByTypeResultList[v];
		sciAccessCheckByTypeResultListAndAuditAlarm = sciTable_wow64_NtAccessCheckByTypeResultListAndAuditAlarm[v];
		sciAccessCheckByTypeResultListAndAuditAlarmByHandle = sciTable_wow64_NtAccessCheckByTypeResultListAndAuditAlarmByHandle[v];
		sciAddAtom = sciTable_wow64_NtAddAtom[v];
		sciAddBootEntry = sciTable_wow64_NtAddBootEntry[v];
		sciAddDriverEntry = sciTable_wow64_NtAddDriverEntry[v];
		sciAdjustGroupsToken = sciTable_wow64_NtAdjustGroupsToken[v];
		sciAdjustPrivilegesToken = sciTable_wow64_NtAdjustPrivilegesToken[v];
		sciAlertResumeThread = sciTable_wow64_NtAlertResumeThread[v];
		sciAlertThread = sciTable_wow64_NtAlertThread[v];
		sciAllocateLocallyUniqueId = sciTable_wow64_NtAllocateLocallyUniqueId[v];
		sciAllocateReserveObject = sciTable_wow64_NtAllocateReserveObject[v];
		sciAllocateUserPhysicalPages = sciTable_wow64_NtAllocateUserPhysicalPages[v];
		sciAllocateUuids = sciTable_wow64_NtAllocateUuids[v];
		sciAllocateVirtualMemory = sciTable_wow64_NtAllocateVirtualMemory[v];
		sciAlpcAcceptConnectPort = sciTable_wow64_NtAlpcAcceptConnectPort[v];
		sciAlpcCancelMessage = sciTable_wow64_NtAlpcCancelMessage[v];
		sciAlpcConnectPort = sciTable_wow64_NtAlpcConnectPort[v];
		sciAlpcCreatePort = sciTable_wow64_NtAlpcCreatePort[v];
		sciAlpcCreatePortSection = sciTable_wow64_NtAlpcCreatePortSection[v];
		sciAlpcCreateResourceReserve = sciTable_wow64_NtAlpcCreateResourceReserve[v];
		sciAlpcCreateSectionView = sciTable_wow64_NtAlpcCreateSectionView[v];
		sciAlpcCreateSecurityContext = sciTable_wow64_NtAlpcCreateSecurityContext[v];
		sciAlpcDeletePortSection = sciTable_wow64_NtAlpcDeletePortSection[v];
		sciAlpcDeleteResourceReserve = sciTable_wow64_NtAlpcDeleteResourceReserve[v];
		sciAlpcDeleteSectionView = sciTable_wow64_NtAlpcDeleteSectionView[v];
		sciAlpcDeleteSecurityContext = sciTable_wow64_NtAlpcDeleteSecurityContext[v];
		sciAlpcDisconnectPort = sciTable_wow64_NtAlpcDisconnectPort[v];
		sciAlpcImpersonateClientOfPort = sciTable_wow64_NtAlpcImpersonateClientOfPort[v];
		sciAlpcOpenSenderProcess = sciTable_wow64_NtAlpcOpenSenderProcess[v];
		sciAlpcOpenSenderThread = sciTable_wow64_NtAlpcOpenSenderThread[v];
		sciAlpcQueryInformation = sciTable_wow64_NtAlpcQueryInformation[v];
		sciAlpcQueryInformationMessage = sciTable_wow64_NtAlpcQueryInformationMessage[v];
		sciAlpcRevokeSecurityContext = sciTable_wow64_NtAlpcRevokeSecurityContext[v];
		sciAlpcSendWaitReceivePort = sciTable_wow64_NtAlpcSendWaitReceivePort[v];
		sciAlpcSetInformation = sciTable_wow64_NtAlpcSetInformation[v];
		sciApphelpCacheControl = sciTable_wow64_NtApphelpCacheControl[v];
		sciAreMappedFilesTheSame = sciTable_wow64_NtAreMappedFilesTheSame[v];
		sciAssignProcessToJobObject = sciTable_wow64_NtAssignProcessToJobObject[v];
		sciCallbackReturn = sciTable_wow64_NtCallbackReturn[v];
		sciCancelIoFile = sciTable_wow64_NtCancelIoFile[v];
		sciCancelIoFileEx = sciTable_wow64_NtCancelIoFileEx[v];
		sciCancelSynchronousIoFile = sciTable_wow64_NtCancelSynchronousIoFile[v];
		sciCancelTimer = sciTable_wow64_NtCancelTimer[v];
		sciClearEvent = sciTable_wow64_NtClearEvent[v];
		sciClose = sciTable_wow64_NtClose[v];
		sciCloseObjectAuditAlarm = sciTable_wow64_NtCloseObjectAuditAlarm[v];
		sciCommitComplete = sciTable_wow64_NtCommitComplete[v];
		sciCommitEnlistment = sciTable_wow64_NtCommitEnlistment[v];
		sciCommitTransaction = sciTable_wow64_NtCommitTransaction[v];
		sciCompactKeys = sciTable_wow64_NtCompactKeys[v];
		sciCompareTokens = sciTable_wow64_NtCompareTokens[v];
		sciCompleteConnectPort = sciTable_wow64_NtCompleteConnectPort[v];
		sciCompressKey = sciTable_wow64_NtCompressKey[v];
		sciConnectPort = sciTable_wow64_NtConnectPort[v];
		sciContinue = sciTable_wow64_NtContinue[v];
		sciCreateDebugObject = sciTable_wow64_NtCreateDebugObject[v];
		sciCreateDirectoryObject = sciTable_wow64_NtCreateDirectoryObject[v];
		sciCreateEnlistment = sciTable_wow64_NtCreateEnlistment[v];
		sciCreateEvent = sciTable_wow64_NtCreateEvent[v];
		sciCreateEventPair = sciTable_wow64_NtCreateEventPair[v];
		sciCreateFile = sciTable_wow64_NtCreateFile[v];
		sciCreateIoCompletion = sciTable_wow64_NtCreateIoCompletion[v];
		sciCreateJobObject = sciTable_wow64_NtCreateJobObject[v];
		sciCreateJobSet = sciTable_wow64_NtCreateJobSet[v];
		sciCreateKey = sciTable_wow64_NtCreateKey[v];
		sciCreateKeyTransacted = sciTable_wow64_NtCreateKeyTransacted[v];
		sciCreateKeyedEvent = sciTable_wow64_NtCreateKeyedEvent[v];
		sciCreateMailslotFile = sciTable_wow64_NtCreateMailslotFile[v];
		sciCreateMutant = sciTable_wow64_NtCreateMutant[v];
		sciCreateNamedPipeFile = sciTable_wow64_NtCreateNamedPipeFile[v];
		sciCreatePagingFile = sciTable_wow64_NtCreatePagingFile[v];
		sciCreatePort = sciTable_wow64_NtCreatePort[v];
		sciCreatePrivateNamespace = sciTable_wow64_NtCreatePrivateNamespace[v];
		sciCreateProcess = sciTable_wow64_NtCreateProcess[v];
		sciCreateProcessEx = sciTable_wow64_NtCreateProcessEx[v];
		sciCreateProfile = sciTable_wow64_NtCreateProfile[v];
		sciCreateProfileEx = sciTable_wow64_NtCreateProfileEx[v];
		sciCreateResourceManager = sciTable_wow64_NtCreateResourceManager[v];
		sciCreateSection = sciTable_wow64_NtCreateSection[v];
		sciCreateSemaphore = sciTable_wow64_NtCreateSemaphore[v];
		sciCreateSymbolicLinkObject = sciTable_wow64_NtCreateSymbolicLinkObject[v];
		sciCreateThread = sciTable_wow64_NtCreateThread[v];
		sciCreateThreadEx = sciTable_wow64_NtCreateThreadEx[v];
		sciCreateTimer = sciTable_wow64_NtCreateTimer[v];
		sciCreateToken = sciTable_wow64_NtCreateToken[v];
		sciCreateTransaction = sciTable_wow64_NtCreateTransaction[v];
		sciCreateTransactionManager = sciTable_wow64_NtCreateTransactionManager[v];
		sciCreateUserProcess = sciTable_wow64_NtCreateUserProcess[v];
		sciCreateWaitablePort = sciTable_wow64_NtCreateWaitablePort[v];
		sciCreateWorkerFactory = sciTable_wow64_NtCreateWorkerFactory[v];
		sciDebugActiveProcess = sciTable_wow64_NtDebugActiveProcess[v];
		sciDebugContinue = sciTable_wow64_NtDebugContinue[v];
		sciDelayExecution = sciTable_wow64_NtDelayExecution[v];
		sciDeleteAtom = sciTable_wow64_NtDeleteAtom[v];
		sciDeleteBootEntry = sciTable_wow64_NtDeleteBootEntry[v];
		sciDeleteDriverEntry = sciTable_wow64_NtDeleteDriverEntry[v];
		sciDeleteFile = sciTable_wow64_NtDeleteFile[v];
		sciDeleteKey = sciTable_wow64_NtDeleteKey[v];
		sciDeleteObjectAuditAlarm = sciTable_wow64_NtDeleteObjectAuditAlarm[v];
		sciDeletePrivateNamespace = sciTable_wow64_NtDeletePrivateNamespace[v];
		sciDeleteValueKey = sciTable_wow64_NtDeleteValueKey[v];
		sciDeviceIoControlFile = sciTable_wow64_NtDeviceIoControlFile[v];
		sciDisableLastKnownGood = sciTable_wow64_NtDisableLastKnownGood[v];
		sciDisplayString = sciTable_wow64_NtDisplayString[v];
		sciDrawText = sciTable_wow64_NtDrawText[v];
		sciDuplicateObject = sciTable_wow64_NtDuplicateObject[v];
		sciDuplicateToken = sciTable_wow64_NtDuplicateToken[v];
		sciEnableLastKnownGood = sciTable_wow64_NtEnableLastKnownGood[v];
		sciEnumerateBootEntries = sciTable_wow64_NtEnumerateBootEntries[v];
		sciEnumerateDriverEntries = sciTable_wow64_NtEnumerateDriverEntries[v];
		sciEnumerateKey = sciTable_wow64_NtEnumerateKey[v];
		sciEnumerateSystemEnvironmentValuesEx = sciTable_wow64_NtEnumerateSystemEnvironmentValuesEx[v];
		sciEnumerateTransactionObject = sciTable_wow64_NtEnumerateTransactionObject[v];
		sciEnumerateValueKey = sciTable_wow64_NtEnumerateValueKey[v];
		sciExtendSection = sciTable_wow64_NtExtendSection[v];
		sciFilterToken = sciTable_wow64_NtFilterToken[v];
		sciFindAtom = sciTable_wow64_NtFindAtom[v];
		sciFlushBuffersFile = sciTable_wow64_NtFlushBuffersFile[v];
		sciFlushInstallUILanguage = sciTable_wow64_NtFlushInstallUILanguage[v];
		sciFlushInstructionCache = sciTable_wow64_NtFlushInstructionCache[v];
		sciFlushKey = sciTable_wow64_NtFlushKey[v];
		sciFlushProcessWriteBuffers = sciTable_wow64_NtFlushProcessWriteBuffers[v];
		sciFlushVirtualMemory = sciTable_wow64_NtFlushVirtualMemory[v];
		sciFlushWriteBuffer = sciTable_wow64_NtFlushWriteBuffer[v];
		sciFreeUserPhysicalPages = sciTable_wow64_NtFreeUserPhysicalPages[v];
		sciFreeVirtualMemory = sciTable_wow64_NtFreeVirtualMemory[v];
		sciFreezeRegistry = sciTable_wow64_NtFreezeRegistry[v];
		sciFreezeTransactions = sciTable_wow64_NtFreezeTransactions[v];
		sciFsControlFile = sciTable_wow64_NtFsControlFile[v];
		sciGetContextThread = sciTable_wow64_NtGetContextThread[v];
		sciGetCurrentProcessorNumber = sciTable_wow64_NtGetCurrentProcessorNumber[v];
		sciGetDevicePowerState = sciTable_wow64_NtGetDevicePowerState[v];
		sciGetMUIRegistryInfo = sciTable_wow64_NtGetMUIRegistryInfo[v];
		sciGetNextProcess = sciTable_wow64_NtGetNextProcess[v];
		sciGetNextThread = sciTable_wow64_NtGetNextThread[v];
		sciGetNlsSectionPtr = sciTable_wow64_NtGetNlsSectionPtr[v];
		sciGetNotificationResourceManager = sciTable_wow64_NtGetNotificationResourceManager[v];
		sciGetWriteWatch = sciTable_wow64_NtGetWriteWatch[v];
		sciImpersonateAnonymousToken = sciTable_wow64_NtImpersonateAnonymousToken[v];
		sciImpersonateClientOfPort = sciTable_wow64_NtImpersonateClientOfPort[v];
		sciImpersonateThread = sciTable_wow64_NtImpersonateThread[v];
		sciInitializeNlsFiles = sciTable_wow64_NtInitializeNlsFiles[v];
		sciInitializeRegistry = sciTable_wow64_NtInitializeRegistry[v];
		sciInitiatePowerAction = sciTable_wow64_NtInitiatePowerAction[v];
		sciIsProcessInJob = sciTable_wow64_NtIsProcessInJob[v];
		sciIsSystemResumeAutomatic = sciTable_wow64_NtIsSystemResumeAutomatic[v];
		sciIsUILanguageComitted = sciTable_wow64_NtIsUILanguageComitted[v];
		sciListenPort = sciTable_wow64_NtListenPort[v];
		sciLoadDriver = sciTable_wow64_NtLoadDriver[v];
		sciLoadKey = sciTable_wow64_NtLoadKey[v];
		sciLoadKey2 = sciTable_wow64_NtLoadKey2[v];
		sciLoadKeyEx = sciTable_wow64_NtLoadKeyEx[v];
		sciLockFile = sciTable_wow64_NtLockFile[v];
		sciLockProductActivationKeys = sciTable_wow64_NtLockProductActivationKeys[v];
		sciLockRegistryKey = sciTable_wow64_NtLockRegistryKey[v];
		sciLockVirtualMemory = sciTable_wow64_NtLockVirtualMemory[v];
		sciMakePermanentObject = sciTable_wow64_NtMakePermanentObject[v];
		sciMakeTemporaryObject = sciTable_wow64_NtMakeTemporaryObject[v];
		sciMapCMFModule = sciTable_wow64_NtMapCMFModule[v];
		sciMapUserPhysicalPages = sciTable_wow64_NtMapUserPhysicalPages[v];
		sciMapUserPhysicalPagesScatter = sciTable_wow64_NtMapUserPhysicalPagesScatter[v];
		sciMapViewOfSection = sciTable_wow64_NtMapViewOfSection[v];
		sciModifyBootEntry = sciTable_wow64_NtModifyBootEntry[v];
		sciModifyDriverEntry = sciTable_wow64_NtModifyDriverEntry[v];
		sciNotifyChangeDirectoryFile = sciTable_wow64_NtNotifyChangeDirectoryFile[v];
		sciNotifyChangeKey = sciTable_wow64_NtNotifyChangeKey[v];
		sciNotifyChangeMultipleKeys = sciTable_wow64_NtNotifyChangeMultipleKeys[v];
		sciNotifyChangeSession = sciTable_wow64_NtNotifyChangeSession[v];
		sciOpenDirectoryObject = sciTable_wow64_NtOpenDirectoryObject[v];
		sciOpenEnlistment = sciTable_wow64_NtOpenEnlistment[v];
		sciOpenEvent = sciTable_wow64_NtOpenEvent[v];
		sciOpenEventPair = sciTable_wow64_NtOpenEventPair[v];
		sciOpenFile = sciTable_wow64_NtOpenFile[v];
		sciOpenIoCompletion = sciTable_wow64_NtOpenIoCompletion[v];
		sciOpenJobObject = sciTable_wow64_NtOpenJobObject[v];
		sciOpenKey = sciTable_wow64_NtOpenKey[v];
		sciOpenKeyEx = sciTable_wow64_NtOpenKeyEx[v];
		sciOpenKeyTransacted = sciTable_wow64_NtOpenKeyTransacted[v];
		sciOpenKeyTransactedEx = sciTable_wow64_NtOpenKeyTransactedEx[v];
		sciOpenKeyedEvent = sciTable_wow64_NtOpenKeyedEvent[v];
		sciOpenMutant = sciTable_wow64_NtOpenMutant[v];
		sciOpenObjectAuditAlarm = sciTable_wow64_NtOpenObjectAuditAlarm[v];
		sciOpenPrivateNamespace = sciTable_wow64_NtOpenPrivateNamespace[v];
		sciOpenProcess = sciTable_wow64_NtOpenProcess[v];
		sciOpenProcessToken = sciTable_wow64_NtOpenProcessToken[v];
		sciOpenProcessTokenEx = sciTable_wow64_NtOpenProcessTokenEx[v];
		sciOpenResourceManager = sciTable_wow64_NtOpenResourceManager[v];
		sciOpenSection = sciTable_wow64_NtOpenSection[v];
		sciOpenSemaphore = sciTable_wow64_NtOpenSemaphore[v];
		sciOpenSession = sciTable_wow64_NtOpenSession[v];
		sciOpenSymbolicLinkObject = sciTable_wow64_NtOpenSymbolicLinkObject[v];
		sciOpenThread = sciTable_wow64_NtOpenThread[v];
		sciOpenThreadToken = sciTable_wow64_NtOpenThreadToken[v];
		sciOpenThreadTokenEx = sciTable_wow64_NtOpenThreadTokenEx[v];
		sciOpenTimer = sciTable_wow64_NtOpenTimer[v];
		sciOpenTransaction = sciTable_wow64_NtOpenTransaction[v];
		sciOpenTransactionManager = sciTable_wow64_NtOpenTransactionManager[v];
		sciPlugPlayControl = sciTable_wow64_NtPlugPlayControl[v];
		sciPowerInformation = sciTable_wow64_NtPowerInformation[v];
		sciPrePrepareComplete = sciTable_wow64_NtPrePrepareComplete[v];
		sciPrePrepareEnlistment = sciTable_wow64_NtPrePrepareEnlistment[v];
		sciPrepareComplete = sciTable_wow64_NtPrepareComplete[v];
		sciPrepareEnlistment = sciTable_wow64_NtPrepareEnlistment[v];
		sciPrivilegeCheck = sciTable_wow64_NtPrivilegeCheck[v];
		sciPrivilegeObjectAuditAlarm = sciTable_wow64_NtPrivilegeObjectAuditAlarm[v];
		sciPrivilegedServiceAuditAlarm = sciTable_wow64_NtPrivilegedServiceAuditAlarm[v];
		sciPropagationComplete = sciTable_wow64_NtPropagationComplete[v];
		sciPropagationFailed = sciTable_wow64_NtPropagationFailed[v];
		sciProtectVirtualMemory = sciTable_wow64_NtProtectVirtualMemory[v];
		sciPulseEvent = sciTable_wow64_NtPulseEvent[v];
		sciQueryAttributesFile = sciTable_wow64_NtQueryAttributesFile[v];
		sciQueryBootEntryOrder = sciTable_wow64_NtQueryBootEntryOrder[v];
		sciQueryBootOptions = sciTable_wow64_NtQueryBootOptions[v];
		sciQueryDebugFilterState = sciTable_wow64_NtQueryDebugFilterState[v];
		sciQueryDefaultLocale = sciTable_wow64_NtQueryDefaultLocale[v];
		sciQueryDefaultUILanguage = sciTable_wow64_NtQueryDefaultUILanguage[v];
		sciQueryDirectoryFile = sciTable_wow64_NtQueryDirectoryFile[v];
		sciQueryDirectoryObject = sciTable_wow64_NtQueryDirectoryObject[v];
		sciQueryDriverEntryOrder = sciTable_wow64_NtQueryDriverEntryOrder[v];
		sciQueryEaFile = sciTable_wow64_NtQueryEaFile[v];
		sciQueryEvent = sciTable_wow64_NtQueryEvent[v];
		sciQueryFullAttributesFile = sciTable_wow64_NtQueryFullAttributesFile[v];
		sciQueryInformationAtom = sciTable_wow64_NtQueryInformationAtom[v];
		sciQueryInformationEnlistment = sciTable_wow64_NtQueryInformationEnlistment[v];
		sciQueryInformationFile = sciTable_wow64_NtQueryInformationFile[v];
		sciQueryInformationJobObject = sciTable_wow64_NtQueryInformationJobObject[v];
		sciQueryInformationPort = sciTable_wow64_NtQueryInformationPort[v];
		sciQueryInformationProcess = sciTable_wow64_NtQueryInformationProcess[v];
		sciQueryInformationResourceManager = sciTable_wow64_NtQueryInformationResourceManager[v];
		sciQueryInformationThread = sciTable_wow64_NtQueryInformationThread[v];
		sciQueryInformationToken = sciTable_wow64_NtQueryInformationToken[v];
		sciQueryInformationTransaction = sciTable_wow64_NtQueryInformationTransaction[v];
		sciQueryInformationTransactionManager = sciTable_wow64_NtQueryInformationTransactionManager[v];
		sciQueryInformationWorkerFactory = sciTable_wow64_NtQueryInformationWorkerFactory[v];
		sciQueryInstallUILanguage = sciTable_wow64_NtQueryInstallUILanguage[v];
		sciQueryIntervalProfile = sciTable_wow64_NtQueryIntervalProfile[v];
		sciQueryIoCompletion = sciTable_wow64_NtQueryIoCompletion[v];
		sciQueryKey = sciTable_wow64_NtQueryKey[v];
		sciQueryLicenseValue = sciTable_wow64_NtQueryLicenseValue[v];
		sciQueryMultipleValueKey = sciTable_wow64_NtQueryMultipleValueKey[v];
		sciQueryMutant = sciTable_wow64_NtQueryMutant[v];
		sciQueryObject = sciTable_wow64_NtQueryObject[v];
		sciQueryOpenSubKeys = sciTable_wow64_NtQueryOpenSubKeys[v];
		sciQueryOpenSubKeysEx = sciTable_wow64_NtQueryOpenSubKeysEx[v];
		sciQueryPerformanceCounter = sciTable_wow64_NtQueryPerformanceCounter[v];
		sciQueryPortInformationProcess = sciTable_wow64_NtQueryPortInformationProcess[v];
		sciQueryQuotaInformationFile = sciTable_wow64_NtQueryQuotaInformationFile[v];
		sciQuerySection = sciTable_wow64_NtQuerySection[v];
		sciQuerySecurityAttributesToken = sciTable_wow64_NtQuerySecurityAttributesToken[v];
		sciQuerySecurityObject = sciTable_wow64_NtQuerySecurityObject[v];
		sciQuerySemaphore = sciTable_wow64_NtQuerySemaphore[v];
		sciQuerySymbolicLinkObject = sciTable_wow64_NtQuerySymbolicLinkObject[v];
		sciQuerySystemEnvironmentValue = sciTable_wow64_NtQuerySystemEnvironmentValue[v];
		sciQuerySystemEnvironmentValueEx = sciTable_wow64_NtQuerySystemEnvironmentValueEx[v];
		sciQuerySystemInformation = sciTable_wow64_NtQuerySystemInformation[v];
		sciQuerySystemInformationEx = sciTable_wow64_NtQuerySystemInformationEx[v];
		sciQuerySystemTime = sciTable_wow64_NtQuerySystemTime[v];
		sciQueryTimer = sciTable_wow64_NtQueryTimer[v];
		sciQueryTimerResolution = sciTable_wow64_NtQueryTimerResolution[v];
		sciQueryValueKey = sciTable_wow64_NtQueryValueKey[v];
		sciQueryVirtualMemory = sciTable_wow64_NtQueryVirtualMemory[v];
		sciQueryVolumeInformationFile = sciTable_wow64_NtQueryVolumeInformationFile[v];
		sciQueueApcThread = sciTable_wow64_NtQueueApcThread[v];
		sciQueueApcThreadEx = sciTable_wow64_NtQueueApcThreadEx[v];
		sciRaiseException = sciTable_wow64_NtRaiseException[v];
		sciRaiseHardError = sciTable_wow64_NtRaiseHardError[v];
		sciReadFile = sciTable_wow64_NtReadFile[v];
		sciReadFileScatter = sciTable_wow64_NtReadFileScatter[v];
		sciReadOnlyEnlistment = sciTable_wow64_NtReadOnlyEnlistment[v];
		sciReadRequestData = sciTable_wow64_NtReadRequestData[v];
		sciReadVirtualMemory = sciTable_wow64_NtReadVirtualMemory[v];
		sciRecoverEnlistment = sciTable_wow64_NtRecoverEnlistment[v];
		sciRecoverResourceManager = sciTable_wow64_NtRecoverResourceManager[v];
		sciRecoverTransactionManager = sciTable_wow64_NtRecoverTransactionManager[v];
		sciRegisterProtocolAddressInformation = sciTable_wow64_NtRegisterProtocolAddressInformation[v];
		sciRegisterThreadTerminatePort = sciTable_wow64_NtRegisterThreadTerminatePort[v];
		sciReleaseKeyedEvent = sciTable_wow64_NtReleaseKeyedEvent[v];
		sciReleaseMutant = sciTable_wow64_NtReleaseMutant[v];
		sciReleaseSemaphore = sciTable_wow64_NtReleaseSemaphore[v];
		sciReleaseWorkerFactoryWorker = sciTable_wow64_NtReleaseWorkerFactoryWorker[v];
		sciRemoveIoCompletion = sciTable_wow64_NtRemoveIoCompletion[v];
		sciRemoveIoCompletionEx = sciTable_wow64_NtRemoveIoCompletionEx[v];
		sciRemoveProcessDebug = sciTable_wow64_NtRemoveProcessDebug[v];
		sciRenameKey = sciTable_wow64_NtRenameKey[v];
		sciRenameTransactionManager = sciTable_wow64_NtRenameTransactionManager[v];
		sciReplaceKey = sciTable_wow64_NtReplaceKey[v];
		sciReplacePartitionUnit = sciTable_wow64_NtReplacePartitionUnit[v];
		sciReplyPort = sciTable_wow64_NtReplyPort[v];
		sciReplyWaitReceivePort = sciTable_wow64_NtReplyWaitReceivePort[v];
		sciReplyWaitReceivePortEx = sciTable_wow64_NtReplyWaitReceivePortEx[v];
		sciReplyWaitReplyPort = sciTable_wow64_NtReplyWaitReplyPort[v];
		sciRequestPort = sciTable_wow64_NtRequestPort[v];
		sciRequestWaitReplyPort = sciTable_wow64_NtRequestWaitReplyPort[v];
		sciResetEvent = sciTable_wow64_NtResetEvent[v];
		sciResetWriteWatch = sciTable_wow64_NtResetWriteWatch[v];
		sciRestoreKey = sciTable_wow64_NtRestoreKey[v];
		sciResumeProcess = sciTable_wow64_NtResumeProcess[v];
		sciResumeThread = sciTable_wow64_NtResumeThread[v];
		sciRollbackComplete = sciTable_wow64_NtRollbackComplete[v];
		sciRollbackEnlistment = sciTable_wow64_NtRollbackEnlistment[v];
		sciRollbackTransaction = sciTable_wow64_NtRollbackTransaction[v];
		sciRollforwardTransactionManager = sciTable_wow64_NtRollforwardTransactionManager[v];
		sciSaveKey = sciTable_wow64_NtSaveKey[v];
		sciSaveKeyEx = sciTable_wow64_NtSaveKeyEx[v];
		sciSaveMergedKeys = sciTable_wow64_NtSaveMergedKeys[v];
		sciSecureConnectPort = sciTable_wow64_NtSecureConnectPort[v];
		sciSerializeBoot = sciTable_wow64_NtSerializeBoot[v];
		sciSetBootEntryOrder = sciTable_wow64_NtSetBootEntryOrder[v];
		sciSetBootOptions = sciTable_wow64_NtSetBootOptions[v];
		sciSetContextThread = sciTable_wow64_NtSetContextThread[v];
		sciSetDebugFilterState = sciTable_wow64_NtSetDebugFilterState[v];
		sciSetDefaultHardErrorPort = sciTable_wow64_NtSetDefaultHardErrorPort[v];
		sciSetDefaultLocale = sciTable_wow64_NtSetDefaultLocale[v];
		sciSetDefaultUILanguage = sciTable_wow64_NtSetDefaultUILanguage[v];
		sciSetDriverEntryOrder = sciTable_wow64_NtSetDriverEntryOrder[v];
		sciSetEaFile = sciTable_wow64_NtSetEaFile[v];
		sciSetEvent = sciTable_wow64_NtSetEvent[v];
		sciSetEventBoostPriority = sciTable_wow64_NtSetEventBoostPriority[v];
		sciSetHighEventPair = sciTable_wow64_NtSetHighEventPair[v];
		sciSetHighWaitLowEventPair = sciTable_wow64_NtSetHighWaitLowEventPair[v];
		sciSetInformationDebugObject = sciTable_wow64_NtSetInformationDebugObject[v];
		sciSetInformationEnlistment = sciTable_wow64_NtSetInformationEnlistment[v];
		sciSetInformationFile = sciTable_wow64_NtSetInformationFile[v];
		sciSetInformationJobObject = sciTable_wow64_NtSetInformationJobObject[v];
		sciSetInformationKey = sciTable_wow64_NtSetInformationKey[v];
		sciSetInformationObject = sciTable_wow64_NtSetInformationObject[v];
		sciSetInformationProcess = sciTable_wow64_NtSetInformationProcess[v];
		sciSetInformationResourceManager = sciTable_wow64_NtSetInformationResourceManager[v];
		sciSetInformationThread = sciTable_wow64_NtSetInformationThread[v];
		sciSetInformationToken = sciTable_wow64_NtSetInformationToken[v];
		sciSetInformationTransaction = sciTable_wow64_NtSetInformationTransaction[v];
		sciSetInformationTransactionManager = sciTable_wow64_NtSetInformationTransactionManager[v];
		sciSetInformationWorkerFactory = sciTable_wow64_NtSetInformationWorkerFactory[v];
		sciSetIntervalProfile = sciTable_wow64_NtSetIntervalProfile[v];
		sciSetIoCompletion = sciTable_wow64_NtSetIoCompletion[v];
		sciSetIoCompletionEx = sciTable_wow64_NtSetIoCompletionEx[v];
		sciSetLdtEntries = sciTable_wow64_NtSetLdtEntries[v];
		sciSetLowEventPair = sciTable_wow64_NtSetLowEventPair[v];
		sciSetLowWaitHighEventPair = sciTable_wow64_NtSetLowWaitHighEventPair[v];
		sciSetQuotaInformationFile = sciTable_wow64_NtSetQuotaInformationFile[v];
		sciSetSecurityObject = sciTable_wow64_NtSetSecurityObject[v];
		sciSetSystemEnvironmentValue = sciTable_wow64_NtSetSystemEnvironmentValue[v];
		sciSetSystemEnvironmentValueEx = sciTable_wow64_NtSetSystemEnvironmentValueEx[v];
		sciSetSystemInformation = sciTable_wow64_NtSetSystemInformation[v];
		sciSetSystemPowerState = sciTable_wow64_NtSetSystemPowerState[v];
		sciSetSystemTime = sciTable_wow64_NtSetSystemTime[v];
		sciSetThreadExecutionState = sciTable_wow64_NtSetThreadExecutionState[v];
		sciSetTimer = sciTable_wow64_NtSetTimer[v];
		sciSetTimerEx = sciTable_wow64_NtSetTimerEx[v];
		sciSetTimerResolution = sciTable_wow64_NtSetTimerResolution[v];
		sciSetUuidSeed = sciTable_wow64_NtSetUuidSeed[v];
		sciSetValueKey = sciTable_wow64_NtSetValueKey[v];
		sciSetVolumeInformationFile = sciTable_wow64_NtSetVolumeInformationFile[v];
		sciShutdownSystem = sciTable_wow64_NtShutdownSystem[v];
		sciShutdownWorkerFactory = sciTable_wow64_NtShutdownWorkerFactory[v];
		sciSignalAndWaitForSingleObject = sciTable_wow64_NtSignalAndWaitForSingleObject[v];
		sciSinglePhaseReject = sciTable_wow64_NtSinglePhaseReject[v];
		sciStartProfile = sciTable_wow64_NtStartProfile[v];
		sciStopProfile = sciTable_wow64_NtStopProfile[v];
		sciSuspendProcess = sciTable_wow64_NtSuspendProcess[v];
		sciSuspendThread = sciTable_wow64_NtSuspendThread[v];
		sciSystemDebugControl = sciTable_wow64_NtSystemDebugControl[v];
		sciTerminateJobObject = sciTable_wow64_NtTerminateJobObject[v];
		sciTerminateProcess = sciTable_wow64_NtTerminateProcess[v];
		sciTerminateThread = sciTable_wow64_NtTerminateThread[v];
		sciTestAlert = sciTable_wow64_NtTestAlert[v];
		sciThawRegistry = sciTable_wow64_NtThawRegistry[v];
		sciThawTransactions = sciTable_wow64_NtThawTransactions[v];
		sciTraceControl = sciTable_wow64_NtTraceControl[v];
		sciTraceEvent = sciTable_wow64_NtTraceEvent[v];
		sciTranslateFilePath = sciTable_wow64_NtTranslateFilePath[v];
		sciUmsThreadYield = sciTable_wow64_NtUmsThreadYield[v];
		sciUnloadDriver = sciTable_wow64_NtUnloadDriver[v];
		sciUnloadKey = sciTable_wow64_NtUnloadKey[v];
		sciUnloadKey2 = sciTable_wow64_NtUnloadKey2[v];
		sciUnloadKeyEx = sciTable_wow64_NtUnloadKeyEx[v];
		sciUnlockFile = sciTable_wow64_NtUnlockFile[v];
		sciUnlockVirtualMemory = sciTable_wow64_NtUnlockVirtualMemory[v];
		sciUnmapViewOfSection = sciTable_wow64_NtUnmapViewOfSection[v];
		sciVdmControl = sciTable_wow64_NtVdmControl[v];
		sciWaitForDebugEvent = sciTable_wow64_NtWaitForDebugEvent[v];
		sciWaitForKeyedEvent = sciTable_wow64_NtWaitForKeyedEvent[v];
		sciWaitForMultipleObjects = sciTable_wow64_NtWaitForMultipleObjects[v];
		sciWaitForMultipleObjects32 = sciTable_wow64_NtWaitForMultipleObjects32[v];
		sciWaitForSingleObject = sciTable_wow64_NtWaitForSingleObject[v];
		sciWaitForWorkViaWorkerFactory = sciTable_wow64_NtWaitForWorkViaWorkerFactory[v];
		sciWaitHighEventPair = sciTable_wow64_NtWaitHighEventPair[v];
		sciWaitLowEventPair = sciTable_wow64_NtWaitLowEventPair[v];
		sciWorkerFactoryWorkerReady = sciTable_wow64_NtWorkerFactoryWorkerReady[v];
		sciWriteFile = sciTable_wow64_NtWriteFile[v];
		sciWriteFileGather = sciTable_wow64_NtWriteFileGather[v];
		sciWriteRequestData = sciTable_wow64_NtWriteRequestData[v];
		sciWriteVirtualMemory = sciTable_wow64_NtWriteVirtualMemory[v];
		sciYieldExecution = sciTable_wow64_NtYieldExecution[v];

		sciClose64 = sciTable_86_64_NtClose[v];
		sciCreateThreadEx64 = sciTable_86_64_NtCreateThreadEx[v];

		sciWow64CallFunction64 = sciTable_wow64_NtWow64CallFunction64[v];
		sciWow64CsrAllocateCaptureBuffer = sciTable_wow64_NtWow64CsrAllocateCaptureBuffer[v];
		sciWow64CsrAllocateMessagePointer = sciTable_wow64_NtWow64CsrAllocateMessagePointer[v];
		sciWow64CsrCaptureMessageBuffer = sciTable_wow64_NtWow64CsrCaptureMessageBuffer[v];
		sciWow64CsrCaptureMessageString = sciTable_wow64_NtWow64CsrCaptureMessageString[v];
		sciWow64CsrClientCallServer = sciTable_wow64_NtWow64CsrClientCallServer[v];
		sciWow64CsrClientConnectToServer = sciTable_wow64_NtWow64CsrClientConnectToServer[v];
		sciWow64CsrFreeCaptureBuffer = sciTable_wow64_NtWow64CsrFreeCaptureBuffer[v];
		sciWow64CsrGetProcessId = sciTable_wow64_NtWow64CsrGetProcessId[v];
		sciWow64CsrIdentifyAlertableThread = sciTable_wow64_NtWow64CsrIdentifyAlertableThread[v];
		sciWow64CsrVerifyRegion = sciTable_wow64_NtWow64CsrVerifyRegion[v];
		sciWow64DebuggerCall = sciTable_wow64_NtWow64DebuggerCall[v];
		sciWow64GetCurrentProcessorNumberEx = sciTable_wow64_NtWow64GetCurrentProcessorNumberEx[v];
		sciWow64GetNativeSystemInformation = sciTable_wow64_NtWow64GetNativeSystemInformation[v];
		sciWow64QueryInformationProcess64 = sciTable_wow64_NtWow64QueryInformationProcess64[v];
		sciWow64ReadVirtualMemory64 = sciTable_wow64_NtWow64ReadVirtualMemory64[v];
		sciWow64WriteVirtualMemory64 = sciTable_wow64_NtWow64WriteVirtualMemory64[v];
		sciWow64AllocateVirtualMemory64 = sciTable_wow64_NtWow64AllocateVirtualMemory64[v];
		*/


		sciAcceptConnectPort = sciTable_86_64_NtAcceptConnectPort[v];
		sciAccessCheck = sciTable_86_64_NtAccessCheck[v];
		sciAccessCheckAndAuditAlarm = sciTable_86_64_NtAccessCheckAndAuditAlarm[v];
		sciAccessCheckByType = sciTable_86_64_NtAccessCheckByType[v];
		sciAccessCheckByTypeAndAuditAlarm = sciTable_86_64_NtAccessCheckByTypeAndAuditAlarm[v];
		sciAccessCheckByTypeResultList = sciTable_86_64_NtAccessCheckByTypeResultList[v];
		sciAccessCheckByTypeResultListAndAuditAlarm = sciTable_86_64_NtAccessCheckByTypeResultListAndAuditAlarm[v];
		sciAccessCheckByTypeResultListAndAuditAlarmByHandle = sciTable_86_64_NtAccessCheckByTypeResultListAndAuditAlarmByHandle[v];
		sciAddAtom = sciTable_86_64_NtAddAtom[v];
		sciAddBootEntry = sciTable_86_64_NtAddBootEntry[v];
		sciAddDriverEntry = sciTable_86_64_NtAddDriverEntry[v];
		sciAdjustGroupsToken = sciTable_86_64_NtAdjustGroupsToken[v];
		sciAdjustPrivilegesToken = sciTable_86_64_NtAdjustPrivilegesToken[v];
		sciAlertResumeThread = sciTable_86_64_NtAlertResumeThread[v];
		sciAlertThread = sciTable_86_64_NtAlertThread[v];
		sciAllocateLocallyUniqueId = sciTable_86_64_NtAllocateLocallyUniqueId[v];
		sciAllocateReserveObject = sciTable_86_64_NtAllocateReserveObject[v];
		sciAllocateUserPhysicalPages = sciTable_86_64_NtAllocateUserPhysicalPages[v];
		sciAllocateUuids = sciTable_86_64_NtAllocateUuids[v];
		sciAllocateVirtualMemory = sciTable_86_64_NtAllocateVirtualMemory[v];
		sciAlpcAcceptConnectPort = sciTable_86_64_NtAlpcAcceptConnectPort[v];
		sciAlpcCancelMessage = sciTable_86_64_NtAlpcCancelMessage[v];
		sciAlpcConnectPort = sciTable_86_64_NtAlpcConnectPort[v];
		sciAlpcCreatePort = sciTable_86_64_NtAlpcCreatePort[v];
		sciAlpcCreatePortSection = sciTable_86_64_NtAlpcCreatePortSection[v];
		sciAlpcCreateResourceReserve = sciTable_86_64_NtAlpcCreateResourceReserve[v];
		sciAlpcCreateSectionView = sciTable_86_64_NtAlpcCreateSectionView[v];
		sciAlpcCreateSecurityContext = sciTable_86_64_NtAlpcCreateSecurityContext[v];
		sciAlpcDeletePortSection = sciTable_86_64_NtAlpcDeletePortSection[v];
		sciAlpcDeleteResourceReserve = sciTable_86_64_NtAlpcDeleteResourceReserve[v];
		sciAlpcDeleteSectionView = sciTable_86_64_NtAlpcDeleteSectionView[v];
		sciAlpcDeleteSecurityContext = sciTable_86_64_NtAlpcDeleteSecurityContext[v];
		sciAlpcDisconnectPort = sciTable_86_64_NtAlpcDisconnectPort[v];
		sciAlpcImpersonateClientOfPort = sciTable_86_64_NtAlpcImpersonateClientOfPort[v];
		sciAlpcOpenSenderProcess = sciTable_86_64_NtAlpcOpenSenderProcess[v];
		sciAlpcOpenSenderThread = sciTable_86_64_NtAlpcOpenSenderThread[v];
		sciAlpcQueryInformation = sciTable_86_64_NtAlpcQueryInformation[v];
		sciAlpcQueryInformationMessage = sciTable_86_64_NtAlpcQueryInformationMessage[v];
		sciAlpcRevokeSecurityContext = sciTable_86_64_NtAlpcRevokeSecurityContext[v];
		sciAlpcSendWaitReceivePort = sciTable_86_64_NtAlpcSendWaitReceivePort[v];
		sciAlpcSetInformation = sciTable_86_64_NtAlpcSetInformation[v];
		sciApphelpCacheControl = sciTable_86_64_NtApphelpCacheControl[v];
		sciAreMappedFilesTheSame = sciTable_86_64_NtAreMappedFilesTheSame[v];
		sciAssignProcessToJobObject = sciTable_86_64_NtAssignProcessToJobObject[v];
		sciCallbackReturn = sciTable_86_64_NtCallbackReturn[v];
		sciCancelIoFile = sciTable_86_64_NtCancelIoFile[v];
		sciCancelIoFileEx = sciTable_86_64_NtCancelIoFileEx[v];
		sciCancelSynchronousIoFile = sciTable_86_64_NtCancelSynchronousIoFile[v];
		sciCancelTimer = sciTable_86_64_NtCancelTimer[v];
		sciClearEvent = sciTable_86_64_NtClearEvent[v];
		sciClose = sciTable_86_64_NtClose[v];
		sciCloseObjectAuditAlarm = sciTable_86_64_NtCloseObjectAuditAlarm[v];
		sciCommitComplete = sciTable_86_64_NtCommitComplete[v];
		sciCommitEnlistment = sciTable_86_64_NtCommitEnlistment[v];
		sciCommitTransaction = sciTable_86_64_NtCommitTransaction[v];
		sciCompactKeys = sciTable_86_64_NtCompactKeys[v];
		sciCompareTokens = sciTable_86_64_NtCompareTokens[v];
		sciCompleteConnectPort = sciTable_86_64_NtCompleteConnectPort[v];
		sciCompressKey = sciTable_86_64_NtCompressKey[v];
		sciConnectPort = sciTable_86_64_NtConnectPort[v];
		sciContinue = sciTable_86_64_NtContinue[v];
		sciCreateDebugObject = sciTable_86_64_NtCreateDebugObject[v];
		sciCreateDirectoryObject = sciTable_86_64_NtCreateDirectoryObject[v];
		sciCreateEnlistment = sciTable_86_64_NtCreateEnlistment[v];
		sciCreateEvent = sciTable_86_64_NtCreateEvent[v];
		sciCreateEventPair = sciTable_86_64_NtCreateEventPair[v];
		sciCreateFile = sciTable_86_64_NtCreateFile[v];
		sciCreateIoCompletion = sciTable_86_64_NtCreateIoCompletion[v];
		sciCreateJobObject = sciTable_86_64_NtCreateJobObject[v];
		sciCreateJobSet = sciTable_86_64_NtCreateJobSet[v];
		sciCreateKey = sciTable_86_64_NtCreateKey[v];
		sciCreateKeyTransacted = sciTable_86_64_NtCreateKeyTransacted[v];
		sciCreateKeyedEvent = sciTable_86_64_NtCreateKeyedEvent[v];
		sciCreateMailslotFile = sciTable_86_64_NtCreateMailslotFile[v];
		sciCreateMutant = sciTable_86_64_NtCreateMutant[v];
		sciCreateNamedPipeFile = sciTable_86_64_NtCreateNamedPipeFile[v];
		sciCreatePagingFile = sciTable_86_64_NtCreatePagingFile[v];
		sciCreatePort = sciTable_86_64_NtCreatePort[v];
		sciCreatePrivateNamespace = sciTable_86_64_NtCreatePrivateNamespace[v];
		sciCreateProcess = sciTable_86_64_NtCreateProcess[v];
		sciCreateProcessEx = sciTable_86_64_NtCreateProcessEx[v];
		sciCreateProfile = sciTable_86_64_NtCreateProfile[v];
		sciCreateProfileEx = sciTable_86_64_NtCreateProfileEx[v];
		sciCreateResourceManager = sciTable_86_64_NtCreateResourceManager[v];
		sciCreateSection = sciTable_86_64_NtCreateSection[v];
		sciCreateSemaphore = sciTable_86_64_NtCreateSemaphore[v];
		sciCreateSymbolicLinkObject = sciTable_86_64_NtCreateSymbolicLinkObject[v];
		sciCreateThread = sciTable_86_64_NtCreateThread[v];
		sciCreateThreadEx = sciTable_86_64_NtCreateThreadEx[v];
		sciCreateTimer = sciTable_86_64_NtCreateTimer[v];
		sciCreateToken = sciTable_86_64_NtCreateToken[v];
		sciCreateTransaction = sciTable_86_64_NtCreateTransaction[v];
		sciCreateTransactionManager = sciTable_86_64_NtCreateTransactionManager[v];
		sciCreateUserProcess = sciTable_86_64_NtCreateUserProcess[v];
		sciCreateWaitablePort = sciTable_86_64_NtCreateWaitablePort[v];
		sciCreateWorkerFactory = sciTable_86_64_NtCreateWorkerFactory[v];
		sciDebugActiveProcess = sciTable_86_64_NtDebugActiveProcess[v];
		sciDebugContinue = sciTable_86_64_NtDebugContinue[v];
		sciDelayExecution = sciTable_86_64_NtDelayExecution[v];
		sciDeleteAtom = sciTable_86_64_NtDeleteAtom[v];
		sciDeleteBootEntry = sciTable_86_64_NtDeleteBootEntry[v];
		sciDeleteDriverEntry = sciTable_86_64_NtDeleteDriverEntry[v];
		sciDeleteFile = sciTable_86_64_NtDeleteFile[v];
		sciDeleteKey = sciTable_86_64_NtDeleteKey[v];
		sciDeleteObjectAuditAlarm = sciTable_86_64_NtDeleteObjectAuditAlarm[v];
		sciDeletePrivateNamespace = sciTable_86_64_NtDeletePrivateNamespace[v];
		sciDeleteValueKey = sciTable_86_64_NtDeleteValueKey[v];
		sciDeviceIoControlFile = sciTable_86_64_NtDeviceIoControlFile[v];
		sciDisableLastKnownGood = sciTable_86_64_NtDisableLastKnownGood[v];
		sciDisplayString = sciTable_86_64_NtDisplayString[v];
		sciDrawText = sciTable_86_64_NtDrawText[v];
		sciDuplicateObject = sciTable_86_64_NtDuplicateObject[v];
		sciDuplicateToken = sciTable_86_64_NtDuplicateToken[v];
		sciEnableLastKnownGood = sciTable_86_64_NtEnableLastKnownGood[v];
		sciEnumerateBootEntries = sciTable_86_64_NtEnumerateBootEntries[v];
		sciEnumerateDriverEntries = sciTable_86_64_NtEnumerateDriverEntries[v];
		sciEnumerateKey = sciTable_86_64_NtEnumerateKey[v];
		sciEnumerateSystemEnvironmentValuesEx = sciTable_86_64_NtEnumerateSystemEnvironmentValuesEx[v];
		sciEnumerateTransactionObject = sciTable_86_64_NtEnumerateTransactionObject[v];
		sciEnumerateValueKey = sciTable_86_64_NtEnumerateValueKey[v];
		sciExtendSection = sciTable_86_64_NtExtendSection[v];
		sciFilterToken = sciTable_86_64_NtFilterToken[v];
		sciFindAtom = sciTable_86_64_NtFindAtom[v];
		sciFlushBuffersFile = sciTable_86_64_NtFlushBuffersFile[v];
		sciFlushInstallUILanguage = sciTable_86_64_NtFlushInstallUILanguage[v];
		sciFlushInstructionCache = sciTable_86_64_NtFlushInstructionCache[v];
		sciFlushKey = sciTable_86_64_NtFlushKey[v];
		sciFlushProcessWriteBuffers = sciTable_86_64_NtFlushProcessWriteBuffers[v];
		sciFlushVirtualMemory = sciTable_86_64_NtFlushVirtualMemory[v];
		sciFlushWriteBuffer = sciTable_86_64_NtFlushWriteBuffer[v];
		sciFreeUserPhysicalPages = sciTable_86_64_NtFreeUserPhysicalPages[v];
		sciFreeVirtualMemory = sciTable_86_64_NtFreeVirtualMemory[v];
		sciFreezeRegistry = sciTable_86_64_NtFreezeRegistry[v];
		sciFreezeTransactions = sciTable_86_64_NtFreezeTransactions[v];
		sciFsControlFile = sciTable_86_64_NtFsControlFile[v];
		sciGetContextThread = sciTable_86_64_NtGetContextThread[v];
		sciGetCurrentProcessorNumber = sciTable_86_64_NtGetCurrentProcessorNumber[v];
		sciGetDevicePowerState = sciTable_86_64_NtGetDevicePowerState[v];
		sciGetMUIRegistryInfo = sciTable_86_64_NtGetMUIRegistryInfo[v];
		sciGetNextProcess = sciTable_86_64_NtGetNextProcess[v];
		sciGetNextThread = sciTable_86_64_NtGetNextThread[v];
		sciGetNlsSectionPtr = sciTable_86_64_NtGetNlsSectionPtr[v];
		sciGetNotificationResourceManager = sciTable_86_64_NtGetNotificationResourceManager[v];
		sciGetWriteWatch = sciTable_86_64_NtGetWriteWatch[v];
		sciImpersonateAnonymousToken = sciTable_86_64_NtImpersonateAnonymousToken[v];
		sciImpersonateClientOfPort = sciTable_86_64_NtImpersonateClientOfPort[v];
		sciImpersonateThread = sciTable_86_64_NtImpersonateThread[v];
		sciInitializeNlsFiles = sciTable_86_64_NtInitializeNlsFiles[v];
		sciInitializeRegistry = sciTable_86_64_NtInitializeRegistry[v];
		sciInitiatePowerAction = sciTable_86_64_NtInitiatePowerAction[v];
		sciIsProcessInJob = sciTable_86_64_NtIsProcessInJob[v];
		sciIsSystemResumeAutomatic = sciTable_86_64_NtIsSystemResumeAutomatic[v];
		sciIsUILanguageComitted = sciTable_86_64_NtIsUILanguageComitted[v];
		sciListenPort = sciTable_86_64_NtListenPort[v];
		sciLoadDriver = sciTable_86_64_NtLoadDriver[v];
		sciLoadKey = sciTable_86_64_NtLoadKey[v];
		sciLoadKey2 = sciTable_86_64_NtLoadKey2[v];
		sciLoadKeyEx = sciTable_86_64_NtLoadKeyEx[v];
		sciLockFile = sciTable_86_64_NtLockFile[v];
		sciLockProductActivationKeys = sciTable_86_64_NtLockProductActivationKeys[v];
		sciLockRegistryKey = sciTable_86_64_NtLockRegistryKey[v];
		sciLockVirtualMemory = sciTable_86_64_NtLockVirtualMemory[v];
		sciMakePermanentObject = sciTable_86_64_NtMakePermanentObject[v];
		sciMakeTemporaryObject = sciTable_86_64_NtMakeTemporaryObject[v];
		sciMapCMFModule = sciTable_86_64_NtMapCMFModule[v];
		sciMapUserPhysicalPages = sciTable_86_64_NtMapUserPhysicalPages[v];
		sciMapUserPhysicalPagesScatter = sciTable_86_64_NtMapUserPhysicalPagesScatter[v];
		sciMapViewOfSection = sciTable_86_64_NtMapViewOfSection[v];
		sciModifyBootEntry = sciTable_86_64_NtModifyBootEntry[v];
		sciModifyDriverEntry = sciTable_86_64_NtModifyDriverEntry[v];
		sciNotifyChangeDirectoryFile = sciTable_86_64_NtNotifyChangeDirectoryFile[v];
		sciNotifyChangeKey = sciTable_86_64_NtNotifyChangeKey[v];
		sciNotifyChangeMultipleKeys = sciTable_86_64_NtNotifyChangeMultipleKeys[v];
		sciNotifyChangeSession = sciTable_86_64_NtNotifyChangeSession[v];
		sciOpenDirectoryObject = sciTable_86_64_NtOpenDirectoryObject[v];
		sciOpenEnlistment = sciTable_86_64_NtOpenEnlistment[v];
		sciOpenEvent = sciTable_86_64_NtOpenEvent[v];
		sciOpenEventPair = sciTable_86_64_NtOpenEventPair[v];
		sciOpenFile = sciTable_86_64_NtOpenFile[v];
		sciOpenIoCompletion = sciTable_86_64_NtOpenIoCompletion[v];
		sciOpenJobObject = sciTable_86_64_NtOpenJobObject[v];
		sciOpenKey = sciTable_86_64_NtOpenKey[v];
		sciOpenKeyEx = sciTable_86_64_NtOpenKeyEx[v];
		sciOpenKeyTransacted = sciTable_86_64_NtOpenKeyTransacted[v];
		sciOpenKeyTransactedEx = sciTable_86_64_NtOpenKeyTransactedEx[v];
		sciOpenKeyedEvent = sciTable_86_64_NtOpenKeyedEvent[v];
		sciOpenMutant = sciTable_86_64_NtOpenMutant[v];
		sciOpenObjectAuditAlarm = sciTable_86_64_NtOpenObjectAuditAlarm[v];
		sciOpenPrivateNamespace = sciTable_86_64_NtOpenPrivateNamespace[v];
		sciOpenProcess = sciTable_86_64_NtOpenProcess[v];
		sciOpenProcessToken = sciTable_86_64_NtOpenProcessToken[v];
		sciOpenProcessTokenEx = sciTable_86_64_NtOpenProcessTokenEx[v];
		sciOpenResourceManager = sciTable_86_64_NtOpenResourceManager[v];
		sciOpenSection = sciTable_86_64_NtOpenSection[v];
		sciOpenSemaphore = sciTable_86_64_NtOpenSemaphore[v];
		sciOpenSession = sciTable_86_64_NtOpenSession[v];
		sciOpenSymbolicLinkObject = sciTable_86_64_NtOpenSymbolicLinkObject[v];
		sciOpenThread = sciTable_86_64_NtOpenThread[v];
		sciOpenThreadToken = sciTable_86_64_NtOpenThreadToken[v];
		sciOpenThreadTokenEx = sciTable_86_64_NtOpenThreadTokenEx[v];
		sciOpenTimer = sciTable_86_64_NtOpenTimer[v];
		sciOpenTransaction = sciTable_86_64_NtOpenTransaction[v];
		sciOpenTransactionManager = sciTable_86_64_NtOpenTransactionManager[v];
		sciPlugPlayControl = sciTable_86_64_NtPlugPlayControl[v];
		sciPowerInformation = sciTable_86_64_NtPowerInformation[v];
		sciPrePrepareComplete = sciTable_86_64_NtPrePrepareComplete[v];
		sciPrePrepareEnlistment = sciTable_86_64_NtPrePrepareEnlistment[v];
		sciPrepareComplete = sciTable_86_64_NtPrepareComplete[v];
		sciPrepareEnlistment = sciTable_86_64_NtPrepareEnlistment[v];
		sciPrivilegeCheck = sciTable_86_64_NtPrivilegeCheck[v];
		sciPrivilegeObjectAuditAlarm = sciTable_86_64_NtPrivilegeObjectAuditAlarm[v];
		sciPrivilegedServiceAuditAlarm = sciTable_86_64_NtPrivilegedServiceAuditAlarm[v];
		sciPropagationComplete = sciTable_86_64_NtPropagationComplete[v];
		sciPropagationFailed = sciTable_86_64_NtPropagationFailed[v];
		sciProtectVirtualMemory = sciTable_86_64_NtProtectVirtualMemory[v];
		sciPulseEvent = sciTable_86_64_NtPulseEvent[v];
		sciQueryAttributesFile = sciTable_86_64_NtQueryAttributesFile[v];
		sciQueryBootEntryOrder = sciTable_86_64_NtQueryBootEntryOrder[v];
		sciQueryBootOptions = sciTable_86_64_NtQueryBootOptions[v];
		sciQueryDebugFilterState = sciTable_86_64_NtQueryDebugFilterState[v];
		sciQueryDefaultLocale = sciTable_86_64_NtQueryDefaultLocale[v];
		sciQueryDefaultUILanguage = sciTable_86_64_NtQueryDefaultUILanguage[v];
		sciQueryDirectoryFile = sciTable_86_64_NtQueryDirectoryFile[v];
		sciQueryDirectoryObject = sciTable_86_64_NtQueryDirectoryObject[v];
		sciQueryDriverEntryOrder = sciTable_86_64_NtQueryDriverEntryOrder[v];
		sciQueryEaFile = sciTable_86_64_NtQueryEaFile[v];
		sciQueryEvent = sciTable_86_64_NtQueryEvent[v];
		sciQueryFullAttributesFile = sciTable_86_64_NtQueryFullAttributesFile[v];
		sciQueryInformationAtom = sciTable_86_64_NtQueryInformationAtom[v];
		sciQueryInformationEnlistment = sciTable_86_64_NtQueryInformationEnlistment[v];
		sciQueryInformationFile = sciTable_86_64_NtQueryInformationFile[v];
		sciQueryInformationJobObject = sciTable_86_64_NtQueryInformationJobObject[v];
		sciQueryInformationPort = sciTable_86_64_NtQueryInformationPort[v];
		sciQueryInformationProcess = sciTable_86_64_NtQueryInformationProcess[v];
		sciQueryInformationResourceManager = sciTable_86_64_NtQueryInformationResourceManager[v];
		sciQueryInformationThread = sciTable_86_64_NtQueryInformationThread[v];
		sciQueryInformationToken = sciTable_86_64_NtQueryInformationToken[v];
		sciQueryInformationTransaction = sciTable_86_64_NtQueryInformationTransaction[v];
		sciQueryInformationTransactionManager = sciTable_86_64_NtQueryInformationTransactionManager[v];
		sciQueryInformationWorkerFactory = sciTable_86_64_NtQueryInformationWorkerFactory[v];
		sciQueryInstallUILanguage = sciTable_86_64_NtQueryInstallUILanguage[v];
		sciQueryIntervalProfile = sciTable_86_64_NtQueryIntervalProfile[v];
		sciQueryIoCompletion = sciTable_86_64_NtQueryIoCompletion[v];
		sciQueryKey = sciTable_86_64_NtQueryKey[v];
		sciQueryLicenseValue = sciTable_86_64_NtQueryLicenseValue[v];
		sciQueryMultipleValueKey = sciTable_86_64_NtQueryMultipleValueKey[v];
		sciQueryMutant = sciTable_86_64_NtQueryMutant[v];
		sciQueryObject = sciTable_86_64_NtQueryObject[v];
		sciQueryOpenSubKeys = sciTable_86_64_NtQueryOpenSubKeys[v];
		sciQueryOpenSubKeysEx = sciTable_86_64_NtQueryOpenSubKeysEx[v];
		sciQueryPerformanceCounter = sciTable_86_64_NtQueryPerformanceCounter[v];
		sciQueryPortInformationProcess = sciTable_86_64_NtQueryPortInformationProcess[v];
		sciQueryQuotaInformationFile = sciTable_86_64_NtQueryQuotaInformationFile[v];
		sciQuerySection = sciTable_86_64_NtQuerySection[v];
		sciQuerySecurityAttributesToken = sciTable_86_64_NtQuerySecurityAttributesToken[v];
		sciQuerySecurityObject = sciTable_86_64_NtQuerySecurityObject[v];
		sciQuerySemaphore = sciTable_86_64_NtQuerySemaphore[v];
		sciQuerySymbolicLinkObject = sciTable_86_64_NtQuerySymbolicLinkObject[v];
		sciQuerySystemEnvironmentValue = sciTable_86_64_NtQuerySystemEnvironmentValue[v];
		sciQuerySystemEnvironmentValueEx = sciTable_86_64_NtQuerySystemEnvironmentValueEx[v];
		sciQuerySystemInformation = sciTable_86_64_NtQuerySystemInformation[v];
		sciQuerySystemInformationEx = sciTable_86_64_NtQuerySystemInformationEx[v];
		sciQuerySystemTime = sciTable_86_64_NtQuerySystemTime[v];
		sciQueryTimer = sciTable_86_64_NtQueryTimer[v];
		sciQueryTimerResolution = sciTable_86_64_NtQueryTimerResolution[v];
		sciQueryValueKey = sciTable_86_64_NtQueryValueKey[v];
		sciQueryVirtualMemory = sciTable_86_64_NtQueryVirtualMemory[v];
		sciQueryVolumeInformationFile = sciTable_86_64_NtQueryVolumeInformationFile[v];
		sciQueueApcThread = sciTable_86_64_NtQueueApcThread[v];
		sciQueueApcThreadEx = sciTable_86_64_NtQueueApcThreadEx[v];
		sciRaiseException = sciTable_86_64_NtRaiseException[v];
		sciRaiseHardError = sciTable_86_64_NtRaiseHardError[v];
		sciReadFile = sciTable_86_64_NtReadFile[v];
		sciReadFileScatter = sciTable_86_64_NtReadFileScatter[v];
		sciReadOnlyEnlistment = sciTable_86_64_NtReadOnlyEnlistment[v];
		sciReadRequestData = sciTable_86_64_NtReadRequestData[v];
		sciReadVirtualMemory = sciTable_86_64_NtReadVirtualMemory[v];
		sciRecoverEnlistment = sciTable_86_64_NtRecoverEnlistment[v];
		sciRecoverResourceManager = sciTable_86_64_NtRecoverResourceManager[v];
		sciRecoverTransactionManager = sciTable_86_64_NtRecoverTransactionManager[v];
		sciRegisterProtocolAddressInformation = sciTable_86_64_NtRegisterProtocolAddressInformation[v];
		sciRegisterThreadTerminatePort = sciTable_86_64_NtRegisterThreadTerminatePort[v];
		sciReleaseKeyedEvent = sciTable_86_64_NtReleaseKeyedEvent[v];
		sciReleaseMutant = sciTable_86_64_NtReleaseMutant[v];
		sciReleaseSemaphore = sciTable_86_64_NtReleaseSemaphore[v];
		sciReleaseWorkerFactoryWorker = sciTable_86_64_NtReleaseWorkerFactoryWorker[v];
		sciRemoveIoCompletion = sciTable_86_64_NtRemoveIoCompletion[v];
		sciRemoveIoCompletionEx = sciTable_86_64_NtRemoveIoCompletionEx[v];
		sciRemoveProcessDebug = sciTable_86_64_NtRemoveProcessDebug[v];
		sciRenameKey = sciTable_86_64_NtRenameKey[v];
		sciRenameTransactionManager = sciTable_86_64_NtRenameTransactionManager[v];
		sciReplaceKey = sciTable_86_64_NtReplaceKey[v];
		sciReplacePartitionUnit = sciTable_86_64_NtReplacePartitionUnit[v];
		sciReplyPort = sciTable_86_64_NtReplyPort[v];
		sciReplyWaitReceivePort = sciTable_86_64_NtReplyWaitReceivePort[v];
		sciReplyWaitReceivePortEx = sciTable_86_64_NtReplyWaitReceivePortEx[v];
		sciReplyWaitReplyPort = sciTable_86_64_NtReplyWaitReplyPort[v];
		sciRequestPort = sciTable_86_64_NtRequestPort[v];
		sciRequestWaitReplyPort = sciTable_86_64_NtRequestWaitReplyPort[v];
		sciResetEvent = sciTable_86_64_NtResetEvent[v];
		sciResetWriteWatch = sciTable_86_64_NtResetWriteWatch[v];
		sciRestoreKey = sciTable_86_64_NtRestoreKey[v];
		sciResumeProcess = sciTable_86_64_NtResumeProcess[v];
		sciResumeThread = sciTable_86_64_NtResumeThread[v];
		sciRollbackComplete = sciTable_86_64_NtRollbackComplete[v];
		sciRollbackEnlistment = sciTable_86_64_NtRollbackEnlistment[v];
		sciRollbackTransaction = sciTable_86_64_NtRollbackTransaction[v];
		sciRollforwardTransactionManager = sciTable_86_64_NtRollforwardTransactionManager[v];
		sciSaveKey = sciTable_86_64_NtSaveKey[v];
		sciSaveKeyEx = sciTable_86_64_NtSaveKeyEx[v];
		sciSaveMergedKeys = sciTable_86_64_NtSaveMergedKeys[v];
		sciSecureConnectPort = sciTable_86_64_NtSecureConnectPort[v];
		sciSerializeBoot = sciTable_86_64_NtSerializeBoot[v];
		sciSetBootEntryOrder = sciTable_86_64_NtSetBootEntryOrder[v];
		sciSetBootOptions = sciTable_86_64_NtSetBootOptions[v];
		sciSetContextThread = sciTable_86_64_NtSetContextThread[v];
		sciSetDebugFilterState = sciTable_86_64_NtSetDebugFilterState[v];
		sciSetDefaultHardErrorPort = sciTable_86_64_NtSetDefaultHardErrorPort[v];
		sciSetDefaultLocale = sciTable_86_64_NtSetDefaultLocale[v];
		sciSetDefaultUILanguage = sciTable_86_64_NtSetDefaultUILanguage[v];
		sciSetDriverEntryOrder = sciTable_86_64_NtSetDriverEntryOrder[v];
		sciSetEaFile = sciTable_86_64_NtSetEaFile[v];
		sciSetEvent = sciTable_86_64_NtSetEvent[v];
		sciSetEventBoostPriority = sciTable_86_64_NtSetEventBoostPriority[v];
		sciSetHighEventPair = sciTable_86_64_NtSetHighEventPair[v];
		sciSetHighWaitLowEventPair = sciTable_86_64_NtSetHighWaitLowEventPair[v];
		sciSetInformationDebugObject = sciTable_86_64_NtSetInformationDebugObject[v];
		sciSetInformationEnlistment = sciTable_86_64_NtSetInformationEnlistment[v];
		sciSetInformationFile = sciTable_86_64_NtSetInformationFile[v];
		sciSetInformationJobObject = sciTable_86_64_NtSetInformationJobObject[v];
		sciSetInformationKey = sciTable_86_64_NtSetInformationKey[v];
		sciSetInformationObject = sciTable_86_64_NtSetInformationObject[v];
		sciSetInformationProcess = sciTable_86_64_NtSetInformationProcess[v];
		sciSetInformationResourceManager = sciTable_86_64_NtSetInformationResourceManager[v];
		sciSetInformationThread = sciTable_86_64_NtSetInformationThread[v];
		sciSetInformationToken = sciTable_86_64_NtSetInformationToken[v];
		sciSetInformationTransaction = sciTable_86_64_NtSetInformationTransaction[v];
		sciSetInformationTransactionManager = sciTable_86_64_NtSetInformationTransactionManager[v];
		sciSetInformationWorkerFactory = sciTable_86_64_NtSetInformationWorkerFactory[v];
		sciSetIntervalProfile = sciTable_86_64_NtSetIntervalProfile[v];
		sciSetIoCompletion = sciTable_86_64_NtSetIoCompletion[v];
		sciSetIoCompletionEx = sciTable_86_64_NtSetIoCompletionEx[v];
		sciSetLdtEntries = sciTable_86_64_NtSetLdtEntries[v];
		sciSetLowEventPair = sciTable_86_64_NtSetLowEventPair[v];
		sciSetLowWaitHighEventPair = sciTable_86_64_NtSetLowWaitHighEventPair[v];
		sciSetQuotaInformationFile = sciTable_86_64_NtSetQuotaInformationFile[v];
		sciSetSecurityObject = sciTable_86_64_NtSetSecurityObject[v];
		sciSetSystemEnvironmentValue = sciTable_86_64_NtSetSystemEnvironmentValue[v];
		sciSetSystemEnvironmentValueEx = sciTable_86_64_NtSetSystemEnvironmentValueEx[v];
		sciSetSystemInformation = sciTable_86_64_NtSetSystemInformation[v];
		sciSetSystemPowerState = sciTable_86_64_NtSetSystemPowerState[v];
		sciSetSystemTime = sciTable_86_64_NtSetSystemTime[v];
		sciSetThreadExecutionState = sciTable_86_64_NtSetThreadExecutionState[v];
		sciSetTimer = sciTable_86_64_NtSetTimer[v];
		sciSetTimerEx = sciTable_86_64_NtSetTimerEx[v];
		sciSetTimerResolution = sciTable_86_64_NtSetTimerResolution[v];
		sciSetUuidSeed = sciTable_86_64_NtSetUuidSeed[v];
		sciSetValueKey = sciTable_86_64_NtSetValueKey[v];
		sciSetVolumeInformationFile = sciTable_86_64_NtSetVolumeInformationFile[v];
		sciShutdownSystem = sciTable_86_64_NtShutdownSystem[v];
		sciShutdownWorkerFactory = sciTable_86_64_NtShutdownWorkerFactory[v];
		sciSignalAndWaitForSingleObject = sciTable_86_64_NtSignalAndWaitForSingleObject[v];
		sciSinglePhaseReject = sciTable_86_64_NtSinglePhaseReject[v];
		sciStartProfile = sciTable_86_64_NtStartProfile[v];
		sciStopProfile = sciTable_86_64_NtStopProfile[v];
		sciSuspendProcess = sciTable_86_64_NtSuspendProcess[v];
		sciSuspendThread = sciTable_86_64_NtSuspendThread[v];
		sciSystemDebugControl = sciTable_86_64_NtSystemDebugControl[v];
		sciTerminateJobObject = sciTable_86_64_NtTerminateJobObject[v];
		sciTerminateProcess = sciTable_86_64_NtTerminateProcess[v];
		sciTerminateThread = sciTable_86_64_NtTerminateThread[v];
		sciTestAlert = sciTable_86_64_NtTestAlert[v];
		sciThawRegistry = sciTable_86_64_NtThawRegistry[v];
		sciThawTransactions = sciTable_86_64_NtThawTransactions[v];
		sciTraceControl = sciTable_86_64_NtTraceControl[v];
		sciTraceEvent = sciTable_86_64_NtTraceEvent[v];
		sciTranslateFilePath = sciTable_86_64_NtTranslateFilePath[v];
		sciUmsThreadYield = sciTable_86_64_NtUmsThreadYield[v];
		sciUnloadDriver = sciTable_86_64_NtUnloadDriver[v];
		sciUnloadKey = sciTable_86_64_NtUnloadKey[v];
		sciUnloadKey2 = sciTable_86_64_NtUnloadKey2[v];
		sciUnloadKeyEx = sciTable_86_64_NtUnloadKeyEx[v];
		sciUnlockFile = sciTable_86_64_NtUnlockFile[v];
		sciUnlockVirtualMemory = sciTable_86_64_NtUnlockVirtualMemory[v];
		sciUnmapViewOfSection = sciTable_86_64_NtUnmapViewOfSection[v];
		sciVdmControl = sciTable_86_64_NtVdmControl[v];
		sciWaitForDebugEvent = sciTable_86_64_NtWaitForDebugEvent[v];
		sciWaitForKeyedEvent = sciTable_86_64_NtWaitForKeyedEvent[v];
		sciWaitForMultipleObjects = sciTable_86_64_NtWaitForMultipleObjects[v];
		sciWaitForMultipleObjects32 = sciTable_86_64_NtWaitForMultipleObjects32[v];
		sciWaitForSingleObject = sciTable_86_64_NtWaitForSingleObject[v];
		sciWaitForWorkViaWorkerFactory = sciTable_86_64_NtWaitForWorkViaWorkerFactory[v];
		sciWaitHighEventPair = sciTable_86_64_NtWaitHighEventPair[v];
		sciWaitLowEventPair = sciTable_86_64_NtWaitLowEventPair[v];
		sciWorkerFactoryWorkerReady = sciTable_86_64_NtWorkerFactoryWorkerReady[v];
		sciWriteFile = sciTable_86_64_NtWriteFile[v];
		sciWriteFileGather = sciTable_86_64_NtWriteFileGather[v];
		sciWriteRequestData = sciTable_86_64_NtWriteRequestData[v];
		sciWriteVirtualMemory = sciTable_86_64_NtWriteVirtualMemory[v];
		sciYieldExecution = sciTable_86_64_NtYieldExecution[v];

	}
	else
	{
		sciAcceptConnectPort = sciTable_86_NtAcceptConnectPort[v];
		sciAccessCheck = sciTable_86_NtAccessCheck[v];
		sciAccessCheckAndAuditAlarm = sciTable_86_NtAccessCheckAndAuditAlarm[v];
		sciAccessCheckByType = sciTable_86_NtAccessCheckByType[v];
		sciAccessCheckByTypeAndAuditAlarm = sciTable_86_NtAccessCheckByTypeAndAuditAlarm[v];
		sciAccessCheckByTypeResultList = sciTable_86_NtAccessCheckByTypeResultList[v];
		sciAccessCheckByTypeResultListAndAuditAlarm = sciTable_86_NtAccessCheckByTypeResultListAndAuditAlarm[v];
		sciAccessCheckByTypeResultListAndAuditAlarmByHandle = sciTable_86_NtAccessCheckByTypeResultListAndAuditAlarmByHandle[v];
		sciAddAtom = sciTable_86_NtAddAtom[v];
		sciAddBootEntry = sciTable_86_NtAddBootEntry[v];
		sciAddDriverEntry = sciTable_86_NtAddDriverEntry[v];
		sciAdjustGroupsToken = sciTable_86_NtAdjustGroupsToken[v];
		sciAdjustPrivilegesToken = sciTable_86_NtAdjustPrivilegesToken[v];
		sciAlertResumeThread = sciTable_86_NtAlertResumeThread[v];
		sciAlertThread = sciTable_86_NtAlertThread[v];
		sciAllocateLocallyUniqueId = sciTable_86_NtAllocateLocallyUniqueId[v];
		sciAllocateReserveObject = sciTable_86_NtAllocateReserveObject[v];
		sciAllocateUserPhysicalPages = sciTable_86_NtAllocateUserPhysicalPages[v];
		sciAllocateUuids = sciTable_86_NtAllocateUuids[v];
		sciAllocateVirtualMemory = sciTable_86_NtAllocateVirtualMemory[v];
		sciAlpcAcceptConnectPort = sciTable_86_NtAlpcAcceptConnectPort[v];
		sciAlpcCancelMessage = sciTable_86_NtAlpcCancelMessage[v];
		sciAlpcConnectPort = sciTable_86_NtAlpcConnectPort[v];
		sciAlpcCreatePort = sciTable_86_NtAlpcCreatePort[v];
		sciAlpcCreatePortSection = sciTable_86_NtAlpcCreatePortSection[v];
		sciAlpcCreateResourceReserve = sciTable_86_NtAlpcCreateResourceReserve[v];
		sciAlpcCreateSectionView = sciTable_86_NtAlpcCreateSectionView[v];
		sciAlpcCreateSecurityContext = sciTable_86_NtAlpcCreateSecurityContext[v];
		sciAlpcDeletePortSection = sciTable_86_NtAlpcDeletePortSection[v];
		sciAlpcDeleteResourceReserve = sciTable_86_NtAlpcDeleteResourceReserve[v];
		sciAlpcDeleteSectionView = sciTable_86_NtAlpcDeleteSectionView[v];
		sciAlpcDeleteSecurityContext = sciTable_86_NtAlpcDeleteSecurityContext[v];
		sciAlpcDisconnectPort = sciTable_86_NtAlpcDisconnectPort[v];
		sciAlpcImpersonateClientOfPort = sciTable_86_NtAlpcImpersonateClientOfPort[v];
		sciAlpcOpenSenderProcess = sciTable_86_NtAlpcOpenSenderProcess[v];
		sciAlpcOpenSenderThread = sciTable_86_NtAlpcOpenSenderThread[v];
		sciAlpcQueryInformation = sciTable_86_NtAlpcQueryInformation[v];
		sciAlpcQueryInformationMessage = sciTable_86_NtAlpcQueryInformationMessage[v];
		sciAlpcRevokeSecurityContext = sciTable_86_NtAlpcRevokeSecurityContext[v];
		sciAlpcSendWaitReceivePort = sciTable_86_NtAlpcSendWaitReceivePort[v];
		sciAlpcSetInformation = sciTable_86_NtAlpcSetInformation[v];
		sciApphelpCacheControl = sciTable_86_NtApphelpCacheControl[v];
		sciAreMappedFilesTheSame = sciTable_86_NtAreMappedFilesTheSame[v];
		sciAssignProcessToJobObject = sciTable_86_NtAssignProcessToJobObject[v];
		sciCallbackReturn = sciTable_86_NtCallbackReturn[v];
		sciCancelIoFile = sciTable_86_NtCancelIoFile[v];
		sciCancelIoFileEx = sciTable_86_NtCancelIoFileEx[v];
		sciCancelSynchronousIoFile = sciTable_86_NtCancelSynchronousIoFile[v];
		sciCancelTimer = sciTable_86_NtCancelTimer[v];
		sciClearEvent = sciTable_86_NtClearEvent[v];
		sciClose = sciTable_86_NtClose[v];
		sciCloseObjectAuditAlarm = sciTable_86_NtCloseObjectAuditAlarm[v];
		sciCommitComplete = sciTable_86_NtCommitComplete[v];
		sciCommitEnlistment = sciTable_86_NtCommitEnlistment[v];
		sciCommitTransaction = sciTable_86_NtCommitTransaction[v];
		sciCompactKeys = sciTable_86_NtCompactKeys[v];
		sciCompareTokens = sciTable_86_NtCompareTokens[v];
		sciCompleteConnectPort = sciTable_86_NtCompleteConnectPort[v];
		sciCompressKey = sciTable_86_NtCompressKey[v];
		sciConnectPort = sciTable_86_NtConnectPort[v];
		sciContinue = sciTable_86_NtContinue[v];
		sciCreateDebugObject = sciTable_86_NtCreateDebugObject[v];
		sciCreateDirectoryObject = sciTable_86_NtCreateDirectoryObject[v];
		sciCreateEnlistment = sciTable_86_NtCreateEnlistment[v];
		sciCreateEvent = sciTable_86_NtCreateEvent[v];
		sciCreateEventPair = sciTable_86_NtCreateEventPair[v];
		sciCreateFile = sciTable_86_NtCreateFile[v];
		sciCreateIoCompletion = sciTable_86_NtCreateIoCompletion[v];
		sciCreateJobObject = sciTable_86_NtCreateJobObject[v];
		sciCreateJobSet = sciTable_86_NtCreateJobSet[v];
		sciCreateKey = sciTable_86_NtCreateKey[v];
		sciCreateKeyTransacted = sciTable_86_NtCreateKeyTransacted[v];
		sciCreateKeyedEvent = sciTable_86_NtCreateKeyedEvent[v];
		sciCreateMailslotFile = sciTable_86_NtCreateMailslotFile[v];
		sciCreateMutant = sciTable_86_NtCreateMutant[v];
		sciCreateNamedPipeFile = sciTable_86_NtCreateNamedPipeFile[v];
		sciCreatePagingFile = sciTable_86_NtCreatePagingFile[v];
		sciCreatePort = sciTable_86_NtCreatePort[v];
		sciCreatePrivateNamespace = sciTable_86_NtCreatePrivateNamespace[v];
		sciCreateProcess = sciTable_86_NtCreateProcess[v];
		sciCreateProcessEx = sciTable_86_NtCreateProcessEx[v];
		sciCreateProfile = sciTable_86_NtCreateProfile[v];
		sciCreateProfileEx = sciTable_86_NtCreateProfileEx[v];
		sciCreateResourceManager = sciTable_86_NtCreateResourceManager[v];
		sciCreateSection = sciTable_86_NtCreateSection[v];
		sciCreateSemaphore = sciTable_86_NtCreateSemaphore[v];
		sciCreateSymbolicLinkObject = sciTable_86_NtCreateSymbolicLinkObject[v];
		sciCreateThread = sciTable_86_NtCreateThread[v];
		sciCreateThreadEx = sciTable_86_NtCreateThreadEx[v];
		sciCreateTimer = sciTable_86_NtCreateTimer[v];
		sciCreateToken = sciTable_86_NtCreateToken[v];
		sciCreateTransaction = sciTable_86_NtCreateTransaction[v];
		sciCreateTransactionManager = sciTable_86_NtCreateTransactionManager[v];
		sciCreateUserProcess = sciTable_86_NtCreateUserProcess[v];
		sciCreateWaitablePort = sciTable_86_NtCreateWaitablePort[v];
		sciCreateWorkerFactory = sciTable_86_NtCreateWorkerFactory[v];
		sciDebugActiveProcess = sciTable_86_NtDebugActiveProcess[v];
		sciDebugContinue = sciTable_86_NtDebugContinue[v];
		sciDelayExecution = sciTable_86_NtDelayExecution[v];
		sciDeleteAtom = sciTable_86_NtDeleteAtom[v];
		sciDeleteBootEntry = sciTable_86_NtDeleteBootEntry[v];
		sciDeleteDriverEntry = sciTable_86_NtDeleteDriverEntry[v];
		sciDeleteFile = sciTable_86_NtDeleteFile[v];
		sciDeleteKey = sciTable_86_NtDeleteKey[v];
		sciDeleteObjectAuditAlarm = sciTable_86_NtDeleteObjectAuditAlarm[v];
		sciDeletePrivateNamespace = sciTable_86_NtDeletePrivateNamespace[v];
		sciDeleteValueKey = sciTable_86_NtDeleteValueKey[v];
		sciDeviceIoControlFile = sciTable_86_NtDeviceIoControlFile[v];
		sciDisableLastKnownGood = sciTable_86_NtDisableLastKnownGood[v];
		sciDisplayString = sciTable_86_NtDisplayString[v];
		sciDrawText = sciTable_86_NtDrawText[v];
		sciDuplicateObject = sciTable_86_NtDuplicateObject[v];
		sciDuplicateToken = sciTable_86_NtDuplicateToken[v];
		sciEnableLastKnownGood = sciTable_86_NtEnableLastKnownGood[v];
		sciEnumerateBootEntries = sciTable_86_NtEnumerateBootEntries[v];
		sciEnumerateDriverEntries = sciTable_86_NtEnumerateDriverEntries[v];
		sciEnumerateKey = sciTable_86_NtEnumerateKey[v];
		sciEnumerateSystemEnvironmentValuesEx = sciTable_86_NtEnumerateSystemEnvironmentValuesEx[v];
		sciEnumerateTransactionObject = sciTable_86_NtEnumerateTransactionObject[v];
		sciEnumerateValueKey = sciTable_86_NtEnumerateValueKey[v];
		sciExtendSection = sciTable_86_NtExtendSection[v];
		sciFilterToken = sciTable_86_NtFilterToken[v];
		sciFindAtom = sciTable_86_NtFindAtom[v];
		sciFlushBuffersFile = sciTable_86_NtFlushBuffersFile[v];
		sciFlushInstallUILanguage = sciTable_86_NtFlushInstallUILanguage[v];
		sciFlushInstructionCache = sciTable_86_NtFlushInstructionCache[v];
		sciFlushKey = sciTable_86_NtFlushKey[v];
		sciFlushProcessWriteBuffers = sciTable_86_NtFlushProcessWriteBuffers[v];
		sciFlushVirtualMemory = sciTable_86_NtFlushVirtualMemory[v];
		sciFlushWriteBuffer = sciTable_86_NtFlushWriteBuffer[v];
		sciFreeUserPhysicalPages = sciTable_86_NtFreeUserPhysicalPages[v];
		sciFreeVirtualMemory = sciTable_86_NtFreeVirtualMemory[v];
		sciFreezeRegistry = sciTable_86_NtFreezeRegistry[v];
		sciFreezeTransactions = sciTable_86_NtFreezeTransactions[v];
		sciFsControlFile = sciTable_86_NtFsControlFile[v];
		sciGetContextThread = sciTable_86_NtGetContextThread[v];
		sciGetCurrentProcessorNumber = sciTable_86_NtGetCurrentProcessorNumber[v];
		sciGetDevicePowerState = sciTable_86_NtGetDevicePowerState[v];
		sciGetMUIRegistryInfo = sciTable_86_NtGetMUIRegistryInfo[v];
		sciGetNextProcess = sciTable_86_NtGetNextProcess[v];
		sciGetNextThread = sciTable_86_NtGetNextThread[v];
		sciGetNlsSectionPtr = sciTable_86_NtGetNlsSectionPtr[v];
		sciGetNotificationResourceManager = sciTable_86_NtGetNotificationResourceManager[v];
		sciGetWriteWatch = sciTable_86_NtGetWriteWatch[v];
		sciImpersonateAnonymousToken = sciTable_86_NtImpersonateAnonymousToken[v];
		sciImpersonateClientOfPort = sciTable_86_NtImpersonateClientOfPort[v];
		sciImpersonateThread = sciTable_86_NtImpersonateThread[v];
		sciInitializeNlsFiles = sciTable_86_NtInitializeNlsFiles[v];
		sciInitializeRegistry = sciTable_86_NtInitializeRegistry[v];
		sciInitiatePowerAction = sciTable_86_NtInitiatePowerAction[v];
		sciIsProcessInJob = sciTable_86_NtIsProcessInJob[v];
		sciIsSystemResumeAutomatic = sciTable_86_NtIsSystemResumeAutomatic[v];
		sciIsUILanguageComitted = sciTable_86_NtIsUILanguageComitted[v];
		sciListenPort = sciTable_86_NtListenPort[v];
		sciLoadDriver = sciTable_86_NtLoadDriver[v];
		sciLoadKey = sciTable_86_NtLoadKey[v];
		sciLoadKey2 = sciTable_86_NtLoadKey2[v];
		sciLoadKeyEx = sciTable_86_NtLoadKeyEx[v];
		sciLockFile = sciTable_86_NtLockFile[v];
		sciLockProductActivationKeys = sciTable_86_NtLockProductActivationKeys[v];
		sciLockRegistryKey = sciTable_86_NtLockRegistryKey[v];
		sciLockVirtualMemory = sciTable_86_NtLockVirtualMemory[v];
		sciMakePermanentObject = sciTable_86_NtMakePermanentObject[v];
		sciMakeTemporaryObject = sciTable_86_NtMakeTemporaryObject[v];
		sciMapCMFModule = sciTable_86_NtMapCMFModule[v];
		sciMapUserPhysicalPages = sciTable_86_NtMapUserPhysicalPages[v];
		sciMapUserPhysicalPagesScatter = sciTable_86_NtMapUserPhysicalPagesScatter[v];
		sciMapViewOfSection = sciTable_86_NtMapViewOfSection[v];
		sciModifyBootEntry = sciTable_86_NtModifyBootEntry[v];
		sciModifyDriverEntry = sciTable_86_NtModifyDriverEntry[v];
		sciNotifyChangeDirectoryFile = sciTable_86_NtNotifyChangeDirectoryFile[v];
		sciNotifyChangeKey = sciTable_86_NtNotifyChangeKey[v];
		sciNotifyChangeMultipleKeys = sciTable_86_NtNotifyChangeMultipleKeys[v];
		sciNotifyChangeSession = sciTable_86_NtNotifyChangeSession[v];
		sciOpenDirectoryObject = sciTable_86_NtOpenDirectoryObject[v];
		sciOpenEnlistment = sciTable_86_NtOpenEnlistment[v];
		sciOpenEvent = sciTable_86_NtOpenEvent[v];
		sciOpenEventPair = sciTable_86_NtOpenEventPair[v];
		sciOpenFile = sciTable_86_NtOpenFile[v];
		sciOpenIoCompletion = sciTable_86_NtOpenIoCompletion[v];
		sciOpenJobObject = sciTable_86_NtOpenJobObject[v];
		sciOpenKey = sciTable_86_NtOpenKey[v];
		sciOpenKeyEx = sciTable_86_NtOpenKeyEx[v];
		sciOpenKeyTransacted = sciTable_86_NtOpenKeyTransacted[v];
		sciOpenKeyTransactedEx = sciTable_86_NtOpenKeyTransactedEx[v];
		sciOpenKeyedEvent = sciTable_86_NtOpenKeyedEvent[v];
		sciOpenMutant = sciTable_86_NtOpenMutant[v];
		sciOpenObjectAuditAlarm = sciTable_86_NtOpenObjectAuditAlarm[v];
		sciOpenPrivateNamespace = sciTable_86_NtOpenPrivateNamespace[v];
		sciOpenProcess = sciTable_86_NtOpenProcess[v];
		sciOpenProcessToken = sciTable_86_NtOpenProcessToken[v];
		sciOpenProcessTokenEx = sciTable_86_NtOpenProcessTokenEx[v];
		sciOpenResourceManager = sciTable_86_NtOpenResourceManager[v];
		sciOpenSection = sciTable_86_NtOpenSection[v];
		sciOpenSemaphore = sciTable_86_NtOpenSemaphore[v];
		sciOpenSession = sciTable_86_NtOpenSession[v];
		sciOpenSymbolicLinkObject = sciTable_86_NtOpenSymbolicLinkObject[v];
		sciOpenThread = sciTable_86_NtOpenThread[v];
		sciOpenThreadToken = sciTable_86_NtOpenThreadToken[v];
		sciOpenThreadTokenEx = sciTable_86_NtOpenThreadTokenEx[v];
		sciOpenTimer = sciTable_86_NtOpenTimer[v];
		sciOpenTransaction = sciTable_86_NtOpenTransaction[v];
		sciOpenTransactionManager = sciTable_86_NtOpenTransactionManager[v];
		sciPlugPlayControl = sciTable_86_NtPlugPlayControl[v];
		sciPowerInformation = sciTable_86_NtPowerInformation[v];
		sciPrePrepareComplete = sciTable_86_NtPrePrepareComplete[v];
		sciPrePrepareEnlistment = sciTable_86_NtPrePrepareEnlistment[v];
		sciPrepareComplete = sciTable_86_NtPrepareComplete[v];
		sciPrepareEnlistment = sciTable_86_NtPrepareEnlistment[v];
		sciPrivilegeCheck = sciTable_86_NtPrivilegeCheck[v];
		sciPrivilegeObjectAuditAlarm = sciTable_86_NtPrivilegeObjectAuditAlarm[v];
		sciPrivilegedServiceAuditAlarm = sciTable_86_NtPrivilegedServiceAuditAlarm[v];
		sciPropagationComplete = sciTable_86_NtPropagationComplete[v];
		sciPropagationFailed = sciTable_86_NtPropagationFailed[v];
		sciProtectVirtualMemory = sciTable_86_NtProtectVirtualMemory[v];
		sciPulseEvent = sciTable_86_NtPulseEvent[v];
		sciQueryAttributesFile = sciTable_86_NtQueryAttributesFile[v];
		sciQueryBootEntryOrder = sciTable_86_NtQueryBootEntryOrder[v];
		sciQueryBootOptions = sciTable_86_NtQueryBootOptions[v];
		sciQueryDebugFilterState = sciTable_86_NtQueryDebugFilterState[v];
		sciQueryDefaultLocale = sciTable_86_NtQueryDefaultLocale[v];
		sciQueryDefaultUILanguage = sciTable_86_NtQueryDefaultUILanguage[v];
		sciQueryDirectoryFile = sciTable_86_NtQueryDirectoryFile[v];
		sciQueryDirectoryObject = sciTable_86_NtQueryDirectoryObject[v];
		sciQueryDriverEntryOrder = sciTable_86_NtQueryDriverEntryOrder[v];
		sciQueryEaFile = sciTable_86_NtQueryEaFile[v];
		sciQueryEvent = sciTable_86_NtQueryEvent[v];
		sciQueryFullAttributesFile = sciTable_86_NtQueryFullAttributesFile[v];
		sciQueryInformationAtom = sciTable_86_NtQueryInformationAtom[v];
		sciQueryInformationEnlistment = sciTable_86_NtQueryInformationEnlistment[v];
		sciQueryInformationFile = sciTable_86_NtQueryInformationFile[v];
		sciQueryInformationJobObject = sciTable_86_NtQueryInformationJobObject[v];
		sciQueryInformationPort = sciTable_86_NtQueryInformationPort[v];
		sciQueryInformationProcess = sciTable_86_NtQueryInformationProcess[v];
		sciQueryInformationResourceManager = sciTable_86_NtQueryInformationResourceManager[v];
		sciQueryInformationThread = sciTable_86_NtQueryInformationThread[v];
		sciQueryInformationToken = sciTable_86_NtQueryInformationToken[v];
		sciQueryInformationTransaction = sciTable_86_NtQueryInformationTransaction[v];
		sciQueryInformationTransactionManager = sciTable_86_NtQueryInformationTransactionManager[v];
		sciQueryInformationWorkerFactory = sciTable_86_NtQueryInformationWorkerFactory[v];
		sciQueryInstallUILanguage = sciTable_86_NtQueryInstallUILanguage[v];
		sciQueryIntervalProfile = sciTable_86_NtQueryIntervalProfile[v];
		sciQueryIoCompletion = sciTable_86_NtQueryIoCompletion[v];
		sciQueryKey = sciTable_86_NtQueryKey[v];
		sciQueryLicenseValue = sciTable_86_NtQueryLicenseValue[v];
		sciQueryMultipleValueKey = sciTable_86_NtQueryMultipleValueKey[v];
		sciQueryMutant = sciTable_86_NtQueryMutant[v];
		sciQueryObject = sciTable_86_NtQueryObject[v];
		sciQueryOpenSubKeys = sciTable_86_NtQueryOpenSubKeys[v];
		sciQueryOpenSubKeysEx = sciTable_86_NtQueryOpenSubKeysEx[v];
		sciQueryPerformanceCounter = sciTable_86_NtQueryPerformanceCounter[v];
		sciQueryPortInformationProcess = sciTable_86_NtQueryPortInformationProcess[v];
		sciQueryQuotaInformationFile = sciTable_86_NtQueryQuotaInformationFile[v];
		sciQuerySection = sciTable_86_NtQuerySection[v];
		sciQuerySecurityAttributesToken = sciTable_86_NtQuerySecurityAttributesToken[v];
		sciQuerySecurityObject = sciTable_86_NtQuerySecurityObject[v];
		sciQuerySemaphore = sciTable_86_NtQuerySemaphore[v];
		sciQuerySymbolicLinkObject = sciTable_86_NtQuerySymbolicLinkObject[v];
		sciQuerySystemEnvironmentValue = sciTable_86_NtQuerySystemEnvironmentValue[v];
		sciQuerySystemEnvironmentValueEx = sciTable_86_NtQuerySystemEnvironmentValueEx[v];
		sciQuerySystemInformation = sciTable_86_NtQuerySystemInformation[v];
		sciQuerySystemInformationEx = sciTable_86_NtQuerySystemInformationEx[v];
		sciQuerySystemTime = sciTable_86_NtQuerySystemTime[v];
		sciQueryTimer = sciTable_86_NtQueryTimer[v];
		sciQueryTimerResolution = sciTable_86_NtQueryTimerResolution[v];
		sciQueryValueKey = sciTable_86_NtQueryValueKey[v];
		sciQueryVirtualMemory = sciTable_86_NtQueryVirtualMemory[v];
		sciQueryVolumeInformationFile = sciTable_86_NtQueryVolumeInformationFile[v];
		sciQueueApcThread = sciTable_86_NtQueueApcThread[v];
		sciQueueApcThreadEx = sciTable_86_NtQueueApcThreadEx[v];
		sciRaiseException = sciTable_86_NtRaiseException[v];
		sciRaiseHardError = sciTable_86_NtRaiseHardError[v];
		sciReadFile = sciTable_86_NtReadFile[v];
		sciReadFileScatter = sciTable_86_NtReadFileScatter[v];
		sciReadOnlyEnlistment = sciTable_86_NtReadOnlyEnlistment[v];
		sciReadRequestData = sciTable_86_NtReadRequestData[v];
		sciReadVirtualMemory = sciTable_86_NtReadVirtualMemory[v];
		sciRecoverEnlistment = sciTable_86_NtRecoverEnlistment[v];
		sciRecoverResourceManager = sciTable_86_NtRecoverResourceManager[v];
		sciRecoverTransactionManager = sciTable_86_NtRecoverTransactionManager[v];
		sciRegisterProtocolAddressInformation = sciTable_86_NtRegisterProtocolAddressInformation[v];
		sciRegisterThreadTerminatePort = sciTable_86_NtRegisterThreadTerminatePort[v];
		sciReleaseKeyedEvent = sciTable_86_NtReleaseKeyedEvent[v];
		sciReleaseMutant = sciTable_86_NtReleaseMutant[v];
		sciReleaseSemaphore = sciTable_86_NtReleaseSemaphore[v];
		sciReleaseWorkerFactoryWorker = sciTable_86_NtReleaseWorkerFactoryWorker[v];
		sciRemoveIoCompletion = sciTable_86_NtRemoveIoCompletion[v];
		sciRemoveIoCompletionEx = sciTable_86_NtRemoveIoCompletionEx[v];
		sciRemoveProcessDebug = sciTable_86_NtRemoveProcessDebug[v];
		sciRenameKey = sciTable_86_NtRenameKey[v];
		sciRenameTransactionManager = sciTable_86_NtRenameTransactionManager[v];
		sciReplaceKey = sciTable_86_NtReplaceKey[v];
		sciReplacePartitionUnit = sciTable_86_NtReplacePartitionUnit[v];
		sciReplyPort = sciTable_86_NtReplyPort[v];
		sciReplyWaitReceivePort = sciTable_86_NtReplyWaitReceivePort[v];
		sciReplyWaitReceivePortEx = sciTable_86_NtReplyWaitReceivePortEx[v];
		sciReplyWaitReplyPort = sciTable_86_NtReplyWaitReplyPort[v];
		sciRequestPort = sciTable_86_NtRequestPort[v];
		sciRequestWaitReplyPort = sciTable_86_NtRequestWaitReplyPort[v];
		sciResetEvent = sciTable_86_NtResetEvent[v];
		sciResetWriteWatch = sciTable_86_NtResetWriteWatch[v];
		sciRestoreKey = sciTable_86_NtRestoreKey[v];
		sciResumeProcess = sciTable_86_NtResumeProcess[v];
		sciResumeThread = sciTable_86_NtResumeThread[v];
		sciRollbackComplete = sciTable_86_NtRollbackComplete[v];
		sciRollbackEnlistment = sciTable_86_NtRollbackEnlistment[v];
		sciRollbackTransaction = sciTable_86_NtRollbackTransaction[v];
		sciRollforwardTransactionManager = sciTable_86_NtRollforwardTransactionManager[v];
		sciSaveKey = sciTable_86_NtSaveKey[v];
		sciSaveKeyEx = sciTable_86_NtSaveKeyEx[v];
		sciSaveMergedKeys = sciTable_86_NtSaveMergedKeys[v];
		sciSecureConnectPort = sciTable_86_NtSecureConnectPort[v];
		sciSerializeBoot = sciTable_86_NtSerializeBoot[v];
		sciSetBootEntryOrder = sciTable_86_NtSetBootEntryOrder[v];
		sciSetBootOptions = sciTable_86_NtSetBootOptions[v];
		sciSetContextThread = sciTable_86_NtSetContextThread[v];
		sciSetDebugFilterState = sciTable_86_NtSetDebugFilterState[v];
		sciSetDefaultHardErrorPort = sciTable_86_NtSetDefaultHardErrorPort[v];
		sciSetDefaultLocale = sciTable_86_NtSetDefaultLocale[v];
		sciSetDefaultUILanguage = sciTable_86_NtSetDefaultUILanguage[v];
		sciSetDriverEntryOrder = sciTable_86_NtSetDriverEntryOrder[v];
		sciSetEaFile = sciTable_86_NtSetEaFile[v];
		sciSetEvent = sciTable_86_NtSetEvent[v];
		sciSetEventBoostPriority = sciTable_86_NtSetEventBoostPriority[v];
		sciSetHighEventPair = sciTable_86_NtSetHighEventPair[v];
		sciSetHighWaitLowEventPair = sciTable_86_NtSetHighWaitLowEventPair[v];
		sciSetInformationDebugObject = sciTable_86_NtSetInformationDebugObject[v];
		sciSetInformationEnlistment = sciTable_86_NtSetInformationEnlistment[v];
		sciSetInformationFile = sciTable_86_NtSetInformationFile[v];
		sciSetInformationJobObject = sciTable_86_NtSetInformationJobObject[v];
		sciSetInformationKey = sciTable_86_NtSetInformationKey[v];
		sciSetInformationObject = sciTable_86_NtSetInformationObject[v];
		sciSetInformationProcess = sciTable_86_NtSetInformationProcess[v];
		sciSetInformationResourceManager = sciTable_86_NtSetInformationResourceManager[v];
		sciSetInformationThread = sciTable_86_NtSetInformationThread[v];
		sciSetInformationToken = sciTable_86_NtSetInformationToken[v];
		sciSetInformationTransaction = sciTable_86_NtSetInformationTransaction[v];
		sciSetInformationTransactionManager = sciTable_86_NtSetInformationTransactionManager[v];
		sciSetInformationWorkerFactory = sciTable_86_NtSetInformationWorkerFactory[v];
		sciSetIntervalProfile = sciTable_86_NtSetIntervalProfile[v];
		sciSetIoCompletion = sciTable_86_NtSetIoCompletion[v];
		sciSetIoCompletionEx = sciTable_86_NtSetIoCompletionEx[v];
		sciSetLdtEntries = sciTable_86_NtSetLdtEntries[v];
		sciSetLowEventPair = sciTable_86_NtSetLowEventPair[v];
		sciSetLowWaitHighEventPair = sciTable_86_NtSetLowWaitHighEventPair[v];
		sciSetQuotaInformationFile = sciTable_86_NtSetQuotaInformationFile[v];
		sciSetSecurityObject = sciTable_86_NtSetSecurityObject[v];
		sciSetSystemEnvironmentValue = sciTable_86_NtSetSystemEnvironmentValue[v];
		sciSetSystemEnvironmentValueEx = sciTable_86_NtSetSystemEnvironmentValueEx[v];
		sciSetSystemInformation = sciTable_86_NtSetSystemInformation[v];
		sciSetSystemPowerState = sciTable_86_NtSetSystemPowerState[v];
		sciSetSystemTime = sciTable_86_NtSetSystemTime[v];
		sciSetThreadExecutionState = sciTable_86_NtSetThreadExecutionState[v];
		sciSetTimer = sciTable_86_NtSetTimer[v];
		sciSetTimerEx = sciTable_86_NtSetTimerEx[v];
		sciSetTimerResolution = sciTable_86_NtSetTimerResolution[v];
		sciSetUuidSeed = sciTable_86_NtSetUuidSeed[v];
		sciSetValueKey = sciTable_86_NtSetValueKey[v];
		sciSetVolumeInformationFile = sciTable_86_NtSetVolumeInformationFile[v];
		sciShutdownSystem = sciTable_86_NtShutdownSystem[v];
		sciShutdownWorkerFactory = sciTable_86_NtShutdownWorkerFactory[v];
		sciSignalAndWaitForSingleObject = sciTable_86_NtSignalAndWaitForSingleObject[v];
		sciSinglePhaseReject = sciTable_86_NtSinglePhaseReject[v];
		sciStartProfile = sciTable_86_NtStartProfile[v];
		sciStopProfile = sciTable_86_NtStopProfile[v];
		sciSuspendProcess = sciTable_86_NtSuspendProcess[v];
		sciSuspendThread = sciTable_86_NtSuspendThread[v];
		sciSystemDebugControl = sciTable_86_NtSystemDebugControl[v];
		sciTerminateJobObject = sciTable_86_NtTerminateJobObject[v];
		sciTerminateProcess = sciTable_86_NtTerminateProcess[v];
		sciTerminateThread = sciTable_86_NtTerminateThread[v];
		sciTestAlert = sciTable_86_NtTestAlert[v];
		sciThawRegistry = sciTable_86_NtThawRegistry[v];
		sciThawTransactions = sciTable_86_NtThawTransactions[v];
		sciTraceControl = sciTable_86_NtTraceControl[v];
		sciTraceEvent = sciTable_86_NtTraceEvent[v];
		sciTranslateFilePath = sciTable_86_NtTranslateFilePath[v];
		sciUmsThreadYield = sciTable_86_NtUmsThreadYield[v];
		sciUnloadDriver = sciTable_86_NtUnloadDriver[v];
		sciUnloadKey = sciTable_86_NtUnloadKey[v];
		sciUnloadKey2 = sciTable_86_NtUnloadKey2[v];
		sciUnloadKeyEx = sciTable_86_NtUnloadKeyEx[v];
		sciUnlockFile = sciTable_86_NtUnlockFile[v];
		sciUnlockVirtualMemory = sciTable_86_NtUnlockVirtualMemory[v];
		sciUnmapViewOfSection = sciTable_86_NtUnmapViewOfSection[v];
		sciVdmControl = sciTable_86_NtVdmControl[v];
		sciWaitForDebugEvent = sciTable_86_NtWaitForDebugEvent[v];
		sciWaitForKeyedEvent = sciTable_86_NtWaitForKeyedEvent[v];
		sciWaitForMultipleObjects = sciTable_86_NtWaitForMultipleObjects[v];
		sciWaitForMultipleObjects32 = sciTable_86_NtWaitForMultipleObjects32[v];
		sciWaitForSingleObject = sciTable_86_NtWaitForSingleObject[v];
		sciWaitForWorkViaWorkerFactory = sciTable_86_NtWaitForWorkViaWorkerFactory[v];
		sciWaitHighEventPair = sciTable_86_NtWaitHighEventPair[v];
		sciWaitLowEventPair = sciTable_86_NtWaitLowEventPair[v];
		sciWorkerFactoryWorkerReady = sciTable_86_NtWorkerFactoryWorkerReady[v];
		sciWriteFile = sciTable_86_NtWriteFile[v];
		sciWriteFileGather = sciTable_86_NtWriteFileGather[v];
		sciWriteRequestData = sciTable_86_NtWriteRequestData[v];
		sciWriteVirtualMemory = sciTable_86_NtWriteVirtualMemory[v];
		sciYieldExecution = sciTable_86_NtYieldExecution[v];
	}
#endif

	return STATUS_SUCCESS;
}

static NTSTATUS INITIALIZATION_ROUTINE InitializeSecurity(VOID)
{
	HANDLE hToken = 0;
	NTSTATUS Status;

	HcGlobal.IsElevated = FALSE;

	Status = HcOpenProcessTokenEx(NtCurrentProcess(),
		TOKEN_QUERY,
		&hToken);

	if (NT_SUCCESS(Status))
	{
		HcTokenIsElevated(hToken, &(HcGlobal.IsElevated));
		HcObjectClose(&hToken);
	}

	if (NtCurrentPeb()->ReadOnlyStaticServerData == NULL)
	{
		return STATUS_INVALID_ADDRESS;
	}

	/* need to connect to csrss before this makes any sense */
	//HcGlobal.BaseStaticServerData = (PBASE_STATIC_SERVER_DATA) NtCurrentPeb()->ReadOnlyStaticServerData[BASESRV_SERVERDLL_INDEX];

	return Status;
}

static NTSTATUS INITIALIZATION_ROUTINE InitializeNamedObjectDirectory()
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;
	HANDLE DirHandle, BnoHandle, Token, NewToken;

	if (NtCurrentTeb()->IsImpersonating)
	{
		Status = HcOpenThreadToken(
			NtCurrentThread(),
			TOKEN_IMPERSONATE,
			TRUE,
			&Token);

		if (!NT_SUCCESS(Status))
		{
			return Status;
		}

		NewToken = NULL;

		Status = HcSetInformationThread(
			NtCurrentThread(),
			ThreadImpersonationToken,
			&NewToken,
			sizeof(HANDLE));

		if (!NT_SUCCESS(Status))
		{
			HcObjectClose(&Token);
			return Status;
		}
	}
	else
	{
		Token = NULL;
	}

	RtlAcquirePebLock();

	InitializeObjectAttributes(
		&ObjectAttributes,
		&HcGlobal.BaseStaticServerData->NamedObjectDirectory,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	Status = HcOpenDirectoryObject(
		&BnoHandle,
		DIRECTORY_QUERY |
		DIRECTORY_TRAVERSE |
		DIRECTORY_CREATE_OBJECT |
		DIRECTORY_CREATE_SUBDIRECTORY,
		&ObjectAttributes);

	if (!NT_SUCCESS(Status))
	{
		Status = HcOpenDirectoryObject(&DirHandle,
			DIRECTORY_TRAVERSE,
			&ObjectAttributes);

		if (NT_SUCCESS(Status))
		{
			InitializeObjectAttributes(
				&ObjectAttributes,
				(PUNICODE_STRING) &Restricted,
				OBJ_CASE_INSENSITIVE,
				DirHandle,
				NULL);

			Status = HcOpenDirectoryObject(&BnoHandle,
				DIRECTORY_QUERY |
				DIRECTORY_TRAVERSE |
				DIRECTORY_CREATE_OBJECT |
				DIRECTORY_CREATE_SUBDIRECTORY,
				&ObjectAttributes);

			HcObjectClose(&DirHandle);
		}
	}

	if (NT_SUCCESS(Status))
	{
		HcGlobal.BaseNamedObjectDirectory = BnoHandle;
	}

	RtlReleasePebLock();

	if (Token)
	{
		HcSetInformationThread(NtCurrentThread(),
			ThreadImpersonationToken,
			&Token,
			sizeof(Token));

		HcObjectClose(&Token);
	}

	return Status;
}

NTSTATUS INITIALIZATION_ROUTINE HcInitialize()
{
	NTSTATUS Status;

	/* Initialize windows version to identify some mandatory syscall identifiers. */
	Status = InitializeVersion();
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	/* Initialize all syscalls */
	Status = InitializeSyscall();
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	Status = InitializeSecurity();

	Status = InitializeModules();
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	/* will need to initialize with csrss before this makes any sense */
	//Status = InitializeNamedObjectDirectory(); 

	HcErrorSetNtStatus(Status);
	return STATUS_SUCCESS;
}

#ifdef _WINDLL

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
) {

	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			NTSTATUS Status = HcInitialize();

			/* Check if we failed. */
			if (!NT_SUCCESS(Status))
			{
				return Status;
			}

			return TRUE;
		}

		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}
#endif