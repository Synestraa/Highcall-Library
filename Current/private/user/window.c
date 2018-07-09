#include <highcall.h>

DECL_EXTERN_API(DWORD, GetWindowThreadProcessId, HWND hWnd, LPDWORD lpdwProcessId)
{
	DWORD Ret = 0;

	if (lpdwProcessId)
		*lpdwProcessId = HcUserQueryWindow(hWnd, QUERY_WINDOW_UNIQUE_PROCESS_ID);

	Ret = HcUserQueryWindow(hWnd, QUERY_WINDOW_UNIQUE_THREAD_ID);

	return Ret;
}

static BOOL
User32EnumWindows(HDESK hDesktop,
	HWND hWndparent,
	WNDENUMPROC lpfn,
	LPARAM lParam,
	DWORD dwThreadId,
	BOOL bChildren)
{
	DWORD i, dwCount = 0;
	HWND* pHwnd = NULL;
	NTSTATUS Status;

	if (!lpfn)
	{
		HcErrorSetDosError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	/* FIXME instead of always making two calls, should we use some
	sort of persistent buffer and only grow it ( requiring a 2nd
	call ) when the buffer wasn't already big enough? */
	/* first get how many window entries there are */
	Status = HcUserBuildHwndList(hDesktop,
		hWndparent,
		bChildren,
		dwThreadId,
		lParam,
		NULL,
		&dwCount,
		NULL);

	if (!NT_SUCCESS(Status))
		return FALSE;

	if (!dwCount)
	{
		if (!dwThreadId)
			return FALSE;
		else
			return TRUE;
	}

	/* allocate buffer to receive HWND handles */
	pHwnd = HcVirtualAlloc(NULL, sizeof(HWND)*(dwCount + 1), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pHwnd)
	{
		HcErrorSetDosError(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}

	Status = HcUserBuildHwndList(hDesktop,
		hWndparent,
		bChildren,
		dwThreadId,
		lParam,
		pHwnd,
		&dwCount,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		if (pHwnd)
			HcVirtualFree(pHwnd, 0, MEM_RELEASE);
		return FALSE;
	}

	for (i = 0; i < dwCount; i++)
	{
		if (!pHwnd[i]) 
			continue;

		if (!(*lpfn)(pHwnd[i], lParam))
		{
			HcVirtualFree(pHwnd, 0, MEM_RELEASE);
			return FALSE;
		}
	}
	if (pHwnd)
		HcVirtualFree(pHwnd, 0, MEM_RELEASE);
	return TRUE;
}

DECL_EXTERN_API(BOOL, EnumChildWindows, HWND hWndParent,
	WNDENUMPROC lpEnumFunc,
	LPARAM lParam)
{
	if (!hWndParent)
	{
		return HcEnumWindows(lpEnumFunc, lParam);
	}
	return User32EnumWindows(NULL, hWndParent, lpEnumFunc, lParam, 0, TRUE);
}

DECL_EXTERN_API(BOOL, EnumThreadWindows, DWORD dwThreadId,
	WNDENUMPROC lpfn,
	LPARAM lParam)
{
	if (!dwThreadId)
		dwThreadId = HcThreadCurrentId();

	return User32EnumWindows(NULL, NULL, lpfn, lParam, dwThreadId, FALSE);
}

DECL_EXTERN_API(BOOL, EnumWindows, WNDENUMPROC lpEnumFunc,
	LPARAM lParam)
{
	return User32EnumWindows(NULL, NULL, lpEnumFunc, lParam, 0, FALSE);
}

DECL_EXTERN_API(BOOL, EnumDesktopWindows, HDESK hDesktop,
	WNDENUMPROC lpfn,
	LPARAM lParam)
{
	return User32EnumWindows(hDesktop, NULL, lpfn, lParam, 0, FALSE);
}

DECL_EXTERN_API(PVOID, DesktopPtrToUser, PVOID Ptr)
{
	PCLIENTINFO pci;
	PDESKTOPINFO pdi;

	pci = GetWin32ClientInfo();
	pdi = pci->pDeskInfo;

	if ((ULONG_PTR) Ptr >= (ULONG_PTR) pdi->pvDesktopBase &&
		(ULONG_PTR) Ptr < (ULONG_PTR) pdi->pvDesktopLimit)
	{
		return (PVOID) ((ULONG_PTR) Ptr - pci->ulClientDelta);
	}
	else
	{
		/* NOTE: This is slow as it requires a call to win32k. This should only be
		neccessary if a thread wants to access an object on a different
		desktop */
		return (PVOID) HcUserCallOneParam((DWORD_PTR) Ptr, ONEPARAM_ROUTINE_GETDESKTOPMAPPING);
	}
}

DECL_EXTERN_API(HWND, GetWindow, HWND hWnd, UINT uCmd)
{
	//PWND Wnd, FoundWnd;
	//HWND Ret = NULL;

	//Wnd = HcValidateHwnd(hWnd);
	//if (!Wnd)
	//	return NULL;

	//__try
	//{
	//	FoundWnd = NULL;
	//	switch (uCmd)
	//	{
	//		case GW_OWNER:
	//		if (Wnd->spwndOwner != NULL)
	//			FoundWnd = HcDesktopPtrToUser(Wnd->spwndOwner);
	//		break;

	//		case GW_HWNDFIRST:
	//		if (Wnd->spwndParent != NULL)
	//		{
	//			FoundWnd = HcDesktopPtrToUser(Wnd->spwndParent);
	//			if (FoundWnd->spwndChild != NULL)
	//				FoundWnd = HcDesktopPtrToUser(FoundWnd->spwndChild);
	//		}
	//		break;
	//		case GW_HWNDNEXT:
	//		if (Wnd->spwndNext != NULL)
	//			FoundWnd = HcDesktopPtrToUser(Wnd->spwndNext);
	//		break;

	//		case GW_HWNDPREV:
	//		if (Wnd->spwndPrev != NULL)
	//			FoundWnd = HcDesktopPtrToUser(Wnd->spwndPrev);
	//		break;

	//		case GW_CHILD:
	//		if (Wnd->spwndChild != NULL)
	//			FoundWnd = HcDesktopPtrToUser(Wnd->spwndChild);
	//		break;

	//		case GW_HWNDLAST:
	//		FoundWnd = Wnd;
	//		while (FoundWnd->spwndNext != NULL)
	//			FoundWnd = HcDesktopPtrToUser(FoundWnd->spwndNext);
	//		break;

	//		default:
	//		Wnd = NULL;
	//		break;
	//	}

	//	if (FoundWnd != NULL)
	//		Ret = UserHMGetHandle(FoundWnd);
	//}
	//__except(EXCEPTION_EXECUTE_HANDLER)
	//{
	//	/* Do nothing */
	//}

	//return Ret;
	return NULL;
}

DECL_EXTERN_API(HWND, GetTopWindow, HWND hWnd)
{
	return HcGetWindow(hWnd, GW_CHILD);
}

DECL_EXTERN_API(PWND, ValidateHwnd, HWND hwnd)
{
	PCLIENTINFO ClientInfo = GetWin32ClientInfo();
		
	/* See if the window is cached */
	if (hwnd && hwnd == ClientInfo->CallbackWnd->hWnd)
		return ClientInfo->CallbackWnd->pWnd;
		
	return HcValidateHandle((HANDLE) hwnd, TYPE_WINDOW);
}

static const BOOL g_ObjectHeapTypeShared[TYPE_CTYPES] =
{
	FALSE, /* TYPE_FREE (not used) */
	FALSE, /* TYPE_WINDOW */
	FALSE, /* TYPE_MENU */
	TRUE,  /* TYPE_CURSOR */
	TRUE,  /* TYPE_SETWINDOWPOS */
	FALSE, /* TYPE_HOOK */
	TRUE,  /* TYPE_CLIPDATA */
	FALSE, /* TYPE_CALLPROC */
	TRUE,  /* TYPE_ACCELTABLE */
	FALSE, /* TYPE_DDEACCESS */
	FALSE, /* TYPE_DDECONV */
	FALSE, /* TYPE_DDEXACT */
	TRUE,  /* TYPE_MONITOR */
	TRUE,  /* TYPE_KBDLAYOUT */
	TRUE,  /* TYPE_KBDFILE */
	TRUE,  /* TYPE_WINEVENTHOOK */
	TRUE,  /* TYPE_TIMER */
	FALSE, /* TYPE_INPUTCONTEXT */
	FALSE, /* TYPE_HIDDATA */
	FALSE, /* TYPE_DEVICEINFO */
	FALSE, /* TYPE_TOUCHINPUTINFO */
	FALSE, /* TYPE_GESTUREINFOOBJ */
};

DECL_EXTERN_API(PVOID, ValidateHandle, HANDLE handle, UINT uType)
{
	PVOID ret;
	PUSER_HANDLE_ENTRY pEntry;

	ASSERT(uType < TYPE_CTYPES);

	pEntry = HcGetUser32Handle(handle);

	if (pEntry && uType == 0)
		uType = pEntry->type;

	// Must have an entry and must be the same type!
	if ((!pEntry) ||
		(pEntry->type != uType) ||
		!pEntry->ptr ||
		(pEntry->flags & HANDLEENTRY_DESTROY) || (pEntry->flags & HANDLEENTRY_INDESTROY))
	{
		switch (uType)
		{  // Test (with wine too) confirms these results!
			case TYPE_WINDOW:
			HcErrorSetDosError(ERROR_INVALID_WINDOW_HANDLE);
			break;
			case TYPE_MENU:
			HcErrorSetDosError(ERROR_INVALID_MENU_HANDLE);
			break;
			case TYPE_CURSOR:
			HcErrorSetDosError(ERROR_INVALID_CURSOR_HANDLE);
			break;
			case TYPE_SETWINDOWPOS:
			HcErrorSetDosError(ERROR_INVALID_DWP_HANDLE);
			break;
			case TYPE_HOOK:
			HcErrorSetDosError(ERROR_INVALID_HOOK_HANDLE);
			break;
			case TYPE_ACCELTABLE:
			HcErrorSetDosError(ERROR_INVALID_ACCEL_HANDLE);
			break;
			default:
			HcErrorSetDosError(ERROR_INVALID_HANDLE);
			break;
		}
		return NULL;
	}

	if (g_ObjectHeapTypeShared[uType])
		ret = HcSharedPtrToUser(pEntry->ptr);
	else
		ret = HcDesktopPtrToUser(pEntry->ptr);

	return ret;
}

DECL_EXTERN_API(PUSER_HANDLE_ENTRY, GetUser32Handle, HANDLE handle)
{
	INT Index;
	USHORT generation;

	if (!handle) return NULL;

	Index = (((UINT_PTR) handle & 0xffff) - FIRST_USER_HANDLE) >> 1;

	if (Index < 0 || Index >= HcGlobal.HandleTable->nb_handles)
		return NULL;

	if (!HcGlobal.HandleEntries[Index].type || !HcGlobal.HandleEntries[Index].ptr)
		return NULL;

	generation = (UINT_PTR) handle >> 16;

	if (generation == HcGlobal.HandleEntries[Index].generation || !generation || generation == 0xffff)
		return &HcGlobal.HandleEntries[Index];

	return NULL;
}


DECL_EXTERN_API(PVOID, SharedPtrToUser, PVOID Ptr)
{
	if (Ptr == NULL || HcGlobal.ulSharedDelta == 0)
		return NULL;

	return (PVOID) ((ULONG_PTR) Ptr - HcGlobal.ulSharedDelta);
}
