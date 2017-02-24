#pragma once
#include "native.h"

typedef struct _DESKTOPINFO
{
	PVOID pvDesktopBase;
	PVOID pvDesktopLimit;
	struct _WND *spwnd;
	DWORD fsHooks;
	LIST_ENTRY aphkStart[NB_HOOKS];

	HWND hTaskManWindow;
	HWND hProgmanWindow;
	HWND hShellWindow;
	struct _WND *spwndShell;
	struct _WND *spwndBkGnd;

	struct _PROCESSINFO *ppiShellProcess;

	union
	{
		UINT Dummy;
		struct
		{
			UINT LastInputWasKbd : 1;
		};
	};

	WCHAR szDesktopName[1];
} DESKTOPINFO, *PDESKTOPINFO;

typedef struct _HEAD
{
	HANDLE h;
	DWORD cLockObj;
} HEAD, *PHEAD;

typedef struct _THROBJHEAD
{
	HEAD obj;
	struct _THREADINFO *pti;
} THROBJHEAD, *PTHROBJHEAD;

typedef struct _THRDESKHEAD
{
	THROBJHEAD obj;
	struct _DESKTOP *rpdesk;
	PVOID pSelf;
} THRDESKHEAD, *PTHRDESKHEAD;

typedef struct tagHOOK
{
	THRDESKHEAD head;
	struct tagHOOK *phkNext; /* This is for user space. */
	int HookId; /* Hook table index */
	ULONG_PTR offPfn;
	ULONG flags; /* Some internal flags */
	INT ihmod;
	struct _THREADINFO *ptiHooked;
	struct _DESKTOP *rpdesk;
	/* ReactOS */
	LIST_ENTRY Chain; /* Hook chain entry */
	LPVOID Proc; /* Hook function */
	BOOLEAN Ansi; /* Is it an Ansi hook? */
	UNICODE_STRING ModuleName; /* Module name for global hooks */
} HOOK, *PHOOK;

typedef struct _CLIENTTHREADINFO
{
	DWORD CTI_flags;
	WORD fsChangeBits;
	WORD fsWakeBits;
	WORD fsWakeBitsJournal;
	WORD fsWakeMask;
	ULONG tickLastMsgChecked;
	DWORD dwcPumpHook;
} CLIENTTHREADINFO, *PCLIENTTHREADINFO;

typedef struct _CALLBACKWND

{
	HWND hWnd;
	struct _WND *pWnd;
	PVOID pActCtx;
} CALLBACKWND, *PCALLBACKWND;

/*
* Message structure
*/

typedef struct tagMSG {
	HWND        hwnd;
	UINT        message;
	WPARAM      wParam;
	LPARAM      lParam;
	DWORD       time;
	POINT       pt;
#ifdef _MAC
	DWORD       lPrivate;
#endif
} MSG, *PMSG, NEAR *NPMSG, FAR *LPMSG;


/*
* Structure used by WH_KEYBOARD_LL
*/

typedef struct tagKBDLLHOOKSTRUCT {
	DWORD   vkCode;
	DWORD   scanCode;
	DWORD   flags;
	DWORD   time;
	ULONG_PTR dwExtraInfo;
} KBDLLHOOKSTRUCT, FAR *LPKBDLLHOOKSTRUCT, *PKBDLLHOOKSTRUCT;

typedef struct _CLIENTINFO
{
	ULONG_PTR CI_flags;
	ULONG_PTR cSpins;
	DWORD dwExpWinVer;
	DWORD dwCompatFlags;
	DWORD dwCompatFlags2;
	DWORD dwTIFlags; /* ThreadInfo TIF_Xxx flags for User space. */
	PDESKTOPINFO pDeskInfo;
	ULONG_PTR ulClientDelta;
	PHOOK phkCurrent;
	ULONG fsHooks;
	CALLBACKWND CallbackWnd;
	DWORD dwHookCurrent;
	INT cInDDEMLCallback;
	PCLIENTTHREADINFO pClientThreadInfo;
	ULONG_PTR dwHookData;
	DWORD dwKeyCache;
	BYTE afKeyState[8];
	DWORD dwAsyncKeyCache;
	BYTE afAsyncKeyState[8];
	BYTE afAsyncKeyStateRecentDow[8];
	HKL hKL;
	USHORT CodePage;
	UCHAR achDbcsCF[2];
	UINT16 msgDbcsCB;
	LPDWORD lpdwRegisteredClasses;
	ULONG Win32ClientInfo3[26];
	/* It's just a pointer reference not to be used w the structure in user space. */
	struct _PROCESSINFO *ppi;
} CLIENTINFO, *PCLIENTINFO;

#define GetWin32ClientInfo()((PCLIENTINFO)(NtCurrentTeb()->Win32ClientInfo))