#pragma once
#include "native.h"

#define UserHMGetHandle(obj) ((obj)->head.h)

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

#ifdef __cplusplus
typedef struct _THROBJHEAD : HEAD
{
#else
typedef struct _THROBJHEAD 
{
	HEAD;
#endif
	struct _THREADINFO *pti;
} THROBJHEAD, *PTHROBJHEAD;

#ifdef __cplusplus
typedef struct _THRDESKHEAD : THROBJHEAD 
{
#else
typedef struct _THRDESKHEAD 
{
	THROBJHEAD;
#endif
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

#define GetWin32ClientInfo()((PCLIENTINFO)(NtCurrentTeb()->Win32ClientInfo))

typedef struct _W32THREAD {
	PVOID pEThread;
	LONG RefCount;
	PVOID ptlW32;
	PVOID pgdiDcattr;
	PVOID pgdiBrushAttr;
	PVOID pUMPDObjs;
	PVOID pUMPDHeap;
	DWORD dwEngAcquireCount;
	PVOID pSemTable;
	PVOID pUMPDObj;
} W32THREAD, *PW32THREAD;

#define QSIDCOUNTS 7

#ifdef __cplusplus
typedef struct _THREADINFO : _W32THREAD {
#else
typedef struct _THREADINFO {
	W32THREAD;
#endif
	PVOID                 ptl;
	struct PROCESSINFO*  ppi;
	struct _USER_MESSAGE_QUEUE* MessageQueue;
	struct tagKL*       KeyboardLayout;
	struct _CLIENTTHREADINFO  * pcti;
	struct _DESKTOP*    rpdesk;
	struct _DESKTOPINFO  *  pDeskInfo;
	struct _CLIENTINFO * pClientInfo;
	FLONG               TIF_flags;
	PUNICODE_STRING     pstrAppName;
	struct _USER_SENT_MESSAGE *pusmSent;
	struct _USER_SENT_MESSAGE *pusmCurrent;
	/* Queue of messages sent to the queue. */
	LIST_ENTRY          SentMessagesListHead;    // psmsReceiveList
												 /* Last time PeekMessage() was called. */
	LONG                timeLast;
	ULONG_PTR           idLast;
	/* True if a WM_QUIT message is pending. */
	BOOLEAN             QuitPosted;
	/* The quit exit code. */
	INT                 exitCode;
	HDESK               hdesk;
	UINT                cPaintsReady; /* Count of paints pending. */
	UINT                cTimersReady; /* Count of timers pending. */
	struct tagMENUSTATE* pMenuState;
	DWORD               dwExpWinVer;
	DWORD               dwCompatFlags;
	DWORD               dwCompatFlags2;
	struct _USER_MESSAGE_QUEUE* pqAttach;
	PVOID         ptiSibling;
	ULONG               fsHooks;
	struct tagHOOK *    sphkCurrent;
	LPARAM              lParamHkCurrent;
	WPARAM              wParamHkCurrent;
	struct tagSBTRACK*  pSBTrack;
	/* Set if there are new messages specified by WakeMask in any of the queues. */
	HANDLE              hEventQueueClient;
	/* Handle for the above event (in the context of the process owning the queue). */
	PVOID             pEventQueueServer;
	LIST_ENTRY          PtiLink;
	INT                 iCursorLevel;
	POINT               ptLast;

	INT                 cEnterCount;
	/* Queue of messages posted to the queue. */
	LIST_ENTRY          PostedMessagesListHead; // mlPost
	WORD                fsChangeBitsRemoved;
	WCHAR               wchInjected;
	UINT                cWindows;
	UINT                cVisWindows;
#ifndef __cplusplus /// FIXME!
	LIST_ENTRY          aphkStart[NB_HOOKS];
	CLIENTTHREADINFO    cti;  // Used only when no Desktop or pcti NULL.

							  /* ReactOS */

							  /* Thread Queue state tracking */
							  // Send list QS_SENDMESSAGE
							  // Post list QS_POSTMESSAGE|QS_HOTKEY|QS_PAINT|QS_TIMER|QS_KEY
							  // Hard list QS_MOUSE|QS_KEY only
							  // Accounting of queue bit sets, the rest are flags. QS_TIMER QS_PAINT counts are handled in thread information.
	DWORD nCntsQBits[QSIDCOUNTS]; // QS_KEY QS_MOUSEMOVE QS_MOUSEBUTTON QS_POSTMESSAGE QS_SENDMESSAGE QS_HOTKEY

	LIST_ENTRY WindowListHead;
	LIST_ENTRY W32CallbackListHead;
	SINGLE_LIST_ENTRY  ReferencesList;
	ULONG cExclusiveLocks;
#if DBG
	USHORT acExclusiveLockCount[GDIObjTypeTotal + 1];
#endif
#endif // __cplusplus
} THREADINFO, *PTHREADINFO;

#define CLIBS 32

typedef struct _W32PROCESS {
	PVOID     peProcess;
	DWORD         RefCount;
	ULONG         W32PF_flags;
	PVOID       InputIdleEvent;
	DWORD         StartCursorHideTime;
	struct _W32PROCESS* NextStart;
	PVOID         pDCAttrList;
	PVOID         pBrushAttrList;
	DWORD         W32Pid;
	LONG          GDIHandleCount;
	LONG          UserHandleCount;
} W32PROCESS, *PW32PROCESS;

typedef struct tagUSERSTARTUPINFO {
	ULONG cb;
	DWORD dwX;        // STARTF_USEPOSITION StartupInfo->dwX/Y
	DWORD dwY;
	DWORD dwXSize;    // STARTF_USESIZE StartupInfo->dwX/YSize
	DWORD dwYSize;
	DWORD dwFlags;    // STARTF_ StartupInfo->dwFlags
	WORD wShowWindow; // StartupInfo->wShowWindow
	USHORT cbReserved2;
} USERSTARTUPINFO, *PUSERSTARTUPINFO;


enum ThreadStateRoutines {
	THREADSTATE_GETTHREADINFO,
	THREADSTATE_INSENDMESSAGE,
	THREADSTATE_FOCUSWINDOW,
	THREADSTATE_ACTIVEWINDOW,
	THREADSTATE_CAPTUREWINDOW,
	THREADSTATE_PROGMANWINDOW,
	THREADSTATE_TASKMANWINDOW,
	THREADSTATE_GETMESSAGETIME,
	THREADSTATE_GETINPUTSTATE,
	THREADSTATE_UPTIMELASTREAD,
	THREADSTATE_FOREGROUNDTHREAD,
	THREADSTATE_GETCURSOR,
	THREADSTATE_GETMESSAGEEXTRAINFO
};

#define NOPARAM_ROUTINE_ISCONSOLEMODE             0xffff0001
#define ONEPARAM_ROUTINE_ENABLEPROCWNDGHSTING     0xfffe000d
#define ONEPARAM_ROUTINE_GETDESKTOPMAPPING        0xfffe000e
#define TWOPARAM_ROUTINE_SETMENUBARHEIGHT         0xfffd0050
#define TWOPARAM_ROUTINE_SETGUITHRDHANDLE         0xfffd0051
#define HWNDLOCK_ROUTINE_SETFOREGROUNDWINDOWMOUSE 0xfffd0052

typedef struct _WND {
	THRDESKHEAD head;
#if 0
	WW ww;
#else
	/* These fields should be moved in the WW at some point. */
	/* Plese do not change them to keep the same layout with WW. */
	DWORD state;
	DWORD state2;
	/* Extended style. */
	DWORD ExStyle;
	/* Style. */
	DWORD style;
	/* Handle of the module that created the window. */
	HINSTANCE hModule;
	DWORD fnid;
#endif
	struct _WND *spwndNext;
	struct _WND *spwndPrev;
	struct _WND *spwndParent;
	struct _WND *spwndChild;
	struct _WND *spwndOwner;
	RECT rcWindow;
	RECT rcClient;
	WNDPROC lpfnWndProc;
	/* Pointer to the window class. */
	PVOID pcls;
	HRGN hrgnUpdate;
	/* Property list head.*/
	LIST_ENTRY PropListHead;
	ULONG PropListItems;
	/* Scrollbar info */
	PVOID pSBInfo;
	/* system menu handle. */
	HMENU SystemMenu;
	//PMENU spmenuSys;
	/* Window menu handle or window id */
	UINT_PTR IDMenu; // Use spmenu
					 //PMENU spmenu;
	HRGN hrgnClip;
	HRGN hrgnNewFrame;
} WND, *PWND;

typedef enum _HANDLE_TYPE {
	TYPE_FREE = 0,
	TYPE_WINDOW = 1,
	TYPE_MENU = 2,
	TYPE_CURSOR = 3,
	TYPE_SETWINDOWPOS = 4,
	TYPE_HOOK = 5,
	TYPE_CLIPDATA = 6,
	TYPE_CALLPROC = 7,
	TYPE_ACCELTABLE = 8,
	TYPE_DDEACCESS = 9,
	TYPE_DDECONV = 10,
	TYPE_DDEXACT = 11,
	TYPE_MONITOR = 12,
	TYPE_KBDLAYOUT = 13,
	TYPE_KBDFILE = 14,
	TYPE_WINEVENTHOOK = 15,
	TYPE_TIMER = 16,
	TYPE_INPUTCONTEXT = 17,
	TYPE_HIDDATA = 18,
	TYPE_DEVICEINFO = 19,
	TYPE_TOUCHINPUTINFO = 20,
	TYPE_GESTUREINFOOBJ = 21,
	TYPE_CTYPES,
	TYPE_GENERIC = 255
} HANDLE_TYPE, *PHANDLE_TYPE;

#define HANDLEENTRY_DESTROY 1
#define HANDLEENTRY_INDESTROY 2

typedef struct _USER_HANDLE_ENTRY {
	void *ptr; /* pointer to object */
	union {
		PVOID pi;
		struct _THREADINFO *pti; /* pointer to Win32ThreadInfo */
		struct _PROCESSINFO *ppi; /* pointer to W32ProcessInfo */
	};
	unsigned char type; /* object type (0 if free) */
	unsigned char flags;
	unsigned short generation; /* generation counter */
} USER_HANDLE_ENTRY, *PUSER_HANDLE_ENTRY;

typedef struct _USER_HANDLE_TABLE {
	PUSER_HANDLE_ENTRY handles;
	PUSER_HANDLE_ENTRY freelist;
	int nb_handles;
	int allocated_handles;
} USER_HANDLE_TABLE, *PUSER_HANDLE_TABLE;

#define FIRST_USER_HANDLE 0x0020 /* first possible value for low word of user handle */
#define LAST_USER_HANDLE 0xffef /* last possible value for low word of user handle */

/* FNID's for NtUserSetWindowFNID, NtUserMessageCall */
#define FNID_FIRST                  0x029A
#define FNID_SCROLLBAR              0x029A
#define FNID_ICONTITLE              0x029B
#define FNID_MENU                   0x029C
#define FNID_DESKTOP                0x029D
#define FNID_DEFWINDOWPROC          0x029E
#define FNID_MESSAGEWND             0x029F
#define FNID_SWITCH                 0x02A0
#define FNID_BUTTON                 0x02A1
#define FNID_COMBOBOX               0x02A2
#define FNID_COMBOLBOX              0x02A3
#define FNID_DIALOG                 0x02A4
#define FNID_EDIT                   0x02A5
#define FNID_LISTBOX                0x02A6
#define FNID_MDICLIENT              0x02A7
#define FNID_STATIC                 0x02A8
#define FNID_IME                    0x02A9
#define FNID_GHOST                  0x02AA
#define FNID_CALLWNDPROC            0x02AB
#define FNID_CALLWNDPROCRET         0x02AC
#define FNID_HKINLPCWPEXSTRUCT      0x02AD
#define FNID_HKINLPCWPRETEXSTRUCT   0x02AE
#define FNID_MB_DLGPROC             0x02AF
#define FNID_MDIACTIVATEDLGPROC     0x02B0
#define FNID_SENDMESSAGE            0x02B1
#define FNID_SENDMESSAGEFF          0x02B2
/* Kernel has option to use TimeOut or normal msg send, based on type of msg. */
#define FNID_SENDMESSAGEWTOOPTION   0x02B3
#define FNID_SENDMESSAGECALLPROC    0x02B4
#define FNID_BROADCASTSYSTEMMESSAGE 0x02B5
#define FNID_TOOLTIPS               0x02B6
#define FNID_SENDNOTIFYMESSAGE      0x02B7
#define FNID_SENDMESSAGECALLBACK    0x02B8
#define FNID_LAST                   0x02B9

#define FNID_NUM FNID_LAST - FNID_FIRST + 1
#define FNID_NUMSERVERPROC FNID_SWITCH - FNID_FIRST + 1

#define FNID_DDEML   0x2000 /* Registers DDEML */
#define FNID_DESTROY 0x4000 /* This is sent when WM_NCDESTROY or in the support routine. */
/* Seen during WM_CREATE on error exit too. */
#define FNID_FREED   0x8000 /* Window being Freed... */

typedef LONG_PTR
(NTAPI *PFN_FNID)(
	PWND,
	UINT,
	WPARAM,
	LPARAM,
	ULONG_PTR);

typedef struct _PFNCLIENT {
	WNDPROC pfnScrollBarWndProc;
	WNDPROC pfnTitleWndProc;
	WNDPROC pfnMenuWndProc;
	WNDPROC pfnDesktopWndProc;
	WNDPROC pfnDefWindowProc;
	WNDPROC pfnMessageWindowProc;
	WNDPROC pfnSwitchWindowProc;
	WNDPROC pfnButtonWndProc;
	WNDPROC pfnComboBoxWndProc;
	WNDPROC pfnComboListBoxProc;
	WNDPROC pfnDialogWndProc;
	WNDPROC pfnEditWndProc;
	WNDPROC pfnListBoxWndProc;
	WNDPROC pfnMDIClientWndProc;
	WNDPROC pfnStaticWndProc;
	WNDPROC pfnImeWndProc;
	WNDPROC pfnGhostWndProc;
	WNDPROC pfnHkINLPCWPSTRUCT;
	WNDPROC pfnHkINLPCWPRETSTRUCT;
	WNDPROC pfnDispatchHook;
	WNDPROC pfnDispatchDefWindowProc;
	WNDPROC pfnDispatchMessage;
	WNDPROC pfnMDIActivateDlgProc;
} PFNCLIENT, *PPFNCLIENT;

typedef LRESULT
(CALLBACK *WNDPROC_EX)(
	HWND,
	UINT,
	WPARAM,
	LPARAM,
	BOOL);

typedef struct _PFNCLIENTWORKER {
	WNDPROC_EX pfnButtonWndProc;
	WNDPROC_EX pfnComboBoxWndProc;
	WNDPROC_EX pfnComboListBoxProc;
	WNDPROC_EX pfnDialogWndProc;
	WNDPROC_EX pfnEditWndProc;
	WNDPROC_EX pfnListBoxWndProc;
	WNDPROC_EX pfnMDIClientWndProc;
	WNDPROC_EX pfnStaticWndProc;
	WNDPROC_EX pfnImeWndProc;
	WNDPROC_EX pfnGhostWndProc;
	WNDPROC_EX pfnCtfHookProc;
} PFNCLIENTWORKER, *PPFNCLIENTWORKER;

typedef struct tagMBSTRING {
	WCHAR szName[16];
	UINT uID;
	UINT uStr;
} MBSTRING, *PMBSTRING;

typedef struct tagOEMBITMAPINFO {
	INT x;
	INT y;
	INT cx;
	INT cy;
} OEMBITMAPINFO, *POEMBITMAPINFO;

typedef struct tagDPISERVERINFO {
	INT gclBorder;      /* 000 */
	HFONT hCaptionFont; /* 004 */
	HFONT hMsgFont;     /* 008 */
	INT cxMsgFontChar;  /* 00C */
	INT cyMsgFontChar;  /* 010 */
	UINT wMaxBtnSize;   /* 014 */
} DPISERVERINFO, *PDPISERVERINFO;
/*
typedef struct tagTEXTMETRICW {
	LONG tmHeight;
	LONG tmAscent;
	LONG tmDescent;
	LONG tmInternalLeading;
	LONG tmExternalLeading;
	LONG tmAveCharWidth;
	LONG tmMaxCharWidth;
	LONG tmWeight;
	LONG tmOverhang;
	LONG tmDigitizedAspectX;
	LONG tmDigitizedAspectY;
	WCHAR tmFirstChar;
	WCHAR tmLastChar;
	WCHAR tmDefaultChar;
	WCHAR tmBreakChar;
	BYTE tmItalic;
	BYTE tmUnderlined;
	BYTE tmStruckOut;
	BYTE tmPitchAndFamily;
	BYTE tmCharSet;
} TEXTMETRICW, *PTEXTMETRICW, *LPTEXTMETRICW*/;

#define NUM_SYSCOLORS 31

typedef enum _OBI_TYPES {
	OBI_CLOSE = 0,
	OBI_UPARROW = 46,
	OBI_UPARROWI = 49,
	OBI_DNARROW = 50,
	OBI_DNARROWI = 53,
	OBI_MNARROW = 62,
	OBI_CTYPES = 93
} OBI_TYPES;

typedef struct _PERUSERSERVERINFO {
	INT aiSysMet[SM_CMETRICS];
	ULONG argbSystemUnmatched[NUM_SYSCOLORS];
	COLORREF argbSystem[NUM_SYSCOLORS];
	HBRUSH ahbrSystem[NUM_SYSCOLORS];
	HBRUSH hbrGray;
	POINT ptCursor;
	POINT ptCursorReal;
	DWORD dwLastRITEventTickCount;
	INT nEvents;
	UINT dtScroll;
	UINT dtLBSearch;
	UINT dtCaretBlink;
	UINT ucWheelScrollLines;
	UINT ucWheelScrollChars;
	INT wMaxLeftOverlapChars;
	INT wMaxRightOverlapChars;
	INT cxSysFontChar;
	INT cySysFontChar;
	PVOID tmSysFont;
	DPISERVERINFO dpiSystem;
	HICON hIconSmWindows;
	HICON hIconWindows;
	DWORD dwKeyCache;
	DWORD dwAsyncKeyCache;
	ULONG cCaptures;
	OEMBITMAPINFO oembmi[OBI_CTYPES];
	RECT rcScreenReal;
	USHORT BitCount;
	USHORT dmLogPixels;
	BYTE Planes;
	BYTE BitsPixel;
	ULONG PUSIFlags;
	UINT uCaretWidth;
	USHORT UILangID;
	DWORD dwLastSystemRITEventTickCountUpdate;
	ULONG adwDBGTAGFlags[35];
	DWORD dwTagCount;
	DWORD dwRIPFlags;
} PERUSERSERVERINFO, *PPERUSERSERVERINFO;

#define ICLS_BUTTON       0
#define ICLS_EDIT         1
#define ICLS_STATIC       2
#define ICLS_LISTBOX      3
#define ICLS_SCROLLBAR    4
#define ICLS_COMBOBOX     5
#define ICLS_MDICLIENT    6
#define ICLS_COMBOLBOX    7
#define ICLS_DDEMLEVENT   8
#define ICLS_DDEMLMOTHER  9
#define ICLS_DDEML16BIT   10
#define ICLS_DDEMLCLIENTA 11
#define ICLS_DDEMLCLIENTW 12
#define ICLS_DDEMLSERVERA 13
#define ICLS_DDEMLSERVERW 14
#define ICLS_IME          15
#define ICLS_GHOST        16
#define ICLS_DESKTOP      17
#define ICLS_DIALOG       18
#define ICLS_MENU         19
#define ICLS_SWITCH       20
#define ICLS_ICONTITLE    21
#define ICLS_TOOLTIPS     22
#if (_WIN32_WINNT <= 0x0501)
#define ICLS_UNKNOWN      22
#define ICLS_NOTUSED      23
#else
#define ICLS_SYSSHADOW    23
#define ICLS_HWNDMESSAGE  24
#define ICLS_NOTUSED      25
#endif
#define ICLS_END          31

#define MAX_MB_STRINGS 11

#ifdef __cplusplus
typedef struct tagSERVERINFO {
	DWORD dwSRVIFlags;
	ULONG_PTR cHandleEntries;
	PFN_FNID mpFnidPfn[FNID_NUM];
	WNDPROC aStoCidPfn[FNID_NUMSERVERPROC];
	USHORT mpFnid_serverCBWndProc[FNID_NUM];
	PFNCLIENT apfnClientA;
	PFNCLIENT apfnClientW;
	PFNCLIENTWORKER apfnClientWorker;
	ULONG cbHandleTable;
	ATOM atomSysClass[ICLS_NOTUSED + 1];
	DWORD dwDefaultHeapBase;
	DWORD dwDefaultHeapSize;
	UINT uiShellMsg;
	MBSTRING MBStrings[MAX_MB_STRINGS];
	ATOM atomIconSmProp;
	ATOM atomIconProp;
	ATOM atomContextHelpIdProp;
	ATOM atomFrostedWindowProp;
	CHAR acOemToAnsi[256];
	CHAR acAnsiToOem[256];
	DWORD dwInstalledEventHooks;
	PERUSERSERVERINFO ServerInfo;
} SERVERINFO, *PSERVERINFO;
#else
typedef struct tagSERVERINFO {
	DWORD dwSRVIFlags;
	ULONG_PTR cHandleEntries;
	PFN_FNID mpFnidPfn[FNID_NUM];
	WNDPROC aStoCidPfn[FNID_NUMSERVERPROC];
	USHORT mpFnid_serverCBWndProc[FNID_NUM];
	PFNCLIENT apfnClientA;
	PFNCLIENT apfnClientW;
	PFNCLIENTWORKER apfnClientWorker;
	ULONG cbHandleTable;
	ATOM atomSysClass[ICLS_NOTUSED + 1];
	DWORD dwDefaultHeapBase;
	DWORD dwDefaultHeapSize;
	UINT uiShellMsg;
	MBSTRING MBStrings[MAX_MB_STRINGS];
	ATOM atomIconSmProp;
	ATOM atomIconProp;
	ATOM atomContextHelpIdProp;
	ATOM atomFrostedWindowProp;
	CHAR acOemToAnsi[256];
	CHAR acAnsiToOem[256];
	DWORD dwInstalledEventHooks;
	PERUSERSERVERINFO;
} SERVERINFO, *PSERVERINFO;
#endif

typedef struct _WNDMSG {
	DWORD maxMsgs;
	PINT abMsgs;
} WNDMSG, *PWNDMSG;

typedef struct _SHAREDINFO {
	PSERVERINFO psi; /* global Server Info */
	PVOID aheList; /* Handle Entry List */
	PVOID pDispInfo; /* global PDISPLAYINFO pointer */
	ULONG_PTR ulSharedDelta; /* Heap delta */
	WNDMSG awmControl[FNID_LAST - FNID_FIRST];
	WNDMSG DefWindowMsgs;
	WNDMSG DefWindowSpecMsgs;
} SHAREDINFO, *PSHAREDINFO;

typedef struct _USERCONNECT {
	ULONG ulVersion;
	ULONG ulCurrentVersion;
	DWORD dwDispatchCount;
	SHAREDINFO siClient;
} USERCONNECT, *PUSERCONNECT;