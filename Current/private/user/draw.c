#include <highcall.h>

DECL_EXTERN_API(BOOL, FlashWindow, HWND hWnd, BOOL bInvert)
{
	FLASHWINFO FlashWndInfo;
	
	FlashWndInfo.cbSize = sizeof(FLASHWINFO);
	FlashWndInfo.hwnd = hWnd;
	FlashWndInfo.dwFlags = !bInvert ? 0 : (FLASHW_TRAY | FLASHW_CAPTION);
	FlashWndInfo.uCount = 1;
	FlashWndInfo.dwTimeout = 0;
	
	return HcUserFlashWindowEx(&FlashWndInfo);
}