#include <highcall.h>

DECL_EXTERN_API(SHORT, GetAsyncKeyState, INT vKey)
{
	return HcUserGetAsyncKeyState(vKey);
}

DECL_EXTERN_API(BOOL, PostThreadMessageA,
	DWORD idThread,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam)
{
	return HcUserPostThreadMessage(idThread, Msg, wParam, lParam);
}

DECL_EXTERN_API(BOOL, PostThreadMessageW,
	DWORD idThread,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam)
{
	return HcUserPostThreadMessage(idThread, Msg, wParam, lParam);
}

DECL_EXTERN_API(LRESULT, SendMessageW, 
	HWND Wnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam)
{
	MSG userMsg;
	LRESULT Result;
	BOOL Ret;

	userMsg.hwnd = Wnd;
	userMsg.message = Msg;
	userMsg.wParam = wParam;
	userMsg.lParam = lParam;
	userMsg.time = 0;
	userMsg.pt.x = 0;
	userMsg.pt.y = 0;

	Ret = HcUserMessageCall(Wnd,
		userMsg.message,
		userMsg.wParam,
		userMsg.lParam,
		(ULONG_PTR) &Result,
		0x02B1, /* FNID_SENDMESSAGE */
		FALSE);

	return Result;
}