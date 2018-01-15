/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/u.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/u.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with U.
*/
void initFuncParamNamesMap_U(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("UnhandledExceptionFilter", 1, "ExceptionInfo"); // struct _EXCEPTION_POINTERS *
	ADD_PARAM_NAME("UnhookWinEvent", 1, "hWinEventHook"); // HWINEVENTHOOK
	ADD_PARAM_NAME("UnhookWindowsHook", 1, "nCode"); // int
	ADD_PARAM_NAME("UnhookWindowsHook", 2, "pfnFilterProc"); // HOOKPROC
	ADD_PARAM_NAME("UnhookWindowsHookEx", 1, "hhk"); // HHOOK
	ADD_PARAM_NAME("UnionRect", 1, "lprcDst"); // LPRECT
	ADD_PARAM_NAME("UnionRect", 2, "lprcSrc1"); // CONST RECT *
	ADD_PARAM_NAME("UnionRect", 3, "lprcSrc2"); // CONST RECT *
	ADD_PARAM_NAME("UnloadKeyboardLayout", 1, "hkl"); // HKL
	ADD_PARAM_NAME("UnlockFile", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("UnlockFile", 2, "dwFileOffsetLow"); // DWORD
	ADD_PARAM_NAME("UnlockFile", 3, "dwFileOffsetHigh"); // DWORD
	ADD_PARAM_NAME("UnlockFile", 4, "nNumberOfBytesToUnlockLow"); // DWORD
	ADD_PARAM_NAME("UnlockFile", 5, "nNumberOfBytesToUnlockHigh"); // DWORD
	ADD_PARAM_NAME("UnlockFileEx", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("UnlockFileEx", 2, "dwReserved"); // DWORD
	ADD_PARAM_NAME("UnlockFileEx", 3, "nNumberOfBytesToUnlockLow"); // DWORD
	ADD_PARAM_NAME("UnlockFileEx", 4, "nNumberOfBytesToUnlockHigh"); // DWORD
	ADD_PARAM_NAME("UnlockFileEx", 5, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("UnlockServiceDatabase", 1, "ScLock"); // SC_LOCK
	ADD_PARAM_NAME("UnmapViewOfFile", 1, "lpBaseAddress"); // LPCVOID
	ADD_PARAM_NAME("UnrealizeObject", 1, "h"); // HGDIOBJ
	ADD_PARAM_NAME("UnregisterClassA", 1, "lpClassName"); // LPCSTR
	ADD_PARAM_NAME("UnregisterClassA", 2, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("UnregisterClassW", 1, "lpClassName"); // LPCWSTR
	ADD_PARAM_NAME("UnregisterClassW", 2, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("UnregisterDeviceNotification", 1, "Handle"); // HDEVNOTIFY
	ADD_PARAM_NAME("UnregisterHotKey", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("UnregisterHotKey", 2, "id"); // int
	ADD_PARAM_NAME("UnregisterPowerSettingNotification", 1, "Handle"); // HPOWERNOTIFY
	ADD_PARAM_NAME("UnregisterTouchWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("UnregisterWait", 1, "WaitHandle"); // HANDLE
	ADD_PARAM_NAME("UnregisterWaitEx", 1, "WaitHandle"); // HANDLE
	ADD_PARAM_NAME("UnregisterWaitEx", 2, "CompletionEvent"); // HANDLE
	ADD_PARAM_NAME("UpdateColors", 1, "hdc"); // HDC
	ADD_PARAM_NAME("UpdateICMRegKeyA", 1, "reserved"); // DWORD
	ADD_PARAM_NAME("UpdateICMRegKeyA", 2, "lpszCMID"); // LPSTR
	ADD_PARAM_NAME("UpdateICMRegKeyA", 3, "lpszFileName"); // LPSTR
	ADD_PARAM_NAME("UpdateICMRegKeyA", 4, "command"); // UINT
	ADD_PARAM_NAME("UpdateICMRegKeyW", 1, "reserved"); // DWORD
	ADD_PARAM_NAME("UpdateICMRegKeyW", 2, "lpszCMID"); // LPWSTR
	ADD_PARAM_NAME("UpdateICMRegKeyW", 3, "lpszFileName"); // LPWSTR
	ADD_PARAM_NAME("UpdateICMRegKeyW", 4, "command"); // UINT
	ADD_PARAM_NAME("UpdateLayeredWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("UpdateLayeredWindow", 2, "hdcDst"); // HDC
	ADD_PARAM_NAME("UpdateLayeredWindow", 3, "pptDst"); // POINT *
	ADD_PARAM_NAME("UpdateLayeredWindow", 4, "psize"); // SIZE *
	ADD_PARAM_NAME("UpdateLayeredWindow", 5, "hdcSrc"); // HDC
	ADD_PARAM_NAME("UpdateLayeredWindow", 6, "pptSrc"); // POINT *
	ADD_PARAM_NAME("UpdateLayeredWindow", 7, "crKey"); // COLORREF
	ADD_PARAM_NAME("UpdateLayeredWindow", 8, "pblend"); // BLENDFUNCTION *
	ADD_PARAM_NAME("UpdateLayeredWindow", 9, "dwFlags"); // DWORD
	ADD_PARAM_NAME("UpdateLayeredWindowIndirect", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("UpdateLayeredWindowIndirect", 2, "pULWInfo"); // UPDATELAYEREDWINDOWINFO CONST *
	ADD_PARAM_NAME("UpdateProcThreadAttribute", 1, "lpAttributeList"); // LPPROC_THREAD_ATTRIBUTE_LIST
	ADD_PARAM_NAME("UpdateProcThreadAttribute", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("UpdateProcThreadAttribute", 3, "Attribute"); // DWORD_PTR
	ADD_PARAM_NAME("UpdateProcThreadAttribute", 4, "lpValue"); // PVOID
	ADD_PARAM_NAME("UpdateProcThreadAttribute", 5, "cbSize"); // SIZE_T
	ADD_PARAM_NAME("UpdateProcThreadAttribute", 6, "lpPreviousValue"); // PVOID
	ADD_PARAM_NAME("UpdateProcThreadAttribute", 7, "lpReturnSize"); // PSIZE_T
	ADD_PARAM_NAME("UpdateResourceA", 1, "hUpdate"); // HANDLE
	ADD_PARAM_NAME("UpdateResourceA", 2, "lpType"); // LPCSTR
	ADD_PARAM_NAME("UpdateResourceA", 3, "lpName"); // LPCSTR
	ADD_PARAM_NAME("UpdateResourceA", 4, "wLanguage"); // WORD
	ADD_PARAM_NAME("UpdateResourceA", 5, "lpData"); // LPVOID
	ADD_PARAM_NAME("UpdateResourceA", 6, "cb"); // DWORD
	ADD_PARAM_NAME("UpdateResourceW", 1, "hUpdate"); // HANDLE
	ADD_PARAM_NAME("UpdateResourceW", 2, "lpType"); // LPCWSTR
	ADD_PARAM_NAME("UpdateResourceW", 3, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("UpdateResourceW", 4, "wLanguage"); // WORD
	ADD_PARAM_NAME("UpdateResourceW", 5, "lpData"); // LPVOID
	ADD_PARAM_NAME("UpdateResourceW", 6, "cb"); // DWORD
	ADD_PARAM_NAME("UpdateWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("UploadPrinterDriverPackageA", 1, "pszServer"); // LPCSTR
	ADD_PARAM_NAME("UploadPrinterDriverPackageA", 2, "pszInfPath"); // LPCSTR
	ADD_PARAM_NAME("UploadPrinterDriverPackageA", 3, "pszEnvironment"); // LPCSTR
	ADD_PARAM_NAME("UploadPrinterDriverPackageA", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("UploadPrinterDriverPackageA", 5, "hWnd"); // HWND
	ADD_PARAM_NAME("UploadPrinterDriverPackageA", 6, "pszDestInfPath"); // LPSTR
	ADD_PARAM_NAME("UploadPrinterDriverPackageA", 7, "pcchDestInfPath"); // PULONG
	ADD_PARAM_NAME("UploadPrinterDriverPackageW", 1, "pszServer"); // LPCWSTR
	ADD_PARAM_NAME("UploadPrinterDriverPackageW", 2, "pszInfPath"); // LPCWSTR
	ADD_PARAM_NAME("UploadPrinterDriverPackageW", 3, "pszEnvironment"); // LPCWSTR
	ADD_PARAM_NAME("UploadPrinterDriverPackageW", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("UploadPrinterDriverPackageW", 5, "hWnd"); // HWND
	ADD_PARAM_NAME("UploadPrinterDriverPackageW", 6, "pszDestInfPath"); // LPWSTR
	ADD_PARAM_NAME("UploadPrinterDriverPackageW", 7, "pcchDestInfPath"); // PULONG
	ADD_PARAM_NAME("UserHandleGrantAccess", 1, "hUserHandle"); // HANDLE
	ADD_PARAM_NAME("UserHandleGrantAccess", 2, "hJob"); // HANDLE
	ADD_PARAM_NAME("UserHandleGrantAccess", 3, "bGrant"); // WINBOOL
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
