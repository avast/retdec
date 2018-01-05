/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/b.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/b.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with B.
*/
void initFuncParamNamesMap_B(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("BackupEventLogA", 1, "hEventLog"); // HANDLE
	ADD_PARAM_NAME("BackupEventLogA", 2, "lpBackupFileName"); // LPCSTR
	ADD_PARAM_NAME("BackupEventLogW", 1, "hEventLog"); // HANDLE
	ADD_PARAM_NAME("BackupEventLogW", 2, "lpBackupFileName"); // LPCWSTR
	ADD_PARAM_NAME("BackupRead", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("BackupRead", 2, "lpBuffer"); // LPBYTE
	ADD_PARAM_NAME("BackupRead", 3, "nNumberOfBytesToRead"); // DWORD
	ADD_PARAM_NAME("BackupRead", 4, "lpNumberOfBytesRead"); // LPDWORD
	ADD_PARAM_NAME("BackupRead", 5, "bAbort"); // WINBOOL
	ADD_PARAM_NAME("BackupRead", 6, "bProcessSecurity"); // WINBOOL
	ADD_PARAM_NAME("BackupRead", 7, "lpContext"); // LPVOID *
	ADD_PARAM_NAME("BackupSeek", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("BackupSeek", 2, "dwLowBytesToSeek"); // DWORD
	ADD_PARAM_NAME("BackupSeek", 3, "dwHighBytesToSeek"); // DWORD
	ADD_PARAM_NAME("BackupSeek", 4, "lpdwLowByteSeeked"); // LPDWORD
	ADD_PARAM_NAME("BackupSeek", 5, "lpdwHighByteSeeked"); // LPDWORD
	ADD_PARAM_NAME("BackupSeek", 6, "lpContext"); // LPVOID *
	ADD_PARAM_NAME("BackupWrite", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("BackupWrite", 2, "lpBuffer"); // LPBYTE
	ADD_PARAM_NAME("BackupWrite", 3, "nNumberOfBytesToWrite"); // DWORD
	ADD_PARAM_NAME("BackupWrite", 4, "lpNumberOfBytesWritten"); // LPDWORD
	ADD_PARAM_NAME("BackupWrite", 5, "bAbort"); // WINBOOL
	ADD_PARAM_NAME("BackupWrite", 6, "bProcessSecurity"); // WINBOOL
	ADD_PARAM_NAME("BackupWrite", 7, "lpContext"); // LPVOID *
	ADD_PARAM_NAME("Beep", 1, "dwFreq"); // DWORD
	ADD_PARAM_NAME("Beep", 2, "dwDuration"); // DWORD
	ADD_PARAM_NAME("BeginDeferWindowPos", 1, "nNumWindows"); // int
	ADD_PARAM_NAME("BeginPaint", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("BeginPaint", 2, "lpPaint"); // LPPAINTSTRUCT
	ADD_PARAM_NAME("BeginPath", 1, "hdc"); // HDC
	ADD_PARAM_NAME("BeginUpdateResourceA", 1, "pFileName"); // LPCSTR
	ADD_PARAM_NAME("BeginUpdateResourceA", 2, "bDeleteExistingResources"); // WINBOOL
	ADD_PARAM_NAME("BeginUpdateResourceW", 1, "pFileName"); // LPCWSTR
	ADD_PARAM_NAME("BeginUpdateResourceW", 2, "bDeleteExistingResources"); // WINBOOL
	ADD_PARAM_NAME("BindIoCompletionCallback", 1, "FileHandle"); // HANDLE
	ADD_PARAM_NAME("BindIoCompletionCallback", 2, "Function"); // LPOVERLAPPED_COMPLETION_ROUTINE
	ADD_PARAM_NAME("BindIoCompletionCallback", 3, "Flags"); // ULONG
	ADD_PARAM_NAME("BitBlt", 1, "hdc"); // HDC
	ADD_PARAM_NAME("BitBlt", 2, "x"); // int
	ADD_PARAM_NAME("BitBlt", 3, "y"); // int
	ADD_PARAM_NAME("BitBlt", 4, "cx"); // int
	ADD_PARAM_NAME("BitBlt", 5, "cy"); // int
	ADD_PARAM_NAME("BitBlt", 6, "hdcSrc"); // HDC
	ADD_PARAM_NAME("BitBlt", 7, "x1"); // int
	ADD_PARAM_NAME("BitBlt", 8, "y1"); // int
	ADD_PARAM_NAME("BitBlt", 9, "rop"); // DWORD
	ADD_PARAM_NAME("BlockInput", 1, "fBlockIt"); // WINBOOL
	ADD_PARAM_NAME("BringWindowToTop", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("BroadcastSystemMessageA", 1, "flags"); // DWORD
	ADD_PARAM_NAME("BroadcastSystemMessageA", 2, "lpInfo"); // LPDWORD
	ADD_PARAM_NAME("BroadcastSystemMessageA", 3, "Msg"); // UINT
	ADD_PARAM_NAME("BroadcastSystemMessageA", 4, "wParam"); // WPARAM
	ADD_PARAM_NAME("BroadcastSystemMessageA", 5, "lParam"); // LPARAM
	ADD_PARAM_NAME("BroadcastSystemMessageExA", 1, "flags"); // DWORD
	ADD_PARAM_NAME("BroadcastSystemMessageExA", 2, "lpInfo"); // LPDWORD
	ADD_PARAM_NAME("BroadcastSystemMessageExA", 3, "Msg"); // UINT
	ADD_PARAM_NAME("BroadcastSystemMessageExA", 4, "wParam"); // WPARAM
	ADD_PARAM_NAME("BroadcastSystemMessageExA", 5, "lParam"); // LPARAM
	ADD_PARAM_NAME("BroadcastSystemMessageExA", 6, "pbsmInfo"); // PBSMINFO
	ADD_PARAM_NAME("BroadcastSystemMessageExW", 1, "flags"); // DWORD
	ADD_PARAM_NAME("BroadcastSystemMessageExW", 2, "lpInfo"); // LPDWORD
	ADD_PARAM_NAME("BroadcastSystemMessageExW", 3, "Msg"); // UINT
	ADD_PARAM_NAME("BroadcastSystemMessageExW", 4, "wParam"); // WPARAM
	ADD_PARAM_NAME("BroadcastSystemMessageExW", 5, "lParam"); // LPARAM
	ADD_PARAM_NAME("BroadcastSystemMessageExW", 6, "pbsmInfo"); // PBSMINFO
	ADD_PARAM_NAME("BroadcastSystemMessageW", 1, "flags"); // DWORD
	ADD_PARAM_NAME("BroadcastSystemMessageW", 2, "lpInfo"); // LPDWORD
	ADD_PARAM_NAME("BroadcastSystemMessageW", 3, "Msg"); // UINT
	ADD_PARAM_NAME("BroadcastSystemMessageW", 4, "wParam"); // WPARAM
	ADD_PARAM_NAME("BroadcastSystemMessageW", 5, "lParam"); // LPARAM
	ADD_PARAM_NAME("BuildCommDCBA", 1, "lpDef"); // LPCSTR
	ADD_PARAM_NAME("BuildCommDCBA", 2, "lpDCB"); // LPDCB
	ADD_PARAM_NAME("BuildCommDCBAndTimeoutsA", 1, "lpDef"); // LPCSTR
	ADD_PARAM_NAME("BuildCommDCBAndTimeoutsA", 2, "lpDCB"); // LPDCB
	ADD_PARAM_NAME("BuildCommDCBAndTimeoutsA", 3, "lpCommTimeouts"); // LPCOMMTIMEOUTS
	ADD_PARAM_NAME("BuildCommDCBAndTimeoutsW", 1, "lpDef"); // LPCWSTR
	ADD_PARAM_NAME("BuildCommDCBAndTimeoutsW", 2, "lpDCB"); // LPDCB
	ADD_PARAM_NAME("BuildCommDCBAndTimeoutsW", 3, "lpCommTimeouts"); // LPCOMMTIMEOUTS
	ADD_PARAM_NAME("BuildCommDCBW", 1, "lpDef"); // LPCWSTR
	ADD_PARAM_NAME("BuildCommDCBW", 2, "lpDCB"); // LPDCB
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
