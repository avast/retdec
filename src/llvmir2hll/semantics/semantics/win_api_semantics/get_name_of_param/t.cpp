/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/t.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/t.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with T.
*/
void initFuncParamNamesMap_T(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("TabbedTextOutA", 1, "hdc"); // HDC
	ADD_PARAM_NAME("TabbedTextOutA", 2, "x"); // int
	ADD_PARAM_NAME("TabbedTextOutA", 3, "y"); // int
	ADD_PARAM_NAME("TabbedTextOutA", 4, "lpString"); // LPCSTR
	ADD_PARAM_NAME("TabbedTextOutA", 5, "chCount"); // int
	ADD_PARAM_NAME("TabbedTextOutA", 6, "nTabPositions"); // int
	ADD_PARAM_NAME("TabbedTextOutA", 7, "lpnTabStopPositions"); // CONST INT *
	ADD_PARAM_NAME("TabbedTextOutA", 8, "nTabOrigin"); // int
	ADD_PARAM_NAME("TabbedTextOutW", 1, "hdc"); // HDC
	ADD_PARAM_NAME("TabbedTextOutW", 2, "x"); // int
	ADD_PARAM_NAME("TabbedTextOutW", 3, "y"); // int
	ADD_PARAM_NAME("TabbedTextOutW", 4, "lpString"); // LPCWSTR
	ADD_PARAM_NAME("TabbedTextOutW", 5, "chCount"); // int
	ADD_PARAM_NAME("TabbedTextOutW", 6, "nTabPositions"); // int
	ADD_PARAM_NAME("TabbedTextOutW", 7, "lpnTabStopPositions"); // CONST INT *
	ADD_PARAM_NAME("TabbedTextOutW", 8, "nTabOrigin"); // int
	ADD_PARAM_NAME("TerminateJobObject", 1, "hJob"); // HANDLE
	ADD_PARAM_NAME("TerminateJobObject", 2, "uExitCode"); // UINT
	ADD_PARAM_NAME("TerminateProcess", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("TerminateProcess", 2, "uExitCode"); // UINT
	ADD_PARAM_NAME("TerminateThread", 1, "hThread"); // HANDLE
	ADD_PARAM_NAME("TerminateThread", 2, "dwExitCode"); // DWORD
	ADD_PARAM_NAME("TextOutA", 1, "hdc"); // HDC
	ADD_PARAM_NAME("TextOutA", 2, "x"); // int
	ADD_PARAM_NAME("TextOutA", 3, "y"); // int
	ADD_PARAM_NAME("TextOutA", 4, "lpString"); // LPCSTR
	ADD_PARAM_NAME("TextOutA", 5, "c"); // int
	ADD_PARAM_NAME("TextOutW", 1, "hdc"); // HDC
	ADD_PARAM_NAME("TextOutW", 2, "x"); // int
	ADD_PARAM_NAME("TextOutW", 3, "y"); // int
	ADD_PARAM_NAME("TextOutW", 4, "lpString"); // LPCWSTR
	ADD_PARAM_NAME("TextOutW", 5, "c"); // int
	ADD_PARAM_NAME("TileWindows", 1, "hwndParent"); // HWND
	ADD_PARAM_NAME("TileWindows", 2, "wHow"); // UINT
	ADD_PARAM_NAME("TileWindows", 3, "lpRect"); // CONST RECT *
	ADD_PARAM_NAME("TileWindows", 4, "cKids"); // UINT
	ADD_PARAM_NAME("TileWindows", 5, "lpKids"); // const HWND *
	ADD_PARAM_NAME("TlsFree", 1, "dwTlsIndex"); // DWORD
	ADD_PARAM_NAME("TlsGetValue", 1, "dwTlsIndex"); // DWORD
	ADD_PARAM_NAME("TlsSetValue", 1, "dwTlsIndex"); // DWORD
	ADD_PARAM_NAME("TlsSetValue", 2, "lpTlsValue"); // LPVOID
	ADD_PARAM_NAME("ToAscii", 1, "uVirtKey"); // UINT
	ADD_PARAM_NAME("ToAscii", 2, "uScanCode"); // UINT
	ADD_PARAM_NAME("ToAscii", 3, "lpKeyState"); // CONST BYTE *
	ADD_PARAM_NAME("ToAscii", 4, "lpChar"); // LPWORD
	ADD_PARAM_NAME("ToAscii", 5, "uFlags"); // UINT
	ADD_PARAM_NAME("ToAsciiEx", 1, "uVirtKey"); // UINT
	ADD_PARAM_NAME("ToAsciiEx", 2, "uScanCode"); // UINT
	ADD_PARAM_NAME("ToAsciiEx", 3, "lpKeyState"); // CONST BYTE *
	ADD_PARAM_NAME("ToAsciiEx", 4, "lpChar"); // LPWORD
	ADD_PARAM_NAME("ToAsciiEx", 5, "uFlags"); // UINT
	ADD_PARAM_NAME("ToAsciiEx", 6, "dwhkl"); // HKL
	ADD_PARAM_NAME("ToUnicode", 1, "wVirtKey"); // UINT
	ADD_PARAM_NAME("ToUnicode", 2, "wScanCode"); // UINT
	ADD_PARAM_NAME("ToUnicode", 3, "lpKeyState"); // CONST BYTE *
	ADD_PARAM_NAME("ToUnicode", 4, "pwszBuff"); // LPWSTR
	ADD_PARAM_NAME("ToUnicode", 5, "cchBuff"); // int
	ADD_PARAM_NAME("ToUnicode", 6, "wFlags"); // UINT
	ADD_PARAM_NAME("ToUnicodeEx", 1, "wVirtKey"); // UINT
	ADD_PARAM_NAME("ToUnicodeEx", 2, "wScanCode"); // UINT
	ADD_PARAM_NAME("ToUnicodeEx", 3, "lpKeyState"); // CONST BYTE *
	ADD_PARAM_NAME("ToUnicodeEx", 4, "pwszBuff"); // LPWSTR
	ADD_PARAM_NAME("ToUnicodeEx", 5, "cchBuff"); // int
	ADD_PARAM_NAME("ToUnicodeEx", 6, "wFlags"); // UINT
	ADD_PARAM_NAME("ToUnicodeEx", 7, "dwhkl"); // HKL
	ADD_PARAM_NAME("TrackMouseEvent", 1, "lpEventTrack"); // LPTRACKMOUSEEVENT
	ADD_PARAM_NAME("TrackPopupMenu", 1, "hMenu"); // HMENU
	ADD_PARAM_NAME("TrackPopupMenu", 2, "uFlags"); // UINT
	ADD_PARAM_NAME("TrackPopupMenu", 3, "x"); // int
	ADD_PARAM_NAME("TrackPopupMenu", 4, "y"); // int
	ADD_PARAM_NAME("TrackPopupMenu", 5, "nReserved"); // int
	ADD_PARAM_NAME("TrackPopupMenu", 6, "hWnd"); // HWND
	ADD_PARAM_NAME("TrackPopupMenu", 7, "prcRect"); // CONST RECT *
	ADD_PARAM_NAME("TrackPopupMenuEx", 1, "hmenu"); // HMENU
	ADD_PARAM_NAME("TrackPopupMenuEx", 2, "fuFlags"); // UINT
	ADD_PARAM_NAME("TrackPopupMenuEx", 3, "x"); // int
	ADD_PARAM_NAME("TrackPopupMenuEx", 4, "y"); // int
	ADD_PARAM_NAME("TrackPopupMenuEx", 5, "hWnd"); // HWND
	ADD_PARAM_NAME("TrackPopupMenuEx", 6, "lptpm"); // LPTPMPARAMS
	ADD_PARAM_NAME("TransactNamedPipe", 1, "hNamedPipe"); // HANDLE
	ADD_PARAM_NAME("TransactNamedPipe", 2, "lpInBuffer"); // LPVOID
	ADD_PARAM_NAME("TransactNamedPipe", 3, "nInBufferSize"); // DWORD
	ADD_PARAM_NAME("TransactNamedPipe", 4, "lpOutBuffer"); // LPVOID
	ADD_PARAM_NAME("TransactNamedPipe", 5, "nOutBufferSize"); // DWORD
	ADD_PARAM_NAME("TransactNamedPipe", 6, "lpBytesRead"); // LPDWORD
	ADD_PARAM_NAME("TransactNamedPipe", 7, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("TranslateAcceleratorA", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("TranslateAcceleratorA", 2, "hAccTable"); // HACCEL
	ADD_PARAM_NAME("TranslateAcceleratorA", 3, "lpMsg"); // LPMSG
	ADD_PARAM_NAME("TranslateAcceleratorW", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("TranslateAcceleratorW", 2, "hAccTable"); // HACCEL
	ADD_PARAM_NAME("TranslateAcceleratorW", 3, "lpMsg"); // LPMSG
	ADD_PARAM_NAME("TranslateCharsetInfo", 1, "lpSrc"); // DWORD *
	ADD_PARAM_NAME("TranslateCharsetInfo", 2, "lpCs"); // LPCHARSETINFO
	ADD_PARAM_NAME("TranslateCharsetInfo", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("TranslateMDISysAccel", 1, "hWndClient"); // HWND
	ADD_PARAM_NAME("TranslateMDISysAccel", 2, "lpMsg"); // LPMSG
	ADD_PARAM_NAME("TranslateMessage", 1, "lpMsg"); // CONST MSG *
	ADD_PARAM_NAME("TransmitCommChar", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("TransmitCommChar", 2, "cChar"); // char
	ADD_PARAM_NAME("TransmitFile", 1, "hSocket"); // SOCKET
	ADD_PARAM_NAME("TransmitFile", 2, "hFile"); // HANDLE
	ADD_PARAM_NAME("TransmitFile", 3, "nNumberOfBytesToWrite"); // DWORD
	ADD_PARAM_NAME("TransmitFile", 4, "nNumberOfBytesPerSend"); // DWORD
	ADD_PARAM_NAME("TransmitFile", 5, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("TransmitFile", 6, "lpTransmitBuffers"); // LPTRANSMIT_FILE_BUFFERS
	ADD_PARAM_NAME("TransmitFile", 7, "dwReserved"); // DWORD
	ADD_PARAM_NAME("TransparentBlt", 1, "hdcDest"); // HDC
	ADD_PARAM_NAME("TransparentBlt", 2, "xoriginDest"); // int
	ADD_PARAM_NAME("TransparentBlt", 3, "yoriginDest"); // int
	ADD_PARAM_NAME("TransparentBlt", 4, "wDest"); // int
	ADD_PARAM_NAME("TransparentBlt", 5, "hDest"); // int
	ADD_PARAM_NAME("TransparentBlt", 6, "hdcSrc"); // HDC
	ADD_PARAM_NAME("TransparentBlt", 7, "xoriginSrc"); // int
	ADD_PARAM_NAME("TransparentBlt", 8, "yoriginSrc"); // int
	ADD_PARAM_NAME("TransparentBlt", 9, "wSrc"); // int
	ADD_PARAM_NAME("TransparentBlt", 10, "hSrc"); // int
	ADD_PARAM_NAME("TransparentBlt", 11, "crTransparent"); // UINT
	ADD_PARAM_NAME("TryEnterCriticalSection", 1, "lpCriticalSection"); // LPCRITICAL_SECTION
	ADD_PARAM_NAME("TrySubmitThreadpoolCallback", 1, "pfns"); // PTP_SIMPLE_CALLBACK
	ADD_PARAM_NAME("TrySubmitThreadpoolCallback", 2, "pv"); // PVOID
	ADD_PARAM_NAME("TrySubmitThreadpoolCallback", 3, "pcbe"); // PTP_CALLBACK_ENVIRON
	ADD_PARAM_NAME("TzSpecificLocalTimeToSystemTime", 1, "lpTimeZoneInformation"); // LPTIME_ZONE_INFORMATION
	ADD_PARAM_NAME("TzSpecificLocalTimeToSystemTime", 2, "lpLocalTime"); // LPSYSTEMTIME
	ADD_PARAM_NAME("TzSpecificLocalTimeToSystemTime", 3, "lpUniversalTime"); // LPSYSTEMTIME
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
