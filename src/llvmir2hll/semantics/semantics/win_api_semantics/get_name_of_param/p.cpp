/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/p.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/p.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with P.
*/
void initFuncParamNamesMap_P(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("PFXExportCertStore", 1, "hStore"); // HCERTSTORE
	ADD_PARAM_NAME("PFXExportCertStore", 2, "pPFX"); // CRYPT_DATA_BLOB *
	ADD_PARAM_NAME("PFXExportCertStore", 3, "szPassword"); // LPCWSTR
	ADD_PARAM_NAME("PFXExportCertStore", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("PFXExportCertStoreEx", 1, "hStore"); // HCERTSTORE
	ADD_PARAM_NAME("PFXExportCertStoreEx", 2, "pPFX"); // CRYPT_DATA_BLOB *
	ADD_PARAM_NAME("PFXExportCertStoreEx", 3, "szPassword"); // LPCWSTR
	ADD_PARAM_NAME("PFXExportCertStoreEx", 4, "pvReserved"); // void *
	ADD_PARAM_NAME("PFXExportCertStoreEx", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("PFXImportCertStore", 1, "pPFX"); // CRYPT_DATA_BLOB *
	ADD_PARAM_NAME("PFXImportCertStore", 2, "szPassword"); // LPCWSTR
	ADD_PARAM_NAME("PFXImportCertStore", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("PFXIsPFXBlob", 1, "pPFX"); // CRYPT_DATA_BLOB *
	ADD_PARAM_NAME("PFXVerifyPassword", 1, "pPFX"); // CRYPT_DATA_BLOB *
	ADD_PARAM_NAME("PFXVerifyPassword", 2, "szPassword"); // LPCWSTR
	ADD_PARAM_NAME("PFXVerifyPassword", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("PaintDesktop", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PaintRgn", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PaintRgn", 2, "hrgn"); // HRGN
	ADD_PARAM_NAME("PartialReplyPrinterChangeNotification", 1, "hNotify"); // HANDLE
	ADD_PARAM_NAME("PartialReplyPrinterChangeNotification", 2, "pInfoDataSrc"); // PPRINTER_NOTIFY_INFO_DATA
	ADD_PARAM_NAME("PatBlt", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PatBlt", 2, "x"); // int
	ADD_PARAM_NAME("PatBlt", 3, "y"); // int
	ADD_PARAM_NAME("PatBlt", 4, "w"); // int
	ADD_PARAM_NAME("PatBlt", 5, "h"); // int
	ADD_PARAM_NAME("PatBlt", 6, "rop"); // DWORD
	ADD_PARAM_NAME("PathToRegion", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PeekConsoleInputA", 1, "hConsoleInput"); // HANDLE
	ADD_PARAM_NAME("PeekConsoleInputA", 2, "lpBuffer"); // PINPUT_RECORD
	ADD_PARAM_NAME("PeekConsoleInputA", 3, "nLength"); // DWORD
	ADD_PARAM_NAME("PeekConsoleInputA", 4, "lpNumberOfEventsRead"); // LPDWORD
	ADD_PARAM_NAME("PeekConsoleInputW", 1, "hConsoleInput"); // HANDLE
	ADD_PARAM_NAME("PeekConsoleInputW", 2, "lpBuffer"); // PINPUT_RECORD
	ADD_PARAM_NAME("PeekConsoleInputW", 3, "nLength"); // DWORD
	ADD_PARAM_NAME("PeekConsoleInputW", 4, "lpNumberOfEventsRead"); // LPDWORD
	ADD_PARAM_NAME("PeekMessageA", 1, "lpMsg"); // LPMSG
	ADD_PARAM_NAME("PeekMessageA", 2, "hWnd"); // HWND
	ADD_PARAM_NAME("PeekMessageA", 3, "wMsgFilterMin"); // UINT
	ADD_PARAM_NAME("PeekMessageA", 4, "wMsgFilterMax"); // UINT
	ADD_PARAM_NAME("PeekMessageA", 5, "wRemoveMsg"); // UINT
	ADD_PARAM_NAME("PeekMessageW", 1, "lpMsg"); // LPMSG
	ADD_PARAM_NAME("PeekMessageW", 2, "hWnd"); // HWND
	ADD_PARAM_NAME("PeekMessageW", 3, "wMsgFilterMin"); // UINT
	ADD_PARAM_NAME("PeekMessageW", 4, "wMsgFilterMax"); // UINT
	ADD_PARAM_NAME("PeekMessageW", 5, "wRemoveMsg"); // UINT
	ADD_PARAM_NAME("PeekNamedPipe", 1, "hNamedPipe"); // HANDLE
	ADD_PARAM_NAME("PeekNamedPipe", 2, "lpBuffer"); // LPVOID
	ADD_PARAM_NAME("PeekNamedPipe", 3, "nBufferSize"); // DWORD
	ADD_PARAM_NAME("PeekNamedPipe", 4, "lpBytesRead"); // LPDWORD
	ADD_PARAM_NAME("PeekNamedPipe", 5, "lpTotalBytesAvail"); // LPDWORD
	ADD_PARAM_NAME("PeekNamedPipe", 6, "lpBytesLeftThisMessage"); // LPDWORD
	ADD_PARAM_NAME("Pie", 1, "hdc"); // HDC
	ADD_PARAM_NAME("Pie", 2, "left"); // int
	ADD_PARAM_NAME("Pie", 3, "top"); // int
	ADD_PARAM_NAME("Pie", 4, "right"); // int
	ADD_PARAM_NAME("Pie", 5, "bottom"); // int
	ADD_PARAM_NAME("Pie", 6, "xr1"); // int
	ADD_PARAM_NAME("Pie", 7, "yr1"); // int
	ADD_PARAM_NAME("Pie", 8, "xr2"); // int
	ADD_PARAM_NAME("Pie", 9, "yr2"); // int
	ADD_PARAM_NAME("PlayEnhMetaFile", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PlayEnhMetaFile", 2, "hmf"); // HENHMETAFILE
	ADD_PARAM_NAME("PlayEnhMetaFile", 3, "lprect"); // CONST RECT *
	ADD_PARAM_NAME("PlayEnhMetaFileRecord", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PlayEnhMetaFileRecord", 2, "pht"); // LPHANDLETABLE
	ADD_PARAM_NAME("PlayEnhMetaFileRecord", 3, "pmr"); // CONST ENHMETARECORD *
	ADD_PARAM_NAME("PlayEnhMetaFileRecord", 4, "cht"); // UINT
	ADD_PARAM_NAME("PlayGdiScriptOnPrinterIC", 1, "hPrinterIC"); // HANDLE
	ADD_PARAM_NAME("PlayGdiScriptOnPrinterIC", 2, "pIn"); // LPBYTE
	ADD_PARAM_NAME("PlayGdiScriptOnPrinterIC", 3, "cIn"); // DWORD
	ADD_PARAM_NAME("PlayGdiScriptOnPrinterIC", 4, "pOut"); // LPBYTE
	ADD_PARAM_NAME("PlayGdiScriptOnPrinterIC", 5, "cOut"); // DWORD
	ADD_PARAM_NAME("PlayGdiScriptOnPrinterIC", 6, "ul"); // DWORD
	ADD_PARAM_NAME("PlayMetaFile", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PlayMetaFile", 2, "hmf"); // HMETAFILE
	ADD_PARAM_NAME("PlayMetaFileRecord", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PlayMetaFileRecord", 2, "lpHandleTable"); // LPHANDLETABLE
	ADD_PARAM_NAME("PlayMetaFileRecord", 3, "lpMR"); // LPMETARECORD
	ADD_PARAM_NAME("PlayMetaFileRecord", 4, "noObjs"); // UINT
	ADD_PARAM_NAME("PlgBlt", 1, "hdcDest"); // HDC
	ADD_PARAM_NAME("PlgBlt", 2, "lpPoint"); // CONST POINT *
	ADD_PARAM_NAME("PlgBlt", 3, "hdcSrc"); // HDC
	ADD_PARAM_NAME("PlgBlt", 4, "xSrc"); // int
	ADD_PARAM_NAME("PlgBlt", 5, "ySrc"); // int
	ADD_PARAM_NAME("PlgBlt", 6, "width"); // int
	ADD_PARAM_NAME("PlgBlt", 7, "height"); // int
	ADD_PARAM_NAME("PlgBlt", 8, "hbmMask"); // HBITMAP
	ADD_PARAM_NAME("PlgBlt", 9, "xMask"); // int
	ADD_PARAM_NAME("PlgBlt", 10, "yMask"); // int
	ADD_PARAM_NAME("PolyBezier", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PolyBezier", 2, "apt"); // CONST POINT *
	ADD_PARAM_NAME("PolyBezier", 3, "cpt"); // DWORD
	ADD_PARAM_NAME("PolyBezierTo", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PolyBezierTo", 2, "apt"); // CONST POINT *
	ADD_PARAM_NAME("PolyBezierTo", 3, "cpt"); // DWORD
	ADD_PARAM_NAME("PolyDraw", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PolyDraw", 2, "apt"); // CONST POINT *
	ADD_PARAM_NAME("PolyDraw", 3, "aj"); // CONST BYTE *
	ADD_PARAM_NAME("PolyDraw", 4, "cpt"); // int
	ADD_PARAM_NAME("PolyPolygon", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PolyPolygon", 2, "apt"); // CONST POINT *
	ADD_PARAM_NAME("PolyPolygon", 3, "asz"); // CONST INT *
	ADD_PARAM_NAME("PolyPolygon", 4, "csz"); // int
	ADD_PARAM_NAME("PolyPolyline", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PolyPolyline", 2, "apt"); // CONST POINT *
	ADD_PARAM_NAME("PolyPolyline", 3, "asz"); // CONST DWORD *
	ADD_PARAM_NAME("PolyPolyline", 4, "csz"); // DWORD
	ADD_PARAM_NAME("PolyTextOutA", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PolyTextOutA", 2, "ppt"); // CONST POLYTEXTA *
	ADD_PARAM_NAME("PolyTextOutA", 3, "nstrings"); // int
	ADD_PARAM_NAME("PolyTextOutW", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PolyTextOutW", 2, "ppt"); // CONST POLYTEXTW *
	ADD_PARAM_NAME("PolyTextOutW", 3, "nstrings"); // int
	ADD_PARAM_NAME("Polygon", 1, "hdc"); // HDC
	ADD_PARAM_NAME("Polygon", 2, "apt"); // CONST POINT *
	ADD_PARAM_NAME("Polygon", 3, "cpt"); // int
	ADD_PARAM_NAME("Polyline", 1, "hdc"); // HDC
	ADD_PARAM_NAME("Polyline", 2, "apt"); // CONST POINT *
	ADD_PARAM_NAME("Polyline", 3, "cpt"); // int
	ADD_PARAM_NAME("PolylineTo", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PolylineTo", 2, "apt"); // CONST POINT *
	ADD_PARAM_NAME("PolylineTo", 3, "cpt"); // DWORD
	ADD_PARAM_NAME("PostMessageA", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("PostMessageA", 2, "Msg"); // UINT
	ADD_PARAM_NAME("PostMessageA", 3, "wParam"); // WPARAM
	ADD_PARAM_NAME("PostMessageA", 4, "lParam"); // LPARAM
	ADD_PARAM_NAME("PostMessageW", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("PostMessageW", 2, "Msg"); // UINT
	ADD_PARAM_NAME("PostMessageW", 3, "wParam"); // WPARAM
	ADD_PARAM_NAME("PostMessageW", 4, "lParam"); // LPARAM
	ADD_PARAM_NAME("PostQueuedCompletionStatus", 1, "CompletionPort"); // HANDLE
	ADD_PARAM_NAME("PostQueuedCompletionStatus", 2, "dwNumberOfBytesTransferred"); // DWORD
	ADD_PARAM_NAME("PostQueuedCompletionStatus", 3, "dwCompletionKey"); // ULONG_PTR
	ADD_PARAM_NAME("PostQueuedCompletionStatus", 4, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("PostQuitMessage", 1, "nExitCode"); // int
	ADD_PARAM_NAME("PostThreadMessageA", 1, "idThread"); // DWORD
	ADD_PARAM_NAME("PostThreadMessageA", 2, "Msg"); // UINT
	ADD_PARAM_NAME("PostThreadMessageA", 3, "wParam"); // WPARAM
	ADD_PARAM_NAME("PostThreadMessageA", 4, "lParam"); // LPARAM
	ADD_PARAM_NAME("PostThreadMessageW", 1, "idThread"); // DWORD
	ADD_PARAM_NAME("PostThreadMessageW", 2, "Msg"); // UINT
	ADD_PARAM_NAME("PostThreadMessageW", 3, "wParam"); // WPARAM
	ADD_PARAM_NAME("PostThreadMessageW", 4, "lParam"); // LPARAM
	ADD_PARAM_NAME("PrepareTape", 1, "hDevice"); // HANDLE
	ADD_PARAM_NAME("PrepareTape", 2, "dwOperation"); // DWORD
	ADD_PARAM_NAME("PrepareTape", 3, "bImmediate"); // WINBOOL
	ADD_PARAM_NAME("PrintWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("PrintWindow", 2, "hdcBlt"); // HDC
	ADD_PARAM_NAME("PrintWindow", 3, "nFlags"); // UINT
	ADD_PARAM_NAME("PrinterMessageBoxA", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("PrinterMessageBoxA", 2, "Error"); // DWORD
	ADD_PARAM_NAME("PrinterMessageBoxA", 3, "hWnd"); // HWND
	ADD_PARAM_NAME("PrinterMessageBoxA", 4, "pText"); // LPSTR
	ADD_PARAM_NAME("PrinterMessageBoxA", 5, "pCaption"); // LPSTR
	ADD_PARAM_NAME("PrinterMessageBoxA", 6, "dwType"); // DWORD
	ADD_PARAM_NAME("PrinterMessageBoxW", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("PrinterMessageBoxW", 2, "Error"); // DWORD
	ADD_PARAM_NAME("PrinterMessageBoxW", 3, "hWnd"); // HWND
	ADD_PARAM_NAME("PrinterMessageBoxW", 4, "pText"); // LPWSTR
	ADD_PARAM_NAME("PrinterMessageBoxW", 5, "pCaption"); // LPWSTR
	ADD_PARAM_NAME("PrinterMessageBoxW", 6, "dwType"); // DWORD
	ADD_PARAM_NAME("PrinterProperties", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("PrinterProperties", 2, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("PrivateExtractIconsA", 1, "szFileName"); // LPCSTR
	ADD_PARAM_NAME("PrivateExtractIconsA", 2, "nIconIndex"); // int
	ADD_PARAM_NAME("PrivateExtractIconsA", 3, "cxIcon"); // int
	ADD_PARAM_NAME("PrivateExtractIconsA", 4, "cyIcon"); // int
	ADD_PARAM_NAME("PrivateExtractIconsA", 5, "phicon"); // HICON *
	ADD_PARAM_NAME("PrivateExtractIconsA", 6, "piconid"); // UINT *
	ADD_PARAM_NAME("PrivateExtractIconsA", 7, "nIcons"); // UINT
	ADD_PARAM_NAME("PrivateExtractIconsA", 8, "flags"); // UINT
	ADD_PARAM_NAME("PrivateExtractIconsW", 1, "szFileName"); // LPCWSTR
	ADD_PARAM_NAME("PrivateExtractIconsW", 2, "nIconIndex"); // int
	ADD_PARAM_NAME("PrivateExtractIconsW", 3, "cxIcon"); // int
	ADD_PARAM_NAME("PrivateExtractIconsW", 4, "cyIcon"); // int
	ADD_PARAM_NAME("PrivateExtractIconsW", 5, "phicon"); // HICON *
	ADD_PARAM_NAME("PrivateExtractIconsW", 6, "piconid"); // UINT *
	ADD_PARAM_NAME("PrivateExtractIconsW", 7, "nIcons"); // UINT
	ADD_PARAM_NAME("PrivateExtractIconsW", 8, "flags"); // UINT
	ADD_PARAM_NAME("PrivilegeCheck", 1, "ClientToken"); // HANDLE
	ADD_PARAM_NAME("PrivilegeCheck", 2, "RequiredPrivileges"); // PPRIVILEGE_SET
	ADD_PARAM_NAME("PrivilegeCheck", 3, "pfResult"); // LPBOOL
	ADD_PARAM_NAME("PrivilegedServiceAuditAlarmA", 1, "SubsystemName"); // LPCSTR
	ADD_PARAM_NAME("PrivilegedServiceAuditAlarmA", 2, "ServiceName"); // LPCSTR
	ADD_PARAM_NAME("PrivilegedServiceAuditAlarmA", 3, "ClientToken"); // HANDLE
	ADD_PARAM_NAME("PrivilegedServiceAuditAlarmA", 4, "Privileges"); // PPRIVILEGE_SET
	ADD_PARAM_NAME("PrivilegedServiceAuditAlarmA", 5, "AccessGranted"); // WINBOOL
	ADD_PARAM_NAME("PrivilegedServiceAuditAlarmW", 1, "SubsystemName"); // LPCWSTR
	ADD_PARAM_NAME("PrivilegedServiceAuditAlarmW", 2, "ServiceName"); // LPCWSTR
	ADD_PARAM_NAME("PrivilegedServiceAuditAlarmW", 3, "ClientToken"); // HANDLE
	ADD_PARAM_NAME("PrivilegedServiceAuditAlarmW", 4, "Privileges"); // PPRIVILEGE_SET
	ADD_PARAM_NAME("PrivilegedServiceAuditAlarmW", 5, "AccessGranted"); // WINBOOL
	ADD_PARAM_NAME("ProcessIdToSessionId", 1, "dwProcessId"); // DWORD
	ADD_PARAM_NAME("ProcessIdToSessionId", 2, "pSessionId"); // DWORD *
	ADD_PARAM_NAME("ProvidorFindClosePrinterChangeNotification", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("ProvidorFindFirstPrinterChangeNotification", 1, "hPrinter"); // HANDLE
	ADD_PARAM_NAME("ProvidorFindFirstPrinterChangeNotification", 2, "fdwFlags"); // DWORD
	ADD_PARAM_NAME("ProvidorFindFirstPrinterChangeNotification", 3, "fdwOptions"); // DWORD
	ADD_PARAM_NAME("ProvidorFindFirstPrinterChangeNotification", 4, "hNotify"); // HANDLE
	ADD_PARAM_NAME("ProvidorFindFirstPrinterChangeNotification", 5, "pvReserved0"); // PVOID
	ADD_PARAM_NAME("ProvidorFindFirstPrinterChangeNotification", 6, "pvReserved1"); // PVOID
	ADD_PARAM_NAME("PtInRect", 1, "lprc"); // CONST RECT *
	ADD_PARAM_NAME("PtInRect", 2, "pt"); // POINT
	ADD_PARAM_NAME("PtInRegion", 1, "hrgn"); // HRGN
	ADD_PARAM_NAME("PtInRegion", 2, "x"); // int
	ADD_PARAM_NAME("PtInRegion", 3, "y"); // int
	ADD_PARAM_NAME("PtVisible", 1, "hdc"); // HDC
	ADD_PARAM_NAME("PtVisible", 2, "x"); // int
	ADD_PARAM_NAME("PtVisible", 3, "y"); // int
	ADD_PARAM_NAME("PulseEvent", 1, "hEvent"); // HANDLE
	ADD_PARAM_NAME("PurgeComm", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("PurgeComm", 2, "dwFlags"); // DWORD
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
