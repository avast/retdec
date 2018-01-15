/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/l.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/l.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with L.
*/
void initFuncParamNamesMap_L(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("LCIDToLocaleName", 1, "Locale"); // LCID
	ADD_PARAM_NAME("LCIDToLocaleName", 2, "lpName"); // LPWSTR
	ADD_PARAM_NAME("LCIDToLocaleName", 3, "cchName"); // int
	ADD_PARAM_NAME("LCIDToLocaleName", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("LCMapStringA", 1, "Locale"); // LCID
	ADD_PARAM_NAME("LCMapStringA", 2, "dwMapFlags"); // DWORD
	ADD_PARAM_NAME("LCMapStringA", 3, "lpSrcStr"); // LPCSTR
	ADD_PARAM_NAME("LCMapStringA", 4, "cchSrc"); // int
	ADD_PARAM_NAME("LCMapStringA", 5, "lpDestStr"); // LPSTR
	ADD_PARAM_NAME("LCMapStringA", 6, "cchDest"); // int
	ADD_PARAM_NAME("LCMapStringEx", 1, "lpLocaleName"); // LPCWSTR
	ADD_PARAM_NAME("LCMapStringEx", 2, "dwMapFlags"); // DWORD
	ADD_PARAM_NAME("LCMapStringEx", 3, "lpSrcStr"); // LPCWSTR
	ADD_PARAM_NAME("LCMapStringEx", 4, "cchSrc"); // int
	ADD_PARAM_NAME("LCMapStringEx", 5, "lpDestStr"); // LPWSTR
	ADD_PARAM_NAME("LCMapStringEx", 6, "cchDest"); // int
	ADD_PARAM_NAME("LCMapStringEx", 7, "lpVersionInformation"); // LPNLSVERSIONINFO
	ADD_PARAM_NAME("LCMapStringEx", 8, "lpReserved"); // LPVOID
	ADD_PARAM_NAME("LCMapStringEx", 9, "lParam"); // LPARAM
	ADD_PARAM_NAME("LCMapStringW", 1, "Locale"); // LCID
	ADD_PARAM_NAME("LCMapStringW", 2, "dwMapFlags"); // DWORD
	ADD_PARAM_NAME("LCMapStringW", 3, "lpSrcStr"); // LPCWSTR
	ADD_PARAM_NAME("LCMapStringW", 4, "cchSrc"); // int
	ADD_PARAM_NAME("LCMapStringW", 5, "lpDestStr"); // LPWSTR
	ADD_PARAM_NAME("LCMapStringW", 6, "cchDest"); // int
	ADD_PARAM_NAME("LPtoDP", 1, "hdc"); // HDC
	ADD_PARAM_NAME("LPtoDP", 2, "lppt"); // LPPOINT
	ADD_PARAM_NAME("LPtoDP", 3, "c"); // int
	ADD_PARAM_NAME("LeaveCriticalSection", 1, "lpCriticalSection"); // LPCRITICAL_SECTION
	ADD_PARAM_NAME("LeaveCriticalSectionWhenCallbackReturns", 1, "pci"); // PTP_CALLBACK_INSTANCE
	ADD_PARAM_NAME("LeaveCriticalSectionWhenCallbackReturns", 2, "pcs"); // PCRITICAL_SECTION
	ADD_PARAM_NAME("LineDDA", 1, "xStart"); // int
	ADD_PARAM_NAME("LineDDA", 2, "yStart"); // int
	ADD_PARAM_NAME("LineDDA", 3, "xEnd"); // int
	ADD_PARAM_NAME("LineDDA", 4, "yEnd"); // int
	ADD_PARAM_NAME("LineDDA", 5, "lpProc"); // LINEDDAPROC
	ADD_PARAM_NAME("LineDDA", 6, "data"); // LPARAM
	ADD_PARAM_NAME("LineTo", 1, "hdc"); // HDC
	ADD_PARAM_NAME("LineTo", 2, "x"); // int
	ADD_PARAM_NAME("LineTo", 3, "y"); // int
	ADD_PARAM_NAME("LoadAcceleratorsA", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadAcceleratorsA", 2, "lpTableName"); // LPCSTR
	ADD_PARAM_NAME("LoadAcceleratorsW", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadAcceleratorsW", 2, "lpTableName"); // LPCWSTR
	ADD_PARAM_NAME("LoadBitmapA", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadBitmapA", 2, "lpBitmapName"); // LPCSTR
	ADD_PARAM_NAME("LoadBitmapW", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadBitmapW", 2, "lpBitmapName"); // LPCWSTR
	ADD_PARAM_NAME("LoadCursorA", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadCursorA", 2, "lpCursorName"); // LPCSTR
	ADD_PARAM_NAME("LoadCursorFromFileA", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("LoadCursorFromFileW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("LoadCursorW", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadCursorW", 2, "lpCursorName"); // LPCWSTR
	ADD_PARAM_NAME("LoadIconA", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadIconA", 2, "lpIconName"); // LPCSTR
	ADD_PARAM_NAME("LoadIconW", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadIconW", 2, "lpIconName"); // LPCWSTR
	ADD_PARAM_NAME("LoadImageA", 1, "hInst"); // HINSTANCE
	ADD_PARAM_NAME("LoadImageA", 2, "name"); // LPCSTR
	ADD_PARAM_NAME("LoadImageA", 3, "type"); // UINT
	ADD_PARAM_NAME("LoadImageA", 4, "cx"); // int
	ADD_PARAM_NAME("LoadImageA", 5, "cy"); // int
	ADD_PARAM_NAME("LoadImageA", 6, "fuLoad"); // UINT
	ADD_PARAM_NAME("LoadImageW", 1, "hInst"); // HINSTANCE
	ADD_PARAM_NAME("LoadImageW", 2, "name"); // LPCWSTR
	ADD_PARAM_NAME("LoadImageW", 3, "type"); // UINT
	ADD_PARAM_NAME("LoadImageW", 4, "cx"); // int
	ADD_PARAM_NAME("LoadImageW", 5, "cy"); // int
	ADD_PARAM_NAME("LoadImageW", 6, "fuLoad"); // UINT
	ADD_PARAM_NAME("LoadKeyboardLayoutA", 1, "pwszKLID"); // LPCSTR
	ADD_PARAM_NAME("LoadKeyboardLayoutA", 2, "Flags"); // UINT
	ADD_PARAM_NAME("LoadKeyboardLayoutW", 1, "pwszKLID"); // LPCWSTR
	ADD_PARAM_NAME("LoadKeyboardLayoutW", 2, "Flags"); // UINT
	ADD_PARAM_NAME("LoadLibraryA", 1, "lpLibFileName"); // LPCSTR
	ADD_PARAM_NAME("LoadLibraryExA", 1, "lpLibFileName"); // LPCSTR
	ADD_PARAM_NAME("LoadLibraryExA", 2, "hFile"); // HANDLE
	ADD_PARAM_NAME("LoadLibraryExA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("LoadLibraryExW", 1, "lpLibFileName"); // LPCWSTR
	ADD_PARAM_NAME("LoadLibraryExW", 2, "hFile"); // HANDLE
	ADD_PARAM_NAME("LoadLibraryExW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("LoadLibraryW", 1, "lpLibFileName"); // LPCWSTR
	ADD_PARAM_NAME("LoadMenuA", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadMenuA", 2, "lpMenuName"); // LPCSTR
	ADD_PARAM_NAME("LoadMenuIndirectA", 1, "lpMenuTemplate"); // CONST MENUTEMPLATEA *
	ADD_PARAM_NAME("LoadMenuIndirectW", 1, "lpMenuTemplate"); // CONST MENUTEMPLATEW *
	ADD_PARAM_NAME("LoadMenuW", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadMenuW", 2, "lpMenuName"); // LPCWSTR
	ADD_PARAM_NAME("LoadModule", 1, "lpModuleName"); // LPCSTR
	ADD_PARAM_NAME("LoadModule", 2, "lpParameterBlock"); // LPVOID
	ADD_PARAM_NAME("LoadResource", 1, "hModule"); // HMODULE
	ADD_PARAM_NAME("LoadResource", 2, "hResInfo"); // HRSRC
	ADD_PARAM_NAME("LoadStringA", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadStringA", 2, "uID"); // UINT
	ADD_PARAM_NAME("LoadStringA", 3, "lpBuffer"); // LPSTR
	ADD_PARAM_NAME("LoadStringA", 4, "cchBufferMax"); // int
	ADD_PARAM_NAME("LoadStringW", 1, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("LoadStringW", 2, "uID"); // UINT
	ADD_PARAM_NAME("LoadStringW", 3, "lpBuffer"); // LPWSTR
	ADD_PARAM_NAME("LoadStringW", 4, "cchBufferMax"); // int
	ADD_PARAM_NAME("LocalAlloc", 1, "uFlags"); // UINT
	ADD_PARAM_NAME("LocalAlloc", 2, "uBytes"); // SIZE_T
	ADD_PARAM_NAME("LocalCompact", 1, "uMinFree"); // UINT
	ADD_PARAM_NAME("LocalFileTimeToFileTime", 1, "lpLocalFileTime"); // CONST FILETIME *
	ADD_PARAM_NAME("LocalFileTimeToFileTime", 2, "lpFileTime"); // LPFILETIME
	ADD_PARAM_NAME("LocalFlags", 1, "hMem"); // HLOCAL
	ADD_PARAM_NAME("LocalFree", 1, "hMem"); // HLOCAL
	ADD_PARAM_NAME("LocalHandle", 1, "pMem"); // LPCVOID
	ADD_PARAM_NAME("LocalLock", 1, "hMem"); // HLOCAL
	ADD_PARAM_NAME("LocalReAlloc", 1, "hMem"); // HLOCAL
	ADD_PARAM_NAME("LocalReAlloc", 2, "uBytes"); // SIZE_T
	ADD_PARAM_NAME("LocalReAlloc", 3, "uFlags"); // UINT
	ADD_PARAM_NAME("LocalShrink", 1, "hMem"); // HLOCAL
	ADD_PARAM_NAME("LocalShrink", 2, "cbNewSize"); // UINT
	ADD_PARAM_NAME("LocalSize", 1, "hMem"); // HLOCAL
	ADD_PARAM_NAME("LocalUnlock", 1, "hMem"); // HLOCAL
	ADD_PARAM_NAME("LocaleNameToLCID", 1, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("LocaleNameToLCID", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("LockFile", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("LockFile", 2, "dwFileOffsetLow"); // DWORD
	ADD_PARAM_NAME("LockFile", 3, "dwFileOffsetHigh"); // DWORD
	ADD_PARAM_NAME("LockFile", 4, "nNumberOfBytesToLockLow"); // DWORD
	ADD_PARAM_NAME("LockFile", 5, "nNumberOfBytesToLockHigh"); // DWORD
	ADD_PARAM_NAME("LockFileEx", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("LockFileEx", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("LockFileEx", 3, "dwReserved"); // DWORD
	ADD_PARAM_NAME("LockFileEx", 4, "nNumberOfBytesToLockLow"); // DWORD
	ADD_PARAM_NAME("LockFileEx", 5, "nNumberOfBytesToLockHigh"); // DWORD
	ADD_PARAM_NAME("LockFileEx", 6, "lpOverlapped"); // LPOVERLAPPED
	ADD_PARAM_NAME("LockResource", 1, "hResData"); // HGLOBAL
	ADD_PARAM_NAME("LockServiceDatabase", 1, "hSCManager"); // SC_HANDLE
	ADD_PARAM_NAME("LockSetForegroundWindow", 1, "uLockCode"); // UINT
	ADD_PARAM_NAME("LockWindowUpdate", 1, "hWndLock"); // HWND
	ADD_PARAM_NAME("LogonUserA", 1, "lpszUsername"); // LPCSTR
	ADD_PARAM_NAME("LogonUserA", 2, "lpszDomain"); // LPCSTR
	ADD_PARAM_NAME("LogonUserA", 3, "lpszPassword"); // LPCSTR
	ADD_PARAM_NAME("LogonUserA", 4, "dwLogonType"); // DWORD
	ADD_PARAM_NAME("LogonUserA", 5, "dwLogonProvider"); // DWORD
	ADD_PARAM_NAME("LogonUserA", 6, "phToken"); // PHANDLE
	ADD_PARAM_NAME("LogonUserExA", 1, "lpszUsername"); // LPCSTR
	ADD_PARAM_NAME("LogonUserExA", 2, "lpszDomain"); // LPCSTR
	ADD_PARAM_NAME("LogonUserExA", 3, "lpszPassword"); // LPCSTR
	ADD_PARAM_NAME("LogonUserExA", 4, "dwLogonType"); // DWORD
	ADD_PARAM_NAME("LogonUserExA", 5, "dwLogonProvider"); // DWORD
	ADD_PARAM_NAME("LogonUserExA", 6, "phToken"); // PHANDLE
	ADD_PARAM_NAME("LogonUserExA", 7, "ppLogonSid"); // PSID *
	ADD_PARAM_NAME("LogonUserExA", 8, "ppProfileBuffer"); // PVOID *
	ADD_PARAM_NAME("LogonUserExA", 9, "pdwProfileLength"); // LPDWORD
	ADD_PARAM_NAME("LogonUserExA", 10, "pQuotaLimits"); // PQUOTA_LIMITS
	ADD_PARAM_NAME("LogonUserExW", 1, "lpszUsername"); // LPCWSTR
	ADD_PARAM_NAME("LogonUserExW", 2, "lpszDomain"); // LPCWSTR
	ADD_PARAM_NAME("LogonUserExW", 3, "lpszPassword"); // LPCWSTR
	ADD_PARAM_NAME("LogonUserExW", 4, "dwLogonType"); // DWORD
	ADD_PARAM_NAME("LogonUserExW", 5, "dwLogonProvider"); // DWORD
	ADD_PARAM_NAME("LogonUserExW", 6, "phToken"); // PHANDLE
	ADD_PARAM_NAME("LogonUserExW", 7, "ppLogonSid"); // PSID *
	ADD_PARAM_NAME("LogonUserExW", 8, "ppProfileBuffer"); // PVOID *
	ADD_PARAM_NAME("LogonUserExW", 9, "pdwProfileLength"); // LPDWORD
	ADD_PARAM_NAME("LogonUserExW", 10, "pQuotaLimits"); // PQUOTA_LIMITS
	ADD_PARAM_NAME("LogonUserW", 1, "lpszUsername"); // LPCWSTR
	ADD_PARAM_NAME("LogonUserW", 2, "lpszDomain"); // LPCWSTR
	ADD_PARAM_NAME("LogonUserW", 3, "lpszPassword"); // LPCWSTR
	ADD_PARAM_NAME("LogonUserW", 4, "dwLogonType"); // DWORD
	ADD_PARAM_NAME("LogonUserW", 5, "dwLogonProvider"); // DWORD
	ADD_PARAM_NAME("LogonUserW", 6, "phToken"); // PHANDLE
	ADD_PARAM_NAME("LookupAccountNameA", 1, "lpSystemName"); // LPCSTR
	ADD_PARAM_NAME("LookupAccountNameA", 2, "lpAccountName"); // LPCSTR
	ADD_PARAM_NAME("LookupAccountNameA", 3, "Sid"); // PSID
	ADD_PARAM_NAME("LookupAccountNameA", 4, "cbSid"); // LPDWORD
	ADD_PARAM_NAME("LookupAccountNameA", 5, "ReferencedDomainName"); // LPSTR
	ADD_PARAM_NAME("LookupAccountNameA", 6, "cchReferencedDomainName"); // LPDWORD
	ADD_PARAM_NAME("LookupAccountNameA", 7, "peUse"); // PSID_NAME_USE
	ADD_PARAM_NAME("LookupAccountNameW", 1, "lpSystemName"); // LPCWSTR
	ADD_PARAM_NAME("LookupAccountNameW", 2, "lpAccountName"); // LPCWSTR
	ADD_PARAM_NAME("LookupAccountNameW", 3, "Sid"); // PSID
	ADD_PARAM_NAME("LookupAccountNameW", 4, "cbSid"); // LPDWORD
	ADD_PARAM_NAME("LookupAccountNameW", 5, "ReferencedDomainName"); // LPWSTR
	ADD_PARAM_NAME("LookupAccountNameW", 6, "cchReferencedDomainName"); // LPDWORD
	ADD_PARAM_NAME("LookupAccountNameW", 7, "peUse"); // PSID_NAME_USE
	ADD_PARAM_NAME("LookupAccountSidA", 1, "lpSystemName"); // LPCSTR
	ADD_PARAM_NAME("LookupAccountSidA", 2, "Sid"); // PSID
	ADD_PARAM_NAME("LookupAccountSidA", 3, "Name"); // LPSTR
	ADD_PARAM_NAME("LookupAccountSidA", 4, "cchName"); // LPDWORD
	ADD_PARAM_NAME("LookupAccountSidA", 5, "ReferencedDomainName"); // LPSTR
	ADD_PARAM_NAME("LookupAccountSidA", 6, "cchReferencedDomainName"); // LPDWORD
	ADD_PARAM_NAME("LookupAccountSidA", 7, "peUse"); // PSID_NAME_USE
	ADD_PARAM_NAME("LookupAccountSidW", 1, "lpSystemName"); // LPCWSTR
	ADD_PARAM_NAME("LookupAccountSidW", 2, "Sid"); // PSID
	ADD_PARAM_NAME("LookupAccountSidW", 3, "Name"); // LPWSTR
	ADD_PARAM_NAME("LookupAccountSidW", 4, "cchName"); // LPDWORD
	ADD_PARAM_NAME("LookupAccountSidW", 5, "ReferencedDomainName"); // LPWSTR
	ADD_PARAM_NAME("LookupAccountSidW", 6, "cchReferencedDomainName"); // LPDWORD
	ADD_PARAM_NAME("LookupAccountSidW", 7, "peUse"); // PSID_NAME_USE
	ADD_PARAM_NAME("LookupIconIdFromDirectory", 1, "presbits"); // PBYTE
	ADD_PARAM_NAME("LookupIconIdFromDirectory", 2, "fIcon"); // WINBOOL
	ADD_PARAM_NAME("LookupIconIdFromDirectoryEx", 1, "presbits"); // PBYTE
	ADD_PARAM_NAME("LookupIconIdFromDirectoryEx", 2, "fIcon"); // WINBOOL
	ADD_PARAM_NAME("LookupIconIdFromDirectoryEx", 3, "cxDesired"); // int
	ADD_PARAM_NAME("LookupIconIdFromDirectoryEx", 4, "cyDesired"); // int
	ADD_PARAM_NAME("LookupIconIdFromDirectoryEx", 5, "Flags"); // UINT
	ADD_PARAM_NAME("LookupPrivilegeDisplayNameA", 1, "lpSystemName"); // LPCSTR
	ADD_PARAM_NAME("LookupPrivilegeDisplayNameA", 2, "lpName"); // LPCSTR
	ADD_PARAM_NAME("LookupPrivilegeDisplayNameA", 3, "lpDisplayName"); // LPSTR
	ADD_PARAM_NAME("LookupPrivilegeDisplayNameA", 4, "cchDisplayName"); // LPDWORD
	ADD_PARAM_NAME("LookupPrivilegeDisplayNameA", 5, "lpLanguageId"); // LPDWORD
	ADD_PARAM_NAME("LookupPrivilegeDisplayNameW", 1, "lpSystemName"); // LPCWSTR
	ADD_PARAM_NAME("LookupPrivilegeDisplayNameW", 2, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("LookupPrivilegeDisplayNameW", 3, "lpDisplayName"); // LPWSTR
	ADD_PARAM_NAME("LookupPrivilegeDisplayNameW", 4, "cchDisplayName"); // LPDWORD
	ADD_PARAM_NAME("LookupPrivilegeDisplayNameW", 5, "lpLanguageId"); // LPDWORD
	ADD_PARAM_NAME("LookupPrivilegeNameA", 1, "lpSystemName"); // LPCSTR
	ADD_PARAM_NAME("LookupPrivilegeNameA", 2, "lpLuid"); // PLUID
	ADD_PARAM_NAME("LookupPrivilegeNameA", 3, "lpName"); // LPSTR
	ADD_PARAM_NAME("LookupPrivilegeNameA", 4, "cchName"); // LPDWORD
	ADD_PARAM_NAME("LookupPrivilegeNameW", 1, "lpSystemName"); // LPCWSTR
	ADD_PARAM_NAME("LookupPrivilegeNameW", 2, "lpLuid"); // PLUID
	ADD_PARAM_NAME("LookupPrivilegeNameW", 3, "lpName"); // LPWSTR
	ADD_PARAM_NAME("LookupPrivilegeNameW", 4, "cchName"); // LPDWORD
	ADD_PARAM_NAME("LookupPrivilegeValueA", 1, "lpSystemName"); // LPCSTR
	ADD_PARAM_NAME("LookupPrivilegeValueA", 2, "lpName"); // LPCSTR
	ADD_PARAM_NAME("LookupPrivilegeValueA", 3, "lpLuid"); // PLUID
	ADD_PARAM_NAME("LookupPrivilegeValueW", 1, "lpSystemName"); // LPCWSTR
	ADD_PARAM_NAME("LookupPrivilegeValueW", 2, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("LookupPrivilegeValueW", 3, "lpLuid"); // PLUID

	ADD_PARAM_NAME("lstrcatA", 1, "lpString1"); // LPSTR
	ADD_PARAM_NAME("lstrcatA", 2, "lpString2"); // LPCSTR
	ADD_PARAM_NAME("lstrcatW", 1, "lpString1"); // LPWSTR
	ADD_PARAM_NAME("lstrcatW", 2, "lpString2"); // LPCWSTR
	ADD_PARAM_NAME("lstrcmpA", 1, "lpString1"); // LPCSTR
	ADD_PARAM_NAME("lstrcmpA", 2, "lpString2"); // LPCSTR
	ADD_PARAM_NAME("lstrcmpW", 1, "lpString1"); // LPCWSTR
	ADD_PARAM_NAME("lstrcmpW", 2, "lpString2"); // LPCWSTR
	ADD_PARAM_NAME("lstrcmpiA", 1, "lpString1"); // LPCSTR
	ADD_PARAM_NAME("lstrcmpiA", 2, "lpString2"); // LPCSTR
	ADD_PARAM_NAME("lstrcmpiW", 1, "lpString1"); // LPCWSTR
	ADD_PARAM_NAME("lstrcmpiW", 2, "lpString2"); // LPCWSTR
	ADD_PARAM_NAME("lstrcpyA", 1, "lpString1"); // LPSTR
	ADD_PARAM_NAME("lstrcpyA", 2, "lpString2"); // LPCSTR
	ADD_PARAM_NAME("lstrcpyW", 1, "lpString1"); // LPWSTR
	ADD_PARAM_NAME("lstrcpyW", 2, "lpString2"); // LPCWSTR
	ADD_PARAM_NAME("lstrcpynA", 1, "lpString1"); // LPSTR
	ADD_PARAM_NAME("lstrcpynA", 2, "lpString2"); // LPCSTR
	ADD_PARAM_NAME("lstrcpynA", 3, "iMaxLength"); // int
	ADD_PARAM_NAME("lstrcpynW", 1, "lpString1"); // LPWSTR
	ADD_PARAM_NAME("lstrcpynW", 2, "lpString2"); // LPCWSTR
	ADD_PARAM_NAME("lstrcpynW", 3, "iMaxLength"); // int
	ADD_PARAM_NAME("lstrlenA", 1, "lpString"); // LPCSTR
	ADD_PARAM_NAME("lstrlenW", 1, "lpString"); // LPCWSTR
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
