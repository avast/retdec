/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/i.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/i.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with I.
*/
void initFuncParamNamesMap_I(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("IMPGetIMEA", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IMPGetIMEA", 2, "ime"); // LPIMEPROA
	ADD_PARAM_NAME("IMPGetIMEW", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IMPGetIMEW", 2, "ime"); // LPIMEPROW
	ADD_PARAM_NAME("IMPQueryIMEA", 1, "ime"); // LPIMEPROA
	ADD_PARAM_NAME("IMPQueryIMEW", 1, "ime"); // LPIMEPROW
	ADD_PARAM_NAME("IMPSetIMEA", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IMPSetIMEA", 2, "ime"); // LPIMEPROA
	ADD_PARAM_NAME("IMPSetIMEW", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IMPSetIMEW", 2, "ime"); // LPIMEPROW
	ADD_PARAM_NAME("IdnToAscii", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("IdnToAscii", 2, "lpUnicodeCharStr"); // LPCWSTR
	ADD_PARAM_NAME("IdnToAscii", 3, "cchUnicodeChar"); // int
	ADD_PARAM_NAME("IdnToAscii", 4, "lpASCIICharStr"); // LPWSTR
	ADD_PARAM_NAME("IdnToAscii", 5, "cchASCIIChar"); // int
	ADD_PARAM_NAME("IdnToNameprepUnicode", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("IdnToNameprepUnicode", 2, "lpUnicodeCharStr"); // LPCWSTR
	ADD_PARAM_NAME("IdnToNameprepUnicode", 3, "cchUnicodeChar"); // int
	ADD_PARAM_NAME("IdnToNameprepUnicode", 4, "lpNameprepCharStr"); // LPWSTR
	ADD_PARAM_NAME("IdnToNameprepUnicode", 5, "cchNameprepChar"); // int
	ADD_PARAM_NAME("IdnToUnicode", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("IdnToUnicode", 2, "lpASCIICharStr"); // LPCWSTR
	ADD_PARAM_NAME("IdnToUnicode", 3, "cchASCIIChar"); // int
	ADD_PARAM_NAME("IdnToUnicode", 4, "lpUnicodeCharStr"); // LPWSTR
	ADD_PARAM_NAME("IdnToUnicode", 5, "cchUnicodeChar"); // int
	ADD_PARAM_NAME("ImpersonateAnonymousToken", 1, "ThreadHandle"); // HANDLE
	ADD_PARAM_NAME("ImpersonateLoggedOnUser", 1, "hToken"); // HANDLE
	ADD_PARAM_NAME("ImpersonateNamedPipeClient", 1, "hNamedPipe"); // HANDLE
	ADD_PARAM_NAME("ImpersonatePrinterClient", 1, "hToken"); // HANDLE
	ADD_PARAM_NAME("ImpersonateSelf", 1, "ImpersonationLevel"); // SECURITY_IMPERSONATION_LEVEL
	ADD_PARAM_NAME("InSendMessageEx", 1, "lpReserved"); // LPVOID
	// ADD_PARAM_NAME("IncrementUrlCacheHeaderData", 1, "?"); // DWORD
	// ADD_PARAM_NAME("IncrementUrlCacheHeaderData", 2, "?"); // LPDWORD
	ADD_PARAM_NAME("InflateRect", 1, "lprc"); // LPRECT
	ADD_PARAM_NAME("InflateRect", 2, "dx"); // int
	ADD_PARAM_NAME("InflateRect", 3, "dy"); // int
	ADD_PARAM_NAME("InitAtomTable", 1, "nSize"); // DWORD
	ADD_PARAM_NAME("InitOnceBeginInitialize", 1, "lpInitOnce"); // LPINIT_ONCE
	ADD_PARAM_NAME("InitOnceBeginInitialize", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("InitOnceBeginInitialize", 3, "fPending"); // PBOOL
	ADD_PARAM_NAME("InitOnceBeginInitialize", 4, "lpContext"); // LPVOID *
	ADD_PARAM_NAME("InitOnceComplete", 1, "lpInitOnce"); // LPINIT_ONCE
	ADD_PARAM_NAME("InitOnceComplete", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("InitOnceComplete", 3, "lpContext"); // LPVOID
	ADD_PARAM_NAME("InitOnceExecuteOnce", 1, "InitOnce"); // PINIT_ONCE
	ADD_PARAM_NAME("InitOnceExecuteOnce", 2, "InitFn"); // PINIT_ONCE_FN
	ADD_PARAM_NAME("InitOnceExecuteOnce", 3, "Parameter"); // PVOID
	ADD_PARAM_NAME("InitOnceExecuteOnce", 4, "Context"); // LPVOID *
	ADD_PARAM_NAME("InitializeAcl", 1, "pAcl"); // PACL
	ADD_PARAM_NAME("InitializeAcl", 2, "nAclLength"); // DWORD
	ADD_PARAM_NAME("InitializeAcl", 3, "dwAclRevision"); // DWORD
	ADD_PARAM_NAME("InitializeConditionVariable", 1, "ConditionVariable"); // PCONDITION_VARIABLE
	ADD_PARAM_NAME("InitializeCriticalSection", 1, "lpCriticalSection"); // LPCRITICAL_SECTION
	ADD_PARAM_NAME("InitializeCriticalSectionAndSpinCount", 1, "lpCriticalSection"); // LPCRITICAL_SECTION
	ADD_PARAM_NAME("InitializeCriticalSectionAndSpinCount", 2, "dwSpinCount"); // DWORD
	ADD_PARAM_NAME("InitializeMonitorEx", 1, "pRegistryRoot"); // LPWSTR
	ADD_PARAM_NAME("InitializeMonitorEx", 2, "pMonitor"); // LPMONITOR
	ADD_PARAM_NAME("InitializePrintMonitor", 1, "pRegistryRoot"); // LPWSTR
	ADD_PARAM_NAME("InitializePrintMonitor2", 1, "pMonitorInit"); // PMONITORINIT
	ADD_PARAM_NAME("InitializePrintMonitor2", 2, "phMonitor"); // PHANDLE
	ADD_PARAM_NAME("InitializeSListHead", 1, "ListHead"); // PSLIST_HEADER
	ADD_PARAM_NAME("InitializeSRWLock", 1, "SRWLock"); // PSRWLOCK
	ADD_PARAM_NAME("InitializeSecurityDescriptor", 1, "pSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("InitializeSecurityDescriptor", 2, "dwRevision"); // DWORD
	ADD_PARAM_NAME("InitializeSid", 1, "Sid"); // PSID
	ADD_PARAM_NAME("InitializeSid", 2, "pIdentifierAuthority"); // PSID_IDENTIFIER_AUTHORITY
	ADD_PARAM_NAME("InitializeSid", 3, "nSubAuthorityCount"); // BYTE
	ADD_PARAM_NAME("InitiateSystemShutdownA", 1, "lpMachineName"); // LPSTR
	ADD_PARAM_NAME("InitiateSystemShutdownA", 2, "lpMessage"); // LPSTR
	ADD_PARAM_NAME("InitiateSystemShutdownA", 3, "dwTimeout"); // DWORD
	ADD_PARAM_NAME("InitiateSystemShutdownA", 4, "bForceAppsClosed"); // WINBOOL
	ADD_PARAM_NAME("InitiateSystemShutdownA", 5, "bRebootAfterShutdown"); // WINBOOL
	ADD_PARAM_NAME("InitiateSystemShutdownExA", 1, "lpMachineName"); // LPSTR
	ADD_PARAM_NAME("InitiateSystemShutdownExA", 2, "lpMessage"); // LPSTR
	ADD_PARAM_NAME("InitiateSystemShutdownExA", 3, "dwTimeout"); // DWORD
	ADD_PARAM_NAME("InitiateSystemShutdownExA", 4, "bForceAppsClosed"); // WINBOOL
	ADD_PARAM_NAME("InitiateSystemShutdownExA", 5, "bRebootAfterShutdown"); // WINBOOL
	ADD_PARAM_NAME("InitiateSystemShutdownExA", 6, "dwReason"); // DWORD
	ADD_PARAM_NAME("InitiateSystemShutdownExW", 1, "lpMachineName"); // LPWSTR
	ADD_PARAM_NAME("InitiateSystemShutdownExW", 2, "lpMessage"); // LPWSTR
	ADD_PARAM_NAME("InitiateSystemShutdownExW", 3, "dwTimeout"); // DWORD
	ADD_PARAM_NAME("InitiateSystemShutdownExW", 4, "bForceAppsClosed"); // WINBOOL
	ADD_PARAM_NAME("InitiateSystemShutdownExW", 5, "bRebootAfterShutdown"); // WINBOOL
	ADD_PARAM_NAME("InitiateSystemShutdownExW", 6, "dwReason"); // DWORD
	ADD_PARAM_NAME("InitiateSystemShutdownW", 1, "lpMachineName"); // LPWSTR
	ADD_PARAM_NAME("InitiateSystemShutdownW", 2, "lpMessage"); // LPWSTR
	ADD_PARAM_NAME("InitiateSystemShutdownW", 3, "dwTimeout"); // DWORD
	ADD_PARAM_NAME("InitiateSystemShutdownW", 4, "bForceAppsClosed"); // WINBOOL
	ADD_PARAM_NAME("InitiateSystemShutdownW", 5, "bRebootAfterShutdown"); // WINBOOL
	ADD_PARAM_NAME("InsertMenuA", 1, "hMenu"); // HMENU
	ADD_PARAM_NAME("InsertMenuA", 2, "uPosition"); // UINT
	ADD_PARAM_NAME("InsertMenuA", 3, "uFlags"); // UINT
	ADD_PARAM_NAME("InsertMenuA", 4, "uIDNewItem"); // UINT_PTR
	ADD_PARAM_NAME("InsertMenuA", 5, "lpNewItem"); // LPCSTR
	ADD_PARAM_NAME("InsertMenuItemA", 1, "hmenu"); // HMENU
	ADD_PARAM_NAME("InsertMenuItemA", 2, "item"); // UINT
	ADD_PARAM_NAME("InsertMenuItemA", 3, "fByPosition"); // WINBOOL
	ADD_PARAM_NAME("InsertMenuItemA", 4, "lpmi"); // LPCMENUITEMINFOA
	ADD_PARAM_NAME("InsertMenuItemW", 1, "hmenu"); // HMENU
	ADD_PARAM_NAME("InsertMenuItemW", 2, "item"); // UINT
	ADD_PARAM_NAME("InsertMenuItemW", 3, "fByPosition"); // WINBOOL
	ADD_PARAM_NAME("InsertMenuItemW", 4, "lpmi"); // LPCMENUITEMINFOW
	ADD_PARAM_NAME("InsertMenuW", 1, "hMenu"); // HMENU
	ADD_PARAM_NAME("InsertMenuW", 2, "uPosition"); // UINT
	ADD_PARAM_NAME("InsertMenuW", 3, "uFlags"); // UINT
	ADD_PARAM_NAME("InsertMenuW", 4, "uIDNewItem"); // UINT_PTR
	ADD_PARAM_NAME("InsertMenuW", 5, "lpNewItem"); // LPCWSTR
	ADD_PARAM_NAME("InstallPrintProcessor", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("InterlockedAnd64", 1, "Destination"); // LONGLONG volatile *
	ADD_PARAM_NAME("InterlockedAnd64", 2, "Value"); // LONGLONG
	ADD_PARAM_NAME("InterlockedCompareExchange", 1, "Destination"); // LONG volatile *
	ADD_PARAM_NAME("InterlockedCompareExchange", 2, "Exchange"); // LONG
	ADD_PARAM_NAME("InterlockedCompareExchange", 3, "Comperand"); // LONG
	ADD_PARAM_NAME("InterlockedCompareExchange64", 1, "Destination"); // LONGLONG volatile *
	ADD_PARAM_NAME("InterlockedCompareExchange64", 2, "Exchange"); // LONGLONG
	ADD_PARAM_NAME("InterlockedCompareExchange64", 3, "Comperand"); // LONGLONG
	ADD_PARAM_NAME("InterlockedDecrement", 1, "lpAddend"); // LONG volatile *
	ADD_PARAM_NAME("InterlockedDecrement64", 1, "Addend"); // LONGLONG volatile *
	ADD_PARAM_NAME("InterlockedExchange", 1, "Target"); // LONG volatile *
	ADD_PARAM_NAME("InterlockedExchange", 2, "Value"); // LONG
	ADD_PARAM_NAME("InterlockedExchange64", 1, "Target"); // LONGLONG volatile *
	ADD_PARAM_NAME("InterlockedExchange64", 2, "Value"); // LONGLONG
	ADD_PARAM_NAME("InterlockedExchangeAdd", 1, "Addend"); // LONG volatile *
	ADD_PARAM_NAME("InterlockedExchangeAdd", 2, "Value"); // LONG
	ADD_PARAM_NAME("InterlockedExchangeAdd64", 1, "Addend"); // LONGLONG volatile *
	ADD_PARAM_NAME("InterlockedExchangeAdd64", 2, "Value"); // LONGLONG
	ADD_PARAM_NAME("InterlockedFlushSList", 1, "ListHead"); // PSLIST_HEADER
	ADD_PARAM_NAME("InterlockedIncrement", 1, "lpAddend"); // LONG volatile *
	ADD_PARAM_NAME("InterlockedIncrement64", 1, "Addend"); // LONGLONG volatile *
	ADD_PARAM_NAME("InterlockedOr64", 1, "Destination"); // LONGLONG volatile *
	ADD_PARAM_NAME("InterlockedOr64", 2, "Value"); // LONGLONG
	ADD_PARAM_NAME("InterlockedPopEntrySList", 1, "ListHead"); // PSLIST_HEADER
	ADD_PARAM_NAME("InterlockedPushEntrySList", 1, "ListHead"); // PSLIST_HEADER
	ADD_PARAM_NAME("InterlockedPushEntrySList", 2, "ListEntry"); // PSLIST_ENTRY
	ADD_PARAM_NAME("InterlockedXor64", 1, "Destination"); // LONGLONG volatile *
	ADD_PARAM_NAME("InterlockedXor64", 2, "Value"); // LONGLONG
	ADD_PARAM_NAME("InternalGetWindowText", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("InternalGetWindowText", 2, "pString"); // LPWSTR
	ADD_PARAM_NAME("InternalGetWindowText", 3, "cchMaxCount"); // int
	// ADD_PARAM_NAME("InternetGetSecurityInfoByURLA", 1, "?"); // ?
	// ADD_PARAM_NAME("InternetGetSecurityInfoByURLW", 1, "?"); // ?
	ADD_PARAM_NAME("InternetQueryFortezzaStatus", 1, "DWORD_PTR"); // DWORD *
	ADD_PARAM_NAME("IntersectClipRect", 1, "hdc"); // HDC
	ADD_PARAM_NAME("IntersectClipRect", 2, "left"); // int
	ADD_PARAM_NAME("IntersectClipRect", 3, "top"); // int
	ADD_PARAM_NAME("IntersectClipRect", 4, "right"); // int
	ADD_PARAM_NAME("IntersectClipRect", 5, "bottom"); // int
	ADD_PARAM_NAME("IntersectRect", 1, "lprcDst"); // LPRECT
	ADD_PARAM_NAME("IntersectRect", 2, "lprcSrc1"); // CONST RECT *
	ADD_PARAM_NAME("IntersectRect", 3, "lprcSrc2"); // CONST RECT *
	ADD_PARAM_NAME("InvalidateRect", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("InvalidateRect", 2, "lpRect"); // CONST RECT *
	ADD_PARAM_NAME("InvalidateRect", 3, "bErase"); // WINBOOL
	ADD_PARAM_NAME("InvalidateRgn", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("InvalidateRgn", 2, "hRgn"); // HRGN
	ADD_PARAM_NAME("InvalidateRgn", 3, "bErase"); // WINBOOL
	ADD_PARAM_NAME("InvertRect", 1, "hDC"); // HDC
	ADD_PARAM_NAME("InvertRect", 2, "lprc"); // CONST RECT *
	ADD_PARAM_NAME("InvertRgn", 1, "hdc"); // HDC
	ADD_PARAM_NAME("InvertRgn", 2, "hrgn"); // HRGN
	ADD_PARAM_NAME("IsBadCodePtr", 1, "lpfn"); // FARPROC
	ADD_PARAM_NAME("IsBadHugeReadPtr", 1, "lp"); // CONST VOID *
	ADD_PARAM_NAME("IsBadHugeReadPtr", 2, "ucb"); // UINT_PTR
	ADD_PARAM_NAME("IsBadHugeWritePtr", 1, "lp"); // LPVOID
	ADD_PARAM_NAME("IsBadHugeWritePtr", 2, "ucb"); // UINT_PTR
	ADD_PARAM_NAME("IsBadReadPtr", 1, "lp"); // CONST VOID *
	ADD_PARAM_NAME("IsBadReadPtr", 2, "ucb"); // UINT_PTR
	ADD_PARAM_NAME("IsBadStringPtrA", 1, "lpsz"); // LPCSTR
	ADD_PARAM_NAME("IsBadStringPtrA", 2, "ucchMax"); // UINT_PTR
	ADD_PARAM_NAME("IsBadStringPtrW", 1, "lpsz"); // LPCWSTR
	ADD_PARAM_NAME("IsBadStringPtrW", 2, "ucchMax"); // UINT_PTR
	ADD_PARAM_NAME("IsBadWritePtr", 1, "lp"); // LPVOID
	ADD_PARAM_NAME("IsBadWritePtr", 2, "ucb"); // UINT_PTR
	ADD_PARAM_NAME("IsCharAlphaA", 1, "ch"); // CHAR
	ADD_PARAM_NAME("IsCharAlphaNumericA", 1, "ch"); // CHAR
	ADD_PARAM_NAME("IsCharAlphaNumericW", 1, "ch"); // WCHAR
	ADD_PARAM_NAME("IsCharAlphaW", 1, "ch"); // WCHAR
	ADD_PARAM_NAME("IsCharLowerA", 1, "ch"); // CHAR
	ADD_PARAM_NAME("IsCharLowerW", 1, "ch"); // WCHAR
	ADD_PARAM_NAME("IsCharUpperA", 1, "ch"); // CHAR
	ADD_PARAM_NAME("IsCharUpperW", 1, "ch"); // WCHAR
	ADD_PARAM_NAME("IsChild", 1, "hWndParent"); // HWND
	ADD_PARAM_NAME("IsChild", 2, "hWnd"); // HWND
	ADD_PARAM_NAME("IsClipboardFormatAvailable", 1, "format"); // UINT
	ADD_PARAM_NAME("IsDBCSLeadByte", 1, "TestChar"); // BYTE
	ADD_PARAM_NAME("IsDBCSLeadByteEx", 1, "CodePage"); // UINT
	ADD_PARAM_NAME("IsDBCSLeadByteEx", 2, "TestChar"); // BYTE
	ADD_PARAM_NAME("IsDialogMessageA", 1, "hDlg"); // HWND
	ADD_PARAM_NAME("IsDialogMessageA", 2, "lpMsg"); // LPMSG
	ADD_PARAM_NAME("IsDialogMessageW", 1, "hDlg"); // HWND
	ADD_PARAM_NAME("IsDialogMessageW", 2, "lpMsg"); // LPMSG
	ADD_PARAM_NAME("IsDlgButtonChecked", 1, "hDlg"); // HWND
	ADD_PARAM_NAME("IsDlgButtonChecked", 2, "nIDButton"); // int
	ADD_PARAM_NAME("IsGUIThread", 1, "bConvert"); // WINBOOL
	ADD_PARAM_NAME("IsHungAppWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IsIconic", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IsMenu", 1, "hMenu"); // HMENU
	ADD_PARAM_NAME("IsNLSDefinedString", 1, "Function"); // NLS_FUNCTION
	ADD_PARAM_NAME("IsNLSDefinedString", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("IsNLSDefinedString", 3, "lpVersionInformation"); // LPNLSVERSIONINFO
	ADD_PARAM_NAME("IsNLSDefinedString", 4, "lpString"); // LPCWSTR
	ADD_PARAM_NAME("IsNLSDefinedString", 5, "cchStr"); // INT
	ADD_PARAM_NAME("IsNormalizedString", 1, "NormForm"); // NORM_FORM
	ADD_PARAM_NAME("IsNormalizedString", 2, "lpString"); // LPCWSTR
	ADD_PARAM_NAME("IsNormalizedString", 3, "cwLength"); // int
	ADD_PARAM_NAME("IsProcessInJob", 1, "ProcessHandle"); // HANDLE
	ADD_PARAM_NAME("IsProcessInJob", 2, "JobHandle"); // HANDLE
	ADD_PARAM_NAME("IsProcessInJob", 3, "Result"); // PBOOL
	ADD_PARAM_NAME("IsProcessorFeaturePresent", 1, "ProcessorFeature"); // DWORD
	ADD_PARAM_NAME("IsRectEmpty", 1, "lprc"); // CONST RECT *
	ADD_PARAM_NAME("IsTextUnicode", 1, "lpv"); // CONST VOID *
	ADD_PARAM_NAME("IsTextUnicode", 2, "iSize"); // int
	ADD_PARAM_NAME("IsTextUnicode", 3, "lpiResult"); // LPINT
	ADD_PARAM_NAME("IsTokenRestricted", 1, "TokenHandle"); // HANDLE
	ADD_PARAM_NAME("IsTokenUntrusted", 1, "TokenHandle"); // HANDLE
	ADD_PARAM_NAME("IsTouchWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IsTouchWindow", 2, "pulFlags"); // PULONG
	// ADD_PARAM_NAME("IsUrlCacheEntryExpiredA", 1, "?"); // ?
	// ADD_PARAM_NAME("IsUrlCacheEntryExpiredW", 1, "?"); // ?
	ADD_PARAM_NAME("IsValidAcl", 1, "pAcl"); // PACL
	ADD_PARAM_NAME("IsValidCodePage", 1, "CodePage"); // UINT
	ADD_PARAM_NAME("IsValidDevmodeA", 1, "pDevmode"); // PDEVMODEA
	ADD_PARAM_NAME("IsValidDevmodeA", 2, "DevmodeSize"); // size_t
	ADD_PARAM_NAME("IsValidDevmodeW", 1, "pDevmode"); // PDEVMODEW
	ADD_PARAM_NAME("IsValidDevmodeW", 2, "DevmodeSize"); // size_t
	ADD_PARAM_NAME("IsValidLanguageGroup", 1, "LanguageGroup"); // LGRPID
	ADD_PARAM_NAME("IsValidLanguageGroup", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("IsValidLocale", 1, "Locale"); // LCID
	ADD_PARAM_NAME("IsValidLocale", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("IsValidSecurityDescriptor", 1, "pSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("IsValidSid", 1, "pSid"); // PSID
	ADD_PARAM_NAME("IsWellKnownSid", 1, "pSid"); // PSID
	ADD_PARAM_NAME("IsWellKnownSid", 2, "WellKnownSidType"); // WELL_KNOWN_SID_TYPE
	ADD_PARAM_NAME("IsWinEventHookInstalled", 1, "event"); // DWORD
	ADD_PARAM_NAME("IsWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IsWindowEnabled", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IsWindowUnicode", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IsWindowVisible", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("IsWow64Process", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("IsWow64Process", 2, "Wow64Process"); // PBOOL
	ADD_PARAM_NAME("IsZoomed", 1, "hWnd"); // HWND
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
