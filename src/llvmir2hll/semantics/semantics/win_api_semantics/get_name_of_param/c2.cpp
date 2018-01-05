/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/c2.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/c2.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with C
*        (second part).
*/
void initFuncParamNamesMap_C2(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("CreateProcessA", 1, "lpApplicationName"); // LPCSTR
	ADD_PARAM_NAME("CreateProcessA", 2, "lpCommandLine"); // LPSTR
	ADD_PARAM_NAME("CreateProcessA", 3, "lpProcessAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateProcessA", 4, "lpThreadAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateProcessA", 5, "bInheritHandles"); // WINBOOL
	ADD_PARAM_NAME("CreateProcessA", 6, "dwCreationFlags"); // DWORD
	ADD_PARAM_NAME("CreateProcessA", 7, "lpEnvironment"); // LPVOID
	ADD_PARAM_NAME("CreateProcessA", 8, "lpCurrentDirectory"); // LPCSTR
	ADD_PARAM_NAME("CreateProcessA", 9, "lpStartupInfo"); // LPSTARTUPINFOA
	ADD_PARAM_NAME("CreateProcessA", 10, "lpProcessInformation"); // LPPROCESS_INFORMATION
	ADD_PARAM_NAME("CreateProcessAsUserA", 1, "hToken"); // HANDLE
	ADD_PARAM_NAME("CreateProcessAsUserA", 2, "lpApplicationName"); // LPCSTR
	ADD_PARAM_NAME("CreateProcessAsUserA", 3, "lpCommandLine"); // LPSTR
	ADD_PARAM_NAME("CreateProcessAsUserA", 4, "lpProcessAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateProcessAsUserA", 5, "lpThreadAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateProcessAsUserA", 6, "bInheritHandles"); // WINBOOL
	ADD_PARAM_NAME("CreateProcessAsUserA", 7, "dwCreationFlags"); // DWORD
	ADD_PARAM_NAME("CreateProcessAsUserA", 8, "lpEnvironment"); // LPVOID
	ADD_PARAM_NAME("CreateProcessAsUserA", 9, "lpCurrentDirectory"); // LPCSTR
	ADD_PARAM_NAME("CreateProcessAsUserA", 10, "lpStartupInfo"); // LPSTARTUPINFOA
	ADD_PARAM_NAME("CreateProcessAsUserA", 11, "lpProcessInformation"); // LPPROCESS_INFORMATION
	ADD_PARAM_NAME("CreateProcessAsUserW", 1, "hToken"); // HANDLE
	ADD_PARAM_NAME("CreateProcessAsUserW", 2, "lpApplicationName"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessAsUserW", 3, "lpCommandLine"); // LPWSTR
	ADD_PARAM_NAME("CreateProcessAsUserW", 4, "lpProcessAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateProcessAsUserW", 5, "lpThreadAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateProcessAsUserW", 6, "bInheritHandles"); // WINBOOL
	ADD_PARAM_NAME("CreateProcessAsUserW", 7, "dwCreationFlags"); // DWORD
	ADD_PARAM_NAME("CreateProcessAsUserW", 8, "lpEnvironment"); // LPVOID
	ADD_PARAM_NAME("CreateProcessAsUserW", 9, "lpCurrentDirectory"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessAsUserW", 10, "lpStartupInfo"); // LPSTARTUPINFOW
	ADD_PARAM_NAME("CreateProcessAsUserW", 11, "lpProcessInformation"); // LPPROCESS_INFORMATION
	ADD_PARAM_NAME("CreateProcessW", 1, "lpApplicationName"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessW", 2, "lpCommandLine"); // LPWSTR
	ADD_PARAM_NAME("CreateProcessW", 3, "lpProcessAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateProcessW", 4, "lpThreadAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateProcessW", 5, "bInheritHandles"); // WINBOOL
	ADD_PARAM_NAME("CreateProcessW", 6, "dwCreationFlags"); // DWORD
	ADD_PARAM_NAME("CreateProcessW", 7, "lpEnvironment"); // LPVOID
	ADD_PARAM_NAME("CreateProcessW", 8, "lpCurrentDirectory"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessW", 9, "lpStartupInfo"); // LPSTARTUPINFOW
	ADD_PARAM_NAME("CreateProcessW", 10, "lpProcessInformation"); // LPPROCESS_INFORMATION
	ADD_PARAM_NAME("CreateProcessWithLogonW", 1, "lpUsername"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessWithLogonW", 2, "lpDomain"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessWithLogonW", 3, "lpPassword"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessWithLogonW", 4, "dwLogonFlags"); // DWORD
	ADD_PARAM_NAME("CreateProcessWithLogonW", 5, "lpApplicationName"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessWithLogonW", 6, "lpCommandLine"); // LPWSTR
	ADD_PARAM_NAME("CreateProcessWithLogonW", 7, "dwCreationFlags"); // DWORD
	ADD_PARAM_NAME("CreateProcessWithLogonW", 8, "lpEnvironment"); // LPVOID
	ADD_PARAM_NAME("CreateProcessWithLogonW", 9, "lpCurrentDirectory"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessWithLogonW", 10, "lpStartupInfo"); // LPSTARTUPINFOW
	ADD_PARAM_NAME("CreateProcessWithLogonW", 11, "lpProcessInformation"); // LPPROCESS_INFORMATION
	ADD_PARAM_NAME("CreateProcessWithTokenW", 1, "hToken"); // HANDLE
	ADD_PARAM_NAME("CreateProcessWithTokenW", 2, "dwLogonFlags"); // DWORD
	ADD_PARAM_NAME("CreateProcessWithTokenW", 3, "lpApplicationName"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessWithTokenW", 4, "lpCommandLine"); // LPWSTR
	ADD_PARAM_NAME("CreateProcessWithTokenW", 5, "dwCreationFlags"); // DWORD
	ADD_PARAM_NAME("CreateProcessWithTokenW", 6, "lpEnvironment"); // LPVOID
	ADD_PARAM_NAME("CreateProcessWithTokenW", 7, "lpCurrentDirectory"); // LPCWSTR
	ADD_PARAM_NAME("CreateProcessWithTokenW", 8, "lpStartupInfo"); // LPSTARTUPINFOW
	ADD_PARAM_NAME("CreateProcessWithTokenW", 9, "lpProcessInformation"); // LPPROCESS_INFORMATION
	ADD_PARAM_NAME("CreateRectRgn", 1, "x1"); // int
	ADD_PARAM_NAME("CreateRectRgn", 2, "y1"); // int
	ADD_PARAM_NAME("CreateRectRgn", 3, "x2"); // int
	ADD_PARAM_NAME("CreateRectRgn", 4, "y2"); // int
	ADD_PARAM_NAME("CreateRectRgnIndirect", 1, "lprect"); // CONST RECT *
	ADD_PARAM_NAME("CreateRemoteThread", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("CreateRemoteThread", 2, "lpThreadAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateRemoteThread", 3, "dwStackSize"); // SIZE_T
	ADD_PARAM_NAME("CreateRemoteThread", 4, "lpStartAddress"); // LPTHREAD_START_ROUTINE
	ADD_PARAM_NAME("CreateRemoteThread", 5, "lpParameter"); // LPVOID
	ADD_PARAM_NAME("CreateRemoteThread", 6, "dwCreationFlags"); // DWORD
	ADD_PARAM_NAME("CreateRemoteThread", 7, "lpThreadId"); // LPDWORD
	ADD_PARAM_NAME("CreateRemoteThreadEx", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("CreateRemoteThreadEx", 2, "lpThreadAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateRemoteThreadEx", 3, "dwStackSize"); // SIZE_T
	ADD_PARAM_NAME("CreateRemoteThreadEx", 4, "lpStartAddress"); // LPTHREAD_START_ROUTINE
	ADD_PARAM_NAME("CreateRemoteThreadEx", 5, "lpParameter"); // LPVOID
	ADD_PARAM_NAME("CreateRemoteThreadEx", 6, "dwCreationFlags"); // DWORD
	ADD_PARAM_NAME("CreateRemoteThreadEx", 7, "lpAttributeList"); // LPPROC_THREAD_ATTRIBUTE_LIST
	ADD_PARAM_NAME("CreateRemoteThreadEx", 8, "lpThreadId"); // LPDWORD
	ADD_PARAM_NAME("CreateRestrictedToken", 1, "ExistingTokenHandle"); // HANDLE
	ADD_PARAM_NAME("CreateRestrictedToken", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("CreateRestrictedToken", 3, "DisableSidCount"); // DWORD
	ADD_PARAM_NAME("CreateRestrictedToken", 4, "SidsToDisable"); // PSID_AND_ATTRIBUTES
	ADD_PARAM_NAME("CreateRestrictedToken", 5, "DeletePrivilegeCount"); // DWORD
	ADD_PARAM_NAME("CreateRestrictedToken", 6, "PrivilegesToDelete"); // PLUID_AND_ATTRIBUTES
	ADD_PARAM_NAME("CreateRestrictedToken", 7, "RestrictedSidCount"); // DWORD
	ADD_PARAM_NAME("CreateRestrictedToken", 8, "SidsToRestrict"); // PSID_AND_ATTRIBUTES
	ADD_PARAM_NAME("CreateRestrictedToken", 9, "NewTokenHandle"); // PHANDLE
	ADD_PARAM_NAME("CreateRoundRectRgn", 1, "x1"); // int
	ADD_PARAM_NAME("CreateRoundRectRgn", 2, "y1"); // int
	ADD_PARAM_NAME("CreateRoundRectRgn", 3, "x2"); // int
	ADD_PARAM_NAME("CreateRoundRectRgn", 4, "y2"); // int
	ADD_PARAM_NAME("CreateRoundRectRgn", 5, "w"); // int
	ADD_PARAM_NAME("CreateRoundRectRgn", 6, "h"); // int
	ADD_PARAM_NAME("CreateScalableFontResourceA", 1, "fdwHidden"); // DWORD
	ADD_PARAM_NAME("CreateScalableFontResourceA", 2, "lpszFont"); // LPCSTR
	ADD_PARAM_NAME("CreateScalableFontResourceA", 3, "lpszFile"); // LPCSTR
	ADD_PARAM_NAME("CreateScalableFontResourceA", 4, "lpszPath"); // LPCSTR
	ADD_PARAM_NAME("CreateScalableFontResourceW", 1, "fdwHidden"); // DWORD
	ADD_PARAM_NAME("CreateScalableFontResourceW", 2, "lpszFont"); // LPCWSTR
	ADD_PARAM_NAME("CreateScalableFontResourceW", 3, "lpszFile"); // LPCWSTR
	ADD_PARAM_NAME("CreateScalableFontResourceW", 4, "lpszPath"); // LPCWSTR
	ADD_PARAM_NAME("CreateSemaphoreA", 1, "lpSemaphoreAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateSemaphoreA", 2, "lInitialCount"); // LONG
	ADD_PARAM_NAME("CreateSemaphoreA", 3, "lMaximumCount"); // LONG
	ADD_PARAM_NAME("CreateSemaphoreA", 4, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CreateSemaphoreExA", 1, "lpSemaphoreAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateSemaphoreExA", 2, "lInitialCount"); // LONG
	ADD_PARAM_NAME("CreateSemaphoreExA", 3, "lMaximumCount"); // LONG
	ADD_PARAM_NAME("CreateSemaphoreExA", 4, "lpName"); // LPCSTR
	ADD_PARAM_NAME("CreateSemaphoreExA", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateSemaphoreExA", 6, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateSemaphoreExW", 1, "lpSemaphoreAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateSemaphoreExW", 2, "lInitialCount"); // LONG
	ADD_PARAM_NAME("CreateSemaphoreExW", 3, "lMaximumCount"); // LONG
	ADD_PARAM_NAME("CreateSemaphoreExW", 4, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateSemaphoreExW", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateSemaphoreExW", 6, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateSemaphoreW", 1, "lpSemaphoreAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateSemaphoreW", 2, "lInitialCount"); // LONG
	ADD_PARAM_NAME("CreateSemaphoreW", 3, "lMaximumCount"); // LONG
	ADD_PARAM_NAME("CreateSemaphoreW", 4, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("CreateServiceA", 1, "hSCManager"); // SC_HANDLE
	ADD_PARAM_NAME("CreateServiceA", 2, "lpServiceName"); // LPCSTR
	ADD_PARAM_NAME("CreateServiceA", 3, "lpDisplayName"); // LPCSTR
	ADD_PARAM_NAME("CreateServiceA", 4, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateServiceA", 5, "dwServiceType"); // DWORD
	ADD_PARAM_NAME("CreateServiceA", 6, "dwStartType"); // DWORD
	ADD_PARAM_NAME("CreateServiceA", 7, "dwErrorControl"); // DWORD
	ADD_PARAM_NAME("CreateServiceA", 8, "lpBinaryPathName"); // LPCSTR
	ADD_PARAM_NAME("CreateServiceA", 9, "lpLoadOrderGroup"); // LPCSTR
	ADD_PARAM_NAME("CreateServiceA", 10, "lpdwTagId"); // LPDWORD
	ADD_PARAM_NAME("CreateServiceA", 11, "lpDependencies"); // LPCSTR
	ADD_PARAM_NAME("CreateServiceA", 12, "lpServiceStartName"); // LPCSTR
	ADD_PARAM_NAME("CreateServiceA", 13, "lpPassword"); // LPCSTR
	ADD_PARAM_NAME("CreateServiceW", 1, "hSCManager"); // SC_HANDLE
	ADD_PARAM_NAME("CreateServiceW", 2, "lpServiceName"); // LPCWSTR
	ADD_PARAM_NAME("CreateServiceW", 3, "lpDisplayName"); // LPCWSTR
	ADD_PARAM_NAME("CreateServiceW", 4, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateServiceW", 5, "dwServiceType"); // DWORD
	ADD_PARAM_NAME("CreateServiceW", 6, "dwStartType"); // DWORD
	ADD_PARAM_NAME("CreateServiceW", 7, "dwErrorControl"); // DWORD
	ADD_PARAM_NAME("CreateServiceW", 8, "lpBinaryPathName"); // LPCWSTR
	ADD_PARAM_NAME("CreateServiceW", 9, "lpLoadOrderGroup"); // LPCWSTR
	ADD_PARAM_NAME("CreateServiceW", 10, "lpdwTagId"); // LPDWORD
	ADD_PARAM_NAME("CreateServiceW", 11, "lpDependencies"); // LPCWSTR
	ADD_PARAM_NAME("CreateServiceW", 12, "lpServiceStartName"); // LPCWSTR
	ADD_PARAM_NAME("CreateServiceW", 13, "lpPassword"); // LPCWSTR
	ADD_PARAM_NAME("CreateSolidBrush", 1, "color"); // COLORREF
	ADD_PARAM_NAME("CreateSymbolicLinkA", 1, "lpSymLinkFileName"); // LPSTR
	ADD_PARAM_NAME("CreateSymbolicLinkA", 2, "lpTargetFileName"); // LPSTR
	ADD_PARAM_NAME("CreateSymbolicLinkA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateSymbolicLinkTransactedA", 1, "lpSymlinkFileName"); // LPSTR
	ADD_PARAM_NAME("CreateSymbolicLinkTransactedA", 2, "lpTargetFileName"); // LPSTR
	ADD_PARAM_NAME("CreateSymbolicLinkTransactedA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateSymbolicLinkTransactedA", 4, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("CreateSymbolicLinkTransactedW", 1, "lpSymlinkFileName"); // LPWSTR
	ADD_PARAM_NAME("CreateSymbolicLinkTransactedW", 2, "lpTargetFileName"); // LPWSTR
	ADD_PARAM_NAME("CreateSymbolicLinkTransactedW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateSymbolicLinkTransactedW", 4, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("CreateSymbolicLinkW", 1, "lpSymLinkFileName"); // LPWSTR
	ADD_PARAM_NAME("CreateSymbolicLinkW", 2, "lpTargetFileName"); // LPWSTR
	ADD_PARAM_NAME("CreateSymbolicLinkW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateTapePartition", 1, "hDevice"); // HANDLE
	ADD_PARAM_NAME("CreateTapePartition", 2, "dwPartitionMethod"); // DWORD
	ADD_PARAM_NAME("CreateTapePartition", 3, "dwCount"); // DWORD
	ADD_PARAM_NAME("CreateTapePartition", 4, "dwSize"); // DWORD
	ADD_PARAM_NAME("CreateThread", 1, "lpThreadAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateThread", 2, "dwStackSize"); // SIZE_T
	ADD_PARAM_NAME("CreateThread", 3, "lpStartAddress"); // LPTHREAD_START_ROUTINE
	ADD_PARAM_NAME("CreateThread", 4, "lpParameter"); // LPVOID
	ADD_PARAM_NAME("CreateThread", 5, "dwCreationFlags"); // DWORD
	ADD_PARAM_NAME("CreateThread", 6, "lpThreadId"); // LPDWORD
	ADD_PARAM_NAME("CreateThreadpool", 1, "reserved"); // PVOID
	ADD_PARAM_NAME("CreateThreadpoolIo", 1, "fl"); // HANDLE
	ADD_PARAM_NAME("CreateThreadpoolIo", 2, "pfnio"); // PTP_WIN32_IO_CALLBACK
	ADD_PARAM_NAME("CreateThreadpoolIo", 3, "pv"); // PVOID
	ADD_PARAM_NAME("CreateThreadpoolIo", 4, "pcbe"); // PTP_CALLBACK_ENVIRON
	ADD_PARAM_NAME("CreateThreadpoolTimer", 1, "pfnti"); // PTP_TIMER_CALLBACK
	ADD_PARAM_NAME("CreateThreadpoolTimer", 2, "pv"); // PVOID
	ADD_PARAM_NAME("CreateThreadpoolTimer", 3, "pcbe"); // PTP_CALLBACK_ENVIRON
	ADD_PARAM_NAME("CreateThreadpoolWait", 1, "pfnwa"); // PTP_WAIT_CALLBACK
	ADD_PARAM_NAME("CreateThreadpoolWait", 2, "pv"); // PVOID
	ADD_PARAM_NAME("CreateThreadpoolWait", 3, "pcbe"); // PTP_CALLBACK_ENVIRON
	ADD_PARAM_NAME("CreateThreadpoolWork", 1, "pfnwk"); // PTP_WORK_CALLBACK
	ADD_PARAM_NAME("CreateThreadpoolWork", 2, "pv"); // PVOID
	ADD_PARAM_NAME("CreateThreadpoolWork", 3, "pcbe"); // PTP_CALLBACK_ENVIRON
	ADD_PARAM_NAME("CreateTimerQueueTimer", 1, "phNewTimer"); // PHANDLE
	ADD_PARAM_NAME("CreateTimerQueueTimer", 2, "TimerQueue"); // HANDLE
	ADD_PARAM_NAME("CreateTimerQueueTimer", 3, "Callback"); // WAITORTIMERCALLBACK
	ADD_PARAM_NAME("CreateTimerQueueTimer", 4, "Parameter"); // PVOID
	ADD_PARAM_NAME("CreateTimerQueueTimer", 5, "DueTime"); // DWORD
	ADD_PARAM_NAME("CreateTimerQueueTimer", 6, "Period"); // DWORD
	ADD_PARAM_NAME("CreateTimerQueueTimer", 7, "Flags"); // ULONG
	ADD_PARAM_NAME("CreateTransaction", 1, "lpTransactionAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateTransaction", 2, "UOW"); // LPGUID
	ADD_PARAM_NAME("CreateTransaction", 3, "CreateOptions"); // DWORD
	ADD_PARAM_NAME("CreateTransaction", 4, "IsolationLevel"); // DWORD
	ADD_PARAM_NAME("CreateTransaction", 5, "IsolationFlags"); // DWORD
	ADD_PARAM_NAME("CreateTransaction", 6, "Timeout"); // DWORD
	ADD_PARAM_NAME("CreateTransaction", 7, "Description"); // LPWSTR
	ADD_PARAM_NAME("CreateWaitableTimerA", 1, "lpTimerAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateWaitableTimerA", 2, "bManualReset"); // WINBOOL
	ADD_PARAM_NAME("CreateWaitableTimerA", 3, "lpTimerName"); // LPCSTR
	ADD_PARAM_NAME("CreateWaitableTimerExA", 1, "lpTimerAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateWaitableTimerExA", 2, "lpTimerName"); // LPCSTR
	ADD_PARAM_NAME("CreateWaitableTimerExA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateWaitableTimerExA", 4, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateWaitableTimerExW", 1, "lpTimerAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateWaitableTimerExW", 2, "lpTimerName"); // LPCWSTR
	ADD_PARAM_NAME("CreateWaitableTimerExW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateWaitableTimerExW", 4, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("CreateWaitableTimerW", 1, "lpTimerAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateWaitableTimerW", 2, "bManualReset"); // WINBOOL
	ADD_PARAM_NAME("CreateWaitableTimerW", 3, "lpTimerName"); // LPCWSTR
	ADD_PARAM_NAME("CreateWellKnownSid", 1, "WellKnownSidType"); // WELL_KNOWN_SID_TYPE
	ADD_PARAM_NAME("CreateWellKnownSid", 2, "DomainSid"); // PSID
	ADD_PARAM_NAME("CreateWellKnownSid", 3, "pSid"); // PSID
	ADD_PARAM_NAME("CreateWellKnownSid", 4, "cbSid"); // DWORD *
	ADD_PARAM_NAME("CreateWindowExA", 1, "dwExStyle"); // DWORD
	ADD_PARAM_NAME("CreateWindowExA", 2, "lpClassName"); // LPCSTR
	ADD_PARAM_NAME("CreateWindowExA", 3, "lpWindowName"); // LPCSTR
	ADD_PARAM_NAME("CreateWindowExA", 4, "dwStyle"); // DWORD
	ADD_PARAM_NAME("CreateWindowExA", 5, "X"); // int
	ADD_PARAM_NAME("CreateWindowExA", 6, "Y"); // int
	ADD_PARAM_NAME("CreateWindowExA", 7, "nWidth"); // int
	ADD_PARAM_NAME("CreateWindowExA", 8, "nHeight"); // int
	ADD_PARAM_NAME("CreateWindowExA", 9, "hWndParent"); // HWND
	ADD_PARAM_NAME("CreateWindowExA", 10, "hMenu"); // HMENU
	ADD_PARAM_NAME("CreateWindowExA", 11, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("CreateWindowExA", 12, "lpParam"); // LPVOID
	ADD_PARAM_NAME("CreateWindowExW", 1, "dwExStyle"); // DWORD
	ADD_PARAM_NAME("CreateWindowExW", 2, "lpClassName"); // LPCWSTR
	ADD_PARAM_NAME("CreateWindowExW", 3, "lpWindowName"); // LPCWSTR
	ADD_PARAM_NAME("CreateWindowExW", 4, "dwStyle"); // DWORD
	ADD_PARAM_NAME("CreateWindowExW", 5, "X"); // int
	ADD_PARAM_NAME("CreateWindowExW", 6, "Y"); // int
	ADD_PARAM_NAME("CreateWindowExW", 7, "nWidth"); // int
	ADD_PARAM_NAME("CreateWindowExW", 8, "nHeight"); // int
	ADD_PARAM_NAME("CreateWindowExW", 9, "hWndParent"); // HWND
	ADD_PARAM_NAME("CreateWindowExW", 10, "hMenu"); // HMENU
	ADD_PARAM_NAME("CreateWindowExW", 11, "hInstance"); // HINSTANCE
	ADD_PARAM_NAME("CreateWindowExW", 12, "lpParam"); // LPVOID
	ADD_PARAM_NAME("CreateWindowStationA", 1, "lpwinsta"); // LPCSTR
	ADD_PARAM_NAME("CreateWindowStationA", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateWindowStationA", 3, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("CreateWindowStationA", 4, "lpsa"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CreateWindowStationW", 1, "lpwinsta"); // LPCWSTR
	ADD_PARAM_NAME("CreateWindowStationW", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CreateWindowStationW", 3, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("CreateWindowStationW", 4, "lpsa"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("CredDeleteA", 1, "TargetName"); // LPCSTR
	ADD_PARAM_NAME("CredDeleteA", 2, "Type"); // DWORD
	ADD_PARAM_NAME("CredDeleteA", 3, "Flags"); // DWORD
	ADD_PARAM_NAME("CredDeleteW", 1, "TargetName"); // LPCWSTR
	ADD_PARAM_NAME("CredDeleteW", 2, "Type"); // DWORD
	ADD_PARAM_NAME("CredDeleteW", 3, "Flags"); // DWORD
	ADD_PARAM_NAME("CredEnumerateA", 1, "Filter"); // LPCSTR
	ADD_PARAM_NAME("CredEnumerateA", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("CredEnumerateA", 3, "Count"); // DWORD *
	ADD_PARAM_NAME("CredEnumerateA", 4, "Credential"); // PCREDENTIALA * *
	ADD_PARAM_NAME("CredEnumerateW", 1, "Filter"); // LPCWSTR
	ADD_PARAM_NAME("CredEnumerateW", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("CredEnumerateW", 3, "Count"); // DWORD *
	ADD_PARAM_NAME("CredEnumerateW", 4, "Credential"); // PCREDENTIALW * *
	ADD_PARAM_NAME("CredFindBestCredentialA", 1, "TargetName"); // LPCSTR
	ADD_PARAM_NAME("CredFindBestCredentialA", 2, "Type"); // DWORD
	ADD_PARAM_NAME("CredFindBestCredentialA", 3, "Flags"); // DWORD
	ADD_PARAM_NAME("CredFindBestCredentialA", 4, "Credential"); // PCREDENTIALA *
	ADD_PARAM_NAME("CredFindBestCredentialW", 1, "TargetName"); // LPCWSTR
	ADD_PARAM_NAME("CredFindBestCredentialW", 2, "Type"); // DWORD
	ADD_PARAM_NAME("CredFindBestCredentialW", 3, "Flags"); // DWORD
	ADD_PARAM_NAME("CredFindBestCredentialW", 4, "Credential"); // PCREDENTIALW *
	ADD_PARAM_NAME("CredFree", 1, "Buffer"); // PVOID
	ADD_PARAM_NAME("CredGetSessionTypes", 1, "MaximumPersistCount"); // DWORD
	ADD_PARAM_NAME("CredGetSessionTypes", 2, "MaximumPersist"); // LPDWORD
	ADD_PARAM_NAME("CredGetTargetInfoA", 1, "TargetName"); // LPCSTR
	ADD_PARAM_NAME("CredGetTargetInfoA", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("CredGetTargetInfoA", 3, "TargetInfo"); // PCREDENTIAL_TARGET_INFORMATIONA *
	ADD_PARAM_NAME("CredGetTargetInfoW", 1, "TargetName"); // LPCWSTR
	ADD_PARAM_NAME("CredGetTargetInfoW", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("CredGetTargetInfoW", 3, "TargetInfo"); // PCREDENTIAL_TARGET_INFORMATIONW *
	ADD_PARAM_NAME("CredIsMarshaledCredentialA", 1, "MarshaledCredential"); // LPCSTR
	ADD_PARAM_NAME("CredIsMarshaledCredentialW", 1, "MarshaledCredential"); // LPCWSTR
	ADD_PARAM_NAME("CredIsProtectedA", 1, "pszProtectedCredentials"); // LPSTR
	ADD_PARAM_NAME("CredIsProtectedA", 2, "pProtectionType"); // CRED_PROTECTION_TYPE *
	ADD_PARAM_NAME("CredIsProtectedW", 1, "pszProtectedCredentials"); // LPWSTR
	ADD_PARAM_NAME("CredIsProtectedW", 2, "pProtectionType"); // CRED_PROTECTION_TYPE *
	ADD_PARAM_NAME("CredMarshalCredentialA", 1, "CredType"); // CRED_MARSHAL_TYPE
	ADD_PARAM_NAME("CredMarshalCredentialA", 2, "Credential"); // PVOID
	ADD_PARAM_NAME("CredMarshalCredentialA", 3, "MarshaledCredential"); // LPSTR *
	ADD_PARAM_NAME("CredMarshalCredentialW", 1, "CredType"); // CRED_MARSHAL_TYPE
	ADD_PARAM_NAME("CredMarshalCredentialW", 2, "Credential"); // PVOID
	ADD_PARAM_NAME("CredMarshalCredentialW", 3, "MarshaledCredential"); // LPWSTR *
	ADD_PARAM_NAME("CredPackAuthenticationBufferA", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CredPackAuthenticationBufferA", 2, "pszUserName"); // LPSTR
	ADD_PARAM_NAME("CredPackAuthenticationBufferA", 3, "pszPassword"); // LPSTR
	ADD_PARAM_NAME("CredPackAuthenticationBufferA", 4, "pPackedCredentials"); // PBYTE
	ADD_PARAM_NAME("CredPackAuthenticationBufferA", 5, "pcbPackedCredentials"); // DWORD *
	ADD_PARAM_NAME("CredPackAuthenticationBufferW", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CredPackAuthenticationBufferW", 2, "pszUserName"); // LPWSTR
	ADD_PARAM_NAME("CredPackAuthenticationBufferW", 3, "pszPassword"); // LPWSTR
	ADD_PARAM_NAME("CredPackAuthenticationBufferW", 4, "pPackedCredentials"); // PBYTE
	ADD_PARAM_NAME("CredPackAuthenticationBufferW", 5, "pcbPackedCredentials"); // DWORD *
	ADD_PARAM_NAME("CredProtectA", 1, "fAsSelf"); // WINBOOL
	ADD_PARAM_NAME("CredProtectA", 2, "pszCredentials"); // LPSTR
	ADD_PARAM_NAME("CredProtectA", 3, "cchCredentials"); // DWORD
	ADD_PARAM_NAME("CredProtectA", 4, "pszProtectedCredentials"); // LPSTR
	ADD_PARAM_NAME("CredProtectA", 5, "pcchMaxChars"); // DWORD *
	ADD_PARAM_NAME("CredProtectA", 6, "ProtectionType"); // CRED_PROTECTION_TYPE *
	ADD_PARAM_NAME("CredProtectW", 1, "fAsSelf"); // WINBOOL
	ADD_PARAM_NAME("CredProtectW", 2, "pszCredentials"); // LPWSTR
	ADD_PARAM_NAME("CredProtectW", 3, "cchCredentials"); // DWORD
	ADD_PARAM_NAME("CredProtectW", 4, "pszProtectedCredentials"); // LPWSTR
	ADD_PARAM_NAME("CredProtectW", 5, "pcchMaxChars"); // DWORD *
	ADD_PARAM_NAME("CredProtectW", 6, "ProtectionType"); // CRED_PROTECTION_TYPE *
	ADD_PARAM_NAME("CredReadA", 1, "TargetName"); // LPCSTR
	ADD_PARAM_NAME("CredReadA", 2, "Type"); // DWORD
	ADD_PARAM_NAME("CredReadA", 3, "Flags"); // DWORD
	ADD_PARAM_NAME("CredReadA", 4, "Credential"); // PCREDENTIALA *
	ADD_PARAM_NAME("CredReadDomainCredentialsA", 1, "TargetInfo"); // PCREDENTIAL_TARGET_INFORMATIONA
	ADD_PARAM_NAME("CredReadDomainCredentialsA", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("CredReadDomainCredentialsA", 3, "Count"); // DWORD *
	ADD_PARAM_NAME("CredReadDomainCredentialsA", 4, "Credential"); // PCREDENTIALA * *
	ADD_PARAM_NAME("CredReadDomainCredentialsW", 1, "TargetInfo"); // PCREDENTIAL_TARGET_INFORMATIONW
	ADD_PARAM_NAME("CredReadDomainCredentialsW", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("CredReadDomainCredentialsW", 3, "Count"); // DWORD *
	ADD_PARAM_NAME("CredReadDomainCredentialsW", 4, "Credential"); // PCREDENTIALW * *
	ADD_PARAM_NAME("CredReadW", 1, "TargetName"); // LPCWSTR
	ADD_PARAM_NAME("CredReadW", 2, "Type"); // DWORD
	ADD_PARAM_NAME("CredReadW", 3, "Flags"); // DWORD
	ADD_PARAM_NAME("CredReadW", 4, "Credential"); // PCREDENTIALW *
	ADD_PARAM_NAME("CredRenameA", 1, "OldTargetName"); // LPCSTR
	ADD_PARAM_NAME("CredRenameA", 2, "NewTargetName"); // LPCSTR
	ADD_PARAM_NAME("CredRenameA", 3, "Type"); // DWORD
	ADD_PARAM_NAME("CredRenameA", 4, "Flags"); // DWORD
	ADD_PARAM_NAME("CredRenameW", 1, "OldTargetName"); // LPCWSTR
	ADD_PARAM_NAME("CredRenameW", 2, "NewTargetName"); // LPCWSTR
	ADD_PARAM_NAME("CredRenameW", 3, "Type"); // DWORD
	ADD_PARAM_NAME("CredRenameW", 4, "Flags"); // DWORD
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsA", 1, "pszTargetName"); // PCSTR
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsA", 2, "pContext"); // PCtxtHandle
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsA", 3, "dwAuthError"); // DWORD
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsA", 4, "UserName"); // PSTR
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsA", 5, "ulUserBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsA", 6, "pszPassword"); // PSTR
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsA", 7, "ulPasswordBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsA", 8, "pfSave"); // PBOOL
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsA", 9, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsW", 1, "pszTargetName"); // PCWSTR
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsW", 2, "pContext"); // PCtxtHandle
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsW", 3, "dwAuthError"); // DWORD
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsW", 4, "UserName"); // PWSTR
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsW", 5, "ulUserBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsW", 6, "pszPassword"); // PWSTR
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsW", 7, "ulPasswordBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsW", 8, "pfSave"); // PBOOL
	ADD_PARAM_NAME("CredUICmdLinePromptForCredentialsW", 9, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CredUIConfirmCredentialsA", 1, "pszTargetName"); // PCSTR
	ADD_PARAM_NAME("CredUIConfirmCredentialsA", 2, "bConfirm"); // WINBOOL
	ADD_PARAM_NAME("CredUIConfirmCredentialsW", 1, "pszTargetName"); // PCWSTR
	ADD_PARAM_NAME("CredUIConfirmCredentialsW", 2, "bConfirm"); // WINBOOL
	ADD_PARAM_NAME("CredUIParseUserNameA", 1, "userName"); // CONST CHAR *
	ADD_PARAM_NAME("CredUIParseUserNameA", 2, "user"); // CHAR *
	ADD_PARAM_NAME("CredUIParseUserNameA", 3, "userBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUIParseUserNameA", 4, "domain"); // CHAR *
	ADD_PARAM_NAME("CredUIParseUserNameA", 5, "domainBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUIParseUserNameW", 1, "UserName"); // CONST WCHAR *
	ADD_PARAM_NAME("CredUIParseUserNameW", 2, "user"); // WCHAR *
	ADD_PARAM_NAME("CredUIParseUserNameW", 3, "userBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUIParseUserNameW", 4, "domain"); // WCHAR *
	ADD_PARAM_NAME("CredUIParseUserNameW", 5, "domainBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUIPromptForCredentialsA", 1, "pUiInfo"); // PCREDUI_INFOA
	ADD_PARAM_NAME("CredUIPromptForCredentialsA", 2, "pszTargetName"); // PCSTR
	ADD_PARAM_NAME("CredUIPromptForCredentialsA", 3, "pContext"); // PCtxtHandle
	ADD_PARAM_NAME("CredUIPromptForCredentialsA", 4, "dwAuthError"); // DWORD
	ADD_PARAM_NAME("CredUIPromptForCredentialsA", 5, "pszUserName"); // PSTR
	ADD_PARAM_NAME("CredUIPromptForCredentialsA", 6, "ulUserNameBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUIPromptForCredentialsA", 7, "pszPassword"); // PSTR
	ADD_PARAM_NAME("CredUIPromptForCredentialsA", 8, "ulPasswordBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUIPromptForCredentialsA", 9, "save"); // WINBOOL *
	ADD_PARAM_NAME("CredUIPromptForCredentialsA", 10, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CredUIPromptForCredentialsW", 1, "pUiInfo"); // PCREDUI_INFOW
	ADD_PARAM_NAME("CredUIPromptForCredentialsW", 2, "pszTargetName"); // PCWSTR
	ADD_PARAM_NAME("CredUIPromptForCredentialsW", 3, "pContext"); // PCtxtHandle
	ADD_PARAM_NAME("CredUIPromptForCredentialsW", 4, "dwAuthError"); // DWORD
	ADD_PARAM_NAME("CredUIPromptForCredentialsW", 5, "pszUserName"); // PWSTR
	ADD_PARAM_NAME("CredUIPromptForCredentialsW", 6, "ulUserNameBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUIPromptForCredentialsW", 7, "pszPassword"); // PWSTR
	ADD_PARAM_NAME("CredUIPromptForCredentialsW", 8, "ulPasswordBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUIPromptForCredentialsW", 9, "save"); // WINBOOL *
	ADD_PARAM_NAME("CredUIPromptForCredentialsW", 10, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsA", 1, "pUiInfo"); // PCREDUI_INFOA
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsA", 2, "dwAuthError"); // DWORD
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsA", 3, "pulAuthPackage"); // ULONG *
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsA", 4, "pvInAuthBuffer"); // LPCVOID
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsA", 5, "ulInAuthBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsA", 6, "ppvOutAuthBuffer"); // LPVOID *
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsA", 7, "pulOutAuthBufferSize"); // ULONG *
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsA", 8, "pfSave"); // WINBOOL *
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsA", 9, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsW", 1, "pUiInfo"); // PCREDUI_INFOW
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsW", 2, "dwAuthError"); // DWORD
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsW", 3, "pulAuthPackage"); // ULONG *
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsW", 4, "pvInAuthBuffer"); // LPCVOID
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsW", 5, "ulInAuthBufferSize"); // ULONG
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsW", 6, "ppvOutAuthBuffer"); // LPVOID *
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsW", 7, "pulOutAuthBufferSize"); // ULONG *
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsW", 8, "pfSave"); // WINBOOL *
	ADD_PARAM_NAME("CredUIPromptForWindowsCredentialsW", 9, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CredUIReadSSOCredW", 1, "pszRealm"); // PCWSTR
	ADD_PARAM_NAME("CredUIReadSSOCredW", 2, "ppszUsername"); // PWSTR *
	ADD_PARAM_NAME("CredUIStoreSSOCredW", 1, "pszRealm"); // PCWSTR
	ADD_PARAM_NAME("CredUIStoreSSOCredW", 2, "pszUsername"); // PCWSTR
	ADD_PARAM_NAME("CredUIStoreSSOCredW", 3, "pszPassword"); // PCWSTR
	ADD_PARAM_NAME("CredUIStoreSSOCredW", 4, "bPersist"); // WINBOOL
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferA", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferA", 2, "pAuthBuffer"); // PVOID
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferA", 3, "cbAuthBuffer"); // DWORD
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferA", 4, "pszUserName"); // LPSTR
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferA", 5, "pcchMaxUserName"); // DWORD *
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferA", 6, "pszDomainName"); // LPSTR
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferA", 7, "pcchMaxDomainame"); // DWORD *
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferA", 8, "pszPassword"); // LPSTR
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferA", 9, "pcchMaxPassword"); // DWORD *
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferW", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferW", 2, "pAuthBuffer"); // PVOID
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferW", 3, "cbAuthBuffer"); // DWORD
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferW", 4, "pszUserName"); // LPWSTR
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferW", 5, "pcchMaxUserName"); // DWORD *
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferW", 6, "pszDomainName"); // LPWSTR
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferW", 7, "pcchMaxDomainame"); // DWORD *
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferW", 8, "pszPassword"); // LPWSTR
	ADD_PARAM_NAME("CredUnPackAuthenticationBufferW", 9, "pcchMaxPassword"); // DWORD *
	ADD_PARAM_NAME("CredUnmarshalCredentialA", 1, "MarshaledCredential"); // LPCSTR
	ADD_PARAM_NAME("CredUnmarshalCredentialA", 2, "CredType"); // PCRED_MARSHAL_TYPE
	ADD_PARAM_NAME("CredUnmarshalCredentialA", 3, "Credential"); // PVOID *
	ADD_PARAM_NAME("CredUnmarshalCredentialW", 1, "MarshaledCredential"); // LPCWSTR
	ADD_PARAM_NAME("CredUnmarshalCredentialW", 2, "CredType"); // PCRED_MARSHAL_TYPE
	ADD_PARAM_NAME("CredUnmarshalCredentialW", 3, "Credential"); // PVOID *
	ADD_PARAM_NAME("CredUnprotectA", 1, "fAsSelf"); // WINBOOL
	ADD_PARAM_NAME("CredUnprotectA", 2, "pszProtectedCredentials"); // LPSTR
	ADD_PARAM_NAME("CredUnprotectA", 3, "cchCredentials"); // DWORD
	ADD_PARAM_NAME("CredUnprotectA", 4, "pszCredentials"); // LPSTR
	ADD_PARAM_NAME("CredUnprotectA", 5, "pcchMaxChars"); // DWORD *
	ADD_PARAM_NAME("CredUnprotectW", 1, "fAsSelf"); // WINBOOL
	ADD_PARAM_NAME("CredUnprotectW", 2, "pszProtectedCredentials"); // LPWSTR
	ADD_PARAM_NAME("CredUnprotectW", 3, "cchCredentials"); // DWORD
	ADD_PARAM_NAME("CredUnprotectW", 4, "pszCredentials"); // LPWSTR
	ADD_PARAM_NAME("CredUnprotectW", 5, "pcchMaxChars"); // DWORD *
	ADD_PARAM_NAME("CredWriteA", 1, "Credential"); // PCREDENTIALA
	ADD_PARAM_NAME("CredWriteA", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("CredWriteDomainCredentialsA", 1, "TargetInfo"); // PCREDENTIAL_TARGET_INFORMATIONA
	ADD_PARAM_NAME("CredWriteDomainCredentialsA", 2, "Credential"); // PCREDENTIALA
	ADD_PARAM_NAME("CredWriteDomainCredentialsA", 3, "Flags"); // DWORD
	ADD_PARAM_NAME("CredWriteDomainCredentialsW", 1, "TargetInfo"); // PCREDENTIAL_TARGET_INFORMATIONW
	ADD_PARAM_NAME("CredWriteDomainCredentialsW", 2, "Credential"); // PCREDENTIALW
	ADD_PARAM_NAME("CredWriteDomainCredentialsW", 3, "Flags"); // DWORD
	ADD_PARAM_NAME("CredWriteW", 1, "Credential"); // PCREDENTIALW
	ADD_PARAM_NAME("CredWriteW", 2, "Flags"); // DWORD
	ADD_PARAM_NAME("CryptAcquireCertificatePrivateKey", 1, "pCert"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CryptAcquireCertificatePrivateKey", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptAcquireCertificatePrivateKey", 3, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptAcquireCertificatePrivateKey", 4, "phCryptProv"); // HCRYPTPROV *
	ADD_PARAM_NAME("CryptAcquireCertificatePrivateKey", 5, "pdwKeySpec"); // DWORD *
	ADD_PARAM_NAME("CryptAcquireCertificatePrivateKey", 6, "pfCallerFreeProv"); // WINBOOL *
	ADD_PARAM_NAME("CryptAcquireContextA", 1, "phProv"); // HCRYPTPROV *
	ADD_PARAM_NAME("CryptAcquireContextA", 2, "szContainer"); // LPCSTR
	ADD_PARAM_NAME("CryptAcquireContextA", 3, "szProvider"); // LPCSTR
	ADD_PARAM_NAME("CryptAcquireContextA", 4, "dwProvType"); // DWORD
	ADD_PARAM_NAME("CryptAcquireContextA", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptAcquireContextW", 1, "phProv"); // HCRYPTPROV *
	ADD_PARAM_NAME("CryptAcquireContextW", 2, "szContainer"); // LPCWSTR
	ADD_PARAM_NAME("CryptAcquireContextW", 3, "szProvider"); // LPCWSTR
	ADD_PARAM_NAME("CryptAcquireContextW", 4, "dwProvType"); // DWORD
	ADD_PARAM_NAME("CryptAcquireContextW", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptBinaryToStringA", 1, "pbBinary"); // CONST BYTE *
	ADD_PARAM_NAME("CryptBinaryToStringA", 2, "cbBinary"); // DWORD
	ADD_PARAM_NAME("CryptBinaryToStringA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptBinaryToStringA", 4, "pszString"); // LPSTR
	ADD_PARAM_NAME("CryptBinaryToStringA", 5, "pcchString"); // DWORD *
	ADD_PARAM_NAME("CryptBinaryToStringW", 1, "pbBinary"); // CONST BYTE *
	ADD_PARAM_NAME("CryptBinaryToStringW", 2, "cbBinary"); // DWORD
	ADD_PARAM_NAME("CryptBinaryToStringW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptBinaryToStringW", 4, "pszString"); // LPWSTR
	ADD_PARAM_NAME("CryptBinaryToStringW", 5, "pcchString"); // DWORD *
	ADD_PARAM_NAME("CryptCancelAsyncRetrieval", 1, "hAsyncRetrieval"); // HCRYPTASYNC
	ADD_PARAM_NAME("CryptCloseAsyncHandle", 1, "hAsync"); // HCRYPTASYNC
	ADD_PARAM_NAME("CryptContextAddRef", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptContextAddRef", 2, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptContextAddRef", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptCreateAsyncHandle", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptCreateAsyncHandle", 2, "phAsync"); // PHCRYPTASYNC
	ADD_PARAM_NAME("CryptCreateHash", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptCreateHash", 2, "Algid"); // ALG_ID
	ADD_PARAM_NAME("CryptCreateHash", 3, "hKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptCreateHash", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptCreateHash", 5, "phHash"); // HCRYPTHASH *
	ADD_PARAM_NAME("CryptCreateKeyIdentifierFromCSP", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptCreateKeyIdentifierFromCSP", 2, "pszPubKeyOID"); // LPCSTR
	ADD_PARAM_NAME("CryptCreateKeyIdentifierFromCSP", 3, "pPubKeyStruc"); // const PUBLICKEYSTRUC *
	ADD_PARAM_NAME("CryptCreateKeyIdentifierFromCSP", 4, "cbPubKeyStruc"); // DWORD
	ADD_PARAM_NAME("CryptCreateKeyIdentifierFromCSP", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptCreateKeyIdentifierFromCSP", 6, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptCreateKeyIdentifierFromCSP", 7, "pbHash"); // BYTE *
	ADD_PARAM_NAME("CryptCreateKeyIdentifierFromCSP", 8, "pcbHash"); // DWORD *
	ADD_PARAM_NAME("CryptDecodeMessage", 1, "dwMsgTypeFlags"); // DWORD
	ADD_PARAM_NAME("CryptDecodeMessage", 2, "pDecryptPara"); // PCRYPT_DECRYPT_MESSAGE_PARA
	ADD_PARAM_NAME("CryptDecodeMessage", 3, "pVerifyPara"); // PCRYPT_VERIFY_MESSAGE_PARA
	ADD_PARAM_NAME("CryptDecodeMessage", 4, "dwSignerIndex"); // DWORD
	ADD_PARAM_NAME("CryptDecodeMessage", 5, "pbEncodedBlob"); // const BYTE *
	ADD_PARAM_NAME("CryptDecodeMessage", 6, "cbEncodedBlob"); // DWORD
	ADD_PARAM_NAME("CryptDecodeMessage", 7, "dwPrevInnerContentType"); // DWORD
	ADD_PARAM_NAME("CryptDecodeMessage", 8, "pdwMsgType"); // DWORD *
	ADD_PARAM_NAME("CryptDecodeMessage", 9, "pdwInnerContentType"); // DWORD *
	ADD_PARAM_NAME("CryptDecodeMessage", 10, "pbDecoded"); // BYTE *
	ADD_PARAM_NAME("CryptDecodeMessage", 11, "pcbDecoded"); // DWORD *
	ADD_PARAM_NAME("CryptDecodeMessage", 12, "ppXchgCert"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CryptDecodeMessage", 13, "ppSignerCert"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CryptDecodeObject", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptDecodeObject", 2, "lpszStructType"); // LPCSTR
	ADD_PARAM_NAME("CryptDecodeObject", 3, "pbEncoded"); // const BYTE *
	ADD_PARAM_NAME("CryptDecodeObject", 4, "cbEncoded"); // DWORD
	ADD_PARAM_NAME("CryptDecodeObject", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptDecodeObject", 6, "pvStructInfo"); // void *
	ADD_PARAM_NAME("CryptDecodeObject", 7, "pcbStructInfo"); // DWORD *
	ADD_PARAM_NAME("CryptDecodeObjectEx", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptDecodeObjectEx", 2, "lpszStructType"); // LPCSTR
	ADD_PARAM_NAME("CryptDecodeObjectEx", 3, "pbEncoded"); // const BYTE *
	ADD_PARAM_NAME("CryptDecodeObjectEx", 4, "cbEncoded"); // DWORD
	ADD_PARAM_NAME("CryptDecodeObjectEx", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptDecodeObjectEx", 6, "pDecodePara"); // PCRYPT_DECODE_PARA
	ADD_PARAM_NAME("CryptDecodeObjectEx", 7, "pvStructInfo"); // void *
	ADD_PARAM_NAME("CryptDecodeObjectEx", 8, "pcbStructInfo"); // DWORD *
	ADD_PARAM_NAME("CryptDecrypt", 1, "hKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptDecrypt", 2, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptDecrypt", 3, "Final"); // WINBOOL
	ADD_PARAM_NAME("CryptDecrypt", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptDecrypt", 5, "pbData"); // BYTE *
	ADD_PARAM_NAME("CryptDecrypt", 6, "pdwDataLen"); // DWORD *
	ADD_PARAM_NAME("CryptDecryptAndVerifyMessageSignature", 1, "pDecryptPara"); // PCRYPT_DECRYPT_MESSAGE_PARA
	ADD_PARAM_NAME("CryptDecryptAndVerifyMessageSignature", 2, "pVerifyPara"); // PCRYPT_VERIFY_MESSAGE_PARA
	ADD_PARAM_NAME("CryptDecryptAndVerifyMessageSignature", 3, "dwSignerIndex"); // DWORD
	ADD_PARAM_NAME("CryptDecryptAndVerifyMessageSignature", 4, "pbEncryptedBlob"); // const BYTE *
	ADD_PARAM_NAME("CryptDecryptAndVerifyMessageSignature", 5, "cbEncryptedBlob"); // DWORD
	ADD_PARAM_NAME("CryptDecryptAndVerifyMessageSignature", 6, "pbDecrypted"); // BYTE *
	ADD_PARAM_NAME("CryptDecryptAndVerifyMessageSignature", 7, "pcbDecrypted"); // DWORD *
	ADD_PARAM_NAME("CryptDecryptAndVerifyMessageSignature", 8, "ppXchgCert"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CryptDecryptAndVerifyMessageSignature", 9, "ppSignerCert"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CryptDecryptMessage", 1, "pDecryptPara"); // PCRYPT_DECRYPT_MESSAGE_PARA
	ADD_PARAM_NAME("CryptDecryptMessage", 2, "pbEncryptedBlob"); // const BYTE *
	ADD_PARAM_NAME("CryptDecryptMessage", 3, "cbEncryptedBlob"); // DWORD
	ADD_PARAM_NAME("CryptDecryptMessage", 4, "pbDecrypted"); // BYTE *
	ADD_PARAM_NAME("CryptDecryptMessage", 5, "pcbDecrypted"); // DWORD *
	ADD_PARAM_NAME("CryptDecryptMessage", 6, "ppXchgCert"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CryptDeriveKey", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptDeriveKey", 2, "Algid"); // ALG_ID
	ADD_PARAM_NAME("CryptDeriveKey", 3, "hBaseData"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptDeriveKey", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptDeriveKey", 5, "phKey"); // HCRYPTKEY *
	ADD_PARAM_NAME("CryptDestroyHash", 1, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptDestroyKey", 1, "hKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptDuplicateHash", 1, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptDuplicateHash", 2, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptDuplicateHash", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptDuplicateHash", 4, "phHash"); // HCRYPTHASH *
	ADD_PARAM_NAME("CryptDuplicateKey", 1, "hKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptDuplicateKey", 2, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptDuplicateKey", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptDuplicateKey", 4, "phKey"); // HCRYPTKEY *
	ADD_PARAM_NAME("CryptEncodeObject", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptEncodeObject", 2, "lpszStructType"); // LPCSTR
	ADD_PARAM_NAME("CryptEncodeObject", 3, "pvStructInfo"); // const void *
	ADD_PARAM_NAME("CryptEncodeObject", 4, "pbEncoded"); // BYTE *
	ADD_PARAM_NAME("CryptEncodeObject", 5, "pcbEncoded"); // DWORD *
	ADD_PARAM_NAME("CryptEncodeObjectEx", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptEncodeObjectEx", 2, "lpszStructType"); // LPCSTR
	ADD_PARAM_NAME("CryptEncodeObjectEx", 3, "pvStructInfo"); // const void *
	ADD_PARAM_NAME("CryptEncodeObjectEx", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptEncodeObjectEx", 5, "pEncodePara"); // PCRYPT_ENCODE_PARA
	ADD_PARAM_NAME("CryptEncodeObjectEx", 6, "pvEncoded"); // void *
	ADD_PARAM_NAME("CryptEncodeObjectEx", 7, "pcbEncoded"); // DWORD *
	ADD_PARAM_NAME("CryptEncrypt", 1, "hKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptEncrypt", 2, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptEncrypt", 3, "Final"); // WINBOOL
	ADD_PARAM_NAME("CryptEncrypt", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptEncrypt", 5, "pbData"); // BYTE *
	ADD_PARAM_NAME("CryptEncrypt", 6, "pdwDataLen"); // DWORD *
	ADD_PARAM_NAME("CryptEncrypt", 7, "dwBufLen"); // DWORD
	ADD_PARAM_NAME("CryptEncryptMessage", 1, "pEncryptPara"); // PCRYPT_ENCRYPT_MESSAGE_PARA
	ADD_PARAM_NAME("CryptEncryptMessage", 2, "cRecipientCert"); // DWORD
	ADD_PARAM_NAME("CryptEncryptMessage", 3, "rgpRecipientCert"); // PCCERT_CONTEXT []
	ADD_PARAM_NAME("CryptEncryptMessage", 4, "pbToBeEncrypted"); // const BYTE *
	ADD_PARAM_NAME("CryptEncryptMessage", 5, "cbToBeEncrypted"); // DWORD
	ADD_PARAM_NAME("CryptEncryptMessage", 6, "pbEncryptedBlob"); // BYTE *
	ADD_PARAM_NAME("CryptEncryptMessage", 7, "pcbEncryptedBlob"); // DWORD *
	ADD_PARAM_NAME("CryptEnumKeyIdentifierProperties", 1, "pKeyIdentifier"); // const CRYPT_HASH_BLOB *
	ADD_PARAM_NAME("CryptEnumKeyIdentifierProperties", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CryptEnumKeyIdentifierProperties", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptEnumKeyIdentifierProperties", 4, "pwszComputerName"); // LPCWSTR
	ADD_PARAM_NAME("CryptEnumKeyIdentifierProperties", 5, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptEnumKeyIdentifierProperties", 6, "pvArg"); // void *
	ADD_PARAM_NAME("CryptEnumKeyIdentifierProperties", 7, "pfnEnum"); // PFN_CRYPT_ENUM_KEYID_PROP
	ADD_PARAM_NAME("CryptEnumOIDFunction", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptEnumOIDFunction", 2, "pszFuncName"); // LPCSTR
	ADD_PARAM_NAME("CryptEnumOIDFunction", 3, "pszOID"); // LPCSTR
	ADD_PARAM_NAME("CryptEnumOIDFunction", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptEnumOIDFunction", 5, "pvArg"); // void *
	ADD_PARAM_NAME("CryptEnumOIDFunction", 6, "pfnEnumOIDFunc"); // PFN_CRYPT_ENUM_OID_FUNC
	ADD_PARAM_NAME("CryptEnumOIDInfo", 1, "dwGroupId"); // DWORD
	ADD_PARAM_NAME("CryptEnumOIDInfo", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptEnumOIDInfo", 3, "pvArg"); // void *
	ADD_PARAM_NAME("CryptEnumOIDInfo", 4, "pfnEnumOIDInfo"); // PFN_CRYPT_ENUM_OID_INFO
	ADD_PARAM_NAME("CryptEnumProviderTypesA", 1, "dwIndex"); // DWORD
	ADD_PARAM_NAME("CryptEnumProviderTypesA", 2, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProviderTypesA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptEnumProviderTypesA", 4, "pdwProvType"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProviderTypesA", 5, "szTypeName"); // LPSTR
	ADD_PARAM_NAME("CryptEnumProviderTypesA", 6, "pcbTypeName"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProviderTypesW", 1, "dwIndex"); // DWORD
	ADD_PARAM_NAME("CryptEnumProviderTypesW", 2, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProviderTypesW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptEnumProviderTypesW", 4, "pdwProvType"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProviderTypesW", 5, "szTypeName"); // LPWSTR
	ADD_PARAM_NAME("CryptEnumProviderTypesW", 6, "pcbTypeName"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProvidersA", 1, "dwIndex"); // DWORD
	ADD_PARAM_NAME("CryptEnumProvidersA", 2, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProvidersA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptEnumProvidersA", 4, "pdwProvType"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProvidersA", 5, "szProvName"); // LPSTR
	ADD_PARAM_NAME("CryptEnumProvidersA", 6, "pcbProvName"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProvidersW", 1, "dwIndex"); // DWORD
	ADD_PARAM_NAME("CryptEnumProvidersW", 2, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProvidersW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptEnumProvidersW", 4, "pdwProvType"); // DWORD *
	ADD_PARAM_NAME("CryptEnumProvidersW", 5, "szProvName"); // LPWSTR
	ADD_PARAM_NAME("CryptEnumProvidersW", 6, "pcbProvName"); // DWORD *
	ADD_PARAM_NAME("CryptExportKey", 1, "hKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptExportKey", 2, "hExpKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptExportKey", 3, "dwBlobType"); // DWORD
	ADD_PARAM_NAME("CryptExportKey", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptExportKey", 5, "pbData"); // BYTE *
	ADD_PARAM_NAME("CryptExportKey", 6, "pdwDataLen"); // DWORD *
	ADD_PARAM_NAME("CryptExportPKCS8", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptExportPKCS8", 2, "dwKeySpec"); // DWORD
	ADD_PARAM_NAME("CryptExportPKCS8", 3, "pszPrivateKeyObjId"); // LPSTR
	ADD_PARAM_NAME("CryptExportPKCS8", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptExportPKCS8", 5, "pvAuxInfo"); // void *
	ADD_PARAM_NAME("CryptExportPKCS8", 6, "pbPrivateKeyBlob"); // BYTE *
	ADD_PARAM_NAME("CryptExportPKCS8", 7, "pcbPrivateKeyBlob"); // DWORD *
	ADD_PARAM_NAME("CryptExportPKCS8Ex", 1, "psExportParams"); // CRYPT_PKCS8_EXPORT_PARAMS *
	ADD_PARAM_NAME("CryptExportPKCS8Ex", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptExportPKCS8Ex", 3, "pvAuxInfo"); // void *
	ADD_PARAM_NAME("CryptExportPKCS8Ex", 4, "pbPrivateKeyBlob"); // BYTE *
	ADD_PARAM_NAME("CryptExportPKCS8Ex", 5, "pcbPrivateKeyBlob"); // DWORD *
	ADD_PARAM_NAME("CryptExportPublicKeyInfo", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptExportPublicKeyInfo", 2, "dwKeySpec"); // DWORD
	ADD_PARAM_NAME("CryptExportPublicKeyInfo", 3, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptExportPublicKeyInfo", 4, "pInfo"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CryptExportPublicKeyInfo", 5, "pcbInfo"); // DWORD *
	ADD_PARAM_NAME("CryptExportPublicKeyInfoEx", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptExportPublicKeyInfoEx", 2, "dwKeySpec"); // DWORD
	ADD_PARAM_NAME("CryptExportPublicKeyInfoEx", 3, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptExportPublicKeyInfoEx", 4, "pszPublicKeyObjId"); // LPSTR
	ADD_PARAM_NAME("CryptExportPublicKeyInfoEx", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptExportPublicKeyInfoEx", 6, "pvAuxInfo"); // void *
	ADD_PARAM_NAME("CryptExportPublicKeyInfoEx", 7, "pInfo"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CryptExportPublicKeyInfoEx", 8, "pcbInfo"); // DWORD *
	ADD_PARAM_NAME("CryptExportPublicKeyInfoFromBCryptKeyHandle", 1, "hBCryptKey"); // BCRYPT_KEY_HANDLE
	ADD_PARAM_NAME("CryptExportPublicKeyInfoFromBCryptKeyHandle", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptExportPublicKeyInfoFromBCryptKeyHandle", 3, "pszPublicKeyObjId"); // LPSTR
	ADD_PARAM_NAME("CryptExportPublicKeyInfoFromBCryptKeyHandle", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptExportPublicKeyInfoFromBCryptKeyHandle", 5, "pvAuxInfo"); // PVOID
	ADD_PARAM_NAME("CryptExportPublicKeyInfoFromBCryptKeyHandle", 6, "pInfo"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CryptExportPublicKeyInfoFromBCryptKeyHandle", 7, "pcbInfo"); // DWORD
	ADD_PARAM_NAME("CryptFindCertificateKeyProvInfo", 1, "pCert"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CryptFindCertificateKeyProvInfo", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptFindCertificateKeyProvInfo", 3, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptFindLocalizedName", 1, "pwszCryptName"); // LPCWSTR
	ADD_PARAM_NAME("CryptFindOIDInfo", 1, "dwKeyType"); // DWORD
	ADD_PARAM_NAME("CryptFindOIDInfo", 2, "pvKey"); // void *
	ADD_PARAM_NAME("CryptFindOIDInfo", 3, "dwGroupId"); // DWORD
	ADD_PARAM_NAME("CryptFlushTimeValidObject", 1, "pszFlushTimeValidOid"); // LPCSTR
	ADD_PARAM_NAME("CryptFlushTimeValidObject", 2, "pvPara"); // LPVOID
	ADD_PARAM_NAME("CryptFlushTimeValidObject", 3, "pIssuer"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CryptFlushTimeValidObject", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptFlushTimeValidObject", 5, "pvReserved"); // LPVOID
	ADD_PARAM_NAME("CryptFormatObject", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptFormatObject", 2, "dwFormatType"); // DWORD
	ADD_PARAM_NAME("CryptFormatObject", 3, "dwFormatStrType"); // DWORD
	ADD_PARAM_NAME("CryptFormatObject", 4, "pFormatStruct"); // void *
	ADD_PARAM_NAME("CryptFormatObject", 5, "lpszStructType"); // LPCSTR
	ADD_PARAM_NAME("CryptFormatObject", 6, "pbEncoded"); // const BYTE *
	ADD_PARAM_NAME("CryptFormatObject", 7, "cbEncoded"); // DWORD
	ADD_PARAM_NAME("CryptFormatObject", 8, "pbFormat"); // void *
	ADD_PARAM_NAME("CryptFormatObject", 9, "pcbFormat"); // DWORD *
	ADD_PARAM_NAME("CryptFreeOIDFunctionAddress", 1, "hFuncAddr"); // HCRYPTOIDFUNCADDR
	ADD_PARAM_NAME("CryptFreeOIDFunctionAddress", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGenKey", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptGenKey", 2, "Algid"); // ALG_ID
	ADD_PARAM_NAME("CryptGenKey", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGenKey", 4, "phKey"); // HCRYPTKEY *
	ADD_PARAM_NAME("CryptGenRandom", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptGenRandom", 2, "dwLen"); // DWORD
	ADD_PARAM_NAME("CryptGenRandom", 3, "pbBuffer"); // BYTE *
	ADD_PARAM_NAME("CryptGetAsyncParam", 1, "hAsync"); // HCRYPTASYNC
	ADD_PARAM_NAME("CryptGetAsyncParam", 2, "pszParamOid"); // LPSTR
	ADD_PARAM_NAME("CryptGetAsyncParam", 3, "ppvParam"); // LPVOID *
	ADD_PARAM_NAME("CryptGetAsyncParam", 4, "ppfnFree"); // PFN_CRYPT_ASYNC_PARAM_FREE_FUNC *
	ADD_PARAM_NAME("CryptGetDefaultOIDDllList", 1, "hFuncSet"); // HCRYPTOIDFUNCSET
	ADD_PARAM_NAME("CryptGetDefaultOIDDllList", 2, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptGetDefaultOIDDllList", 3, "pwszDllList"); // LPWSTR
	ADD_PARAM_NAME("CryptGetDefaultOIDDllList", 4, "pcchDllList"); // DWORD *
	ADD_PARAM_NAME("CryptGetDefaultOIDFunctionAddress", 1, "hFuncSet"); // HCRYPTOIDFUNCSET
	ADD_PARAM_NAME("CryptGetDefaultOIDFunctionAddress", 2, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptGetDefaultOIDFunctionAddress", 3, "pwszDll"); // LPCWSTR
	ADD_PARAM_NAME("CryptGetDefaultOIDFunctionAddress", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetDefaultOIDFunctionAddress", 5, "ppvFuncAddr"); // void * *
	ADD_PARAM_NAME("CryptGetDefaultOIDFunctionAddress", 6, "phFuncAddr"); // HCRYPTOIDFUNCADDR *
	ADD_PARAM_NAME("CryptGetDefaultProviderA", 1, "dwProvType"); // DWORD
	ADD_PARAM_NAME("CryptGetDefaultProviderA", 2, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptGetDefaultProviderA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetDefaultProviderA", 4, "pszProvName"); // LPSTR
	ADD_PARAM_NAME("CryptGetDefaultProviderA", 5, "pcbProvName"); // DWORD *
	ADD_PARAM_NAME("CryptGetDefaultProviderW", 1, "dwProvType"); // DWORD
	ADD_PARAM_NAME("CryptGetDefaultProviderW", 2, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptGetDefaultProviderW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetDefaultProviderW", 4, "pszProvName"); // LPWSTR
	ADD_PARAM_NAME("CryptGetDefaultProviderW", 5, "pcbProvName"); // DWORD *
	ADD_PARAM_NAME("CryptGetHashParam", 1, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptGetHashParam", 2, "dwParam"); // DWORD
	ADD_PARAM_NAME("CryptGetHashParam", 3, "pbData"); // BYTE *
	ADD_PARAM_NAME("CryptGetHashParam", 4, "pdwDataLen"); // DWORD *
	ADD_PARAM_NAME("CryptGetHashParam", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetKeyIdentifierProperty", 1, "pKeyIdentifier"); // const CRYPT_HASH_BLOB *
	ADD_PARAM_NAME("CryptGetKeyIdentifierProperty", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CryptGetKeyIdentifierProperty", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetKeyIdentifierProperty", 4, "pwszComputerName"); // LPCWSTR
	ADD_PARAM_NAME("CryptGetKeyIdentifierProperty", 5, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptGetKeyIdentifierProperty", 6, "pvData"); // void *
	ADD_PARAM_NAME("CryptGetKeyIdentifierProperty", 7, "pcbData"); // DWORD *
	ADD_PARAM_NAME("CryptGetKeyParam", 1, "hKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptGetKeyParam", 2, "dwParam"); // DWORD
	ADD_PARAM_NAME("CryptGetKeyParam", 3, "pbData"); // BYTE *
	ADD_PARAM_NAME("CryptGetKeyParam", 4, "pdwDataLen"); // DWORD *
	ADD_PARAM_NAME("CryptGetKeyParam", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetMessageCertificates", 1, "dwMsgAndCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptGetMessageCertificates", 2, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptGetMessageCertificates", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetMessageCertificates", 4, "pbSignedBlob"); // const BYTE *
	ADD_PARAM_NAME("CryptGetMessageCertificates", 5, "cbSignedBlob"); // DWORD
	ADD_PARAM_NAME("CryptGetMessageSignerCount", 1, "dwMsgEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptGetMessageSignerCount", 2, "pbSignedBlob"); // const BYTE *
	ADD_PARAM_NAME("CryptGetMessageSignerCount", 3, "cbSignedBlob"); // DWORD
	ADD_PARAM_NAME("CryptGetOIDFunctionAddress", 1, "hFuncSet"); // HCRYPTOIDFUNCSET
	ADD_PARAM_NAME("CryptGetOIDFunctionAddress", 2, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptGetOIDFunctionAddress", 3, "pszOID"); // LPCSTR
	ADD_PARAM_NAME("CryptGetOIDFunctionAddress", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetOIDFunctionAddress", 5, "ppvFuncAddr"); // void * *
	ADD_PARAM_NAME("CryptGetOIDFunctionAddress", 6, "phFuncAddr"); // HCRYPTOIDFUNCADDR *
	ADD_PARAM_NAME("CryptGetOIDFunctionValue", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptGetOIDFunctionValue", 2, "pszFuncName"); // LPCSTR
	ADD_PARAM_NAME("CryptGetOIDFunctionValue", 3, "pszOID"); // LPCSTR
	ADD_PARAM_NAME("CryptGetOIDFunctionValue", 4, "pwszValueName"); // LPCWSTR
	ADD_PARAM_NAME("CryptGetOIDFunctionValue", 5, "pdwValueType"); // DWORD *
	ADD_PARAM_NAME("CryptGetOIDFunctionValue", 6, "pbValueData"); // BYTE *
	ADD_PARAM_NAME("CryptGetOIDFunctionValue", 7, "pcbValueData"); // DWORD *
	ADD_PARAM_NAME("CryptGetObjectUrl", 1, "pszUrlOid"); // LPCSTR
	ADD_PARAM_NAME("CryptGetObjectUrl", 2, "pvPara"); // LPVOID
	ADD_PARAM_NAME("CryptGetObjectUrl", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetObjectUrl", 4, "pUrlArray"); // PCRYPT_URL_ARRAY
	ADD_PARAM_NAME("CryptGetObjectUrl", 5, "pcbUrlArray"); // DWORD *
	ADD_PARAM_NAME("CryptGetObjectUrl", 6, "pUrlInfo"); // PCRYPT_URL_INFO
	ADD_PARAM_NAME("CryptGetObjectUrl", 7, "pcbUrlInfo"); // DWORD *
	ADD_PARAM_NAME("CryptGetObjectUrl", 8, "pvReserved"); // LPVOID
	ADD_PARAM_NAME("CryptGetProvParam", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptGetProvParam", 2, "dwParam"); // DWORD
	ADD_PARAM_NAME("CryptGetProvParam", 3, "pbData"); // BYTE *
	ADD_PARAM_NAME("CryptGetProvParam", 4, "pdwDataLen"); // DWORD *
	ADD_PARAM_NAME("CryptGetProvParam", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetTimeValidObject", 1, "pszTimeValidOid"); // LPCSTR
	ADD_PARAM_NAME("CryptGetTimeValidObject", 2, "pvPara"); // LPVOID
	ADD_PARAM_NAME("CryptGetTimeValidObject", 3, "pIssuer"); // PCCERT_CONTEXT
	ADD_PARAM_NAME("CryptGetTimeValidObject", 4, "pftValidFor"); // LPFILETIME
	ADD_PARAM_NAME("CryptGetTimeValidObject", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptGetTimeValidObject", 6, "dwTimeout"); // DWORD
	ADD_PARAM_NAME("CryptGetTimeValidObject", 7, "ppvObject"); // LPVOID *
	ADD_PARAM_NAME("CryptGetTimeValidObject", 8, "pCredentials"); // PCRYPT_CREDENTIALS
	ADD_PARAM_NAME("CryptGetTimeValidObject", 9, "pvReserved"); // LPVOID
	ADD_PARAM_NAME("CryptGetUserKey", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptGetUserKey", 2, "dwKeySpec"); // DWORD
	ADD_PARAM_NAME("CryptGetUserKey", 3, "phUserKey"); // HCRYPTKEY *
	ADD_PARAM_NAME("CryptHashCertificate", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptHashCertificate", 2, "Algid"); // ALG_ID
	ADD_PARAM_NAME("CryptHashCertificate", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptHashCertificate", 4, "pbEncoded"); // const BYTE *
	ADD_PARAM_NAME("CryptHashCertificate", 5, "cbEncoded"); // DWORD
	ADD_PARAM_NAME("CryptHashCertificate", 6, "pbComputedHash"); // BYTE *
	ADD_PARAM_NAME("CryptHashCertificate", 7, "pcbComputedHash"); // DWORD *
	ADD_PARAM_NAME("CryptHashCertificate2", 1, "pwszCNGHashAlgid"); // LPCWSTR
	ADD_PARAM_NAME("CryptHashCertificate2", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptHashCertificate2", 3, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptHashCertificate2", 4, "pbEncoded"); // BYTE *
	ADD_PARAM_NAME("CryptHashCertificate2", 5, "cbEncoded"); // DWORD
	ADD_PARAM_NAME("CryptHashCertificate2", 6, "pbComputedHash"); // BYTE *
	ADD_PARAM_NAME("CryptHashCertificate2", 7, "pcbComputedHash"); // DWORD *
	ADD_PARAM_NAME("CryptHashData", 1, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptHashData", 2, "pbData"); // CONST BYTE *
	ADD_PARAM_NAME("CryptHashData", 3, "dwDataLen"); // DWORD
	ADD_PARAM_NAME("CryptHashData", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptHashMessage", 1, "pHashPara"); // PCRYPT_HASH_MESSAGE_PARA
	ADD_PARAM_NAME("CryptHashMessage", 2, "fDetachedHash"); // WINBOOL
	ADD_PARAM_NAME("CryptHashMessage", 3, "cToBeHashed"); // DWORD
	ADD_PARAM_NAME("CryptHashMessage", 4, "rgpbToBeHashed"); // const BYTE * []
	ADD_PARAM_NAME("CryptHashMessage", 5, "rgcbToBeHashed"); // DWORD []
	ADD_PARAM_NAME("CryptHashMessage", 6, "pbHashedBlob"); // BYTE *
	ADD_PARAM_NAME("CryptHashMessage", 7, "pcbHashedBlob"); // DWORD *
	ADD_PARAM_NAME("CryptHashMessage", 8, "pbComputedHash"); // BYTE *
	ADD_PARAM_NAME("CryptHashMessage", 9, "pcbComputedHash"); // DWORD *
	ADD_PARAM_NAME("CryptHashPublicKeyInfo", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptHashPublicKeyInfo", 2, "Algid"); // ALG_ID
	ADD_PARAM_NAME("CryptHashPublicKeyInfo", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptHashPublicKeyInfo", 4, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptHashPublicKeyInfo", 5, "pInfo"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CryptHashPublicKeyInfo", 6, "pbComputedHash"); // BYTE *
	ADD_PARAM_NAME("CryptHashPublicKeyInfo", 7, "pcbComputedHash"); // DWORD *
	ADD_PARAM_NAME("CryptHashSessionKey", 1, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptHashSessionKey", 2, "hKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptHashSessionKey", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptHashToBeSigned", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptHashToBeSigned", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptHashToBeSigned", 3, "pbEncoded"); // const BYTE *
	ADD_PARAM_NAME("CryptHashToBeSigned", 4, "cbEncoded"); // DWORD
	ADD_PARAM_NAME("CryptHashToBeSigned", 5, "pbComputedHash"); // BYTE *
	ADD_PARAM_NAME("CryptHashToBeSigned", 6, "pcbComputedHash"); // DWORD *
	ADD_PARAM_NAME("CryptImportKey", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptImportKey", 2, "pbData"); // CONST BYTE *
	ADD_PARAM_NAME("CryptImportKey", 3, "dwDataLen"); // DWORD
	ADD_PARAM_NAME("CryptImportKey", 4, "hPubKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptImportKey", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptImportKey", 6, "phKey"); // HCRYPTKEY *
	ADD_PARAM_NAME("CryptImportPKCS8", 1, "sImportParams"); // CRYPT_PKCS8_IMPORT_PARAMS
	ADD_PARAM_NAME("CryptImportPKCS8", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptImportPKCS8", 3, "phCryptProv"); // HCRYPTPROV *
	ADD_PARAM_NAME("CryptImportPKCS8", 4, "pvAuxInfo"); // void *
	ADD_PARAM_NAME("CryptImportPublicKeyInfo", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptImportPublicKeyInfo", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptImportPublicKeyInfo", 3, "pInfo"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CryptImportPublicKeyInfo", 4, "phKey"); // HCRYPTKEY *
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx", 3, "pInfo"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx", 4, "aiKeyAlg"); // ALG_ID
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx", 6, "pvAuxInfo"); // void *
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx", 7, "phKey"); // HCRYPTKEY *
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx2", 1, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx2", 2, "pInfo"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx2", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx2", 4, "pvAuxInfo"); // void *
	ADD_PARAM_NAME("CryptImportPublicKeyInfoEx2", 5, "phKey"); // BCRYPT_KEY_HANDLE *
	ADD_PARAM_NAME("CryptInitOIDFunctionSet", 1, "pszFuncName"); // LPCSTR
	ADD_PARAM_NAME("CryptInitOIDFunctionSet", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptInstallCancelRetrieval", 1, "pfnCancel"); // PFN_CRYPT_CANCEL_RETRIEVAL
	ADD_PARAM_NAME("CryptInstallCancelRetrieval", 2, "pvArg"); // const void *
	ADD_PARAM_NAME("CryptInstallCancelRetrieval", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptInstallCancelRetrieval", 4, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptInstallDefaultContext", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptInstallDefaultContext", 2, "dwDefaultType"); // DWORD
	ADD_PARAM_NAME("CryptInstallDefaultContext", 3, "pvDefaultPara"); // const void *
	ADD_PARAM_NAME("CryptInstallDefaultContext", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptInstallDefaultContext", 5, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptInstallDefaultContext", 6, "phDefaultContext"); // HCRYPTDEFAULTCONTEXT *
	ADD_PARAM_NAME("CryptInstallOIDFunctionAddress", 1, "hModule"); // HMODULE
	ADD_PARAM_NAME("CryptInstallOIDFunctionAddress", 2, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptInstallOIDFunctionAddress", 3, "pszFuncName"); // LPCSTR
	ADD_PARAM_NAME("CryptInstallOIDFunctionAddress", 4, "cFuncEntry"); // DWORD
	ADD_PARAM_NAME("CryptInstallOIDFunctionAddress", 5, "rgFuncEntry"); // const CRYPT_OID_FUNC_ENTRY []
	ADD_PARAM_NAME("CryptInstallOIDFunctionAddress", 6, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptMemAlloc", 1, "cbSize"); // ULONG
	ADD_PARAM_NAME("CryptMemFree", 1, "pv"); // LPVOID
	ADD_PARAM_NAME("CryptMemRealloc", 1, "pv"); // LPVOID
	ADD_PARAM_NAME("CryptMemRealloc", 2, "cbSize"); // ULONG
	ADD_PARAM_NAME("CryptMsgCalculateEncodedLength", 1, "dwMsgEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptMsgCalculateEncodedLength", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptMsgCalculateEncodedLength", 3, "dwMsgType"); // DWORD
	ADD_PARAM_NAME("CryptMsgCalculateEncodedLength", 4, "pvMsgEncodeInfo"); // void const *
	ADD_PARAM_NAME("CryptMsgCalculateEncodedLength", 5, "pszInnerContentObjID"); // LPSTR
	ADD_PARAM_NAME("CryptMsgCalculateEncodedLength", 6, "cbData"); // DWORD
	ADD_PARAM_NAME("CryptMsgClose", 1, "hCryptMsg"); // HCRYPTMSG
	ADD_PARAM_NAME("CryptMsgControl", 1, "hCryptMsg"); // HCRYPTMSG
	ADD_PARAM_NAME("CryptMsgControl", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptMsgControl", 3, "dwCtrlType"); // DWORD
	ADD_PARAM_NAME("CryptMsgControl", 4, "pvCtrlPara"); // void const *
	ADD_PARAM_NAME("CryptMsgCountersign", 1, "hCryptMsg"); // HCRYPTMSG
	ADD_PARAM_NAME("CryptMsgCountersign", 2, "dwIndex"); // DWORD
	ADD_PARAM_NAME("CryptMsgCountersign", 3, "cCountersigners"); // DWORD
	ADD_PARAM_NAME("CryptMsgCountersign", 4, "rgCountersigners"); // PCMSG_SIGNER_ENCODE_INFO
	ADD_PARAM_NAME("CryptMsgCountersignEncoded", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptMsgCountersignEncoded", 2, "pbSignerInfo"); // PBYTE
	ADD_PARAM_NAME("CryptMsgCountersignEncoded", 3, "cbSignerInfo"); // DWORD
	ADD_PARAM_NAME("CryptMsgCountersignEncoded", 4, "cCountersigners"); // DWORD
	ADD_PARAM_NAME("CryptMsgCountersignEncoded", 5, "rgCountersigners"); // PCMSG_SIGNER_ENCODE_INFO
	ADD_PARAM_NAME("CryptMsgCountersignEncoded", 6, "pbCountersignature"); // PBYTE
	ADD_PARAM_NAME("CryptMsgCountersignEncoded", 7, "pcbCountersignature"); // PDWORD
	ADD_PARAM_NAME("CryptMsgDuplicate", 1, "hCryptMsg"); // HCRYPTMSG
	ADD_PARAM_NAME("CryptMsgEncodeAndSignCTL", 1, "dwMsgEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptMsgEncodeAndSignCTL", 2, "pCtlInfo"); // PCTL_INFO
	ADD_PARAM_NAME("CryptMsgEncodeAndSignCTL", 3, "pSignInfo"); // PCMSG_SIGNED_ENCODE_INFO
	ADD_PARAM_NAME("CryptMsgEncodeAndSignCTL", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptMsgEncodeAndSignCTL", 5, "pbEncoded"); // BYTE *
	ADD_PARAM_NAME("CryptMsgEncodeAndSignCTL", 6, "pcbEncoded"); // DWORD *
	ADD_PARAM_NAME("CryptMsgGetAndVerifySigner", 1, "hCryptMsg"); // HCRYPTMSG
	ADD_PARAM_NAME("CryptMsgGetAndVerifySigner", 2, "cSignerStore"); // DWORD
	ADD_PARAM_NAME("CryptMsgGetAndVerifySigner", 3, "rghSignerStore"); // HCERTSTORE *
	ADD_PARAM_NAME("CryptMsgGetAndVerifySigner", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptMsgGetAndVerifySigner", 5, "ppSigner"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CryptMsgGetAndVerifySigner", 6, "pdwSignerIndex"); // DWORD *
	ADD_PARAM_NAME("CryptMsgGetParam", 1, "hCryptMsg"); // HCRYPTMSG
	ADD_PARAM_NAME("CryptMsgGetParam", 2, "dwParamType"); // DWORD
	ADD_PARAM_NAME("CryptMsgGetParam", 3, "dwIndex"); // DWORD
	ADD_PARAM_NAME("CryptMsgGetParam", 4, "pvData"); // void *
	ADD_PARAM_NAME("CryptMsgGetParam", 5, "pcbData"); // DWORD *
	ADD_PARAM_NAME("CryptMsgOpenToDecode", 1, "dwMsgEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptMsgOpenToDecode", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptMsgOpenToDecode", 3, "dwMsgType"); // DWORD
	ADD_PARAM_NAME("CryptMsgOpenToDecode", 4, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptMsgOpenToDecode", 5, "pRecipientInfo"); // PCERT_INFO
	ADD_PARAM_NAME("CryptMsgOpenToDecode", 6, "pStreamInfo"); // PCMSG_STREAM_INFO
	ADD_PARAM_NAME("CryptMsgOpenToEncode", 1, "dwMsgEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptMsgOpenToEncode", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptMsgOpenToEncode", 3, "dwMsgType"); // DWORD
	ADD_PARAM_NAME("CryptMsgOpenToEncode", 4, "pvMsgEncodeInfo"); // void const *
	ADD_PARAM_NAME("CryptMsgOpenToEncode", 5, "pszInnerContentObjID"); // LPSTR
	ADD_PARAM_NAME("CryptMsgOpenToEncode", 6, "pStreamInfo"); // PCMSG_STREAM_INFO
	ADD_PARAM_NAME("CryptMsgSignCTL", 1, "dwMsgEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptMsgSignCTL", 2, "pbCtlContent"); // BYTE *
	ADD_PARAM_NAME("CryptMsgSignCTL", 3, "cbCtlContent"); // DWORD
	ADD_PARAM_NAME("CryptMsgSignCTL", 4, "pSignInfo"); // PCMSG_SIGNED_ENCODE_INFO
	ADD_PARAM_NAME("CryptMsgSignCTL", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptMsgSignCTL", 6, "pbEncoded"); // BYTE *
	ADD_PARAM_NAME("CryptMsgSignCTL", 7, "pcbEncoded"); // DWORD *
	ADD_PARAM_NAME("CryptMsgUpdate", 1, "hCryptMsg"); // HCRYPTMSG
	ADD_PARAM_NAME("CryptMsgUpdate", 2, "pbData"); // const BYTE *
	ADD_PARAM_NAME("CryptMsgUpdate", 3, "cbData"); // DWORD
	ADD_PARAM_NAME("CryptMsgUpdate", 4, "fFinal"); // WINBOOL
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncoded", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncoded", 2, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncoded", 3, "pbSignerInfo"); // PBYTE
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncoded", 4, "cbSignerInfo"); // DWORD
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncoded", 5, "pbSignerInfoCountersignature"); // PBYTE
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncoded", 6, "cbSignerInfoCountersignature"); // DWORD
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncoded", 7, "pciCountersigner"); // PCERT_INFO
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncodedEx", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncodedEx", 2, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncodedEx", 3, "pbSignerInfo"); // PBYTE
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncodedEx", 4, "cbSignerInfo"); // DWORD
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncodedEx", 5, "pbSignerInfoCountersignature"); // PBYTE
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncodedEx", 6, "cbSignerInfoCountersignature"); // DWORD
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncodedEx", 7, "dwSignerType"); // DWORD
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncodedEx", 8, "pvSigner"); // void *
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncodedEx", 9, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptMsgVerifyCountersignatureEncodedEx", 10, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptProtectData", 1, "pDataIn"); // DATA_BLOB *
	ADD_PARAM_NAME("CryptProtectData", 2, "szDataDescr"); // LPCWSTR
	ADD_PARAM_NAME("CryptProtectData", 3, "pOptionalEntropy"); // DATA_BLOB *
	ADD_PARAM_NAME("CryptProtectData", 4, "pvReserved"); // PVOID
	ADD_PARAM_NAME("CryptProtectData", 5, "pPromptStruct"); // CRYPTPROTECT_PROMPTSTRUCT *
	ADD_PARAM_NAME("CryptProtectData", 6, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptProtectData", 7, "pDataOut"); // DATA_BLOB *
	ADD_PARAM_NAME("CryptProtectMemory", 1, "pDataIn"); // LPVOID
	ADD_PARAM_NAME("CryptProtectMemory", 2, "cbDataIn"); // DWORD
	ADD_PARAM_NAME("CryptProtectMemory", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptQueryObject", 1, "dwObjectType"); // DWORD
	ADD_PARAM_NAME("CryptQueryObject", 2, "pvObject"); // const void *
	ADD_PARAM_NAME("CryptQueryObject", 3, "dwExpectedContentTypeFlags"); // DWORD
	ADD_PARAM_NAME("CryptQueryObject", 4, "dwExpectedFormatTypeFlags"); // DWORD
	ADD_PARAM_NAME("CryptQueryObject", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptQueryObject", 6, "pdwMsgAndCertEncodingType"); // DWORD *
	ADD_PARAM_NAME("CryptQueryObject", 7, "pdwContentType"); // DWORD *
	ADD_PARAM_NAME("CryptQueryObject", 8, "pdwFormatType"); // DWORD *
	ADD_PARAM_NAME("CryptQueryObject", 9, "phCertStore"); // HCERTSTORE *
	ADD_PARAM_NAME("CryptQueryObject", 10, "phMsg"); // HCRYPTMSG *
	ADD_PARAM_NAME("CryptQueryObject", 11, "ppvContext"); // const void * *
	ADD_PARAM_NAME("CryptRegisterDefaultOIDFunction", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptRegisterDefaultOIDFunction", 2, "pszFuncName"); // LPCSTR
	ADD_PARAM_NAME("CryptRegisterDefaultOIDFunction", 3, "dwIndex"); // DWORD
	ADD_PARAM_NAME("CryptRegisterDefaultOIDFunction", 4, "pwszDll"); // LPCWSTR
	ADD_PARAM_NAME("CryptRegisterOIDFunction", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptRegisterOIDFunction", 2, "pszFuncName"); // LPCSTR
	ADD_PARAM_NAME("CryptRegisterOIDFunction", 3, "pszOID"); // LPCSTR
	ADD_PARAM_NAME("CryptRegisterOIDFunction", 4, "pwszDll"); // LPCWSTR
	ADD_PARAM_NAME("CryptRegisterOIDFunction", 5, "pszOverrideFuncName"); // LPCSTR
	ADD_PARAM_NAME("CryptRegisterOIDInfo", 1, "pInfo"); // PCCRYPT_OID_INFO
	ADD_PARAM_NAME("CryptRegisterOIDInfo", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptReleaseContext", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptReleaseContext", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlA", 1, "pszUrl"); // LPCSTR
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlA", 2, "pszObjectOid"); // LPCSTR
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlA", 3, "dwRetrievalFlags"); // DWORD
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlA", 4, "dwTimeout"); // DWORD
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlA", 5, "ppvObject"); // LPVOID *
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlA", 6, "hAsyncRetrieve"); // HCRYPTASYNC
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlA", 7, "pCredentials"); // PCRYPT_CREDENTIALS
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlA", 8, "pvVerify"); // LPVOID
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlA", 9, "pAuxInfo"); // PCRYPT_RETRIEVE_AUX_INFO
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlW", 1, "pszUrl"); // LPCWSTR
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlW", 2, "pszObjectOid"); // LPCSTR
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlW", 3, "dwRetrievalFlags"); // DWORD
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlW", 4, "dwTimeout"); // DWORD
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlW", 5, "ppvObject"); // LPVOID *
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlW", 6, "hAsyncRetrieve"); // HCRYPTASYNC
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlW", 7, "pCredentials"); // PCRYPT_CREDENTIALS
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlW", 8, "pvVerify"); // LPVOID
	ADD_PARAM_NAME("CryptRetrieveObjectByUrlW", 9, "pAuxInfo"); // PCRYPT_RETRIEVE_AUX_INFO
	ADD_PARAM_NAME("CryptRetrieveTimeStamp", 1, "wszUrl"); // LPCWSTR
	ADD_PARAM_NAME("CryptRetrieveTimeStamp", 2, "dwRetrievalFlags"); // DWORD
	ADD_PARAM_NAME("CryptRetrieveTimeStamp", 3, "dwTimeout"); // DWORD
	ADD_PARAM_NAME("CryptRetrieveTimeStamp", 4, "pszHashId"); // LPCSTR
	ADD_PARAM_NAME("CryptRetrieveTimeStamp", 5, "pPara"); // const CRYPT_TIMESTAMP_PARA *
	ADD_PARAM_NAME("CryptRetrieveTimeStamp", 6, "pbData"); // const BYTE *
	ADD_PARAM_NAME("CryptRetrieveTimeStamp", 7, "cbData"); // DWORD
	ADD_PARAM_NAME("CryptRetrieveTimeStamp", 8, "ppTsContext"); // PCRYPT_TIMESTAMP_CONTEXT *
	ADD_PARAM_NAME("CryptRetrieveTimeStamp", 9, "ppTsSigner"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CryptRetrieveTimeStamp", 10, "phStore"); // HCERTSTORE
	ADD_PARAM_NAME("CryptSetAsyncParam", 1, "hAsync"); // HCRYPTASYNC
	ADD_PARAM_NAME("CryptSetAsyncParam", 2, "pszParamOid"); // LPSTR
	ADD_PARAM_NAME("CryptSetAsyncParam", 3, "pvParam"); // LPVOID
	ADD_PARAM_NAME("CryptSetAsyncParam", 4, "pfnFree"); // PFN_CRYPT_ASYNC_PARAM_FREE_FUNC
	ADD_PARAM_NAME("CryptSetHashParam", 1, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptSetHashParam", 2, "dwParam"); // DWORD
	ADD_PARAM_NAME("CryptSetHashParam", 3, "pbData"); // CONST BYTE *
	ADD_PARAM_NAME("CryptSetHashParam", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptSetKeyIdentifierProperty", 1, "pKeyIdentifier"); // const CRYPT_HASH_BLOB *
	ADD_PARAM_NAME("CryptSetKeyIdentifierProperty", 2, "dwPropId"); // DWORD
	ADD_PARAM_NAME("CryptSetKeyIdentifierProperty", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptSetKeyIdentifierProperty", 4, "pwszComputerName"); // LPCWSTR
	ADD_PARAM_NAME("CryptSetKeyIdentifierProperty", 5, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptSetKeyIdentifierProperty", 6, "pvData"); // const void *
	ADD_PARAM_NAME("CryptSetKeyParam", 1, "hKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptSetKeyParam", 2, "dwParam"); // DWORD
	ADD_PARAM_NAME("CryptSetKeyParam", 3, "pbData"); // CONST BYTE *
	ADD_PARAM_NAME("CryptSetKeyParam", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptSetOIDFunctionValue", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptSetOIDFunctionValue", 2, "pszFuncName"); // LPCSTR
	ADD_PARAM_NAME("CryptSetOIDFunctionValue", 3, "pszOID"); // LPCSTR
	ADD_PARAM_NAME("CryptSetOIDFunctionValue", 4, "pwszValueName"); // LPCWSTR
	ADD_PARAM_NAME("CryptSetOIDFunctionValue", 5, "dwValueType"); // DWORD
	ADD_PARAM_NAME("CryptSetOIDFunctionValue", 6, "pbValueData"); // const BYTE *
	ADD_PARAM_NAME("CryptSetOIDFunctionValue", 7, "cbValueData"); // DWORD
	ADD_PARAM_NAME("CryptSetProvParam", 1, "hProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptSetProvParam", 2, "dwParam"); // DWORD
	ADD_PARAM_NAME("CryptSetProvParam", 3, "pbData"); // CONST BYTE *
	ADD_PARAM_NAME("CryptSetProvParam", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptSetProviderA", 1, "pszProvName"); // LPCSTR
	ADD_PARAM_NAME("CryptSetProviderA", 2, "dwProvType"); // DWORD
	ADD_PARAM_NAME("CryptSetProviderExA", 1, "pszProvName"); // LPCSTR
	ADD_PARAM_NAME("CryptSetProviderExA", 2, "dwProvType"); // DWORD
	ADD_PARAM_NAME("CryptSetProviderExA", 3, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptSetProviderExA", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptSetProviderExW", 1, "pszProvName"); // LPCWSTR
	ADD_PARAM_NAME("CryptSetProviderExW", 2, "dwProvType"); // DWORD
	ADD_PARAM_NAME("CryptSetProviderExW", 3, "pdwReserved"); // DWORD *
	ADD_PARAM_NAME("CryptSetProviderExW", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptSetProviderW", 1, "pszProvName"); // LPCWSTR
	ADD_PARAM_NAME("CryptSetProviderW", 2, "dwProvType"); // DWORD
	ADD_PARAM_NAME("CryptSignAndEncodeCertificate", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptSignAndEncodeCertificate", 2, "dwKeySpec"); // DWORD
	ADD_PARAM_NAME("CryptSignAndEncodeCertificate", 3, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptSignAndEncodeCertificate", 4, "lpszStructType"); // LPCSTR
	ADD_PARAM_NAME("CryptSignAndEncodeCertificate", 5, "pvStructInfo"); // const void *
	ADD_PARAM_NAME("CryptSignAndEncodeCertificate", 6, "pSignatureAlgorithm"); // PCRYPT_ALGORITHM_IDENTIFIER
	ADD_PARAM_NAME("CryptSignAndEncodeCertificate", 7, "pvHashAuxInfo"); // const void *
	ADD_PARAM_NAME("CryptSignAndEncodeCertificate", 8, "pbEncoded"); // PBYTE
	ADD_PARAM_NAME("CryptSignAndEncodeCertificate", 9, "pcbEncoded"); // DWORD *
	ADD_PARAM_NAME("CryptSignAndEncryptMessage", 1, "pSignPara"); // PCRYPT_SIGN_MESSAGE_PARA
	ADD_PARAM_NAME("CryptSignAndEncryptMessage", 2, "pEncryptPara"); // PCRYPT_ENCRYPT_MESSAGE_PARA
	ADD_PARAM_NAME("CryptSignAndEncryptMessage", 3, "cRecipientCert"); // DWORD
	ADD_PARAM_NAME("CryptSignAndEncryptMessage", 4, "rgpRecipientCert"); // PCCERT_CONTEXT []
	ADD_PARAM_NAME("CryptSignAndEncryptMessage", 5, "pbToBeSignedAndEncrypted"); // const BYTE *
	ADD_PARAM_NAME("CryptSignAndEncryptMessage", 6, "cbToBeSignedAndEncrypted"); // DWORD
	ADD_PARAM_NAME("CryptSignAndEncryptMessage", 7, "pbSignedAndEncryptedBlob"); // BYTE *
	ADD_PARAM_NAME("CryptSignAndEncryptMessage", 8, "pcbSignedAndEncryptedBlob"); // DWORD *
	ADD_PARAM_NAME("CryptSignCertificate", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptSignCertificate", 2, "dwKeySpec"); // DWORD
	ADD_PARAM_NAME("CryptSignCertificate", 3, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptSignCertificate", 4, "pbEncodedToBeSigned"); // const BYTE *
	ADD_PARAM_NAME("CryptSignCertificate", 5, "cbEncodedToBeSigned"); // DWORD
	ADD_PARAM_NAME("CryptSignCertificate", 6, "pSignatureAlgorithm"); // PCRYPT_ALGORITHM_IDENTIFIER
	ADD_PARAM_NAME("CryptSignCertificate", 7, "pvHashAuxInfo"); // const void *
	ADD_PARAM_NAME("CryptSignCertificate", 8, "pbSignature"); // BYTE *
	ADD_PARAM_NAME("CryptSignCertificate", 9, "pcbSignature"); // DWORD *
	ADD_PARAM_NAME("CryptSignHashA", 1, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptSignHashA", 2, "dwKeySpec"); // DWORD
	ADD_PARAM_NAME("CryptSignHashA", 3, "szDescription"); // LPCSTR
	ADD_PARAM_NAME("CryptSignHashA", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptSignHashA", 5, "pbSignature"); // BYTE *
	ADD_PARAM_NAME("CryptSignHashA", 6, "pdwSigLen"); // DWORD *
	ADD_PARAM_NAME("CryptSignHashW", 1, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptSignHashW", 2, "dwKeySpec"); // DWORD
	ADD_PARAM_NAME("CryptSignHashW", 3, "szDescription"); // LPCWSTR
	ADD_PARAM_NAME("CryptSignHashW", 4, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptSignHashW", 5, "pbSignature"); // BYTE *
	ADD_PARAM_NAME("CryptSignHashW", 6, "pdwSigLen"); // DWORD *
	ADD_PARAM_NAME("CryptSignMessage", 1, "pSignPara"); // PCRYPT_SIGN_MESSAGE_PARA
	ADD_PARAM_NAME("CryptSignMessage", 2, "fDetachedSignature"); // WINBOOL
	ADD_PARAM_NAME("CryptSignMessage", 3, "cToBeSigned"); // DWORD
	ADD_PARAM_NAME("CryptSignMessage", 4, "rgpbToBeSigned"); // const BYTE * []
	ADD_PARAM_NAME("CryptSignMessage", 5, "rgcbToBeSigned"); // DWORD []
	ADD_PARAM_NAME("CryptSignMessage", 6, "pbSignedBlob"); // BYTE *
	ADD_PARAM_NAME("CryptSignMessage", 7, "pcbSignedBlob"); // DWORD *
	ADD_PARAM_NAME("CryptSignMessageWithKey", 1, "pSignPara"); // PCRYPT_KEY_SIGN_MESSAGE_PARA
	ADD_PARAM_NAME("CryptSignMessageWithKey", 2, "pbToBeSigned"); // const BYTE *
	ADD_PARAM_NAME("CryptSignMessageWithKey", 3, "cbToBeSigned"); // DWORD
	ADD_PARAM_NAME("CryptSignMessageWithKey", 4, "pbSignedBlob"); // BYTE *
	ADD_PARAM_NAME("CryptSignMessageWithKey", 5, "pcbSignedBlob"); // DWORD *
	ADD_PARAM_NAME("CryptStringToBinaryA", 1, "pszString"); // LPCSTR
	ADD_PARAM_NAME("CryptStringToBinaryA", 2, "cchString"); // DWORD
	ADD_PARAM_NAME("CryptStringToBinaryA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptStringToBinaryA", 4, "pbBinary"); // BYTE *
	ADD_PARAM_NAME("CryptStringToBinaryA", 5, "pcbBinary"); // DWORD *
	ADD_PARAM_NAME("CryptStringToBinaryA", 6, "pdwSkip"); // DWORD *
	ADD_PARAM_NAME("CryptStringToBinaryA", 7, "pdwFlags"); // DWORD *
	ADD_PARAM_NAME("CryptStringToBinaryW", 1, "pszString"); // LPCWSTR
	ADD_PARAM_NAME("CryptStringToBinaryW", 2, "cchString"); // DWORD
	ADD_PARAM_NAME("CryptStringToBinaryW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptStringToBinaryW", 4, "pbBinary"); // BYTE *
	ADD_PARAM_NAME("CryptStringToBinaryW", 5, "pcbBinary"); // DWORD *
	ADD_PARAM_NAME("CryptStringToBinaryW", 6, "pdwSkip"); // DWORD *
	ADD_PARAM_NAME("CryptStringToBinaryW", 7, "pdwFlags"); // DWORD *
	ADD_PARAM_NAME("CryptUninstallCancelRetrieval", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptUninstallCancelRetrieval", 2, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptUninstallDefaultContext", 1, "hDefaultContext"); // HCRYPTDEFAULTCONTEXT
	ADD_PARAM_NAME("CryptUninstallDefaultContext", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptUninstallDefaultContext", 3, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptUnprotectData", 1, "pDataIn"); // DATA_BLOB *
	ADD_PARAM_NAME("CryptUnprotectData", 2, "ppszDataDescr"); // LPWSTR *
	ADD_PARAM_NAME("CryptUnprotectData", 3, "pOptionalEntropy"); // DATA_BLOB *
	ADD_PARAM_NAME("CryptUnprotectData", 4, "pvReserved"); // PVOID
	ADD_PARAM_NAME("CryptUnprotectData", 5, "pPromptStruct"); // CRYPTPROTECT_PROMPTSTRUCT *
	ADD_PARAM_NAME("CryptUnprotectData", 6, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptUnprotectData", 7, "pDataOut"); // DATA_BLOB *
	ADD_PARAM_NAME("CryptUnprotectMemory", 1, "pDataIn"); // LPVOID
	ADD_PARAM_NAME("CryptUnprotectMemory", 2, "cbDataIn"); // DWORD
	ADD_PARAM_NAME("CryptUnprotectMemory", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptUnregisterDefaultOIDFunction", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptUnregisterDefaultOIDFunction", 2, "pszFuncName"); // LPCSTR
	ADD_PARAM_NAME("CryptUnregisterDefaultOIDFunction", 3, "pwszDll"); // LPCWSTR
	ADD_PARAM_NAME("CryptUnregisterOIDFunction", 1, "dwEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptUnregisterOIDFunction", 2, "pszFuncName"); // LPCSTR
	ADD_PARAM_NAME("CryptUnregisterOIDFunction", 3, "pszOID"); // LPCSTR
	ADD_PARAM_NAME("CryptUnregisterOIDInfo", 1, "pInfo"); // PCCRYPT_OID_INFO
	ADD_PARAM_NAME("CryptUpdateProtectedState", 1, "pOldSid"); // PSID
	ADD_PARAM_NAME("CryptUpdateProtectedState", 2, "pwszOldPassword"); // LPCWSTR
	ADD_PARAM_NAME("CryptUpdateProtectedState", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptUpdateProtectedState", 4, "pdwSuccessCount"); // DWORD *
	ADD_PARAM_NAME("CryptUpdateProtectedState", 5, "pdwFailureCount"); // DWORD *
	ADD_PARAM_NAME("CryptVerifyCertificateSignature", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptVerifyCertificateSignature", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptVerifyCertificateSignature", 3, "pbEncoded"); // const BYTE *
	ADD_PARAM_NAME("CryptVerifyCertificateSignature", 4, "cbEncoded"); // DWORD
	ADD_PARAM_NAME("CryptVerifyCertificateSignature", 5, "pPublicKey"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CryptVerifyCertificateSignatureEx", 1, "hCryptProv"); // HCRYPTPROV
	ADD_PARAM_NAME("CryptVerifyCertificateSignatureEx", 2, "dwCertEncodingType"); // DWORD
	ADD_PARAM_NAME("CryptVerifyCertificateSignatureEx", 3, "dwSubjectType"); // DWORD
	ADD_PARAM_NAME("CryptVerifyCertificateSignatureEx", 4, "pvSubject"); // void *
	ADD_PARAM_NAME("CryptVerifyCertificateSignatureEx", 5, "dwIssuerType"); // DWORD
	ADD_PARAM_NAME("CryptVerifyCertificateSignatureEx", 6, "pvIssuer"); // void *
	ADD_PARAM_NAME("CryptVerifyCertificateSignatureEx", 7, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptVerifyCertificateSignatureEx", 8, "pvReserved"); // void *
	ADD_PARAM_NAME("CryptVerifyDetachedMessageHash", 1, "pHashPara"); // PCRYPT_HASH_MESSAGE_PARA
	ADD_PARAM_NAME("CryptVerifyDetachedMessageHash", 2, "pbDetachedHashBlob"); // BYTE *
	ADD_PARAM_NAME("CryptVerifyDetachedMessageHash", 3, "cbDetachedHashBlob"); // DWORD
	ADD_PARAM_NAME("CryptVerifyDetachedMessageHash", 4, "cToBeHashed"); // DWORD
	ADD_PARAM_NAME("CryptVerifyDetachedMessageHash", 5, "rgpbToBeHashed"); // const BYTE * []
	ADD_PARAM_NAME("CryptVerifyDetachedMessageHash", 6, "rgcbToBeHashed"); // DWORD []
	ADD_PARAM_NAME("CryptVerifyDetachedMessageHash", 7, "pbComputedHash"); // BYTE *
	ADD_PARAM_NAME("CryptVerifyDetachedMessageHash", 8, "pcbComputedHash"); // DWORD *
	ADD_PARAM_NAME("CryptVerifyDetachedMessageSignature", 1, "pVerifyPara"); // PCRYPT_VERIFY_MESSAGE_PARA
	ADD_PARAM_NAME("CryptVerifyDetachedMessageSignature", 2, "dwSignerIndex"); // DWORD
	ADD_PARAM_NAME("CryptVerifyDetachedMessageSignature", 3, "pbDetachedSignBlob"); // const BYTE *
	ADD_PARAM_NAME("CryptVerifyDetachedMessageSignature", 4, "cbDetachedSignBlob"); // DWORD
	ADD_PARAM_NAME("CryptVerifyDetachedMessageSignature", 5, "cToBeSigned"); // DWORD
	ADD_PARAM_NAME("CryptVerifyDetachedMessageSignature", 6, "rgpbToBeSigned"); // const BYTE * []
	ADD_PARAM_NAME("CryptVerifyDetachedMessageSignature", 7, "rgcbToBeSigned"); // DWORD []
	ADD_PARAM_NAME("CryptVerifyDetachedMessageSignature", 8, "ppSignerCert"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CryptVerifyMessageHash", 1, "pHashPara"); // PCRYPT_HASH_MESSAGE_PARA
	ADD_PARAM_NAME("CryptVerifyMessageHash", 2, "pbHashedBlob"); // BYTE *
	ADD_PARAM_NAME("CryptVerifyMessageHash", 3, "cbHashedBlob"); // DWORD
	ADD_PARAM_NAME("CryptVerifyMessageHash", 4, "pbToBeHashed"); // BYTE *
	ADD_PARAM_NAME("CryptVerifyMessageHash", 5, "pcbToBeHashed"); // DWORD *
	ADD_PARAM_NAME("CryptVerifyMessageHash", 6, "pbComputedHash"); // BYTE *
	ADD_PARAM_NAME("CryptVerifyMessageHash", 7, "pcbComputedHash"); // DWORD *
	ADD_PARAM_NAME("CryptVerifyMessageSignature", 1, "pVerifyPara"); // PCRYPT_VERIFY_MESSAGE_PARA
	ADD_PARAM_NAME("CryptVerifyMessageSignature", 2, "dwSignerIndex"); // DWORD
	ADD_PARAM_NAME("CryptVerifyMessageSignature", 3, "pbSignedBlob"); // const BYTE *
	ADD_PARAM_NAME("CryptVerifyMessageSignature", 4, "cbSignedBlob"); // DWORD
	ADD_PARAM_NAME("CryptVerifyMessageSignature", 5, "pbDecoded"); // BYTE *
	ADD_PARAM_NAME("CryptVerifyMessageSignature", 6, "pcbDecoded"); // DWORD *
	ADD_PARAM_NAME("CryptVerifyMessageSignature", 7, "ppSignerCert"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CryptVerifyMessageSignatureWithKey", 1, "pVerifyPara"); // PCRYPT_KEY_VERIFY_MESSAGE_PARA
	ADD_PARAM_NAME("CryptVerifyMessageSignatureWithKey", 2, "pPublicKeyInfo"); // PCERT_PUBLIC_KEY_INFO
	ADD_PARAM_NAME("CryptVerifyMessageSignatureWithKey", 3, "pbSignedBlob"); // const BYTE *
	ADD_PARAM_NAME("CryptVerifyMessageSignatureWithKey", 4, "cbSignedBlob"); // DWORD
	ADD_PARAM_NAME("CryptVerifyMessageSignatureWithKey", 5, "pbDecoded"); // BYTE *
	ADD_PARAM_NAME("CryptVerifyMessageSignatureWithKey", 6, "pcbDecoded"); // DWORD *
	ADD_PARAM_NAME("CryptVerifySignatureA", 1, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptVerifySignatureA", 2, "pbSignature"); // CONST BYTE *
	ADD_PARAM_NAME("CryptVerifySignatureA", 3, "dwSigLen"); // DWORD
	ADD_PARAM_NAME("CryptVerifySignatureA", 4, "hPubKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptVerifySignatureA", 5, "szDescription"); // LPCSTR
	ADD_PARAM_NAME("CryptVerifySignatureA", 6, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptVerifySignatureW", 1, "hHash"); // HCRYPTHASH
	ADD_PARAM_NAME("CryptVerifySignatureW", 2, "pbSignature"); // CONST BYTE *
	ADD_PARAM_NAME("CryptVerifySignatureW", 3, "dwSigLen"); // DWORD
	ADD_PARAM_NAME("CryptVerifySignatureW", 4, "hPubKey"); // HCRYPTKEY
	ADD_PARAM_NAME("CryptVerifySignatureW", 5, "szDescription"); // LPCWSTR
	ADD_PARAM_NAME("CryptVerifySignatureW", 6, "dwFlags"); // DWORD
	ADD_PARAM_NAME("CryptVerifyTimeStampSignature", 1, "pbTSContentInfo"); // const BYTE
	ADD_PARAM_NAME("CryptVerifyTimeStampSignature", 2, "cbTSContentInfo"); // DWORD
	ADD_PARAM_NAME("CryptVerifyTimeStampSignature", 3, "pbData"); // const DWORD
	ADD_PARAM_NAME("CryptVerifyTimeStampSignature", 4, "cbData"); // DWORD
	ADD_PARAM_NAME("CryptVerifyTimeStampSignature", 5, "hAdditionalStore"); // HCERTSTORE
	ADD_PARAM_NAME("CryptVerifyTimeStampSignature", 6, "ppTsContext"); // PCRYPT_TIMESTAMP_CONTEXT
	ADD_PARAM_NAME("CryptVerifyTimeStampSignature", 7, "ppTsSigner"); // PCCERT_CONTEXT *
	ADD_PARAM_NAME("CryptVerifyTimeStampSignature", 8, "phStore"); // HCERTSTORE *
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
