/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/q.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/q.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with Q.
*/
void initFuncParamNamesMap_Q(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("QueryActCtxSettingsW", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("QueryActCtxSettingsW", 2, "hActCtx"); // HANDLE
	ADD_PARAM_NAME("QueryActCtxSettingsW", 3, "settingsNameSpace"); // PCWSTR
	ADD_PARAM_NAME("QueryActCtxSettingsW", 4, "settingName"); // PCWSTR
	ADD_PARAM_NAME("QueryActCtxSettingsW", 5, "pvBuffer"); // PWSTR
	ADD_PARAM_NAME("QueryActCtxSettingsW", 6, "dwBuffer"); // SIZE_T
	ADD_PARAM_NAME("QueryActCtxSettingsW", 7, "pdwWrittenOrRequired"); // SIZE_T *
	ADD_PARAM_NAME("QueryActCtxW", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("QueryActCtxW", 2, "hActCtx"); // HANDLE
	ADD_PARAM_NAME("QueryActCtxW", 3, "pvSubInstance"); // PVOID
	ADD_PARAM_NAME("QueryActCtxW", 4, "ulInfoClass"); // ULONG
	ADD_PARAM_NAME("QueryActCtxW", 5, "pvBuffer"); // PVOID
	ADD_PARAM_NAME("QueryActCtxW", 6, "cbBuffer"); // SIZE_T
	ADD_PARAM_NAME("QueryActCtxW", 7, "pcbWrittenOrRequired"); // SIZE_T *
	ADD_PARAM_NAME("QueryDepthSList", 1, "ListHead"); // PSLIST_HEADER
	ADD_PARAM_NAME("QueryDosDeviceA", 1, "lpDeviceName"); // LPCSTR
	ADD_PARAM_NAME("QueryDosDeviceA", 2, "lpTargetPath"); // LPSTR
	ADD_PARAM_NAME("QueryDosDeviceA", 3, "ucchMax"); // DWORD
	ADD_PARAM_NAME("QueryDosDeviceW", 1, "lpDeviceName"); // LPCWSTR
	ADD_PARAM_NAME("QueryDosDeviceW", 2, "lpTargetPath"); // LPWSTR
	ADD_PARAM_NAME("QueryDosDeviceW", 3, "ucchMax"); // DWORD
	ADD_PARAM_NAME("QueryFullProcessImageNameA", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("QueryFullProcessImageNameA", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("QueryFullProcessImageNameA", 3, "lpExeName"); // LPSTR
	ADD_PARAM_NAME("QueryFullProcessImageNameA", 4, "lpdwSize"); // PDWORD
	ADD_PARAM_NAME("QueryFullProcessImageNameW", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("QueryFullProcessImageNameW", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("QueryFullProcessImageNameW", 3, "lpExeName"); // LPWSTR
	ADD_PARAM_NAME("QueryFullProcessImageNameW", 4, "lpdwSize"); // PDWORD
	ADD_PARAM_NAME("QueryIdleProcessorCycleTime", 1, "BufferLength"); // PULONG
	ADD_PARAM_NAME("QueryIdleProcessorCycleTime", 2, "ProcessorIdleCycleTime"); // PULONG64
	ADD_PARAM_NAME("QueryIdleProcessorCycleTimeEx", 1, "Group"); // USHORT
	ADD_PARAM_NAME("QueryIdleProcessorCycleTimeEx", 2, "BufferLength"); // PULONG
	ADD_PARAM_NAME("QueryIdleProcessorCycleTimeEx", 3, "ProcessorIdleCycleTime"); // PULONG64
	ADD_PARAM_NAME("QueryInformationJobObject", 1, "hJob"); // HANDLE
	ADD_PARAM_NAME("QueryInformationJobObject", 2, "JobObjectInformationClass"); // JOBOBJECTINFOCLASS
	ADD_PARAM_NAME("QueryInformationJobObject", 3, "lpJobObjectInformation"); // LPVOID
	ADD_PARAM_NAME("QueryInformationJobObject", 4, "cbJobObjectInformationLength"); // DWORD
	ADD_PARAM_NAME("QueryInformationJobObject", 5, "lpReturnLength"); // LPDWORD
	ADD_PARAM_NAME("QueryMemoryResourceNotification", 1, "ResourceNotificationHandle"); // HANDLE
	ADD_PARAM_NAME("QueryMemoryResourceNotification", 2, "ResourceState"); // PBOOL
	ADD_PARAM_NAME("QueryPerformanceCounter", 1, "lpPerformanceCount"); // LARGE_INTEGER *
	ADD_PARAM_NAME("QueryPerformanceFrequency", 1, "lpFrequency"); // LARGE_INTEGER *
	ADD_PARAM_NAME("QueryProcessAffinityUpdateMode", 1, "ProcessHandle"); // HANDLE
	ADD_PARAM_NAME("QueryProcessAffinityUpdateMode", 2, "lpdwFlags"); // DWORD
	ADD_PARAM_NAME("QueryProcessCycleTime", 1, "ProcessHandle"); // HANDLE
	ADD_PARAM_NAME("QueryProcessCycleTime", 2, "CycleTime"); // PULONG64
	ADD_PARAM_NAME("QueryRecoveryAgentsOnEncryptedFile", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("QueryRecoveryAgentsOnEncryptedFile", 2, "pRecoveryAgents"); // PENCRYPTION_CERTIFICATE_HASH_LIST *
	ADD_PARAM_NAME("QuerySecurityAccessMask", 1, "SecurityInformation"); // SECURITY_INFORMATION
	ADD_PARAM_NAME("QuerySecurityAccessMask", 2, "DesiredAccess"); // LPDWORD
	ADD_PARAM_NAME("QueryServiceConfig2A", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("QueryServiceConfig2A", 2, "dwInfoLevel"); // DWORD
	ADD_PARAM_NAME("QueryServiceConfig2A", 3, "lpBuffer"); // LPBYTE
	ADD_PARAM_NAME("QueryServiceConfig2A", 4, "cbBufSize"); // DWORD
	ADD_PARAM_NAME("QueryServiceConfig2A", 5, "pcbBytesNeeded"); // LPDWORD
	ADD_PARAM_NAME("QueryServiceConfig2W", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("QueryServiceConfig2W", 2, "dwInfoLevel"); // DWORD
	ADD_PARAM_NAME("QueryServiceConfig2W", 3, "lpBuffer"); // LPBYTE
	ADD_PARAM_NAME("QueryServiceConfig2W", 4, "cbBufSize"); // DWORD
	ADD_PARAM_NAME("QueryServiceConfig2W", 5, "pcbBytesNeeded"); // LPDWORD
	ADD_PARAM_NAME("QueryServiceConfigA", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("QueryServiceConfigA", 2, "lpServiceConfig"); // LPQUERY_SERVICE_CONFIGA
	ADD_PARAM_NAME("QueryServiceConfigA", 3, "cbBufSize"); // DWORD
	ADD_PARAM_NAME("QueryServiceConfigA", 4, "pcbBytesNeeded"); // LPDWORD
	ADD_PARAM_NAME("QueryServiceConfigW", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("QueryServiceConfigW", 2, "lpServiceConfig"); // LPQUERY_SERVICE_CONFIGW
	ADD_PARAM_NAME("QueryServiceConfigW", 3, "cbBufSize"); // DWORD
	ADD_PARAM_NAME("QueryServiceConfigW", 4, "pcbBytesNeeded"); // LPDWORD
	ADD_PARAM_NAME("QueryServiceLockStatusA", 1, "hSCManager"); // SC_HANDLE
	ADD_PARAM_NAME("QueryServiceLockStatusA", 2, "lpLockStatus"); // LPQUERY_SERVICE_LOCK_STATUSA
	ADD_PARAM_NAME("QueryServiceLockStatusA", 3, "cbBufSize"); // DWORD
	ADD_PARAM_NAME("QueryServiceLockStatusA", 4, "pcbBytesNeeded"); // LPDWORD
	ADD_PARAM_NAME("QueryServiceLockStatusW", 1, "hSCManager"); // SC_HANDLE
	ADD_PARAM_NAME("QueryServiceLockStatusW", 2, "lpLockStatus"); // LPQUERY_SERVICE_LOCK_STATUSW
	ADD_PARAM_NAME("QueryServiceLockStatusW", 3, "cbBufSize"); // DWORD
	ADD_PARAM_NAME("QueryServiceLockStatusW", 4, "pcbBytesNeeded"); // LPDWORD
	ADD_PARAM_NAME("QueryServiceObjectSecurity", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("QueryServiceObjectSecurity", 2, "dwSecurityInformation"); // SECURITY_INFORMATION
	ADD_PARAM_NAME("QueryServiceObjectSecurity", 3, "lpSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("QueryServiceObjectSecurity", 4, "cbBufSize"); // DWORD
	ADD_PARAM_NAME("QueryServiceObjectSecurity", 5, "pcbBytesNeeded"); // LPDWORD
	ADD_PARAM_NAME("QueryServiceStatus", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("QueryServiceStatus", 2, "lpServiceStatus"); // LPSERVICE_STATUS
	ADD_PARAM_NAME("QueryServiceStatusEx", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("QueryServiceStatusEx", 2, "InfoLevel"); // SC_STATUS_TYPE
	ADD_PARAM_NAME("QueryServiceStatusEx", 3, "lpBuffer"); // LPBYTE
	ADD_PARAM_NAME("QueryServiceStatusEx", 4, "cbBufSize"); // DWORD
	ADD_PARAM_NAME("QueryServiceStatusEx", 5, "pcbBytesNeeded"); // LPDWORD
	ADD_PARAM_NAME("QueryThreadCycleTime", 1, "ThreadHandle"); // HANDLE
	ADD_PARAM_NAME("QueryThreadCycleTime", 2, "CycleTime"); // PULONG64
	ADD_PARAM_NAME("QueryUnbiasedInterruptTime", 1, "UnbiasedTime"); // PULONGLONG
	ADD_PARAM_NAME("QueryUsersOnEncryptedFile", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("QueryUsersOnEncryptedFile", 2, "pUsers"); // PENCRYPTION_CERTIFICATE_HASH_LIST *
	ADD_PARAM_NAME("QueueUserAPC", 1, "pfnAPC"); // PAPCFUNC
	ADD_PARAM_NAME("QueueUserAPC", 2, "hThread"); // HANDLE
	ADD_PARAM_NAME("QueueUserAPC", 3, "dwData"); // ULONG_PTR
	ADD_PARAM_NAME("QueueUserWorkItem", 1, "Function"); // LPTHREAD_START_ROUTINE
	ADD_PARAM_NAME("QueueUserWorkItem", 2, "Context"); // PVOID
	ADD_PARAM_NAME("QueueUserWorkItem", 3, "Flags"); // ULONG
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
