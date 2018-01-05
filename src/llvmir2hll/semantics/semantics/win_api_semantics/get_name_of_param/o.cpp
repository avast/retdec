/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/o.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/o.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with O.
*/
void initFuncParamNamesMap_O(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("ObjectCloseAuditAlarmA", 1, "SubsystemName"); // LPCSTR
	ADD_PARAM_NAME("ObjectCloseAuditAlarmA", 2, "HandleId"); // LPVOID
	ADD_PARAM_NAME("ObjectCloseAuditAlarmA", 3, "GenerateOnClose"); // WINBOOL
	ADD_PARAM_NAME("ObjectCloseAuditAlarmW", 1, "SubsystemName"); // LPCWSTR
	ADD_PARAM_NAME("ObjectCloseAuditAlarmW", 2, "HandleId"); // LPVOID
	ADD_PARAM_NAME("ObjectCloseAuditAlarmW", 3, "GenerateOnClose"); // WINBOOL
	ADD_PARAM_NAME("ObjectDeleteAuditAlarmA", 1, "SubsystemName"); // LPCSTR
	ADD_PARAM_NAME("ObjectDeleteAuditAlarmA", 2, "HandleId"); // LPVOID
	ADD_PARAM_NAME("ObjectDeleteAuditAlarmA", 3, "GenerateOnClose"); // WINBOOL
	ADD_PARAM_NAME("ObjectDeleteAuditAlarmW", 1, "SubsystemName"); // LPCWSTR
	ADD_PARAM_NAME("ObjectDeleteAuditAlarmW", 2, "HandleId"); // LPVOID
	ADD_PARAM_NAME("ObjectDeleteAuditAlarmW", 3, "GenerateOnClose"); // WINBOOL
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 1, "SubsystemName"); // LPCSTR
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 2, "HandleId"); // LPVOID
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 3, "ObjectTypeName"); // LPSTR
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 4, "ObjectName"); // LPSTR
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 5, "pSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 6, "ClientToken"); // HANDLE
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 7, "DesiredAccess"); // DWORD
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 8, "GrantedAccess"); // DWORD
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 9, "Privileges"); // PPRIVILEGE_SET
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 10, "ObjectCreation"); // WINBOOL
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 11, "AccessGranted"); // WINBOOL
	ADD_PARAM_NAME("ObjectOpenAuditAlarmA", 12, "GenerateOnClose"); // LPBOOL
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 1, "SubsystemName"); // LPCWSTR
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 2, "HandleId"); // LPVOID
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 3, "ObjectTypeName"); // LPWSTR
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 4, "ObjectName"); // LPWSTR
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 5, "pSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 6, "ClientToken"); // HANDLE
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 7, "DesiredAccess"); // DWORD
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 8, "GrantedAccess"); // DWORD
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 9, "Privileges"); // PPRIVILEGE_SET
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 10, "ObjectCreation"); // WINBOOL
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 11, "AccessGranted"); // WINBOOL
	ADD_PARAM_NAME("ObjectOpenAuditAlarmW", 12, "GenerateOnClose"); // LPBOOL
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmA", 1, "SubsystemName"); // LPCSTR
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmA", 2, "HandleId"); // LPVOID
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmA", 3, "ClientToken"); // HANDLE
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmA", 4, "DesiredAccess"); // DWORD
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmA", 5, "Privileges"); // PPRIVILEGE_SET
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmA", 6, "AccessGranted"); // WINBOOL
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmW", 1, "SubsystemName"); // LPCWSTR
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmW", 2, "HandleId"); // LPVOID
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmW", 3, "ClientToken"); // HANDLE
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmW", 4, "DesiredAccess"); // DWORD
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmW", 5, "Privileges"); // PPRIVILEGE_SET
	ADD_PARAM_NAME("ObjectPrivilegeAuditAlarmW", 6, "AccessGranted"); // WINBOOL
	ADD_PARAM_NAME("OemKeyScan", 1, "wOemChar"); // WORD
	ADD_PARAM_NAME("OemToCharA", 1, "lpszSrc"); // LPCSTR
	ADD_PARAM_NAME("OemToCharA", 2, "lpszDst"); // LPSTR
	ADD_PARAM_NAME("OemToCharBuffA", 1, "lpszSrc"); // LPCSTR
	ADD_PARAM_NAME("OemToCharBuffA", 2, "lpszDst"); // LPSTR
	ADD_PARAM_NAME("OemToCharBuffA", 3, "cchDstLength"); // DWORD
	ADD_PARAM_NAME("OemToCharBuffW", 1, "lpszSrc"); // LPCSTR
	ADD_PARAM_NAME("OemToCharBuffW", 2, "lpszDst"); // LPWSTR
	ADD_PARAM_NAME("OemToCharBuffW", 3, "cchDstLength"); // DWORD
	ADD_PARAM_NAME("OemToCharW", 1, "lpszSrc"); // LPCSTR
	ADD_PARAM_NAME("OemToCharW", 2, "lpszDst"); // LPWSTR
	ADD_PARAM_NAME("OffsetClipRgn", 1, "hdc"); // HDC
	ADD_PARAM_NAME("OffsetClipRgn", 2, "x"); // int
	ADD_PARAM_NAME("OffsetClipRgn", 3, "y"); // int
	ADD_PARAM_NAME("OffsetRect", 1, "lprc"); // LPRECT
	ADD_PARAM_NAME("OffsetRect", 2, "dx"); // int
	ADD_PARAM_NAME("OffsetRect", 3, "dy"); // int
	ADD_PARAM_NAME("OffsetRgn", 1, "hrgn"); // HRGN
	ADD_PARAM_NAME("OffsetRgn", 2, "x"); // int
	ADD_PARAM_NAME("OffsetRgn", 3, "y"); // int
	ADD_PARAM_NAME("OffsetViewportOrgEx", 1, "hdc"); // HDC
	ADD_PARAM_NAME("OffsetViewportOrgEx", 2, "x"); // int
	ADD_PARAM_NAME("OffsetViewportOrgEx", 3, "y"); // int
	ADD_PARAM_NAME("OffsetViewportOrgEx", 4, "lppt"); // LPPOINT
	ADD_PARAM_NAME("OffsetWindowOrgEx", 1, "hdc"); // HDC
	ADD_PARAM_NAME("OffsetWindowOrgEx", 2, "x"); // int
	ADD_PARAM_NAME("OffsetWindowOrgEx", 3, "y"); // int
	ADD_PARAM_NAME("OffsetWindowOrgEx", 4, "lppt"); // LPPOINT
	ADD_PARAM_NAME("OpenBackupEventLogA", 1, "lpUNCServerName"); // LPCSTR
	ADD_PARAM_NAME("OpenBackupEventLogA", 2, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("OpenBackupEventLogW", 1, "lpUNCServerName"); // LPCWSTR
	ADD_PARAM_NAME("OpenBackupEventLogW", 2, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("OpenClipboard", 1, "hWndNewOwner"); // HWND
	ADD_PARAM_NAME("OpenDesktopA", 1, "lpszDesktop"); // LPCSTR
	ADD_PARAM_NAME("OpenDesktopA", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("OpenDesktopA", 3, "fInherit"); // WINBOOL
	ADD_PARAM_NAME("OpenDesktopA", 4, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("OpenDesktopW", 1, "lpszDesktop"); // LPCWSTR
	ADD_PARAM_NAME("OpenDesktopW", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("OpenDesktopW", 3, "fInherit"); // WINBOOL
	ADD_PARAM_NAME("OpenDesktopW", 4, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("OpenEncryptedFileRawA", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("OpenEncryptedFileRawA", 2, "ulFlags"); // ULONG
	ADD_PARAM_NAME("OpenEncryptedFileRawA", 3, "pvContext"); // PVOID *
	ADD_PARAM_NAME("OpenEncryptedFileRawW", 1, "lpFileName"); // LPCWSTR
	ADD_PARAM_NAME("OpenEncryptedFileRawW", 2, "ulFlags"); // ULONG
	ADD_PARAM_NAME("OpenEncryptedFileRawW", 3, "pvContext"); // PVOID *
	ADD_PARAM_NAME("OpenEventA", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenEventA", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenEventA", 3, "lpName"); // LPCSTR
	ADD_PARAM_NAME("OpenEventLogA", 1, "lpUNCServerName"); // LPCSTR
	ADD_PARAM_NAME("OpenEventLogA", 2, "lpSourceName"); // LPCSTR
	ADD_PARAM_NAME("OpenEventLogW", 1, "lpUNCServerName"); // LPCWSTR
	ADD_PARAM_NAME("OpenEventLogW", 2, "lpSourceName"); // LPCWSTR
	ADD_PARAM_NAME("OpenEventW", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenEventW", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenEventW", 3, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("OpenFile", 1, "lpFileName"); // LPCSTR
	ADD_PARAM_NAME("OpenFile", 2, "lpReOpenBuff"); // LPOFSTRUCT
	ADD_PARAM_NAME("OpenFile", 3, "uStyle"); // UINT
	ADD_PARAM_NAME("OpenFileById", 1, "hFile"); // HANDLE
	ADD_PARAM_NAME("OpenFileById", 2, "lpFileID"); // LPFILE_ID_DESCRIPTOR
	ADD_PARAM_NAME("OpenFileById", 3, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenFileById", 4, "dwShareMode"); // DWORD
	ADD_PARAM_NAME("OpenFileById", 5, "lpSecurityAttributes"); // LPSECURITY_ATTRIBUTES
	ADD_PARAM_NAME("OpenFileById", 6, "dwFlags"); // DWORD
	ADD_PARAM_NAME("OpenFileMappingA", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenFileMappingA", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenFileMappingA", 3, "lpName"); // LPCSTR
	ADD_PARAM_NAME("OpenFileMappingW", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenFileMappingW", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenFileMappingW", 3, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("OpenIcon", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("OpenInputDesktop", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("OpenInputDesktop", 2, "fInherit"); // WINBOOL
	ADD_PARAM_NAME("OpenInputDesktop", 3, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("OpenJobObjectA", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenJobObjectA", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenJobObjectA", 3, "lpName"); // LPCSTR
	ADD_PARAM_NAME("OpenJobObjectW", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenJobObjectW", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenJobObjectW", 3, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("OpenMutexA", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenMutexA", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenMutexA", 3, "lpName"); // LPCSTR
	ADD_PARAM_NAME("OpenMutexW", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenMutexW", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenMutexW", 3, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("OpenPrinter2A", 1, "pPrinterName"); // LPCSTR
	ADD_PARAM_NAME("OpenPrinter2A", 2, "phPrinter"); // LPHANDLE
	ADD_PARAM_NAME("OpenPrinter2A", 3, "pDefault"); // LPPRINTER_DEFAULTS
	ADD_PARAM_NAME("OpenPrinter2A", 4, "pOptions"); // PPRINTER_OPTIONS
	ADD_PARAM_NAME("OpenPrinter2W", 1, "pPrinterName"); // LPCWSTR
	ADD_PARAM_NAME("OpenPrinter2W", 2, "phPrinter"); // LPHANDLE
	ADD_PARAM_NAME("OpenPrinter2W", 3, "pDefault"); // LPPRINTER_DEFAULTS
	ADD_PARAM_NAME("OpenPrinter2W", 4, "pOptions"); // PPRINTER_OPTIONS
	ADD_PARAM_NAME("OpenPrinterA", 1, "pPrinterName"); // LPSTR
	ADD_PARAM_NAME("OpenPrinterA", 2, "phPrinter"); // LPHANDLE
	ADD_PARAM_NAME("OpenPrinterA", 3, "pDefault"); // LPPRINTER_DEFAULTSA
	ADD_PARAM_NAME("OpenPrinterToken", 1, "phToken"); // PHANDLE
	ADD_PARAM_NAME("OpenPrinterW", 1, "pPrinterName"); // LPWSTR
	ADD_PARAM_NAME("OpenPrinterW", 2, "phPrinter"); // LPHANDLE
	ADD_PARAM_NAME("OpenPrinterW", 3, "pDefault"); // LPPRINTER_DEFAULTSW
	ADD_PARAM_NAME("OpenPrivateNamespaceA", 1, "lpBoundaryDescriptor"); // LPVOID
	ADD_PARAM_NAME("OpenPrivateNamespaceA", 2, "lpAliasPrefix"); // LPCSTR
	ADD_PARAM_NAME("OpenPrivateNamespaceW", 1, "lpBoundaryDescriptor"); // LPVOID
	ADD_PARAM_NAME("OpenPrivateNamespaceW", 2, "lpAliasPrefix"); // LPCWSTR
	ADD_PARAM_NAME("OpenProcess", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenProcess", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenProcess", 3, "dwProcessId"); // DWORD
	ADD_PARAM_NAME("OpenProcessToken", 1, "ProcessHandle"); // HANDLE
	ADD_PARAM_NAME("OpenProcessToken", 2, "DesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenProcessToken", 3, "TokenHandle"); // PHANDLE
	ADD_PARAM_NAME("OpenSCManagerA", 1, "lpMachineName"); // LPCSTR
	ADD_PARAM_NAME("OpenSCManagerA", 2, "lpDatabaseName"); // LPCSTR
	ADD_PARAM_NAME("OpenSCManagerA", 3, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenSCManagerW", 1, "lpMachineName"); // LPCWSTR
	ADD_PARAM_NAME("OpenSCManagerW", 2, "lpDatabaseName"); // LPCWSTR
	ADD_PARAM_NAME("OpenSCManagerW", 3, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenSemaphoreA", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenSemaphoreA", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenSemaphoreA", 3, "lpName"); // LPCSTR
	ADD_PARAM_NAME("OpenSemaphoreW", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenSemaphoreW", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenSemaphoreW", 3, "lpName"); // LPCWSTR
	ADD_PARAM_NAME("OpenServiceA", 1, "hSCManager"); // SC_HANDLE
	ADD_PARAM_NAME("OpenServiceA", 2, "lpServiceName"); // LPCSTR
	ADD_PARAM_NAME("OpenServiceA", 3, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenServiceW", 1, "hSCManager"); // SC_HANDLE
	ADD_PARAM_NAME("OpenServiceW", 2, "lpServiceName"); // LPCWSTR
	ADD_PARAM_NAME("OpenServiceW", 3, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenThread", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenThread", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenThread", 3, "dwThreadId"); // DWORD
	ADD_PARAM_NAME("OpenThreadToken", 1, "ThreadHandle"); // HANDLE
	ADD_PARAM_NAME("OpenThreadToken", 2, "DesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenThreadToken", 3, "OpenAsSelf"); // WINBOOL
	ADD_PARAM_NAME("OpenThreadToken", 4, "TokenHandle"); // PHANDLE
	ADD_PARAM_NAME("OpenWaitableTimerA", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenWaitableTimerA", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenWaitableTimerA", 3, "lpTimerName"); // LPCSTR
	ADD_PARAM_NAME("OpenWaitableTimerW", 1, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("OpenWaitableTimerW", 2, "bInheritHandle"); // WINBOOL
	ADD_PARAM_NAME("OpenWaitableTimerW", 3, "lpTimerName"); // LPCWSTR
	ADD_PARAM_NAME("OpenWindowStationA", 1, "lpszWinSta"); // LPCSTR
	ADD_PARAM_NAME("OpenWindowStationA", 2, "fInherit"); // WINBOOL
	ADD_PARAM_NAME("OpenWindowStationA", 3, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("OpenWindowStationW", 1, "lpszWinSta"); // LPCWSTR
	ADD_PARAM_NAME("OpenWindowStationW", 2, "fInherit"); // WINBOOL
	ADD_PARAM_NAME("OpenWindowStationW", 3, "dwDesiredAccess"); // ACCESS_MASK
	ADD_PARAM_NAME("OutputDebugStringA", 1, "lpOutputString"); // LPCSTR
	ADD_PARAM_NAME("OutputDebugStringW", 1, "lpOutputString"); // LPCWSTR
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
