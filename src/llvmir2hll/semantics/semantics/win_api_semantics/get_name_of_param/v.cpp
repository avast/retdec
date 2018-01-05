/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/v.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/v.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with V.
*/
void initFuncParamNamesMap_V(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("ValidateRect", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("ValidateRect", 2, "lpRect"); // CONST RECT *
	ADD_PARAM_NAME("ValidateRgn", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("ValidateRgn", 2, "hRgn"); // HRGN
	ADD_PARAM_NAME("VerFindFileA", 1, "uFlags"); // DWORD
	ADD_PARAM_NAME("VerFindFileA", 2, "szFileName"); // LPSTR
	ADD_PARAM_NAME("VerFindFileA", 3, "szWinDir"); // LPSTR
	ADD_PARAM_NAME("VerFindFileA", 4, "szAppDir"); // LPSTR
	ADD_PARAM_NAME("VerFindFileA", 5, "szCurDir"); // LPSTR
	ADD_PARAM_NAME("VerFindFileA", 6, "lpuCurDirLen"); // PUINT
	ADD_PARAM_NAME("VerFindFileA", 7, "szDestDir"); // LPSTR
	ADD_PARAM_NAME("VerFindFileA", 8, "lpuDestDirLen"); // PUINT
	ADD_PARAM_NAME("VerFindFileW", 1, "uFlags"); // DWORD
	ADD_PARAM_NAME("VerFindFileW", 2, "szFileName"); // LPWSTR
	ADD_PARAM_NAME("VerFindFileW", 3, "szWinDir"); // LPWSTR
	ADD_PARAM_NAME("VerFindFileW", 4, "szAppDir"); // LPWSTR
	ADD_PARAM_NAME("VerFindFileW", 5, "szCurDir"); // LPWSTR
	ADD_PARAM_NAME("VerFindFileW", 6, "lpuCurDirLen"); // PUINT
	ADD_PARAM_NAME("VerFindFileW", 7, "szDestDir"); // LPWSTR
	ADD_PARAM_NAME("VerFindFileW", 8, "lpuDestDirLen"); // PUINT
	ADD_PARAM_NAME("VerInstallFileA", 1, "uFlags"); // DWORD
	ADD_PARAM_NAME("VerInstallFileA", 2, "szSrcFileName"); // LPSTR
	ADD_PARAM_NAME("VerInstallFileA", 3, "szDestFileName"); // LPSTR
	ADD_PARAM_NAME("VerInstallFileA", 4, "szSrcDir"); // LPSTR
	ADD_PARAM_NAME("VerInstallFileA", 5, "szDestDir"); // LPSTR
	ADD_PARAM_NAME("VerInstallFileA", 6, "szCurDir"); // LPSTR
	ADD_PARAM_NAME("VerInstallFileA", 7, "szTmpFile"); // LPSTR
	ADD_PARAM_NAME("VerInstallFileA", 8, "lpuTmpFileLen"); // PUINT
	ADD_PARAM_NAME("VerInstallFileW", 1, "uFlags"); // DWORD
	ADD_PARAM_NAME("VerInstallFileW", 2, "szSrcFileName"); // LPWSTR
	ADD_PARAM_NAME("VerInstallFileW", 3, "szDestFileName"); // LPWSTR
	ADD_PARAM_NAME("VerInstallFileW", 4, "szSrcDir"); // LPWSTR
	ADD_PARAM_NAME("VerInstallFileW", 5, "szDestDir"); // LPWSTR
	ADD_PARAM_NAME("VerInstallFileW", 6, "szCurDir"); // LPWSTR
	ADD_PARAM_NAME("VerInstallFileW", 7, "szTmpFile"); // LPWSTR
	ADD_PARAM_NAME("VerInstallFileW", 8, "lpuTmpFileLen"); // PUINT
	ADD_PARAM_NAME("VerLanguageNameA", 1, "wLang"); // DWORD
	ADD_PARAM_NAME("VerLanguageNameA", 2, "szLang"); // LPSTR
	ADD_PARAM_NAME("VerLanguageNameA", 3, "nSize"); // DWORD
	ADD_PARAM_NAME("VerLanguageNameW", 1, "wLang"); // DWORD
	ADD_PARAM_NAME("VerLanguageNameW", 2, "szLang"); // LPWSTR
	ADD_PARAM_NAME("VerLanguageNameW", 3, "nSize"); // DWORD
	ADD_PARAM_NAME("VerQueryValueA", 1, "pBlock"); // const LPVOID
	ADD_PARAM_NAME("VerQueryValueA", 2, "lpSubBlock"); // LPCSTR
	ADD_PARAM_NAME("VerQueryValueA", 3, "lplpBuffer"); // LPVOID *
	ADD_PARAM_NAME("VerQueryValueA", 4, "puLen"); // PUINT
	ADD_PARAM_NAME("VerQueryValueW", 1, "pBlock"); // const LPVOID
	ADD_PARAM_NAME("VerQueryValueW", 2, "lpSubBlock"); // LPCWSTR
	ADD_PARAM_NAME("VerQueryValueW", 3, "lplpBuffer"); // LPVOID *
	ADD_PARAM_NAME("VerQueryValueW", 4, "puLen"); // PUINT
	ADD_PARAM_NAME("VerifyScripts", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("VerifyScripts", 2, "lpLocaleScripts"); // LPCWSTR
	ADD_PARAM_NAME("VerifyScripts", 3, "cchLocaleScripts"); // int
	ADD_PARAM_NAME("VerifyScripts", 4, "lpTestScripts"); // LPCWSTR
	ADD_PARAM_NAME("VerifyScripts", 5, "cchTestScripts"); // int
	ADD_PARAM_NAME("VerifyVersionInfoA", 1, "lpVersionInformation"); // LPOSVERSIONINFOEXA
	ADD_PARAM_NAME("VerifyVersionInfoA", 2, "dwTypeMask"); // DWORD
	ADD_PARAM_NAME("VerifyVersionInfoA", 3, "dwlConditionMask"); // DWORDLONG
	ADD_PARAM_NAME("VerifyVersionInfoW", 1, "lpVersionInformation"); // LPOSVERSIONINFOEXW
	ADD_PARAM_NAME("VerifyVersionInfoW", 2, "dwTypeMask"); // DWORD
	ADD_PARAM_NAME("VerifyVersionInfoW", 3, "dwlConditionMask"); // DWORDLONG
	ADD_PARAM_NAME("VirtualAlloc", 1, "lpAddress"); // LPVOID
	ADD_PARAM_NAME("VirtualAlloc", 2, "dwSize"); // SIZE_T
	ADD_PARAM_NAME("VirtualAlloc", 3, "flAllocationType"); // DWORD
	ADD_PARAM_NAME("VirtualAlloc", 4, "flProtect"); // DWORD
	ADD_PARAM_NAME("VirtualAllocEx", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("VirtualAllocEx", 2, "lpAddress"); // LPVOID
	ADD_PARAM_NAME("VirtualAllocEx", 3, "dwSize"); // SIZE_T
	ADD_PARAM_NAME("VirtualAllocEx", 4, "flAllocationType"); // DWORD
	ADD_PARAM_NAME("VirtualAllocEx", 5, "flProtect"); // DWORD
	ADD_PARAM_NAME("VirtualAllocExNuma", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("VirtualAllocExNuma", 2, "lpAddress"); // LPVOID
	ADD_PARAM_NAME("VirtualAllocExNuma", 3, "dwSize"); // SIZE_T
	ADD_PARAM_NAME("VirtualAllocExNuma", 4, "flAllocationType"); // DWORD
	ADD_PARAM_NAME("VirtualAllocExNuma", 5, "flProtect"); // DWORD
	ADD_PARAM_NAME("VirtualAllocExNuma", 6, "nndPreferred"); // DWORD
	ADD_PARAM_NAME("VirtualFree", 1, "lpAddress"); // LPVOID
	ADD_PARAM_NAME("VirtualFree", 2, "dwSize"); // SIZE_T
	ADD_PARAM_NAME("VirtualFree", 3, "dwFreeType"); // DWORD
	ADD_PARAM_NAME("VirtualFreeEx", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("VirtualFreeEx", 2, "lpAddress"); // LPVOID
	ADD_PARAM_NAME("VirtualFreeEx", 3, "dwSize"); // SIZE_T
	ADD_PARAM_NAME("VirtualFreeEx", 4, "dwFreeType"); // DWORD
	ADD_PARAM_NAME("VirtualLock", 1, "lpAddress"); // LPVOID
	ADD_PARAM_NAME("VirtualLock", 2, "dwSize"); // SIZE_T
	ADD_PARAM_NAME("VirtualProtect", 1, "lpAddress"); // LPVOID
	ADD_PARAM_NAME("VirtualProtect", 2, "dwSize"); // SIZE_T
	ADD_PARAM_NAME("VirtualProtect", 3, "flNewProtect"); // DWORD
	ADD_PARAM_NAME("VirtualProtect", 4, "lpflOldProtect"); // PDWORD
	ADD_PARAM_NAME("VirtualProtectEx", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("VirtualProtectEx", 2, "lpAddress"); // LPVOID
	ADD_PARAM_NAME("VirtualProtectEx", 3, "dwSize"); // SIZE_T
	ADD_PARAM_NAME("VirtualProtectEx", 4, "flNewProtect"); // DWORD
	ADD_PARAM_NAME("VirtualProtectEx", 5, "lpflOldProtect"); // PDWORD
	ADD_PARAM_NAME("VirtualQuery", 1, "lpAddress"); // LPCVOID
	ADD_PARAM_NAME("VirtualQuery", 2, "lpBuffer"); // PMEMORY_BASIC_INFORMATION
	ADD_PARAM_NAME("VirtualQuery", 3, "dwLength"); // SIZE_T
	ADD_PARAM_NAME("VirtualQueryEx", 1, "hProcess"); // HANDLE
	ADD_PARAM_NAME("VirtualQueryEx", 2, "lpAddress"); // LPCVOID
	ADD_PARAM_NAME("VirtualQueryEx", 3, "lpBuffer"); // PMEMORY_BASIC_INFORMATION
	ADD_PARAM_NAME("VirtualQueryEx", 4, "dwLength"); // SIZE_T
	ADD_PARAM_NAME("VirtualUnlock", 1, "lpAddress"); // LPVOID
	ADD_PARAM_NAME("VirtualUnlock", 2, "dwSize"); // SIZE_T
	ADD_PARAM_NAME("VkKeyScanA", 1, "ch"); // CHAR
	ADD_PARAM_NAME("VkKeyScanExA", 1, "ch"); // CHAR
	ADD_PARAM_NAME("VkKeyScanExA", 2, "dwhkl"); // HKL
	ADD_PARAM_NAME("VkKeyScanExW", 1, "ch"); // WCHAR
	ADD_PARAM_NAME("VkKeyScanExW", 2, "dwhkl"); // HKL
	ADD_PARAM_NAME("VkKeyScanW", 1, "ch"); // WCHAR
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
