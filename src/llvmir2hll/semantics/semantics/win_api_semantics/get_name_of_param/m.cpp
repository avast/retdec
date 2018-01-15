/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/m.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/m.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with M.
*/
void initFuncParamNamesMap_M(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("MakeAbsoluteSD", 1, "pSelfRelativeSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("MakeAbsoluteSD", 2, "pAbsoluteSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("MakeAbsoluteSD", 3, "lpdwAbsoluteSecurityDescriptorSize"); // LPDWORD
	ADD_PARAM_NAME("MakeAbsoluteSD", 4, "pDacl"); // PACL
	ADD_PARAM_NAME("MakeAbsoluteSD", 5, "lpdwDaclSize"); // LPDWORD
	ADD_PARAM_NAME("MakeAbsoluteSD", 6, "pSacl"); // PACL
	ADD_PARAM_NAME("MakeAbsoluteSD", 7, "lpdwSaclSize"); // LPDWORD
	ADD_PARAM_NAME("MakeAbsoluteSD", 8, "pOwner"); // PSID
	ADD_PARAM_NAME("MakeAbsoluteSD", 9, "lpdwOwnerSize"); // LPDWORD
	ADD_PARAM_NAME("MakeAbsoluteSD", 10, "pPrimaryGroup"); // PSID
	ADD_PARAM_NAME("MakeAbsoluteSD", 11, "lpdwPrimaryGroupSize"); // LPDWORD
	ADD_PARAM_NAME("MakeAbsoluteSD2", 1, "pSelfRelativeSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("MakeAbsoluteSD2", 2, "lpdwBufferSize"); // LPDWORD
	ADD_PARAM_NAME("MakeSelfRelativeSD", 1, "pAbsoluteSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("MakeSelfRelativeSD", 2, "pSelfRelativeSecurityDescriptor"); // PSECURITY_DESCRIPTOR
	ADD_PARAM_NAME("MakeSelfRelativeSD", 3, "lpdwBufferLength"); // LPDWORD
	ADD_PARAM_NAME("MapDialogRect", 1, "hDlg"); // HWND
	ADD_PARAM_NAME("MapDialogRect", 2, "lpRect"); // LPRECT
	ADD_PARAM_NAME("MapGenericMask", 1, "AccessMask"); // PDWORD
	ADD_PARAM_NAME("MapGenericMask", 2, "GenericMapping"); // PGENERIC_MAPPING
	ADD_PARAM_NAME("MapUserPhysicalPages", 1, "VirtualAddress"); // PVOID
	ADD_PARAM_NAME("MapUserPhysicalPages", 2, "NumberOfPages"); // ULONG_PTR
	ADD_PARAM_NAME("MapUserPhysicalPages", 3, "PageArray"); // PULONG_PTR
	ADD_PARAM_NAME("MapUserPhysicalPagesScatter", 1, "VirtualAddresses"); // PVOID *
	ADD_PARAM_NAME("MapUserPhysicalPagesScatter", 2, "NumberOfPages"); // ULONG_PTR
	ADD_PARAM_NAME("MapUserPhysicalPagesScatter", 3, "PageArray"); // PULONG_PTR
	ADD_PARAM_NAME("MapViewOfFile", 1, "hFileMappingObject"); // HANDLE
	ADD_PARAM_NAME("MapViewOfFile", 2, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("MapViewOfFile", 3, "dwFileOffsetHigh"); // DWORD
	ADD_PARAM_NAME("MapViewOfFile", 4, "dwFileOffsetLow"); // DWORD
	ADD_PARAM_NAME("MapViewOfFile", 5, "dwNumberOfBytesToMap"); // SIZE_T
	ADD_PARAM_NAME("MapViewOfFileEx", 1, "hFileMappingObject"); // HANDLE
	ADD_PARAM_NAME("MapViewOfFileEx", 2, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("MapViewOfFileEx", 3, "dwFileOffsetHigh"); // DWORD
	ADD_PARAM_NAME("MapViewOfFileEx", 4, "dwFileOffsetLow"); // DWORD
	ADD_PARAM_NAME("MapViewOfFileEx", 5, "dwNumberOfBytesToMap"); // SIZE_T
	ADD_PARAM_NAME("MapViewOfFileEx", 6, "lpBaseAddress"); // LPVOID
	ADD_PARAM_NAME("MapViewOfFileExNuma", 1, "hFileMappingObject"); // HANDLE
	ADD_PARAM_NAME("MapViewOfFileExNuma", 2, "dwDesiredAccess"); // DWORD
	ADD_PARAM_NAME("MapViewOfFileExNuma", 3, "dwFileOffsetHigh"); // DWORD
	ADD_PARAM_NAME("MapViewOfFileExNuma", 4, "dwFileOffsetLow"); // DWORD
	ADD_PARAM_NAME("MapViewOfFileExNuma", 5, "dwNumberOfBytesToMap"); // SIZE_T
	ADD_PARAM_NAME("MapViewOfFileExNuma", 6, "lpBaseAddress"); // LPVOID
	ADD_PARAM_NAME("MapViewOfFileExNuma", 7, "nndPreferred"); // DWORD
	ADD_PARAM_NAME("MapVirtualKeyA", 1, "uCode"); // UINT
	ADD_PARAM_NAME("MapVirtualKeyA", 2, "uMapType"); // UINT
	ADD_PARAM_NAME("MapVirtualKeyExA", 1, "uCode"); // UINT
	ADD_PARAM_NAME("MapVirtualKeyExA", 2, "uMapType"); // UINT
	ADD_PARAM_NAME("MapVirtualKeyExA", 3, "dwhkl"); // HKL
	ADD_PARAM_NAME("MapVirtualKeyExW", 1, "uCode"); // UINT
	ADD_PARAM_NAME("MapVirtualKeyExW", 2, "uMapType"); // UINT
	ADD_PARAM_NAME("MapVirtualKeyExW", 3, "dwhkl"); // HKL
	ADD_PARAM_NAME("MapVirtualKeyW", 1, "uCode"); // UINT
	ADD_PARAM_NAME("MapVirtualKeyW", 2, "uMapType"); // UINT
	ADD_PARAM_NAME("MapWindowPoints", 1, "hWndFrom"); // HWND
	ADD_PARAM_NAME("MapWindowPoints", 2, "hWndTo"); // HWND
	ADD_PARAM_NAME("MapWindowPoints", 3, "lpPoints"); // LPPOINT
	ADD_PARAM_NAME("MapWindowPoints", 4, "cPoints"); // UINT
	ADD_PARAM_NAME("MaskBlt", 1, "hdcDest"); // HDC
	ADD_PARAM_NAME("MaskBlt", 2, "xDest"); // int
	ADD_PARAM_NAME("MaskBlt", 3, "yDest"); // int
	ADD_PARAM_NAME("MaskBlt", 4, "width"); // int
	ADD_PARAM_NAME("MaskBlt", 5, "height"); // int
	ADD_PARAM_NAME("MaskBlt", 6, "hdcSrc"); // HDC
	ADD_PARAM_NAME("MaskBlt", 7, "xSrc"); // int
	ADD_PARAM_NAME("MaskBlt", 8, "ySrc"); // int
	ADD_PARAM_NAME("MaskBlt", 9, "hbmMask"); // HBITMAP
	ADD_PARAM_NAME("MaskBlt", 10, "xMask"); // int
	ADD_PARAM_NAME("MaskBlt", 11, "yMask"); // int
	ADD_PARAM_NAME("MaskBlt", 12, "rop"); // DWORD
	ADD_PARAM_NAME("MenuItemFromPoint", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("MenuItemFromPoint", 2, "hMenu"); // HMENU
	ADD_PARAM_NAME("MenuItemFromPoint", 3, "ptScreen"); // POINT
	ADD_PARAM_NAME("MessageBeep", 1, "uType"); // UINT
	ADD_PARAM_NAME("MessageBoxA", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("MessageBoxA", 2, "lpText"); // LPCSTR
	ADD_PARAM_NAME("MessageBoxA", 3, "lpCaption"); // LPCSTR
	ADD_PARAM_NAME("MessageBoxA", 4, "uType"); // UINT
	ADD_PARAM_NAME("MessageBoxExA", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("MessageBoxExA", 2, "lpText"); // LPCSTR
	ADD_PARAM_NAME("MessageBoxExA", 3, "lpCaption"); // LPCSTR
	ADD_PARAM_NAME("MessageBoxExA", 4, "uType"); // UINT
	ADD_PARAM_NAME("MessageBoxExA", 5, "wLanguageId"); // WORD
	ADD_PARAM_NAME("MessageBoxExW", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("MessageBoxExW", 2, "lpText"); // LPCWSTR
	ADD_PARAM_NAME("MessageBoxExW", 3, "lpCaption"); // LPCWSTR
	ADD_PARAM_NAME("MessageBoxExW", 4, "uType"); // UINT
	ADD_PARAM_NAME("MessageBoxExW", 5, "wLanguageId"); // WORD
	ADD_PARAM_NAME("MessageBoxIndirectA", 1, "lpmbp"); // CONST MSGBOXPARAMSA *
	ADD_PARAM_NAME("MessageBoxIndirectW", 1, "lpmbp"); // CONST MSGBOXPARAMSW *
	ADD_PARAM_NAME("MessageBoxW", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("MessageBoxW", 2, "lpText"); // LPCWSTR
	ADD_PARAM_NAME("MessageBoxW", 3, "lpCaption"); // LPCWSTR
	ADD_PARAM_NAME("MessageBoxW", 4, "uType"); // UINT
	ADD_PARAM_NAME("ModifyMenuA", 1, "hMnu"); // HMENU
	ADD_PARAM_NAME("ModifyMenuA", 2, "uPosition"); // UINT
	ADD_PARAM_NAME("ModifyMenuA", 3, "uFlags"); // UINT
	ADD_PARAM_NAME("ModifyMenuA", 4, "uIDNewItem"); // UINT_PTR
	ADD_PARAM_NAME("ModifyMenuA", 5, "lpNewItem"); // LPCSTR
	ADD_PARAM_NAME("ModifyMenuW", 1, "hMnu"); // HMENU
	ADD_PARAM_NAME("ModifyMenuW", 2, "uPosition"); // UINT
	ADD_PARAM_NAME("ModifyMenuW", 3, "uFlags"); // UINT
	ADD_PARAM_NAME("ModifyMenuW", 4, "uIDNewItem"); // UINT_PTR
	ADD_PARAM_NAME("ModifyMenuW", 5, "lpNewItem"); // LPCWSTR
	ADD_PARAM_NAME("ModifyWorldTransform", 1, "hdc"); // HDC
	ADD_PARAM_NAME("ModifyWorldTransform", 2, "lpxf"); // CONST XFORM *
	ADD_PARAM_NAME("ModifyWorldTransform", 3, "mode"); // DWORD
	ADD_PARAM_NAME("MonitorFromPoint", 1, "pt"); // POINT
	ADD_PARAM_NAME("MonitorFromPoint", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MonitorFromRect", 1, "lprc"); // LPCRECT
	ADD_PARAM_NAME("MonitorFromRect", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MonitorFromWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("MonitorFromWindow", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MoveFileA", 1, "lpExistingFileName"); // LPCSTR
	ADD_PARAM_NAME("MoveFileA", 2, "lpNewFileName"); // LPCSTR
	ADD_PARAM_NAME("MoveFileExA", 1, "lpExistingFileName"); // LPCSTR
	ADD_PARAM_NAME("MoveFileExA", 2, "lpNewFileName"); // LPCSTR
	ADD_PARAM_NAME("MoveFileExA", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MoveFileExW", 1, "lpExistingFileName"); // LPCWSTR
	ADD_PARAM_NAME("MoveFileExW", 2, "lpNewFileName"); // LPCWSTR
	ADD_PARAM_NAME("MoveFileExW", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MoveFileTransactedA", 1, "lpExistingFileName"); // LPCSTR
	ADD_PARAM_NAME("MoveFileTransactedA", 2, "lpNewFileName"); // LPCSTR
	ADD_PARAM_NAME("MoveFileTransactedA", 3, "lpProgressRoutine"); // LPPROGRESS_ROUTINE
	ADD_PARAM_NAME("MoveFileTransactedA", 4, "lpData"); // LPVOID
	ADD_PARAM_NAME("MoveFileTransactedA", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MoveFileTransactedA", 6, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("MoveFileTransactedW", 1, "lpExistingFileName"); // LPCWSTR
	ADD_PARAM_NAME("MoveFileTransactedW", 2, "lpNewFileName"); // LPCWSTR
	ADD_PARAM_NAME("MoveFileTransactedW", 3, "lpProgressRoutine"); // LPPROGRESS_ROUTINE
	ADD_PARAM_NAME("MoveFileTransactedW", 4, "lpData"); // LPVOID
	ADD_PARAM_NAME("MoveFileTransactedW", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MoveFileTransactedW", 6, "hTransaction"); // HANDLE
	ADD_PARAM_NAME("MoveFileW", 1, "lpExistingFileName"); // LPCWSTR
	ADD_PARAM_NAME("MoveFileW", 2, "lpNewFileName"); // LPCWSTR
	ADD_PARAM_NAME("MoveFileWithProgressA", 1, "lpExistingFileName"); // LPCSTR
	ADD_PARAM_NAME("MoveFileWithProgressA", 2, "lpNewFileName"); // LPCSTR
	ADD_PARAM_NAME("MoveFileWithProgressA", 3, "lpProgressRoutine"); // LPPROGRESS_ROUTINE
	ADD_PARAM_NAME("MoveFileWithProgressA", 4, "lpData"); // LPVOID
	ADD_PARAM_NAME("MoveFileWithProgressA", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MoveFileWithProgressW", 1, "lpExistingFileName"); // LPCWSTR
	ADD_PARAM_NAME("MoveFileWithProgressW", 2, "lpNewFileName"); // LPCWSTR
	ADD_PARAM_NAME("MoveFileWithProgressW", 3, "lpProgressRoutine"); // LPPROGRESS_ROUTINE
	ADD_PARAM_NAME("MoveFileWithProgressW", 4, "lpData"); // LPVOID
	ADD_PARAM_NAME("MoveFileWithProgressW", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MoveToEx", 1, "hdc"); // HDC
	ADD_PARAM_NAME("MoveToEx", 2, "x"); // int
	ADD_PARAM_NAME("MoveToEx", 3, "y"); // int
	ADD_PARAM_NAME("MoveToEx", 4, "lppt"); // LPPOINT
	ADD_PARAM_NAME("MoveWindow", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("MoveWindow", 2, "X"); // int
	ADD_PARAM_NAME("MoveWindow", 3, "Y"); // int
	ADD_PARAM_NAME("MoveWindow", 4, "nWidth"); // int
	ADD_PARAM_NAME("MoveWindow", 5, "nHeight"); // int
	ADD_PARAM_NAME("MoveWindow", 6, "bRepaint"); // WINBOOL
	ADD_PARAM_NAME("MsgWaitForMultipleObjects", 1, "nCount"); // DWORD
	ADD_PARAM_NAME("MsgWaitForMultipleObjects", 2, "pHandles"); // CONST HANDLE *
	ADD_PARAM_NAME("MsgWaitForMultipleObjects", 3, "fWaitAll"); // WINBOOL
	ADD_PARAM_NAME("MsgWaitForMultipleObjects", 4, "dwMilliseconds"); // DWORD
	ADD_PARAM_NAME("MsgWaitForMultipleObjects", 5, "dwWakeMask"); // DWORD
	ADD_PARAM_NAME("MsgWaitForMultipleObjectsEx", 1, "nCount"); // DWORD
	ADD_PARAM_NAME("MsgWaitForMultipleObjectsEx", 2, "pHandles"); // CONST HANDLE *
	ADD_PARAM_NAME("MsgWaitForMultipleObjectsEx", 3, "dwMilliseconds"); // DWORD
	ADD_PARAM_NAME("MsgWaitForMultipleObjectsEx", 4, "dwWakeMask"); // DWORD
	ADD_PARAM_NAME("MsgWaitForMultipleObjectsEx", 5, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MulDiv", 1, "nNumber"); // int
	ADD_PARAM_NAME("MulDiv", 2, "nNumerator"); // int
	ADD_PARAM_NAME("MulDiv", 3, "nDenominator"); // int
	ADD_PARAM_NAME("MultiByteToWideChar", 1, "CodePage"); // UINT
	ADD_PARAM_NAME("MultiByteToWideChar", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("MultiByteToWideChar", 3, "lpMultiByteStr"); // LPCSTR
	ADD_PARAM_NAME("MultiByteToWideChar", 4, "cbMultiByte"); // int
	ADD_PARAM_NAME("MultiByteToWideChar", 5, "lpWideCharStr"); // LPWSTR
	ADD_PARAM_NAME("MultiByteToWideChar", 6, "cchWideChar"); // int
	ADD_PARAM_NAME("MultinetGetConnectionPerformanceA", 1, "lpNetResource"); // LPNETRESOURCEA
	ADD_PARAM_NAME("MultinetGetConnectionPerformanceA", 2, "lpNetConnectInfoStruct"); // LPNETCONNECTINFOSTRUCT
	ADD_PARAM_NAME("MultinetGetConnectionPerformanceW", 1, "lpNetResource"); // LPNETRESOURCEW
	ADD_PARAM_NAME("MultinetGetConnectionPerformanceW", 2, "lpNetConnectInfoStruct"); // LPNETCONNECTINFOSTRUCT

	ADD_PARAM_NAME("mouse_event", 1, "dwFlags"); // DWORD
	ADD_PARAM_NAME("mouse_event", 2, "dx"); // DWORD
	ADD_PARAM_NAME("mouse_event", 3, "dy"); // DWORD
	ADD_PARAM_NAME("mouse_event", 4, "dwData"); // DWORD
	ADD_PARAM_NAME("mouse_event", 5, "dwExtraInfo"); // ULONG_PTR
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
