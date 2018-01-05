/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/h.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/h.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with H.
*/
void initFuncParamNamesMap_H(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("HeapAlloc", 1, "hHeap"); // HANDLE
	ADD_PARAM_NAME("HeapAlloc", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("HeapAlloc", 3, "dwBytes"); // SIZE_T
	ADD_PARAM_NAME("HeapCompact", 1, "hHeap"); // HANDLE
	ADD_PARAM_NAME("HeapCompact", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("HeapCreate", 1, "flOptions"); // DWORD
	ADD_PARAM_NAME("HeapCreate", 2, "dwInitialSize"); // SIZE_T
	ADD_PARAM_NAME("HeapCreate", 3, "dwMaximumSize"); // SIZE_T
	ADD_PARAM_NAME("HeapDestroy", 1, "hHeap"); // HANDLE
	ADD_PARAM_NAME("HeapFree", 1, "hHeap"); // HANDLE
	ADD_PARAM_NAME("HeapFree", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("HeapFree", 3, "lpMem"); // LPVOID
	ADD_PARAM_NAME("HeapLock", 1, "hHeap"); // HANDLE
	ADD_PARAM_NAME("HeapQueryInformation", 1, "HeapHandle"); // HANDLE
	ADD_PARAM_NAME("HeapQueryInformation", 2, "HeapInformationClass"); // HEAP_INFORMATION_CLASS
	ADD_PARAM_NAME("HeapQueryInformation", 3, "HeapInformation"); // PVOID
	ADD_PARAM_NAME("HeapQueryInformation", 4, "HeapInformationLength"); // SIZE_T
	ADD_PARAM_NAME("HeapQueryInformation", 5, "ReturnLength"); // PSIZE_T
	ADD_PARAM_NAME("HeapReAlloc", 1, "hHeap"); // HANDLE
	ADD_PARAM_NAME("HeapReAlloc", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("HeapReAlloc", 3, "lpMem"); // LPVOID
	ADD_PARAM_NAME("HeapReAlloc", 4, "dwBytes"); // SIZE_T
	ADD_PARAM_NAME("HeapSetInformation", 1, "HeapHandle"); // HANDLE
	ADD_PARAM_NAME("HeapSetInformation", 2, "HeapInformationClass"); // HEAP_INFORMATION_CLASS
	ADD_PARAM_NAME("HeapSetInformation", 3, "HeapInformation"); // PVOID
	ADD_PARAM_NAME("HeapSetInformation", 4, "HeapInformationLength"); // SIZE_T
	ADD_PARAM_NAME("HeapSize", 1, "hHeap"); // HANDLE
	ADD_PARAM_NAME("HeapSize", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("HeapSize", 3, "lpMem"); // LPCVOID
	ADD_PARAM_NAME("HeapUnlock", 1, "hHeap"); // HANDLE
	ADD_PARAM_NAME("HeapValidate", 1, "hHeap"); // HANDLE
	ADD_PARAM_NAME("HeapValidate", 2, "dwFlags"); // DWORD
	ADD_PARAM_NAME("HeapValidate", 3, "lpMem"); // LPCVOID
	ADD_PARAM_NAME("HeapWalk", 1, "hHeap"); // HANDLE
	ADD_PARAM_NAME("HeapWalk", 2, "lpEntry"); // LPPROCESS_HEAP_ENTRY
	ADD_PARAM_NAME("HideCaret", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("HiliteMenuItem", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("HiliteMenuItem", 2, "hMenu"); // HMENU
	ADD_PARAM_NAME("HiliteMenuItem", 3, "uIDHiliteItem"); // UINT
	ADD_PARAM_NAME("HiliteMenuItem", 4, "uHilite"); // UINT
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
