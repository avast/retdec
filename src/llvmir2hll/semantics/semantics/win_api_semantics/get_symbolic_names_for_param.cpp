/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_symbolic_names_for_param.cpp
* @brief Implementation of semantics::win_api::getSymbolicNamesForParam() for
*        WinAPISemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_symbolic_names_for_param.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_symbolic_names_for_param.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

namespace {

/**
* @brief This function is used to initialize FUNC_PARAMS_MAP later in the file.
*/
const FuncParamsMap &initFuncParamsMap() {
	static FuncParamsMap funcParamsMap;

	// Temporary maps used to store the symbols for the current parameter of
	// the current function. In this way, we don't have to keep separate maps
	// for every function and every parameter. The only downside is that before
	// adding new data into it, it has to be cleared.
	ParamSymbolsMap paramSymbolsMap;
	IntStringMap symbolicNamesMap;

	//
	// #include <windows.h>
	// LONG WINAPI RegOpenKey(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegOpenKeyEx(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegOpenKeyExA(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegOpenKeyExW(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegSetKeyValue(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegSetKeyValueA(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegSetKeyValueW(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegCreateKey(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegCreateKeyA(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegCreateKeyW(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegCreateKeyEx(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegCreateKeyExA(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegCreateKeyExW(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegOpenKey(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegOpenKeyA(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegOpenKeyW(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegOpenKeyEx(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegOpenKeyExA(HKEY hKey, /* other parameters */);
	// LONG WINAPI RegOpenKeyExW(HKEY hKey, /* other parameters */);
	//
	// Info from: <winreg.h>
	//
	paramSymbolsMap.clear();
	// hKey
	symbolicNamesMap.clear();
	// We have to use -2147483647 - 1 instead of -2147483648 because the latter
	// is recognized as 2147483648, and only negated afterwards. This use of
	// -2147483648 issues a warning on some compilers. See
	// http://stackoverflow.com/q/9941261/2580955
	symbolicNamesMap[-2147483647 - 1] = "HKEY_CLASSES_ROOT";
	symbolicNamesMap[-2147483647] = "HKEY_CURRENT_USER";
	symbolicNamesMap[-2147483646] = "HKEY_LOCAL_MACHINE";
	symbolicNamesMap[-2147483645] = "HKEY_USRS";
	symbolicNamesMap[-2147483644] = "HKEY_PERFORMANCE_DATA";
	symbolicNamesMap[-2147483643] = "HKEY_CURRENT_CONFIG";
	symbolicNamesMap[-2147483642] = "HKEY_DYN_DATA";
	paramSymbolsMap[1] = symbolicNamesMap;
	funcParamsMap["RegOpenKey"] = paramSymbolsMap;
	funcParamsMap["RegOpenKey"] = paramSymbolsMap;
	funcParamsMap["RegOpenKeyEx"] = paramSymbolsMap;
	funcParamsMap["RegOpenKeyExA"] = paramSymbolsMap;
	funcParamsMap["RegOpenKeyExW"] = paramSymbolsMap;
	funcParamsMap["RegSetKeyValue"] = paramSymbolsMap;
	funcParamsMap["RegSetKeyValueA"] = paramSymbolsMap;
	funcParamsMap["RegSetKeyValueW"] = paramSymbolsMap;
	funcParamsMap["RegCreateKey"] = paramSymbolsMap;
	funcParamsMap["RegCreateKeyA"] = paramSymbolsMap;
	funcParamsMap["RegCreateKeyW"] = paramSymbolsMap;
	funcParamsMap["RegCreateKeyEx"] = paramSymbolsMap;
	funcParamsMap["RegCreateKeyExA"] = paramSymbolsMap;
	funcParamsMap["RegCreateKeyExW"] = paramSymbolsMap;

	return funcParamsMap;
}

/// Mapping of function names into symbolic names of their parameters.
const FuncParamsMap &FUNC_PARAMS_MAP(initFuncParamsMap());

} // anonymous namespace

/**
* @brief Implements getSymbolicNamesForParam() for WinAPISemantics.
*
* See its description for more details.
*/
Maybe<IntStringMap> getSymbolicNamesForParam(const std::string &funcName,
		unsigned paramPos) {
	return getSymbolicNamesForParamFromMap(funcName, paramPos, FUNC_PARAMS_MAP);
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
