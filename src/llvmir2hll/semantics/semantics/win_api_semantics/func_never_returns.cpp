/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/func_never_returns.cpp
* @brief Implementation of semantics::win_api::funcNeverReturns() for
*        WinAPISemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/func_never_returns.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

namespace {

/**
* @brief This function is used to initialize FUNC_NEVER_RETURNS later in
*        the file.
*/
const StringSet &initFuncNeverReturns() {
	static StringSet fnr;

	// Currently, we only list the functions about which we actually know that
	// they never return. The reason is that when using funcNeverReturns(), we
	// actually only care whether it returns true. If it returns false or no
	// answer at all is irrelevant.

	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682658(v=vs.85).aspx
	fnr.insert("ExitProcess");
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682659(v=vs.85).aspx
	fnr.insert("ExitThread");

	return fnr;
}

/// Functions that do not return.
const StringSet &FUNC_NEVER_RETURNS(initFuncNeverReturns());

} // anonymous namespace

/**
* @brief Implements funcNeverReturns() for WinAPISemantics.
*
* See its description for more details.
*/
Maybe<bool> funcNeverReturns(const std::string &funcName) {
	return hasItem(FUNC_NEVER_RETURNS, funcName) ? Just(true) : Nothing<bool>();
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec
