/**
* @file include/retdec/llvmir2hll/semantics/semantics/libc_semantics/func_never_returns.h
* @brief Provides function funcNeverReturns() for LibcSemantics in the
*        semantics::libc namespace.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_LIBC_SEMANTICS_FUNC_NEVER_RETURNS_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_LIBC_SEMANTICS_FUNC_NEVER_RETURNS_H

#include <optional>
#include <string>

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace libc {

std::optional<bool> funcNeverReturns(const std::string &funcName);

} // namespace libc
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif
