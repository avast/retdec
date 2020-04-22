/**
* @file include/retdec/llvmir2hll/semantics/semantics/win_api_semantics.h
* @brief Semantics for Windows API.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_H

#include <optional>
#include <string>

#include "retdec/llvmir2hll/semantics/semantics/default_semantics.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Semantics for Windows API.
*
* This class provides the semantics for Windows API.
*
* Instances of this class have reference object semantics.
*/
class WinAPISemantics: public DefaultSemantics {
public:
	static ShPtr<Semantics> create();

	/// @name Semantics Interface
	/// @{
	virtual std::string getId() const override;
	virtual std::optional<std::string> getCHeaderFileForFunc(
		const std::string &funcName) const override;
	virtual std::optional<bool> funcNeverReturns(
		const std::string &funcName) const override;
	virtual std::optional<std::string> getNameOfVarStoringResult(
		const std::string &funcName) const override;
	virtual std::optional<std::string> getNameOfParam(const std::string &funcName,
		unsigned paramPos) const override;
	virtual std::optional<IntStringMap> getSymbolicNamesForParam(
		const std::string &funcName, unsigned paramPos) const override;
	/// @}

protected:
	WinAPISemantics();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
