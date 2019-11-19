/**
* @file include/retdec/llvmir2hll/semantics/semantics/default_semantics.h
* @brief A default semantics which doesn't know anything.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_DEFAULT_SEMANTICS_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_DEFAULT_SEMANTICS_H

#include <optional>
#include <string>

#include "retdec/llvmir2hll/semantics/semantics.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A default semantics which doesn't know anything.
*
* This class overrides all the pure virtual functions from Semantics so that
* they always return an "I don't know" answer. Use this class as the base class
* of your semantics if you just want to override selected functions only.
*
* Instances of this class have reference object semantics.
*/
class DefaultSemantics: public Semantics {
public:
	static ShPtr<Semantics> create();

	/// @name Semantics Interface
	/// @{
	virtual std::string getId() const override;
	virtual std::optional<std::string> getMainFuncName() const override;
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
	DefaultSemantics();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
