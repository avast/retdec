/**
* @file include/llvmir2hll/semantics/semantics/default_semantics.h
* @brief A default semantics which doesn't know anything.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_DEFAULT_SEMANTICS_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_DEFAULT_SEMANTICS_H

#include <string>

#include "llvmir2hll/semantics/semantics.h"
#include "llvmir2hll/support/smart_ptr.h"

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
	virtual Maybe<std::string> getMainFuncName() const override;
	virtual Maybe<std::string> getCHeaderFileForFunc(
		const std::string &funcName) const override;
	virtual Maybe<bool> funcNeverReturns(
		const std::string &funcName) const override;
	virtual Maybe<std::string> getNameOfVarStoringResult(
		const std::string &funcName) const override;
	virtual Maybe<std::string> getNameOfParam(const std::string &funcName,
		unsigned paramPos) const override;
	virtual Maybe<IntStringMap> getSymbolicNamesForParam(
		const std::string &funcName, unsigned paramPos) const override;
	/// @}

protected:
	DefaultSemantics();
};

} // namespace llvmir2hll

#endif
