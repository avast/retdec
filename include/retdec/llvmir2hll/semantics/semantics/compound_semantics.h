/**
* @file include/retdec/llvmir2hll/semantics/semantics/compound_semantics.h
* @brief A class providing compound semantics from several different
*        semantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_COMPOUND_SEMANTICS_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_COMPOUND_SEMANTICS_H

#include <deque>
#include <string>

#include "retdec/llvmir2hll/semantics/semantics.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A class providing compound semantics from several different
*        semantics.
*
* For example, consider that we have semantics for the standard C library (@c
* sem1), for the extensions to this library as defined by POSIX (@c sem2), and
* some specific semantics for the GCC compiler version 4.8 on GNU/Linux (@c
* sem3). Then, after creating this semantics by calling create(), we may do the
* following actions to set-up this compound semantics:
* @code
* compoundSemantics->appendSemantics(sem1);
* compoundSemantics->appendSemantics(sem2);
* compoundSemantics->appendSemantics(sem3);
* @endcode
* Then, when calling a function from the Semantics' interface, @c sem1 is asked
* first. If it knows the answer, it is returned. Otherwise, if it doesn't know
* the answer, @c sem2 is asked and so on. When none of the semantics know the
* answer, an "I don't know" answer is returned.
*
* This class is not registered in SemanticsFactory.
*
* To create an instance of it by simply providing a list of identifiers of
* semantics to be used, use CompoundSemanticsBuilder.
*
* Instances of this class have reference object semantics.
*/
class CompoundSemantics: public Semantics {
public:
	static ShPtr<CompoundSemantics> create();

	void prependSemantics(ShPtr<Semantics> semantics);
	void appendSemantics(ShPtr<Semantics> semantics);

	/// @name Semantics Interface
	/// @{
	virtual std::string getId() const override { return "compound"; }
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
	/// A list of semantics.
	using SemanticsList = std::deque<ShPtr<Semantics>>;

protected:
	CompoundSemantics();

protected:
	/// A list of provided semantics.
	SemanticsList providedSemantics;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
