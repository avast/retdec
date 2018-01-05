/**
* @file include/retdec/llvmir2hll/analysis/alias_analysis/alias_analysis.h
* @brief A base class for all alias analyses.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_ALIAS_ANALYSIS_ALIAS_ANALYSIS_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_ALIAS_ANALYSIS_ALIAS_ANALYSIS_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Module;
class Variable;

/**
* @brief A base class for all alias analyses.
*
* Use create() to create instances. After create(), the alias analysis has to
* be initialized by calling init(). If this member function is not called prior
* to calling analysis member functions, like @c mayPointTo(), the behavior of
* these member functions is undefined.
*
* Instances of this class have reference object semantics.
*/
class AliasAnalysis: private retdec::utils::NonCopyable {
public:
	virtual ~AliasAnalysis() = 0;

	virtual void init(ShPtr<Module> module);
	virtual bool isInitialized() const;

	/**
	* @brief Returns the set of variables to which @a var may point to.
	*
	* If @a var is not a pointer, the empty set is returned. If @c
	* pointsTo(var) returns a variable (non-null), then this function returns
	* the singleton set containing the result of @c pointsTo(var).
	*
	* If the analysis hasn't been initialized, the behavior of this member
	* function is undefined.
	*/
	virtual const VarSet &mayPointTo(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns the variable to which @a var always points.
	*
	* If the variable may point to several variables or it is unknown to what
	* the variable points to, the null pointer is returned.
	*
	* If the analysis hasn't been initialized, the behavior of this member
	* function is undefined.
	*/
	virtual ShPtr<Variable> pointsTo(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if a pointer may point to @a var, @c false
	*        otherwise.
	*/
	virtual bool mayBePointed(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns the ID of the analysis.
	*/
	virtual std::string getId() const = 0;

protected:
	AliasAnalysis();

protected:
	/// The current module.
	ShPtr<Module> module;

	/// Global variables in @c module. This is here to speedup the analysis. By
	/// using this set, we do not have to ask @c module every time we need such
	/// information.
	VarSet globalVars;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
