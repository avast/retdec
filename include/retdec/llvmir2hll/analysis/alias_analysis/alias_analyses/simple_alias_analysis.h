/**
* @file include/retdec/llvmir2hll/analysis/alias_analysis/alias_analyses/simple_alias_analysis.h
* @brief A very simple alias analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_ANALYSIS_ALIAS_ANALYSIS_ALIAS_ANALYSES_SIMPLE_ALIAS_ANALYSIS_H
#define RETDEC_LLVMIR2HLL_ANALYSIS_ALIAS_ANALYSIS_ALIAS_ANALYSES_SIMPLE_ALIAS_ANALYSIS_H

#include <string>

#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analysis.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"

namespace retdec {
namespace llvmir2hll {

class Module;
class Variable;

/**
* @brief A very simple alias analysis.
*
* The analysis utilizes the following assumptions:
*  - a non-pointer variable never points to any variable
*  - a global pointer may point to any variable that has its address taken
*  - a local pointer may point to any local variable that has its address taken
*  - a variable may be pointed if and only if its address is taken
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class SimpleAliasAnalysis: public AliasAnalysis, private OrderedAllVisitor {
public:
	virtual ~SimpleAliasAnalysis() override;

	static ShPtr<AliasAnalysis> create();

	virtual void init(ShPtr<Module> module) override;
	virtual std::string getId() const override;
	virtual const VarSet &mayPointTo(ShPtr<Variable> var) const override;
	virtual ShPtr<Variable> pointsTo(ShPtr<Variable> var) const override;
	virtual bool mayBePointed(ShPtr<Variable> var) const override;

private:
	/// Mapping of a function into a set of variables.
	using FuncVarSetMap = std::map<ShPtr<Function>, VarSet>;

	/// Mapping of a variable into a function.
	using VarFuncMap = std::map<ShPtr<Variable>, ShPtr<Function>>;

private:
	SimpleAliasAnalysis();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<AddressOpExpr> expr) override;
	/// @}

private:
	/// All variables in the module whose address is taken.
	VarSet allAddressedVars;

	/// Mapping of a function into the set of variables whose address
	/// is taken in there. Function arguments are included.
	FuncVarSetMap funcAddressedVarsMap;

	/// Mapping of a local variable into the function in which it is defined.
	/// Function arguments are included.
	VarFuncMap varFuncMap;

	/// Currently traversed function.
	ShPtr<Function> func;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
