/**
* @file src/llvmir2hll/analysis/alias_analysis/alias_analyses/simple_alias_analysis.cpp
* @brief Implementation SimpleAliasAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analyses/simple_alias_analysis.h"
#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analysis_factory.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("simple", SIMPLE_ALIAS_ANALYSIS_ID, AliasAnalysisFactory,
	SimpleAliasAnalysis::create);

namespace {
/// The empty set of variables.
const VarSet EMPTY_VAR_SET = VarSet();
}

/**
* @brief Constructs a new analysis.
*/
SimpleAliasAnalysis::SimpleAliasAnalysis(): AliasAnalysis(),
	OrderedAllVisitor(true, true), allAddressedVars(), funcAddressedVarsMap(),
	varFuncMap(), func() {}

/**
* @brief Destructs the analysis.
*/
SimpleAliasAnalysis::~SimpleAliasAnalysis() {}

/**
* @brief Creates a new alias analysis.
*/
ShPtr<AliasAnalysis> SimpleAliasAnalysis::create() {
	return ShPtr<SimpleAliasAnalysis>(new SimpleAliasAnalysis());
}

std::string SimpleAliasAnalysis::getId() const {
	return SIMPLE_ALIAS_ANALYSIS_ID;
}

void SimpleAliasAnalysis::init(ShPtr<Module> module) {
	AliasAnalysis::init(module);

	allAddressedVars.clear();
	funcAddressedVarsMap.clear();
	varFuncMap.clear();
	func.reset();
	restart();

	// Check the initializers of global variables whether they contain a taking
	// of an address of a variable.
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		if (ShPtr<Expression> init = (*i)->getInitializer()) {
			init->accept(this);
		}
	}

	// For every function...
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		func = *i;

		// Add an entry to varFuncMap for every local variable, including
		// parameters.
		VarSet localVars((*i)->getLocalVars(true));
		for (const auto &var : localVars) {
			varFuncMap[var] = func;
		}

		// Compute variables whose address is taken in the function. First,
		// however, initialize funcAddressedVarsMap for the current function so
		// that if no variables are found, the map will return the empty set.
		funcAddressedVarsMap[func];
		visitStmt(func->getBody());
	}
}

const VarSet &SimpleAliasAnalysis::mayPointTo(ShPtr<Variable> var) const {
	if (!isa<PointerType>(var->getType())) {
		// Assumption: a non-pointer variable never points to any variable.
		return EMPTY_VAR_SET;
	}

	if (hasItem(globalVars, var)) {
		// Assumption: a global pointer may point to any variable that has its
		// address taken.
		return allAddressedVars;
	}

	// Assumption: a local pointer may point to any local variable that has its
	// address taken.
	auto funcOfVarIter = varFuncMap.find(var);
	if (funcOfVarIter == varFuncMap.end()) {
		// We have no information about the given pointer -> assume that it
		// may alias with all the variables that have their address taken.
		return allAddressedVars;
	}
	auto mayPointToVarsIter = funcAddressedVarsMap.find(funcOfVarIter->second);
	ASSERT_MSG(mayPointToVarsIter != funcAddressedVarsMap.end(),
		"Addressed variables for the given function haven't been computed.");
	return mayPointToVarsIter->second;
}

ShPtr<Variable> SimpleAliasAnalysis::pointsTo(ShPtr<Variable> var) const {
	// Currently, we always return the null pointer because the analysis is not
	// robust enough to find whether a pointer always points to a single
	// variable.
	return ShPtr<Variable>();
}

bool SimpleAliasAnalysis::mayBePointed(ShPtr<Variable> var) const {
	// Assumption: a variable may be pointed if and only if its address is
	// taken.
	return hasItem(allAddressedVars, var);
}

void SimpleAliasAnalysis::visit(ShPtr<AddressOpExpr> expr) {
	if (ShPtr<Variable> var = cast<Variable>(expr->getOperand())) {
		allAddressedVars.insert(var);
		// Initializers of global variables may contain the `&` operator.
		// However, there is no function associated with them. Hence the
		// following check.
		if (func) {
			funcAddressedVarsMap[func].insert(var);
		}
	} else {
		OrderedAllVisitor::visit(expr);
	}
}

} // namespace llvmir2hll
} // namespace retdec
