/**
* @file src/llvmir2hll/support/variable_replacer.cpp
* @brief Implementation of VariableReplacer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/variable_replacer.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new replacer.
*
* @param[in] oldVar Old variable.
* @param[in] newVar New variable.
*/
VariableReplacer::VariableReplacer(ShPtr<Variable> oldVar, ShPtr<Variable> newVar):
	OrderedAllVisitor(), oldVar(oldVar), newVar(newVar) {}

/**
* @brief Destructs the replacer.
*/
VariableReplacer::~VariableReplacer() {}

/**
* @brief Replaces @a oldVar with @a newVar in @a func.
*/
void VariableReplacer::replaceVariable(ShPtr<Variable> oldVar,
		ShPtr<Variable> newVar, ShPtr<Function> func) {
	ShPtr<VariableReplacer> replacer(new VariableReplacer(oldVar, newVar));
	replacer->performReplace(func);
}

/**
* @brief Performs the replace in @a func.
*/
void VariableReplacer::performReplace(ShPtr<Function> func) {
	visitStmt(func->getBody());
}

void VariableReplacer::visit(ShPtr<Variable> var) {
	if (var == oldVar) {
		lastStmt->replace(var, newVar);
	}
}

} // namespace llvmir2hll
} // namespace retdec
