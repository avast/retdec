/**
* @file src/llvmir2hll/hll/bracket_managers/no_bracket_manager.cpp
* @brief A brackets manager that turns off eleminating redundant brackets.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/bracket_managers/no_bracket_manager.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new brackets manager thath turns off eleminating redundant
*        brackets.
*
* @param[in] module The module to be written.
*/
NoBracketManager::NoBracketManager(ShPtr<Module> module):BracketManager(module) {
}

std::string NoBracketManager::getId() const {
	return "NoBracketManager";
}

/**
* @brief Overrided function from base class, because HLL writer call this
*        function to decide if brackets are needed or not.
*
* @param[in] expr Input expression.
*
* @return always @c true.
*/
bool NoBracketManager::areBracketsNeeded(ShPtr<Expression> expr) {
	return true;
}

/**
* @brief Overrided from base class @c BracketManager.
*
* @param[in] currentOperator @a current operator.
* @param[in] prevOperator @a previous operator.
*
* @return item of @c precedenceTable.
*/
BracketManager::ItemOfPrecTable NoBracketManager::checkPrecTable(
		Operators currentOperator, Operators prevOperator) {
	return ItemOfPrecTable();
}

/**
* @brief Overrided from base class BracketManager.
*
* @param currentOperator @a current operator.
*
* @return always @c true.
*/
bool NoBracketManager::isOperatorSupported(Operators currentOperator) {
	return true;
}

} // namespace llvmir2hll
} // namespace retdec
