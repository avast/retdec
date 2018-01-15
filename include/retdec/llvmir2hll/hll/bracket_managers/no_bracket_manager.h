/**
* @file include/retdec/llvmir2hll/hll/bracket_managers/no_bracket_manager.h
* @brief A brackets manager that turns off eleminating redundant brackets.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_BRACKET_MANAGERS_NO_BRACKET_MANAGER_H
#define RETDEC_LLVMIR2HLL_HLL_BRACKET_MANAGERS_NO_BRACKET_MANAGER_H

#include "retdec/llvmir2hll/hll/bracket_manager.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A class that that turns off eleminating redundant brackets.
*
* For this purpose need to change @a emitTargetCode(...) in chosen HLL writer.
* Need to change there
* @code
* bracketsManager = ShPtr<BracketManager>(new ..BracketManager(module));
* to
* bracketsManager = ShPtr<BracketManager>(new NoBracketManager(module));
* @endcode
*/
class NoBracketManager: public BracketManager {
public:
	NoBracketManager(ShPtr<Module> module);

	virtual std::string getId() const override;

	bool areBracketsNeeded(ShPtr<Expression> expr);

private:
	virtual ItemOfPrecTable checkPrecTable(Operators currentOperator,
		Operators prevOperator) override;
	virtual bool isOperatorSupported(Operators currentOperator) override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
