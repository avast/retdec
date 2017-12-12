/**
* @file include/llvmir2hll/ir/constant.h
* @brief A base class for all constants.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_IR_CONSTANT_H
#define LLVMIR2HLL_IR_CONSTANT_H

#include "llvmir2hll/ir/expression.h"

namespace llvmir2hll {

/**
* @brief A base class for all constants.
*
* Instances of this class have reference object semantics.
*/
class Constant: public Expression {
public:
	virtual ~Constant() = 0;

protected:
	Constant();
};

} // namespace llvmir2hll

#endif
