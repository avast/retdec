/**
* @file include/retdec/llvmir2hll/ir/constant.h
* @brief A base class for all constants.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CONSTANT_H
#define RETDEC_LLVMIR2HLL_IR_CONSTANT_H

#include "retdec/llvmir2hll/ir/expression.h"

namespace retdec {
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
} // namespace retdec

#endif
