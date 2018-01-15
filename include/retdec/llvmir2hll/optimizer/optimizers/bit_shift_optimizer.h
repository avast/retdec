/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/bit_shift_optimizer.h
* @brief Change bit shift to division or multiplication.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_BIT_SHIFT_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_BIT_SHIFT_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class BinaryOpExpr;

/**
* @brief Change bit shift to division or multiplication
*
* This optimizer removes bit shift operations and change them to division or
* multiplication.
*
* A left arithmetical/logical shift by @c n is equivalent to multiplying by @c
* 2^n (provided the value does not overflow), while a right arithmetical shift
* by @c n of a two's complement value is equivalent to dividing by @c 2^n and
* rounding toward negative infinity.
*
* Some conditions for the optimization:
* 1. Left shift:
*    IntType <<(logical/arithmetical) unsigned/signed(only >= 0) constant
* 2. Right shift logical/arithmetical:
*    unsigned IntType, unsigned/signed(only >=0) constant >>(logical/arithmetical)
*    unsigned/signed(only >= 0) constant
*
* Examples:
* The following left shift
* @code
* return 8 << 2;
* @endcode
* can be optimized to
* @code
* return 8 * 4;
* @endcode
* The following right shift
* @code
* return 8 >> 2;
* @endcode
* can be optimized to
* @code
* return 8 / 4;
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class BitShiftOptimizer final: public Optimizer {
public:
	BitShiftOptimizer(ShPtr<Module> module);

	virtual ~BitShiftOptimizer() override;

	virtual std::string getId() const override { return "BitShift"; }

private:
	void doOptimization() override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<BitShlOpExpr> expr) override;
	virtual void visit(ShPtr<BitShrOpExpr> expr) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
