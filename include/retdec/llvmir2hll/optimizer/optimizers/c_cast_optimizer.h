/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/c_cast_optimizer.h
* @brief Removes useless casts when emitting C code.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_C_CAST_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_C_CAST_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class AssignStmt;
class CastExpr;
class Expression;
class Module;
class VarDefStmt;

/**
* @brief Removes casts that are in the C language implicit.
*
* The following conversions in the C language are automatic, so we can remove
* them.
*
* 1. From integer to integer:
* @code
* int16_t a = 42;
* int32_t b = (int32_t)a;
* int32_t c = (int16_t)a;
* @endcode
* is replaced with
* @code
* int16_t a = 42;
* int32_t b = a;
* int32_t c = a;
* @endcode
*
* 2. From float to integer:
* @code
* float32_t a = 23.452;
* int32_t b = (int32_t)a;
* @endcode
* is replaced with
* @code
* float32_t a = 23.452;
* int32_t b = a;
* @endcode
*
* 3. From integer to float:
* @code
* int32_t a = 42;
* float32_t b = (float32_t)a;
* @endcode
* is replaced with
* @code
* int32_t a = 42;
* float32_t b = a;
* @endcode
*
* 4. From float to float:
* @code
* float16_t a = 23.452;
* float32_t b = (float32_t)a;
* @endcode
* is replaced with
* @code
* float16_t a = 23.452;
* float32_t b = a;
* @endcode
*
* These optimizations are used in the following expressions and statements:
* @code
* - Assignments: float32_t b; b = (float32_t)a;
* - Variable definitions: float32_t b = (float32_t)a;
* - Call expressions and statements: func((float32_t)a);
* - Return statements: int32_t random() { return (int32_t)4; }
* - Binary expressions: (int32_t)a + (int16_t)b
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class CCastOptimizer final: public FuncOptimizer {
public:
	CCastOptimizer(ShPtr<Module> module);

	virtual ~CCastOptimizer() override;

	ShPtr<Expression> checkAndOptimize(ShPtr<Expression> dst,
		ShPtr<Expression> src);

	virtual std::string getId() const override { return "CCast"; }

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<CallExpr> expr) override;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	virtual void visit(ShPtr<ReturnStmt> stmt) override;
	/// @}

private:
	/// @c true if a part of code has been optimized, @c false otherwise.
	bool optimized;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
