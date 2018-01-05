/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/if_structure_optimizer.h
* @brief Optimizes the structure of if statements.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_IF_STRUCTURE_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_IF_STRUCTURE_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Optimizes the structure of if statements.
*
* This optimization optimizes the structure of if statements. More
* specifically, it transforms if/else-if/else clauses so the resulting code
* become more readable.
*
* The following transformations are performed:
*
* (1) If there is an if-else statement, where the body of the if clause ends
* with a return or unreachable statement, then the body of the else clause can
* be put after the if statement and the else clause can be removed. For
* example, the following code
* @code
* if a < 1:
*    return 0
* else:
*    i = 0
* @endcode
* can be optimized into
* @code
* if a < 1:
*    return 0
* i = 0
* @endcode
*
* (2) Similar to (1), but the return/unreachable statement is in the if clause.
* For example, the following code
* @code
* if a < 1:
*    i = 0
* else:
*    return 0
* @endcode
* can be optimized into
* @code
* if a >= 1:
*    return 0
* i = 0
* @endcode
*
* (3) To decrease the level of nesting, we transform every piece of code of the
* form
* @code
* if cond:
*     // ... (A)
*     return/unreachable (A)
* // ... (B)
* return/unreachable (B)
* @endcode
* to
* @code
* if not cond:
*     // ... (B)
*     return/unreachable (B)
* // ... (A)
* return/unreachable (A)
* @endcode
* However, this is done only if (A) contains more statements than (B). In this
* way, a hierarchy of if statements like this
* @code
* if condA:
*     if condB:
*         if condC:
*             // ...
*             return/unreachable (D)
*         return/unreachable (C)
*     return/unreachable (B)
* return/unreachable (A)
* @endcode
* gets squeezed into a more readable form
* @code
* if not condA:
*     return/unreachable (A)
* if not condB:
*     return/unreachable (B)
* if not condC:
*     return/unreachable (C)
* // ...
* return/unreachable (D)
* @endcode
*
* (4) If there are two successive if statements with no else-if/else clauses
* and with identical bodies (both ending with a return/unreachable statement),
* the conditions may be joined by the @c or operator, so only one if statement
* will remain (of course, their bodies are merged). For example, the following
* code
* @code
* if i == 0:
*     return 0
* if j == 0:
*     return 0
* @endcode
* may be transformed into
* @code
* if i == 0 or j == 0:
*     return 0
* @endcode
*
* (5) If there is an else clause with no statements, we can remove it. For
* example, the following code
* @code
* if a == b:
*     return 0
* else:
*     pass
* @endcode
* may be transformed into
* @code
* if a == b:
*     return 0
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class IfStructureOptimizer final: public FuncOptimizer {
public:
	IfStructureOptimizer(ShPtr<Module> module);

	virtual ~IfStructureOptimizer() override;

	virtual std::string getId() const override { return "IfStructure"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<IfStmt> stmt) override;
	/// @}

	bool tryOptimization1(ShPtr<IfStmt> stmt);
	bool tryOptimization2(ShPtr<IfStmt> stmt);
	bool tryOptimization3(ShPtr<IfStmt> stmt);
	bool tryOptimization4(ShPtr<IfStmt> stmt);
	bool tryOptimization5(ShPtr<IfStmt> stmt);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
