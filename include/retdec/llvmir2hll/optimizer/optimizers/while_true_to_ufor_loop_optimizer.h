/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/while_true_to_ufor_loop_optimizer.h
* @brief Optimizes while loops into for universal for loops.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_WHILE_TRUE_TO_UFOR_LOOP_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_WHILE_TRUE_TO_UFOR_LOOP_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/utils/loop_optimizer.h"

namespace retdec {
namespace llvmir2hll {

class ValueAnalysis;

/**
* @brief Optimizes while loops into universal for loops.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class WhileTrueToUForLoopOptimizer final: public FuncOptimizer {
public:
	WhileTrueToUForLoopOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va);

	virtual ~WhileTrueToUForLoopOptimizer() override;

	virtual std::string getId() const override { return "WhileTrueToUForLoop"; }

private:
	virtual void doOptimization() override;

	void tryReplacementWithUForLoop(ShPtr<WhileLoopStmt> whileLoop);
	void initializeReplacement(ShPtr<WhileLoopStmt> stmt);
	bool gatherInfoAboutOptimizedWhileLoop();
	ShPtr<UForLoopStmt> tryConversionToUForLoop();
	ShPtr<EmptyStmt> getLastEmptyStatement(ShPtr<Statement> stmts) const;
	void removeUselessSucessors(ShPtr<UForLoopStmt> forLoop);
	void performReplacement(ShPtr<UForLoopStmt> forLoop);
	void removeStatementsToBeRemoved();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) override;
	/// @}

private:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// While loop that is being optimized.
	ShPtr<WhileLoopStmt> whileLoop;

	/// Splitted loop that is being optimized.
	ShPtr<SplittedWhileTrueLoop> splittedLoop;

	/// Can the loop be optimized?
	bool canBeOptimized;

	/// Statements to be removed when the optimization is successful.
	StmtSet toRemoveStmts;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
