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
	WhileTrueToUForLoopOptimizer(Module* module, ValueAnalysis* va);

	virtual std::string getId() const override { return "WhileTrueToUForLoop"; }

private:
	virtual void doOptimization() override;

	void tryReplacementWithUForLoop(WhileLoopStmt* whileLoop);
	void initializeReplacement(WhileLoopStmt* stmt);
	bool gatherInfoAboutOptimizedWhileLoop();
	UForLoopStmt* tryConversionToUForLoop();
	EmptyStmt* getLastEmptyStatement(Statement* stmts) const;
	void removeUselessSucessors(UForLoopStmt* forLoop);
	void performReplacement(UForLoopStmt* forLoop);
	void removeStatementsToBeRemoved();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(WhileLoopStmt* stmt) override;
	/// @}

private:
	/// Analysis of values.
	ValueAnalysis* va = nullptr;

	/// While loop that is being optimized.
	WhileLoopStmt* whileLoop = nullptr;

	/// Splitted loop that is being optimized.
	SplittedWhileTrueLoop* splittedLoop = nullptr;

	/// Can the loop be optimized?
	bool canBeOptimized;

	/// Statements to be removed when the optimization is successful.
	StmtSet toRemoveStmts;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
