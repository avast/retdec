/**
* @file include/retdec/bin2llvmir/optimizations/phi2seq/phi2seq.h
* @brief Solves parallel processing of PHI nodes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PHI2SEQ_PHI2SEQ_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PHI2SEQ_PHI2SEQ_H

#include <vector>

#include <llvm/IR/IRBuilder.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/analyses/var_depend_analysis.h"

namespace retdec {
namespace bin2llvmir {

/**
* @brief Optimization that solves the problem of parallel processing of PHI
*        nodes.
*
* @pre The <em>Assign names to anonymous instructions</em>
*      (<tt>-instnamer</tt>) pass has to be run before this optimization. This
*      optimization automatically runs it.
*
* This optimization is needed because PHI nodes in a single block in LLVM IR
* are executed in parallel basic block but our output languages like C or
* Python are sequential. Hence, we need to transform the parallel processing to
* equivalent sequential processing.
*
* We can divide this problem into two sub-problems. The first sub-problem
* represents the dependency of variables like this:
* @code
* .bb
* %A = phi i32 [ %D, %bb1 ], [ 10, %0 ]
* %B = phi i32 [ %A, %bb1 ], [ 66, %0 ]
* @endcode
* If we look at this example with sequential processing, to variable A was
* assigned the value of variable D and this value was assigned in B which is
* not equivalent with parallel processing. The solution is to order PHI nodes
* to a correct sequential order which is equivalent with parallel processing
* like this:
* @code
*   %B = phi i32 [ %A, %bb1 ], [ 66, %0 ]
*   %A = phi i32 [ %D, %bb1 ], [ 10, %0 ]
* @endcode
*
* The second sub-problem that we need to solve is when we have a cycle
* dependency of variables in PHI nodes. For example:
* @code
* .bb:
*   %A = phi i32 [ %B, %bb1 ], [ 1, %0 ]
*   %B = phi i32 [ %C, %bb1 ], [ 2, %0 ]
*   %C = phi i32 [ %A, %bb1 ], [ 3, %0 ]
* @endcode
* All PHI nodes are performed in parallel but we need for the back-end an
* equivalent sequential processing. A solution is to create new PHI nodes in a
* new basic block an update the dependencies. Something like this:
* @code
* .bb.phi2seq.pre:
*   %C.phi2seq.tmp = [ %C, %bb1 ]
*   br label %.bb
*
* .bb:
*   %A = phi i32 [ %B, %.bb.phi2seq.pre ], [ 1, %0 ]
*   %B = phi i32 [ %C.phi2seq.tmp, %.bb.phi2seq.pre ], [ 2, %0 ]
*   %C = phi i32 [ %A, %.bb.phi2seq.pre ], [ 3, %0 ]
* @endcode
*
* This optimization solves both of these sub-problems, thus making sequential
* processing of PHI nodes possible.
*/
class PHI2Seq: public llvm::FunctionPass {
public:
	PHI2Seq();
	virtual ~PHI2Seq() override;

	static const char *getName() { return NAME; }

	virtual bool runOnFunction(llvm::Function &func) override;
	virtual void getAnalysisUsage(llvm::AnalysisUsage &au) const override;

public:
	static char ID;

private:
	/// Name of the optimization.
	static const char *NAME;

	/**
	* @brief Structure for PHI node on which we substitute values.
	*/
	struct PHINodeToSubs {
		/**
		* @brief Constructs a new @c PHINodeToSubs.
		*
		* @param[in] phiNodeToSubs PHI node to substitute.
		* @param[in] oldValue Old value that will be substituted.
		* @param[in] newValue New value to substitute.
		*/
		PHINodeToSubs(llvm::PHINode *phiNodeToSubs, llvm::Value *oldValue,
			llvm::Value *newValue): phiNodeToSubs(phiNodeToSubs),
				oldValue(oldValue), newValue(newValue) {}

		/// PHI node to substitute.
		llvm::PHINode *phiNodeToSubs;

		/// Old value that will be substituted.
		llvm::Value *oldValue;

		/// New value to to substitute.
		llvm::Value *newValue;
	};

	/// Vector of @c PHINodeToSubs.
	using PHINodeToSubsVec = std::vector<PHINodeToSubs>;

private:
	llvm::BasicBlock &createPreBBAndSolveConnection(
		const VarDependAnalysis::BBVecOfPHINodes &bbWithPHINodesVec,
		llvm::BasicBlock &currBB);
	void createTmpPHINodes(llvm::IRBuilder<> &builder,
		const VarDependAnalysis::BBVecOfPHINodes &bbWithPHINodesVec);
	void initVarDependAnalysis(llvm::BasicBlock &bb);
	void iteratePHINodesAndInitVarDependAnalysis(llvm::BasicBlock &bb);
	void iterateIncValuesAndInitVarDependAnalysis(llvm::PHINode &phiNode);
	void orderDependentPHINodes(llvm::BasicBlock &bb,
		const VarDependAnalysis::PHINodeVec &nonCyclesDependResult);
	void orderDependentPHINodesAndSolveCycles(llvm::BasicBlock &bb);
	void replaceValueForPHINode(llvm::PHINode &phiNodeToUpdate, llvm::Value
		&oldValue, llvm::Value &newValue, llvm::BasicBlock &pred);
	void solveCycleVarDependency(llvm::BasicBlock &bb,
		const VarDependAnalysis::StringBBVecOfPHINodesMap &cyclesDetectResult);
	void updateBBTermInstr(llvm::BasicBlock &bbToUpdate, llvm::BasicBlock
		&oldSucc, llvm::BasicBlock &newSucc);
	void updateBBWithCycle(llvm::BasicBlock &bb, llvm::BasicBlock &oldBB, llvm::
		BasicBlock &newBB);
	void updatePredecessorsInPHINodes(llvm::BasicBlock &bb, llvm::BasicBlock
		&oldBB, llvm::BasicBlock &newBB);

private:
	/// PHI nodes dependency analysis.
	VarDependAnalysis varDependAnalysis;

	/// Vector of PHI nodes on which are substitute values.
	PHINodeToSubsVec phiNodeToSubsVec;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
