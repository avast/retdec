/**
 * @file include/retdec/bin2llvmir/analyses/symbolic_tree.h
 * @brief Construction of symbolic tree from the given node.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 *
 * This is an implementation of symbolic interpret. It is provided with
 * an initial node (llvm::Value) and it builds symbolic tree representing
 * the value of the node.
 */

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_SYMBOLIC_TREE_H
#define RETDEC_BIN2LLVMIR_ANALYSES_SYMBOLIC_TREE_H

#include <set>
#include <unordered_set>
#include <vector>

#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class SymbolicTree
{
	public:
		SymbolicTree(
				ReachingDefinitionsAnalysis& rda,
				llvm::Value* v,
				std::map<llvm::Value*, llvm::Value*>* val2val = nullptr,
				unsigned maxUniqueNodes = 80,
				bool debug = false);
		SymbolicTree(
				ReachingDefinitionsAnalysis* rda,
				llvm::Value* v,
				llvm::Value* u,
				std::unordered_set<llvm::Value*>& processed,
				unsigned maxUniqueNodes,
				std::map<llvm::Value*, llvm::Value*>* v2v = nullptr);

		SymbolicTree(const SymbolicTree& other) = default;
		SymbolicTree(SymbolicTree&& other) = default;
		SymbolicTree& operator=(SymbolicTree&& other);
		friend std::ostream& operator<<(
				std::ostream& out,
				const SymbolicTree& s);

		bool isConstructedSuccessfully() const;
		bool isVal2ValMapUsed() const;
		void removeRegisterValues(Config* config);
		void removeGeneralRegisterLoads(Config* config);
		void removeStackLoads(Config* config);

		void simplifyNode(Config* config);
		void _simplifyNode(Config* config);
		void simplifyNodeLoadStore();

		void solveMemoryLoads(FileImage* image);
		SymbolicTree* getMaxIntValue();
		std::string print(unsigned indent = 0) const;

		std::vector<SymbolicTree*> getPreOrder() const;
		std::vector<SymbolicTree*> getPostOrder() const;

	private:
		void expandNode(
				ReachingDefinitionsAnalysis* RDA,
				std::map<llvm::Value*, llvm::Value*>* val2val,
				unsigned maxUniqueNodes,
				std::unordered_set<llvm::Value*>& processed);
		void propagateFlags();

		void _getPreOrder(std::vector<SymbolicTree*>& res) const;
		void _getPostOrder(std::vector<SymbolicTree*>& res) const;

	public:
		llvm::Value* value = nullptr;
		llvm::Value* user = nullptr;
		std::vector<SymbolicTree> ops;

	private:
		bool _failed = false;
		bool _val2valUsed = false;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
