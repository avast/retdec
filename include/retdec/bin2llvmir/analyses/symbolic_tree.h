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

/**
 * Tracking values through load/store operations using reaching definition
 * analysis.
 *
 * For optimization reasons, some data members of this structure are static,
 * i.e. common for all instances.
 * The typical usage of this class is: creation -> simplification -> pattern
 * detection -> action based on pattern -> throwing away the current instance
 * before creating and processing the new one.
 * In such a case, global data members and global behaviour configuration is
 * not a problem. If you, for whatever reason, want to store instances, keep
 * this in mind.
 */
class SymbolicTree
{
	// Ctors, dtors.
	//
	public:
		SymbolicTree(
				llvm::Value* v,
				unsigned maxNodeLevel = 10);
		SymbolicTree(
				ReachingDefinitionsAnalysis& rda,
				llvm::Value* v,
				unsigned maxNodeLevel = 10);
		SymbolicTree(
				ReachingDefinitionsAnalysis& rda,
				llvm::Value* v,
				std::map<llvm::Value*, llvm::Value*>* val2val,
				unsigned maxNodeLevel = 10);

	// Copy/move ctors, operators, etc.
	//
	public:
		SymbolicTree(const SymbolicTree& other) = default;
		SymbolicTree(SymbolicTree&& other) = default;
		SymbolicTree& operator=(SymbolicTree&& other);
		bool operator==(const SymbolicTree& o) const;
		bool operator!=(const SymbolicTree& o) const;
		friend std::ostream& operator<<(
				std::ostream& out,
				const SymbolicTree& s);
		std::string print(unsigned indent = 0) const;

	// Misc methods.
	//
	public:
		bool isNullary() const;
		bool isUnary() const;
		bool isBinary() const;
		bool isTernary() const;
		bool isNary(unsigned N) const;

		unsigned getLevel() const;

		void simplifyNode();
		void solveMemoryLoads(FileImage* image);

		SymbolicTree* getMaxIntValue();

	// Tree linearization methods.
	//
	public:
		std::vector<SymbolicTree*> getPreOrder() const;
		std::vector<SymbolicTree*> getPostOrder() const;
		std::vector<SymbolicTree*> getLevelOrder() const;

	// Public data.
	//
	public:
		llvm::Value* value = nullptr;
		llvm::Value* user = nullptr;
		std::vector<SymbolicTree> ops;

	// Global SymbolicTree configuration methods and data.
	//
	public:
		static bool isVal2ValMapUsed();
		static void setAbi(Abi* abi);
		static void setConfig(Config* config);
		static void setToDefaultConfiguration();
		static void setTrackThroughAllocaLoads(bool b);
		static void setTrackThroughGeneralRegisterLoads(bool b);
		static void setTrackOnlyFlagRegisters(bool b);
		static void setSimplifyAtCreation(bool b);
		static void setNaryLimit(unsigned n);

	private:
		static Abi* _abi;
		static Config* _config;
		static bool _val2valUsed;
		static bool _trackThroughAllocaLoads;
		static bool _trackThroughGeneralRegisterLoads;
		static bool _trackOnlyFlagRegisters;
		static bool _simplifyAtCreation;
		static unsigned _naryLimit;

	// Private methods.
	//
	private:
		void expandNode(
				ReachingDefinitionsAnalysis* RDA,
				std::map<llvm::Value*, llvm::Value*>* val2val,
				unsigned maxNodeLevel,
				std::unordered_set<llvm::Value*>& processed);

		void _simplifyNode();
		void fixLevel(unsigned level = 0);

		void _getPreOrder(std::vector<SymbolicTree*>& res) const;
		void _getPostOrder(std::vector<SymbolicTree*>& res) const;

	// Private ctors, dtors.
	// This is a private constructor, do not use it. It is made public only
	// so it can be used in std::vector<>::emplace_back().
	//
	public:
		SymbolicTree(
				ReachingDefinitionsAnalysis* rda,
				llvm::Value* v,
				std::map<llvm::Value*, llvm::Value*>* val2val,
				unsigned maxNodeLevel = 14);
		SymbolicTree(
				ReachingDefinitionsAnalysis* rda,
				llvm::Value* v,
				llvm::Value* u,
				std::unordered_set<llvm::Value*>& processed,
				unsigned nodeLevel,
				unsigned maxNodeLevel,
				std::map<llvm::Value*, llvm::Value*>* v2v = nullptr);

	// Private data.
	//
	private:
		unsigned _level = 1;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
