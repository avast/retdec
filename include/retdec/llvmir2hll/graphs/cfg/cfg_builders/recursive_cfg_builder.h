/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_builders/recursive_cfg_builder.h
* @brief A recursive creator of control-flow graphs (CFGs) from functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_BUILDERS_RECURSIVE_CFG_BUILDER_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_BUILDERS_RECURSIVE_CFG_BUILDER_H

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builder.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A recursive creator of control-flow graphs (CFGs) from functions.
*
* @deprecated Use of this class to build CFGs is deprecated. Use
*             NonRecursiveCFGBuilder, which can handle large code without
*             requiring too much space on the stack.
*/
class RecursiveCFGBuilder: public CFGBuilder,
		private OrderedAllVisitor {
public:
	virtual void buildCFG() override;

	static RecursiveCFGBuilder* create();

private:
	/// Mapping of a statement into its corresponding node.
	using StmtNodeMapping = std::unordered_map<Statement*, CFG::Node*>;

private:
	RecursiveCFGBuilder();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(Function* func) override;
	virtual void visit(AssignStmt* stmt) override;
	virtual void visit(VarDefStmt* stmt) override;
	virtual void visit(CallStmt* stmt) override;
	virtual void visit(ReturnStmt* stmt) override;
	virtual void visit(EmptyStmt* stmt) override;
	virtual void visit(IfStmt* stmt) override;
	virtual void visit(SwitchStmt* stmt) override;
	virtual void visit(WhileLoopStmt* stmt) override;
	virtual void visit(ForLoopStmt* stmt) override;
	virtual void visit(UForLoopStmt* stmt) override;
	virtual void visit(BreakStmt* stmt) override;
	virtual void visit(ContinueStmt* stmt) override;
	virtual void visit(GotoStmt* stmt) override;
	virtual void visit(UnreachableStmt* stmt) override;
	virtual void visitStmt(Statement* stmt, bool visitSuccessors = true,
		bool visitNestedStmts = true) override;
	/// @}

	CFG::Node* addNode(Statement* stmt);
	void addStatement(Statement* stmt);
	void addForwardOrBackwardEdge(Statement* stmt,
		Expression* edgeCond = nullptr);
	CFG::Node* getIndirectSuccessor(Statement* stmt);
	void visitForOrUForLoop(Statement* loop, Statement* body);

private:
	/// Currently generated node.
	CFG::Node* currNode = nullptr;

	/// Mapping between a statement @c S and a node @c N of which @c S is the
	/// first statement.
	StmtNodeMapping firstStmtNodeMapping;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
