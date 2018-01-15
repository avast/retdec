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
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~RecursiveCFGBuilder() override;

	virtual void buildCFG() override;

	static ShPtr<RecursiveCFGBuilder> create();

private:
	/// Mapping of a statement into its corresponding node.
	using StmtNodeMapping = std::unordered_map<ShPtr<Statement>, ShPtr<CFG::Node>>;

private:
	RecursiveCFGBuilder();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<Function> func) override;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	virtual void visit(ShPtr<CallStmt> stmt) override;
	virtual void visit(ShPtr<ReturnStmt> stmt) override;
	virtual void visit(ShPtr<EmptyStmt> stmt) override;
	virtual void visit(ShPtr<IfStmt> stmt) override;
	virtual void visit(ShPtr<SwitchStmt> stmt) override;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) override;
	virtual void visit(ShPtr<ForLoopStmt> stmt) override;
	virtual void visit(ShPtr<UForLoopStmt> stmt) override;
	virtual void visit(ShPtr<BreakStmt> stmt) override;
	virtual void visit(ShPtr<ContinueStmt> stmt) override;
	virtual void visit(ShPtr<GotoStmt> stmt) override;
	virtual void visit(ShPtr<UnreachableStmt> stmt) override;
	virtual void visitStmt(ShPtr<Statement> stmt, bool visitSuccessors = true,
		bool visitNestedStmts = true) override;
	/// @}

	ShPtr<CFG::Node> addNode(ShPtr<Statement> stmt);
	void addStatement(ShPtr<Statement> stmt);
	void addForwardOrBackwardEdge(ShPtr<Statement> stmt,
		ShPtr<Expression> edgeCond = nullptr);
	ShPtr<CFG::Node> getIndirectSuccessor(ShPtr<Statement> stmt);
	void visitForOrUForLoop(ShPtr<Statement> loop, ShPtr<Statement> body);

private:
	/// Currently generated node.
	ShPtr<CFG::Node> currNode;

	/// Mapping between a statement @c S and a node @c N of which @c S is the
	/// first statement.
	StmtNodeMapping firstStmtNodeMapping;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
