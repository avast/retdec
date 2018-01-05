/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_builders/non_recursive_cfg_builder.h
* @brief A non-recursive creator of control-flow graphs (CFGs) from functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_BUILDERS_NON_RECURSIVE_CFG_BUILDER_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_BUILDERS_NON_RECURSIVE_CFG_BUILDER_H

#include <queue>
#include <unordered_map>
#include <vector>

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builder.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitor_adapter.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Statement;

/**
* @brief A non-recursive creator of control-flow graphs (CFGs) from functions.
*/
class NonRecursiveCFGBuilder: public CFGBuilder, private VisitorAdapter {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~NonRecursiveCFGBuilder() override;

	virtual void buildCFG() override;

	static ShPtr<NonRecursiveCFGBuilder> create();

private:
	/// Structure for jobs that have to be performed.
	struct Job {
		/**
		* @brief Constructs a new job.
		*
		* @param[in] pred Predecessor node.
		* @param[in] cond Condition.
		* @param[in] stmt First statement of job.
		*/
		Job(ShPtr<CFG::Node> pred, ShPtr<Expression> cond, ShPtr<Statement>
			stmt): pred(pred), cond(cond), stmt(stmt) {}

		/// Predecessor node of this job.
		ShPtr<CFG::Node> pred;

		/// Condition for edge.
		ShPtr<Expression> cond;

		/// First statement from which job starts.
		ShPtr<Statement> stmt;
	};

	/// Structure for edges that will be added to CFG.
	struct EdgeToAdd {
		/**
		* @brief Constructs a new edge to add.
		*
		* @param[in] node First node of connection.
		* @param[in] succStmt Statement of second one node.
		* @param[in] cond Condition for edge.
		*/
		EdgeToAdd(ShPtr<CFG::Node> node, ShPtr<Statement> succStmt,
			ShPtr<Expression> cond = nullptr):
				node(node), succStmt(succStmt), cond(cond) {}

		/// Predecessor node.
		ShPtr<CFG::Node> node;

		/// Statement of second one node.
		ShPtr<Statement> succStmt;

		/// Condition for edge.
		ShPtr<Expression> cond;
	};

	/// Queue of jobs.
	using JobQueue = std::queue<Job>;

	/// Vector of edges.
	using EdgesToAdd = std::vector<EdgeToAdd>;

	/// Mapping of a statement into its corresponding node.
	using StmtNodeMapping = std::unordered_map<ShPtr<Statement>, ShPtr<CFG::Node>>;

private:
	NonRecursiveCFGBuilder();

	/// @name Visitor Interface
	/// @{
	using VisitorAdapter::visit;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<BreakStmt> stmt) override;
	virtual void visit(ShPtr<CallStmt> stmt) override;
	virtual void visit(ShPtr<ContinueStmt> stmt) override;
	virtual void visit(ShPtr<EmptyStmt> stmt) override;
	virtual void visit(ShPtr<ForLoopStmt> stmt) override;
	virtual void visit(ShPtr<UForLoopStmt> stmt) override;
	virtual void visit(ShPtr<GotoStmt> stmt) override;
	virtual void visit(ShPtr<IfStmt> stmt) override;
	virtual void visit(ShPtr<ReturnStmt> stmt) override;
	virtual void visit(ShPtr<SwitchStmt> stmt) override;
	virtual void visit(ShPtr<UnreachableStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) override;
	/// @}

	void addEdgeFromCurrNodeToSuccNode(ShPtr<Statement> stmt,
		EdgesToAdd &edgesToAdd,
		ShPtr<Expression> edgeCond = nullptr);
	void addEdgeFromVector(const EdgeToAdd &edge);
	void addJobToQueue(ShPtr<CFG::Node> pred, ShPtr<Expression> cond,
		ShPtr<Statement> stmt);
	void addEdgesFromVector(const EdgesToAdd &edgesToAdd);
	void addStatement(ShPtr<Statement> stmt);
	void addStmtToNodeAndToMapOfStmtToNode(ShPtr<Statement> stmt);
	void resolveGotoTargets(ShPtr<Statement> stmt);
	void createAndAddNode();
	void createEdgesToBeAdded();
	void createEntryNode();
	void createExitNode();
	void createNewNodeAndConnectWithPredNode(ShPtr<Statement> stmt);
	void createNewNodeForIfSwitchForWhileStmtAndAddStmtToNode(
		ShPtr<Statement> stmt);
	void createNewNodeIfStmtHasSucc(ShPtr<Statement> stmt);
	void createOtherNodes();
	void doJob(const Job &job);
	void doJobs();
	void initializeCFGBuild();
	void purgeCFG();
	void validateCFG();
	void visitForOrUForLoop(ShPtr<Statement> loop, ShPtr<Statement> body);

private:
	/// Queue of all jobs.
	JobQueue jobQueue;

	/// Vector of saved edges for nodes that will be added first.
	EdgesToAdd edgesToAddFirst;

	/// Vector of saved edges that have to be added at the end.
	EdgesToAdd edgesToAddLast;

	/// Currently generated node.
	ShPtr<CFG::Node> currNode;

	/// Mapping of an empty statement to its node.
	StmtNodeMapping emptyStmtToNodeMap;

	/// Signalizes if we want to iterate through statements or not.
	bool stopIterNextStmts;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
