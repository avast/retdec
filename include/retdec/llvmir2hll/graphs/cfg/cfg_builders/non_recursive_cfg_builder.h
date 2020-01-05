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
	virtual void buildCFG() override;

	static NonRecursiveCFGBuilder* create();

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
		Job(CFG::Node* pred, Expression* cond, Statement*
			stmt): pred(pred), cond(cond), stmt(stmt) {}

		/// Predecessor node of this job.
		CFG::Node* pred = nullptr;

		/// Condition for edge.
		Expression* cond = nullptr;

		/// First statement from which job starts.
		Statement* stmt = nullptr;
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
		EdgeToAdd(CFG::Node* node, Statement* succStmt,
			Expression* cond = nullptr):
				node(node), succStmt(succStmt), cond(cond) {}

		/// Predecessor node.
		CFG::Node* node = nullptr;

		/// Statement of second one node.
		Statement* succStmt = nullptr;

		/// Condition for edge.
		Expression* cond = nullptr;
	};

	/// Queue of jobs.
	using JobQueue = std::queue<Job>;

	/// Vector of edges.
	using EdgesToAdd = std::vector<EdgeToAdd>;

	/// Mapping of a statement into its corresponding node.
	using StmtNodeMapping = std::unordered_map<Statement*, CFG::Node*>;

private:
	NonRecursiveCFGBuilder();

	/// @name Visitor Interface
	/// @{
	using VisitorAdapter::visit;
	virtual void visit(AssignStmt* stmt) override;
	virtual void visit(BreakStmt* stmt) override;
	virtual void visit(CallStmt* stmt) override;
	virtual void visit(ContinueStmt* stmt) override;
	virtual void visit(EmptyStmt* stmt) override;
	virtual void visit(ForLoopStmt* stmt) override;
	virtual void visit(UForLoopStmt* stmt) override;
	virtual void visit(GotoStmt* stmt) override;
	virtual void visit(IfStmt* stmt) override;
	virtual void visit(ReturnStmt* stmt) override;
	virtual void visit(SwitchStmt* stmt) override;
	virtual void visit(UnreachableStmt* stmt) override;
	virtual void visit(VarDefStmt* stmt) override;
	virtual void visit(WhileLoopStmt* stmt) override;
	/// @}

	void addEdgeFromCurrNodeToSuccNode(Statement* stmt,
		EdgesToAdd &edgesToAdd,
		Expression* edgeCond = nullptr);
	void addEdgeFromVector(const EdgeToAdd &edge);
	void addJobToQueue(CFG::Node* pred, Expression* cond,
		Statement* stmt);
	void addEdgesFromVector(const EdgesToAdd &edgesToAdd);
	void addStatement(Statement* stmt);
	void addStmtToNodeAndToMapOfStmtToNode(Statement* stmt);
	void resolveGotoTargets(Statement* stmt);
	void createAndAddNode();
	void createEdgesToBeAdded();
	void createEntryNode();
	void createExitNode();
	void createNewNodeAndConnectWithPredNode(Statement* stmt);
	void createNewNodeForIfSwitchForWhileStmtAndAddStmtToNode(
		Statement* stmt);
	void createNewNodeIfStmtHasSucc(Statement* stmt);
	void createOtherNodes();
	void doJob(const Job &job);
	void doJobs();
	void initializeCFGBuild();
	void purgeCFG();
	void validateCFG();
	void visitForOrUForLoop(Statement* loop, Statement* body);

private:
	/// Queue of all jobs.
	JobQueue jobQueue;

	/// Vector of saved edges for nodes that will be added first.
	EdgesToAdd edgesToAddFirst;

	/// Vector of saved edges that have to be added at the end.
	EdgesToAdd edgesToAddLast;

	/// Currently generated node.
	CFG::Node* currNode = nullptr;

	/// Mapping of an empty statement to its node.
	StmtNodeMapping emptyStmtToNodeMap;

	/// Signalizes if we want to iterate through statements or not.
	bool stopIterNextStmts;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
