/**
* @file src/llvmir2hll/graphs/cfg/cfg_builders/non_recursive_cfg_builder.cpp
* @brief Implementation of NonRecursiveCFGBuilder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/graphs/cfg/cfg_builders/non_recursive_cfg_builder.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expression_negater.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/container.h"

using namespace retdec::llvm_support;

using retdec::utils::clear;

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Generates a label for an edge going from an if statement to some
*        clause body.
*
* @param[in] conds Conditions of clauses that have already been processed.
* @param[in] currCond Condition of the currently processed clause (may be the
*                     null pointer for else clauses).
*
* For example, if @a conds contains @c cond1 and @c cond2, the returned
* expression is of the form
* @code
* not cond1 and not cond2 and currCond
* @endcode
*/
Expression* generateIfCondEdgeLabel(const ExprVector &conds,
		Expression* currCond = nullptr) {
	if (conds.empty()) {
		if (currCond) {
			return ucast<Expression>(currCond->clone());
		} else {
			// The if statement didn't have any clauses.
			return nullptr;
		}
	}

	Expression* label = nullptr;
	for (const auto &cond : conds) {
		if (label) {
			label = AndOpExpr::create(ucast<Expression>(label->clone()),
				ExpressionNegater::negate(cond));
		} else {
			label = ExpressionNegater::negate(cond);
		}
	}
	if (currCond) {
		return AndOpExpr::create(label, currCond);
	}
	return label;
}

/**
* @brief Generates a label for an edge going from a switch statement @a stmt to
*        its default clause.
*
* If there are no non-default clauses in @a stmt, it returns the null pointer.
*/
Expression* generateSwitchDefaultCondLabel(SwitchStmt* stmt) {
	Expression* label = nullptr;

	// For example, for the following switch statement:
	//
	//     switch x:
	//         case 1:
	//         case 2:
	//         case 3:
	//         default:
	//
	// we generate the following condition:
	//
	//     (x != 1) and (x != 2) and (x != 3)
	//

	// For each clause...
	Expression* switchCond(stmt->getControlExpr());
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		if (!i->first) {
			// The default clause.
			continue;
		}

		if (!label) {
			label = NeqOpExpr::create(switchCond, i->first);
		} else {
			label = AndOpExpr::create(label, NeqOpExpr::create(switchCond, i->first));
		}
	}

	return label;
}

/**
* @brief Finds first parent of @a stmt which is not a loop when statement is in
*        a loop body.
*
* @param[in] stmt Statement of which parent is searched.
*
* @return When statement is in loop body, returns the first parent of @a stmt
*         which is not a loop statement, otherwise return same @a stmt.
*/
Statement* findParentWhichIsNotLoopIfStmtIsInLoop(Statement* stmt) {
	Statement* parent(stmt->getParent());
	if (parent && isLoop(parent)) {
		return findParentWhichIsNotLoopIfStmtIsInLoop(parent);
	} else {
		return stmt;
	}
}

} // anonymous namespace

/**
* @brief Constructs a new builder.
*/
NonRecursiveCFGBuilder::NonRecursiveCFGBuilder():
	CFGBuilder(), stopIterNextStmts(false) {}

/**
* @brief Creates and returns a new NonRecursiveCFGBuilder.
*/
NonRecursiveCFGBuilder* NonRecursiveCFGBuilder::create() {
	return new NonRecursiveCFGBuilder();
}

/**
* @brief Initializes all the needed data so the CFG can be built.
*/
void NonRecursiveCFGBuilder::initializeCFGBuild() {
	clear(jobQueue);
	clear(edgesToAddFirst);
	clear(edgesToAddLast);
	currNode = nullptr;
	clear(emptyStmtToNodeMap);
	stopIterNextStmts = false;
}

/**
* @brief Creates entry node.
*/
void NonRecursiveCFGBuilder::createEntryNode() {
	cfg->addEntryNode(new CFG::Node("entry"));

	// We introduce a VarDefStmt for each parameter into the entry block. This
	// way, we can store the function's parameters into the CFG in a uniform
	// way.
	// For each parameter...
	for (const auto &param : func->getParams()) {
		Statement* varDefStmt(
			VarDefStmt::create(param, nullptr, nullptr, func->getStartAddress()));
		cfg->stmtNodeMapping[varDefStmt] = cfg->entryNode;
		cfg->entryNode->stmts.push_back(varDefStmt);
	}
}

/**
* @brief Creates exit node.
*/
void NonRecursiveCFGBuilder::createExitNode() {
	cfg->addExitNode(new CFG::Node("exit"));
}

/**
* @brief Creates other nodes.
*/
void NonRecursiveCFGBuilder::createOtherNodes() {
	// Add first job for top level of function body.
	addJobToQueue(cfg->entryNode, nullptr, func->getBody());

	// Start of doing jobs and creating new jobs.
	doJobs();
}

/**
* @brief Purges the CFG by removing useless nodes.
*/
void NonRecursiveCFGBuilder::purgeCFG() {
	cfg->removeUnreachableNodes();
	cfg->removeEmptyNodes();
}

/**
* @brief Validates the created CFG.
*/
void NonRecursiveCFGBuilder::validateCFG() {
	cfg->validateThereAreNoEmptyNodes();
	cfg->validateEveryNonEmptyStatementHasNode();
	cfg->validateEveryPredAndSuccIsInNodes();
	cfg->validateIngoingAndOutgoingEdges();
}

/**
* @brief Implementation of visit() for for loops.
*/
void NonRecursiveCFGBuilder::visitForOrUForLoop(Statement* loop,
		Statement* body) {
	createNewNodeForIfSwitchForWhileStmtAndAddStmtToNode(loop);

	// Generate the loop's condition.
	// TODO Should we generate the condition? If so, how?
	// Expression* loopCond;

	// Create a job for the loop's body.
	addJobToQueue(currNode, nullptr, body);

	// Create an edge for the loop's successor.
	if (loop->getSuccessor()) {
		edgesToAddLast.push_back(EdgeToAdd(currNode, loop->getSuccessor(),
			nullptr));
	} else {
		addEdgeFromCurrNodeToSuccNode(loop, edgesToAddLast);
	}

	createNewNodeIfStmtHasSucc(loop);
}

void NonRecursiveCFGBuilder::buildCFG() {
	initializeCFGBuild();
	createEntryNode();
	createExitNode();
	createOtherNodes();
	createEdgesToBeAdded();
	purgeCFG();

	#if 0 // Enable them only when needed (they slow down the llvmir2hll).
	// Some validations to make sure the CFG is correct.
	validateCFG();
	#endif

	// TODO What about merging nodes with a single if statement with no else-if
	//      clauses into its predecessor?
	// TODO What about other optimizations of the generated CFG?
}

/**
* @brief Creates new job and add new job to queue of jobs.
*
* @param[in] pred Predecessor of node where is a @a stmt.
* @param[in] cond Condition for the edge from node where is a @a stmt and @a pred
*                 node.
* @param[in] stmt First statement of new node.
*/
void NonRecursiveCFGBuilder::addJobToQueue(CFG::Node* pred,
		Expression* cond, Statement* stmt) {
	jobQueue.push(Job(pred, cond, stmt));
}

/**
* @brief Tops and pop one job from queue and starts doing of job.
*/
void NonRecursiveCFGBuilder::doJobs() {
	while (!jobQueue.empty()) {
		doJob(jobQueue.front());
		jobQueue.pop();
	}
}

/**
* @brief Performs the given job.
*
* Iterates through one nested level from statement which is saved in job. Also
* create new node for job and add backward edge from this new node to
* predecessor node.
*
* @param[in] job A job to perform.
*/
void NonRecursiveCFGBuilder::doJob(const Job &job) {
	// Create new node for job.
	createAndAddNode();

	// Iterates through one nested level from statement saved in the job.
	for (Statement* stmt = job.stmt; stmt; stmt = stmt->getSuccessor()) {
		if (cfg->getNodeForStmt(stmt).first) {
			// When goto statement point backward we don't want to do jobs and
			// visit statements where we were one time before. Because if we
			// allow this we create new nodes and edges which will be same with
			// the nodes when we goes at first time. But we have to add edge. 7
			// Example mentioned below shows this situation. We have to add edge
			// from a = 2 to d = 1.
			// goto d = 1;
			// if (a > b) {
			//    a = 2;
			//    d = 1;
			//    goto if;
			// }
			edgesToAddFirst.push_back(EdgeToAdd(currNode, stmt));
			break;
		}

		if (stopIterNextStmts) {
			// In some cases like statements after return, continue and so on
			// we want to stop iterate and visiting next statements in same
			// nested level, because after for example return statement next
			// statements after this return are not visited.
			stopIterNextStmts = false;
			break;
		}

		stmt->accept(this);
	}
	// In special case like mentioned below we don't want to create
	// edge to predecessor node.
	//
	// In case on example mentioned below is first statement of job set to
	// While because CFG due to loop starts here. But edge was created in visit
	// of goto stmt because here we don't have information about creating edge
	// to a = b; So in this case we want to have a choice to don't create edge
	// to prede- cessor node.
	//
	// goto a = b;
	//
	// while(a > b) {
	//    a = b;
	// }
	if (job.pred) {
		edgesToAddFirst.push_back(EdgeToAdd(job.pred, job.stmt, job.cond));
	}
}

/**
* @brief Creates connecting edges for all nodes.
*
* This function add edges from two vectors of edges. It is needed because
* we want to have ordered edges like for example
* @code
* if (a < b) {}
* @endcode
* We want to have first edge the true condition and second edge the false
* condition. The @c edgesToAddLast contains edges that have to be last edges for
* its node.
*/
void NonRecursiveCFGBuilder::createEdgesToBeAdded() {
	addEdgesFromVector(edgesToAddFirst);
	// Add edges at the end.
	addEdgesFromVector(edgesToAddLast);
}

/**
* @brief Adds edges from @a edgesToAdd.
*
* @param[in] edgesToAdd Edges to add.
*/
void NonRecursiveCFGBuilder::addEdgesFromVector(const EdgesToAdd &edgesToAdd) {
	for (const auto &edge : edgesToAdd) {
		addEdgeFromVector(edge);
	}
}

/**
* @brief Add edge to CFG.
*
* @param[in] edge Edge to add.
*/
void NonRecursiveCFGBuilder::addEdgeFromVector(const EdgeToAdd &edge) {
	if (!edge.succStmt) {
		// If the successor is not set, then the edge has to go to the exit
		// node.
		cfg->addEdge(edge.node, cfg->exitNode, edge.cond);
	} else if (isa<EmptyStmt>(edge.succStmt)) {
		// Empty statements need their own mapping, so find the correct node.
		auto i = emptyStmtToNodeMap.find(edge.succStmt);

		// TODO This is the same problem as in the TODO below.
		if (i == emptyStmtToNodeMap.end()) {
			printWarningMessage("[NonRecursiveCFGBuilder] there is no node for"
				" an edge to `", edge.succStmt, "` -> skipping this edge");
			return;
		}

		cfg->addEdge(edge.node, i->second, edge.cond);
	} else {
		// Find the target node for the connection and create it.
		CFG::Node* targetNode(cfg->getNodeForStmt(edge.succStmt).first);

		// TODO There is the following problem with some decompilations: In
		// addEdgeFromCurrNodeToSuccNode(), an edge to a statement is
		// constructed. However, a job for this statement is never created.
		// Hence, we get an edge that is leading to a non-existing node, and
		// that is why sometimes the above call to cfg->getNodeForStmt()
		// returns a null pointer.
		//
		// From what I have analyzed, such edges are created in
		// addEdgeFromCurrNodeToSuccNode() when creating an edge from a
		// statement to the successor of a parent.
		//
		// Currently, we emit a warning and do not add such and edge.
		// Otherwise, we would end up in the following assertion fault:
		//
		//     CFG.cpp: addEdge: Precondition failed: `dst`
		//                       (expected a non-null pointer).
		//
		// A proper fix would require to analyze why exactly is this happening
		// and why there is no job created for the targets of such edges. After
		// 6 hours or so, I was unable to find the reason...
		//
		// Sample files whose decompilation causes the problem:
		//
		//  - binaries-suite/x86-elf/O0/x86-elf-gcc4.6.3-O0-g--mkdir
		//  - binaries-suite/x86-elf/O3/x86-elf-gcc4.6.3-O3-g--icombine
		//  - binaries-suite/mips-elf/compiler/psp-gcc-O1--lame
		//  - binaries-suite/arm-elf/O2/gnuarm-elf-gcc-O2--gzip
		//
		if (!targetNode) {
			printWarningMessage("[NonRecursiveCFGBuilder] there is no node for"
				" an edge to `", edge.succStmt, "` -> skipping this edge");
			return;
		}

		cfg->addEdge(edge.node, targetNode, edge.cond);
	}
}

/**
* @brief Finds successor and add edges to @a edgesToAdd for @a stmt.
*
* @param[in] stmt Finds successor for this statement.
* @param[out] edgesToAdd Place to save edge.
* @param[in] edgeCond Condition of edge.
*/
void NonRecursiveCFGBuilder::addEdgeFromCurrNodeToSuccNode(Statement* stmt,
		EdgesToAdd &edgesToAdd, Expression* edgeCond) {
	if (isa<ContinueStmt>(stmt)) {
		// A continue statement has to be inside of a loop.
		Statement* innLoop(getInnermostLoop(stmt));
		if (!innLoop) {
			edgesToAdd.push_back(EdgeToAdd(currNode, nullptr));
			return;
		}
		edgesToAdd.push_back(EdgeToAdd(currNode, innLoop));
		return;
	}

	if (isa<BreakStmt>(stmt)) {
		// A break statement has to be inside a loop or switch.
		Statement* innLoopOrSwitch(getInnermostLoopOrSwitch(stmt));
		if (!innLoopOrSwitch) {
			edgesToAdd.push_back(EdgeToAdd(currNode, nullptr));
			return;
		}

		if (Statement* succ = innLoopOrSwitch->getSuccessor()) {
			edgesToAdd.push_back(EdgeToAdd(currNode, succ));
			return;
		}
		addEdgeFromCurrNodeToSuccNode(innLoopOrSwitch, edgesToAdd);
		return;
	}

	Statement* stmtParent(stmt->getParent());
	if (!stmtParent) {
		// There is an implicit return from the function.
		edgesToAdd.push_back(EdgeToAdd(currNode, nullptr, edgeCond));
		return;
	}

	if (isLoop(stmtParent)) {
		edgesToAdd.push_back(EdgeToAdd(currNode, stmtParent, edgeCond));
		return;
	}

	if (isa<IfStmt>(stmtParent) && stmtParent->getSuccessor()) {
		edgesToAdd.push_back(EdgeToAdd(currNode, stmtParent->getSuccessor(),
			edgeCond));
		return;
	}

	if (SwitchStmt* stmtParentSwitch = cast<SwitchStmt>(stmtParent)) {
		// There should be a fall-through to the next switch clause (or to the
		// switch's successor, if there is no next clause).
		// Find out in which clause we are.
		auto i = stmtParentSwitch->clause_begin();
		auto e = stmtParentSwitch->clause_end();
		while (i != e) {
			if (Statement::isStatementInStatements(stmt, i->second)) {
				break;
			}
			++i;
		}

		// Create an edge to the next clause (if any).
		++i;
		if (i != e) {
			// There is a next clause.
			edgesToAdd.push_back(EdgeToAdd(currNode, i->second));
			return;
		}
	}

	// Traverse over parents (of parents) until a parent with a successor is
	// found. If there is no such parent, then there is an implicit return from
	// the current function.
	do {
		if (Statement* stmtParentSucc = stmtParent->getSuccessor()) {
			edgesToAdd.push_back(EdgeToAdd(currNode, stmtParentSucc));
			return;
		}
	} while ((stmtParent = stmtParent->getParent()));

	// There is an implicit return from the function.
	edgesToAdd.push_back(EdgeToAdd(currNode, nullptr));
}

/**
* @brief Resolve goto targets.
*
* When the statement is a goto target and there are some statements in the
* current node, we have to add the statement into a new node. Otherwise do
* nothing.
*
* @param[in] stmt Statement to check.
*/
void NonRecursiveCFGBuilder::resolveGotoTargets(Statement* stmt) {
	if (stmt->isGotoTarget() && !currNode->stmts.empty()) {
		createNewNodeAndConnectWithPredNode(stmt);
	}
}

/**
* @brief Adds @a stmt to @c currNode and to @c stmtNodeMapping.
*
* @param[in] stmt Statement to add.
*/
void NonRecursiveCFGBuilder::addStmtToNodeAndToMapOfStmtToNode(
		Statement* stmt) {
	cfg->stmtNodeMapping[stmt] = currNode;
	currNode->addStmt(stmt);
}

/**
* @brief Adds a statement to the current node and to map of statements to node,
*        and adds a forward or backward edge from the current node to the
*        successor/parent of @a stmt.
*
* @param[in] stmt Statement to add.
*/
void NonRecursiveCFGBuilder::addStatement(Statement* stmt) {
	resolveGotoTargets(stmt);
	addStmtToNodeAndToMapOfStmtToNode(stmt);

	// Add forward or backward edge.
	if (!stmt->hasSuccessor()) {
		addEdgeFromCurrNodeToSuccNode(stmt, edgesToAddFirst);
	}
}

/**
* @brief Creates new node and add it. Also save edge from this new node to
*        previous node.
*
* @param[in] stmt Statement of new node.
*/
void NonRecursiveCFGBuilder::createNewNodeAndConnectWithPredNode(Statement*
		stmt) {
	CFG::Node* prevNode(currNode);
	createAndAddNode();
	edgesToAddFirst.push_back(EdgeToAdd(prevNode, stmt));
}

/**
* @brief Creates new node if is needed for if, while, for, switch statements and
*        also add statement to node.
*
* @param[in] stmt Statement to add.
*/
void NonRecursiveCFGBuilder::createNewNodeForIfSwitchForWhileStmtAndAddStmtToNode(
		Statement* stmt) {
	if (stmt->hasPredecessors()) {
		// Create new node is needed only when statement has predecessors.
		// It is needed because when this statement don't have predecessors the
		// new node was created after doing a job and so we don't need redundant
		// new node.
		createNewNodeAndConnectWithPredNode(stmt);
	}
	addStmtToNodeAndToMapOfStmtToNode(stmt);
}

/**
* @brief Creates a new node for @a stmt if it has a successor.
*
* @param[in] stmt Statement to check if has a successor.
*/
void NonRecursiveCFGBuilder::createNewNodeIfStmtHasSucc(Statement* stmt) {
	if (stmt->hasSuccessor()) {
		// If we have successor we add new node for next statements.
		createAndAddNode();
	}
}

/**
* @brief Creates new node and set it to current node.
*/
void NonRecursiveCFGBuilder::createAndAddNode() {
	currNode = new CFG::Node();
	cfg->addNode(currNode);
}

void NonRecursiveCFGBuilder::visit(AssignStmt* stmt) {
	addStatement(stmt);
}

void NonRecursiveCFGBuilder::visit(VarDefStmt* stmt) {
	addStatement(stmt);
}

void NonRecursiveCFGBuilder::visit(CallStmt* stmt) {
	addStatement(stmt);
}

void NonRecursiveCFGBuilder::visit(ReturnStmt* stmt) {
	resolveGotoTargets(stmt);
	addStmtToNodeAndToMapOfStmtToNode(stmt);

	// Add edge to exit-node because return end function. Create edge to exit-
	// node is possible when save nullptr to second parameter of edge.
	edgesToAddFirst.push_back(EdgeToAdd(currNode, nullptr));

	if (stmt->hasSuccessor()) {
		// After return statement we don't want iterate next statements.
		stopIterNextStmts = true;
	}
}

void NonRecursiveCFGBuilder::visit(EmptyStmt* stmt) {
	resolveGotoTargets(stmt);

	// We don't add EmptyStmt to mapping statement to node and don't add
	// statement to node, because we don't want to have EmptyStmt in CFG. But
	// we need to have mapping of stmt to some node. We need this when we create
	// edges.
	emptyStmtToNodeMap[stmt] = currNode;

	if (!stmt->hasSuccessor()) {
		addEdgeFromCurrNodeToSuccNode(stmt, edgesToAddFirst);
	}
}

void NonRecursiveCFGBuilder::visit(IfStmt* stmt) {
	createNewNodeForIfSwitchForWhileStmtAndAddStmtToNode(stmt);

	// Create new jobs for the bodies of the if statement.
	ExprVector conds;
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		addJobToQueue(currNode, generateIfCondEdgeLabel(conds, i->first),
			i->second);
		conds.push_back(i->first);
	}

	if (stmt->hasElseClause()) {
		// Create new job for else body.
		addJobToQueue(currNode, generateIfCondEdgeLabel(conds),
			stmt->getElseClause());
	} else {
		// When we don't have else clause we need to create false edge for
		// if statement.
		Expression* edgeCond(generateIfCondEdgeLabel(conds));
		if (stmt->hasSuccessor()) {
			edgesToAddLast.push_back(EdgeToAdd(currNode, stmt->getSuccessor(),
				edgeCond));
		} else {
			addEdgeFromCurrNodeToSuccNode(stmt, edgesToAddLast, edgeCond);
		}
	}

	createNewNodeIfStmtHasSucc(stmt);
}

void NonRecursiveCFGBuilder::visit(SwitchStmt* stmt) {
	createNewNodeForIfSwitchForWhileStmtAndAddStmtToNode(stmt);

	// Create a new job for each clause.
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		Expression* cond;
		if (i->first) {
			// Generate a label of the form `switchCond == clauseCond`.
			cond = EqOpExpr::create(stmt->getControlExpr(), i->first);
		} else {
			cond = generateSwitchDefaultCondLabel(stmt);
		}
		addJobToQueue(currNode, cond, i->second);
	}

	if (!stmt->hasDefaultClause()) {
		// When we don't have default clause we need to create false edge for
		// switch statement.
		if (stmt->hasSuccessor()) {
			edgesToAddLast.push_back(EdgeToAdd(currNode, stmt->getSuccessor()));
		} else {
			addEdgeFromCurrNodeToSuccNode(stmt, edgesToAddLast);
		}
	}

	createNewNodeIfStmtHasSucc(stmt);
}

void NonRecursiveCFGBuilder::visit(WhileLoopStmt* stmt) {
	createNewNodeForIfSwitchForWhileStmtAndAddStmtToNode(stmt);

	// Create a job for the loop's body.
	addJobToQueue(currNode, stmt->getCondition(), stmt->getBody());

	// Create an edge for the loop's successor. However, do this only
	// if it is not a "while True" loop (the "False" edge is never taken).
	if (!isWhileTrueLoop(stmt)) {
		Expression* edgeCond(ExpressionNegater::negate(ucast<Expression>(
			stmt->getCondition()->clone())));
		if (stmt->hasSuccessor()) {
			edgesToAddLast.push_back(EdgeToAdd(currNode, stmt->getSuccessor(),
				edgeCond));
		} else {
			addEdgeFromCurrNodeToSuccNode(stmt, edgesToAddLast, edgeCond);
		}
	}
	createNewNodeIfStmtHasSucc(stmt);
}

void NonRecursiveCFGBuilder::visit(ForLoopStmt* stmt) {
	visitForOrUForLoop(stmt, stmt->getBody());
}

void NonRecursiveCFGBuilder::visit(UForLoopStmt* stmt) {
	visitForOrUForLoop(stmt, stmt->getBody());
}

void NonRecursiveCFGBuilder::visit(BreakStmt* stmt) {
	resolveGotoTargets(stmt);
	addStmtToNodeAndToMapOfStmtToNode(stmt);

	// Create an edge to the successor.
	addEdgeFromCurrNodeToSuccNode(stmt, edgesToAddFirst);

	if (stmt->hasSuccessor()) {
		// After break statement we don't want iterate next statements.
		stopIterNextStmts = true;
	}
}

void NonRecursiveCFGBuilder::visit(ContinueStmt* stmt) {
	resolveGotoTargets(stmt);
	addStmtToNodeAndToMapOfStmtToNode(stmt);

	// Create an edge to the successor.
	addEdgeFromCurrNodeToSuccNode(stmt, edgesToAddFirst);

	if (stmt->hasSuccessor()) {
		// After continue statement we don't want iterate next statements.
		stopIterNextStmts = true;
	}
}

void NonRecursiveCFGBuilder::visit(GotoStmt* stmt) {
	resolveGotoTargets(stmt);
	addStmtToNodeAndToMapOfStmtToNode(stmt);

	if (Statement* gotoTarget = stmt->getTarget()) {
		Statement* stmtToTargetJob = findParentWhichIsNotLoopIfStmtIsInLoop(
			gotoTarget);
		if (stmtToTargetJob != stmt->getTarget()) {
			// We need to iterate not from targe statement, bud for another one.
			// For example when target is in loop, but we need iterate from
			// this loop.
			edgesToAddFirst.push_back(EdgeToAdd(currNode, gotoTarget));
			addJobToQueue(nullptr, nullptr, stmtToTargetJob);
		} else {
			addJobToQueue(currNode, nullptr, stmtToTargetJob);
		}
		if (stmt->hasSuccessor()) {
			// After goto we don't want to iterate next statements.
			stopIterNextStmts = true;
		}
	}
}

void NonRecursiveCFGBuilder::visit(UnreachableStmt* stmt) {
	resolveGotoTargets(stmt);
	addStmtToNodeAndToMapOfStmtToNode(stmt);

	// Create edge to exit node.
	edgesToAddFirst.push_back(EdgeToAdd(currNode, nullptr));

	if (stmt->hasSuccessor()) {
		// After unreachable statement we don't want iterate next statements.
		stopIterNextStmts = true;
	}
}

} // namespace llvmir2hll
} // namespace retdec
