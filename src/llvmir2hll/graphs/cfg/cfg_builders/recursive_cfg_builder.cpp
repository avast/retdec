/**
* @file src/llvmir2hll/graphs/cfg/cfg_builders/recursive_cfg_builder.cpp
* @brief Implementation of RecursiveCFGBuilder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/graphs/cfg/cfg_builders/recursive_cfg_builder.h"
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
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expression_negater.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

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
ShPtr<Expression> generateIfCondEdgeLabel(const ExprVector &conds,
		ShPtr<Expression> currCond = nullptr) {
	if (conds.empty()) {
		return ucast<Expression>(currCond->clone());
	}

	ShPtr<Expression> label;
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
ShPtr<Expression> generateSwitchDefaultCondLabel(ShPtr<SwitchStmt> stmt) {
	ShPtr<Expression> label;

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
	ShPtr<Expression> switchCond(stmt->getControlExpr());
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
* @brief Returns @c true if the statement @a stmt is in a sequence of
*        statements @a stmts, @c false otherwise.
*
* @param[in] stmt Statement.
* @param[in] stmts Sequence of statements (may be empty).
*
* Only successors of statements in @a stmts are searched, i.e. if there is a
* compound statement, no search in the nested statements is done.
*
* Precondition:
*  - @a stmt is non-null
*/
bool isStatementInStatements(ShPtr<Statement> stmt, ShPtr<Statement> stmts) {
	PRECONDITION_NON_NULL(stmt);

	ShPtr<Statement> currStmt(stmts);
	while (currStmt && currStmt != stmt) {
		currStmt = currStmt->getSuccessor();
	}
	return currStmt == stmt;
}

} // anonymous namespace

/**
* @brief Constructs a new builder.
*/
RecursiveCFGBuilder::RecursiveCFGBuilder():
	CFGBuilder(), OrderedAllVisitor(), currNode(), firstStmtNodeMapping() {}

/**
* @brief Destructs the builder.
*/
RecursiveCFGBuilder::~RecursiveCFGBuilder() {}

void RecursiveCFGBuilder::buildCFG() {
	// Initialization.
	currNode.reset();
	firstStmtNodeMapping.clear();
	OrderedAllVisitor::restart();

	// We use OrderedAllVisitor and visit() functions to build the CFG.
	func->accept(this);

	// Since during creating the CFG empty nodes may be introduced, we should
	// remove them prior to returning the CFG.
	cfg->removeEmptyNodes();

	#if 0 // Enable them only when needed (they slow down the llvmir2hll).
	// Some validations to make sure the CFG is correct.
	cfg->validateThereAreNoEmptyNodes();
	cfg->validateEveryNonEmptyStatementHasNode();
	cfg->validateEveryPredAndSuccIsInNodes();
	cfg->validateIngoingAndOutgoingEdges();
	#endif

	// TODO What about merging nodes with a single if statement with no else-if
	//      clauses into its predecessor?
	// TODO What about other optimizations of the generated CFG?
}

/**
* @brief Creates and returns a new RecursiveCFGBuilder.
*/
ShPtr<RecursiveCFGBuilder> RecursiveCFGBuilder::create() {
	return ShPtr<RecursiveCFGBuilder>(new RecursiveCFGBuilder());
}

void RecursiveCFGBuilder::visit(ShPtr<Function> func) {
	//
	// Create the entry node.
	//
	cfg->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	// We introduce a VarDefStmt for each parameter into the entry block. This
	// way, we can store the function's parameters into the CFG in a uniform
	// way.
	// For each parameter...
	for (const auto &param : func->getParams()) {
		ShPtr<Statement> varDefStmt(VarDefStmt::create(param));
		cfg->stmtNodeMapping[varDefStmt] = cfg->entryNode;
		cfg->entryNode->stmts.push_back(varDefStmt);
	}

	//
	// Create the exit node.
	//
	cfg->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	//
	// Create the rest of the CFG.
	//
	ShPtr<CFG::Node> afterEntryNode(addNode(func->getBody()));
	cfg->addEdge(cfg->getEntryNode(), afterEntryNode);
}

void RecursiveCFGBuilder::visit(ShPtr<AssignStmt> stmt) {
	addStatement(stmt);
}

void RecursiveCFGBuilder::visit(ShPtr<VarDefStmt> stmt) {
	addStatement(stmt);
}

void RecursiveCFGBuilder::visit(ShPtr<CallStmt> stmt) {
	addStatement(stmt);
}

void RecursiveCFGBuilder::visit(ShPtr<ReturnStmt> stmt) {
	cfg->stmtNodeMapping[stmt] = currNode;
	currNode->stmts.push_back(stmt);
	cfg->addEdge(currNode, cfg->exitNode);
}

void RecursiveCFGBuilder::visit(ShPtr<EmptyStmt> stmt) {
	addStatement(stmt);
}

void RecursiveCFGBuilder::visit(ShPtr<IfStmt> stmt) {
	ShPtr<CFG::Node> beforeIfNode(currNode);

	// Create a node for the if statement.
	ShPtr<CFG::Node> ifNode(new CFG::Node());
	firstStmtNodeMapping[stmt] = ifNode;
	cfg->stmtNodeMapping[stmt] = ifNode;
	ifNode->stmts.push_back(stmt);
	cfg->addNode(ifNode);
	cfg->addEdge(beforeIfNode, ifNode);

	// Create a node for the bodies of the if statement.
	ExprVector conds;
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		ShPtr<CFG::Node> clauseBody(addNode(i->second));
		cfg->addEdge(ifNode, clauseBody, generateIfCondEdgeLabel(conds, i->first));
		conds.push_back(i->first);
	}

	// Create a node for the else clause/statement's successor. If there is an
	// else clause, then we don't have to generate a node for the statement's
	// successor here. Indeed, if the else clause always ends with a return
	// statement, then the statement's successor is never entered. If the else
	// clause doesn't always ends with a return, the statement's successor will
	// be traversed when adding a node for the else clause.
	if (stmt->hasElseClause()) {
		ShPtr<CFG::Node> clauseBody(addNode(stmt->getElseClause()));
		cfg->addEdge(ifNode, clauseBody, generateIfCondEdgeLabel(conds));
		return;
	}
	ShPtr<Expression> edgeCond(generateIfCondEdgeLabel(conds));
	if (ShPtr<Statement> stmtSucc = stmt->getSuccessor()) {
		ShPtr<CFG::Node> afterIfNode(addNode(stmtSucc));
		cfg->addEdge(ifNode, afterIfNode, edgeCond);
		return;
	}
	currNode = ifNode;
	addForwardOrBackwardEdge(stmt, edgeCond);
}

void RecursiveCFGBuilder::visit(ShPtr<SwitchStmt> stmt) {
	ShPtr<CFG::Node> beforeSwitchNode(currNode);

	// Create a node for the switch statement.
	ShPtr<CFG::Node> switchNode(new CFG::Node());
	firstStmtNodeMapping[stmt] = switchNode;
	cfg->stmtNodeMapping[stmt] = switchNode;
	switchNode->stmts.push_back(stmt);
	cfg->addNode(switchNode);
	cfg->addEdge(beforeSwitchNode, switchNode);

	// Create a node for each clause.
	for (auto i = stmt->clause_begin(),
			e = stmt->clause_end(); i != e; ++i) {
		ShPtr<CFG::Node> clauseBody(addNode(i->second));
		ShPtr<Expression> cond;
		if (i->first) {
			// Generate a label of the form `switchCond == clauseCond`.
			cond = EqOpExpr::create(stmt->getControlExpr(), i->first);
		} else {
			cond = generateSwitchDefaultCondLabel(stmt);
		}
		cfg->addEdge(switchNode, clauseBody, cond);
	}

	// Create a node (an edge) for the switch's successor. However, if there is
	// a default clause, we don't have to do this. Indeed, if the default
	// clause always ends with a return statement, the statement's successor is
	// never entered. If the default clause doesn't always end with a return
	// statement, then the statement's successor has been already traversed
	// when a node for the default clause was added.
	if (stmt->hasDefaultClause()) {
		return;
	}
	if (ShPtr<Statement> stmtSucc = stmt->getSuccessor()) {
		ShPtr<CFG::Node> afterSwitchNode(addNode(stmtSucc));
		cfg->addEdge(switchNode, afterSwitchNode);
		return;
	}

	currNode = switchNode;
	addForwardOrBackwardEdge(stmt);
}

void RecursiveCFGBuilder::visit(ShPtr<WhileLoopStmt> stmt) {
	ShPtr<CFG::Node> beforeLoopNode(currNode);

	// Create a node for the loop.
	ShPtr<CFG::Node> loopNode(new CFG::Node());
	firstStmtNodeMapping[stmt] = loopNode;
	cfg->stmtNodeMapping[stmt] = loopNode;
	loopNode->stmts.push_back(stmt);
	cfg->addNode(loopNode);
	cfg->addEdge(beforeLoopNode, loopNode);

	// Create a node for the loop's body.
	ShPtr<CFG::Node> loopBody(addNode(stmt->getBody()));
	cfg->addEdge(loopNode, loopBody, stmt->getCondition());

	// Create a node (an edge) for the loop's successor. However, do this only
	// if it is not a "while True" loop (the "False" edge is never taken).
	if (!isWhileTrueLoop(stmt)) {
		ShPtr<Expression> edgeCond(ExpressionNegater::negate(ucast<Expression>(
			stmt->getCondition()->clone())));
		if (ShPtr<Statement> stmtSucc = stmt->getSuccessor()) {
			ShPtr<CFG::Node> afterLoopNode(addNode(stmtSucc));
			cfg->addEdge(loopNode, afterLoopNode, edgeCond);
		} else {
			currNode = loopNode;
			addForwardOrBackwardEdge(stmt, edgeCond);
		}
	}
}

void RecursiveCFGBuilder::visit(ShPtr<ForLoopStmt> stmt) {
	visitForOrUForLoop(stmt, stmt->getBody());
}

void RecursiveCFGBuilder::visit(ShPtr<UForLoopStmt> stmt) {
	visitForOrUForLoop(stmt, stmt->getBody());
}

void RecursiveCFGBuilder::visit(ShPtr<BreakStmt> stmt) {
	cfg->stmtNodeMapping[stmt] = currNode;
	currNode->stmts.push_back(stmt);

	// Create an edge to the successor.
	ShPtr<CFG::Node> currNodeBackup(currNode);
	cfg->addEdge(currNodeBackup, getIndirectSuccessor(stmt));
}

void RecursiveCFGBuilder::visit(ShPtr<ContinueStmt> stmt) {
	cfg->stmtNodeMapping[stmt] = currNode;
	currNode->stmts.push_back(stmt);

	// Create an edge to the successor.
	ShPtr<CFG::Node> currNodeBackup(currNode);
	cfg->addEdge(currNodeBackup, getIndirectSuccessor(stmt));
}

void RecursiveCFGBuilder::visit(ShPtr<GotoStmt> stmt) {
	cfg->stmtNodeMapping[stmt] = currNode;
	currNode->stmts.push_back(stmt);

	if (ShPtr<Statement> gotoTarget = stmt->getTarget()) {
		ShPtr<CFG::Node> currNodeBackup(currNode);
		ShPtr<CFG::Node> targetNode(addNode(gotoTarget));
		cfg->addEdge(currNodeBackup, targetNode);
	}
}

void RecursiveCFGBuilder::visit(ShPtr<UnreachableStmt> stmt) {
	cfg->stmtNodeMapping[stmt] = currNode;
	currNode->stmts.push_back(stmt);
	cfg->addEdge(currNode, cfg->exitNode);
}

void RecursiveCFGBuilder::visitStmt(ShPtr<Statement> stmt, bool visitSuccessors,
		bool visitNestedStmts) {
	if (!stmt) {
		return;
	}

	if (hasItem(accessedStmts, stmt)) {
		// The statement has been accessed.
		ShPtr<CFG::Node> stmtNode(firstStmtNodeMapping[stmt]);
		cfg->addEdge(currNode, stmtNode);
		return;
	}

	// When the statement is a goto target and there are some statements in the
	// current node, we have to emit the statement into a new node.
	if (stmt->isGotoTarget() && !currNode->stmts.empty()) {
		ShPtr<CFG::Node> prevNode(currNode);
		ShPtr<CFG::Node> stmtNode(addNode(stmt));
		cfg->addEdge(prevNode, stmtNode);
		return;
	}

	accessedStmts.insert(stmt);

	// The statement is not a goto target, so process it normally.
	stmt->accept(this);
}

/**
* @brief Adds a (either new or existing) node starting with @a stmt into the
*        CFG and returns it.
*
* @par Preconditions
*  - @a stmt is non-null
*/
ShPtr<CFG::Node> RecursiveCFGBuilder::addNode(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	// Does a node corresponding to stmt already exist?
	auto stmtNodeIter = firstStmtNodeMapping.find(stmt);
	if (stmtNodeIter != firstStmtNodeMapping.end()) {
		return stmtNodeIter->second;
	}

	// Add a new node.
	ShPtr<CFG::Node> nodeToAdd = currNode = ShPtr<CFG::Node>(new CFG::Node());
	firstStmtNodeMapping[stmt] = currNode;
	visitStmt(stmt);
	cfg->addNode(nodeToAdd);
	return nodeToAdd;
}

/**
* @brief Adds a statement to the current node, visits its successors, and adds
*        a forward or backward edge from the current node to the
*        successor/parent of @a stmt.
*
* Empty statements are skipped (i.e. not added to <tt>cfg->stmtNodeMapping</tt>
* and <tt>currNode->stmts</tt>).
*/
void RecursiveCFGBuilder::addStatement(ShPtr<Statement> stmt) {
	if (!isa<EmptyStmt>(stmt)) {
		cfg->stmtNodeMapping[stmt] = currNode;
		currNode->stmts.push_back(stmt);
	}
	if (ShPtr<Statement> stmtSucc = stmt->getSuccessor()) {
		visitStmt(stmtSucc);
		return;
	}

	addForwardOrBackwardEdge(stmt);
}

/**
* @brief Adds a forward or backward edge from the current node to the
*        successor/parent of @a stmt.
*
* @param[in] stmt Statement for which the edge is added.
* @param[in] edgeCond Optional condition of the added edge.
*
* If @c stmt->getParent() does not exist, it implies that there is an implicit
* return from the function. If it exists and it is a while or for loop, it
* creates a backward edge. If it is an if or switch statement, it creates a
* forward edge.
*
* Precondition:
*  - @a stmt doesn't have a (direct) successor
*
* This function may add new nodes.
*/
void RecursiveCFGBuilder::addForwardOrBackwardEdge(ShPtr<Statement> stmt,
		ShPtr<Expression> edgeCond) {
	PRECONDITION(!stmt->getSuccessor(), stmt << "should not have a successor;"
		"the successor is `" << stmt->getSuccessor() << "`");

	ShPtr<CFG::Node> stmtNode(currNode);
	cfg->addEdge(stmtNode, getIndirectSuccessor(stmt), edgeCond);
}

/**
* @brief Returns the (indirect) successor node of the given statement @a stmt.
*
* This function may add new nodes.
*/
ShPtr<CFG::Node> RecursiveCFGBuilder::getIndirectSuccessor(ShPtr<Statement> stmt) {
	if (isa<ContinueStmt>(stmt)) {
		// A continue statement has to be inside of a loop.
		ShPtr<Statement> innLoop(getInnermostLoop(stmt));
		if (!innLoop) {
			return cfg->getExitNode();
		}

		return addNode(innLoop);
	}

	if (isa<BreakStmt>(stmt)) {
		// A break statement has to be inside a loop or switch.
		ShPtr<Statement> innLoopOrSwitch(getInnermostLoopOrSwitch(stmt));
		if (!innLoopOrSwitch) {
			return cfg->getExitNode();
		}

		if (ShPtr<Statement> succ = innLoopOrSwitch->getSuccessor()) {
			return addNode(succ);
		}
		return getIndirectSuccessor(innLoopOrSwitch);
	}

	ShPtr<Statement> stmtParent(stmt->getParent());
	if (!stmtParent) {
		// There is an implicit return from the function.
		return cfg->exitNode;
	}

	if (isLoop(stmtParent)) {
		return addNode(stmtParent);
	}

	if (isa<IfStmt>(stmtParent) && stmtParent->getSuccessor()) {
		return addNode(stmtParent->getSuccessor());
	}

	if (ShPtr<SwitchStmt> stmtParentSwitch = cast<SwitchStmt>(stmtParent)) {
		// There should be a fall-through to the next switch clause (or to the
		// switch's successor, if there is no next clause).

		// Find out in which clause we are.
		auto i = stmtParentSwitch->clause_begin();
		auto e = stmtParentSwitch->clause_end();
		while (i != e) {
			if (isStatementInStatements(stmt, i->second)) {
				break;
			}
			++i;
		}

		// Create an edge to the next clause (if any).
		++i;
		if (i != e) {
			// There is a next clause.
			return addNode(i->second);
		}
	}

	// Traverse over parents (of parents) until a parent with a successor is
	// found. If there is no such parent, then there is an implicit return from
	// the current function.
	do {
		if (ShPtr<Statement> stmtParentSucc = stmtParent->getSuccessor()) {
			return addNode(stmtParentSucc);
		}
	} while ((stmtParent = stmtParent->getParent()));
	// There is an implicit return from the function.
	return cfg->exitNode;
}

/**
* @brief Implementation of visit() for for loops.
*/
void RecursiveCFGBuilder::visitForOrUForLoop(ShPtr<Statement> loop,
		ShPtr<Statement> body) {
	ShPtr<CFG::Node> beforeLoopNode(currNode);

	// Create a node for the loop.
	ShPtr<CFG::Node> loopNode(new CFG::Node());
	firstStmtNodeMapping[loop] = loopNode;
	cfg->stmtNodeMapping[loop] = loopNode;
	loopNode->stmts.push_back(loop);
	cfg->addNode(loopNode);
	cfg->addEdge(beforeLoopNode, loopNode);

	// Generate the loop's condition.
	// TODO
	// ShPtr<Expression> loopCond;

	// Create a node for the loop's body.
	ShPtr<CFG::Node> loopBody(addNode(body));
	cfg->addEdge(loopNode, loopBody);

	// Create a node (an edge) for the loop's successor.
	if (ShPtr<Statement> loopSucc = loop->getSuccessor()) {
		ShPtr<CFG::Node> afterLoopNode(addNode(loopSucc));
		cfg->addEdge(loopNode, afterLoopNode);
	} else {
		currNode = loopNode;
		addForwardOrBackwardEdge(loop);
	}
}

} // namespace llvmir2hll
} // namespace retdec
