/**
* @file tests/llvmir2hll/graphs/cfg/cfg_builders/non_recursive_cfg_builder_tests.cpp
* @brief Tests for the @c non_recursive_cfg_builder module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <fstream>
#include <set>

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builders/non_recursive_cfg_builder.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_writer.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_writers/graphviz_cfg_writer.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/utils/container.h"

using namespace ::testing;

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {
namespace tests {

namespace {

// If you want to emit CFGs, set to 1.
#if 0
/**
* @brief Emits CFG to cfgTest.dot.
*
* @param[in] CFGToEmit CFG to emit.
* @param[in] canEmit Emit the CFG?
*/
void emitCFG(ShPtr<CFG> CFGToEmit) {
	std::ofstream out("cfgTest.dot");
	ShPtr<retdec::llvmir2hll::CFGWriter> writer(GraphvizCFGWriter::create(CFGToEmit, out,
		false));
	writer->emitCFG();
}
#endif

/**
* @brief Support function that emits the statements in @a node into @c
*        std::errs().
*/
void printNode(ShPtr<CFG::Node> node) {
	if (node->getLabel() == "entry") {
		llvm::errs() << "Entry node";
	} else if (node->getLabel() == "exit") {
		llvm::errs() << "Exit node";
	}
	llvm::errs() << "\n";
	for (auto i = node->stmt_begin(), e = node->stmt_end(); i != e; ++i) {
		llvm::errs() << *i << "\n";
	}
}

/**
* @brief Support function that print to @c std::err the statements in nodes.
*
* @param[in] compNode First printed node.
* @param[in] refNode Second printed node.
*/
void printNodes(ShPtr<CFG::Node> compNode, ShPtr<CFG::Node> refNode) {
	if (compNode->getLabel() == "entry") {
		llvm::errs() << "Entry node in compared CFG";
	} else if (compNode->getLabel() == "exit") {
		llvm::errs() << "Exit node in compared CFG";
	}
	if (refNode->getLabel() == "entry") {
		llvm::errs() << "Entry node in reference CFG";
	} else if (refNode->getLabel() == "exit") {
		llvm::errs() << "Exit node in reference CFG";
	}

	llvm::errs() << "Statements in node of compared CFG \n";
	for (auto i = compNode->stmt_begin(), e = compNode->stmt_end(); i != e; ++i) {
		llvm::errs() << *i << "\n";
	}
	llvm::errs() << "Statements in node of reference CFG \n";
	for (auto i = refNode->stmt_begin(),
			e = refNode->stmt_end(); i != e; ++i) {
		llvm::errs() << *i << "\n";
	}
}

} // anonymous namespace

/**
* @brief Tests for the @c non_recursive_cfg_builder module.
*/
class NonRecursiveCFGBuilderTests: public TestsWithModule {
protected:
	void checkEquivalenceOfCFGs(const ShPtr<CFG> &toCompCFG, const ShPtr<CFG>
		&refCFG);
	void checkNodes(ShPtr<CFG::Node> nodeOfCompCFG, ShPtr<CFG::Node>
		nodeOfRefCFG);

protected:
	/// Visited nodes.
	CFG::NodeVector visitedNodes;
};

/**
* @brief Compare reference CFG with created CFG.
*
* @param[in] toCompCFG CFG to compare.
* @param[in] refCFG Reference CFG.
*/
void NonRecursiveCFGBuilderTests::checkEquivalenceOfCFGs(const ShPtr<CFG>
		&toCompCFG, const ShPtr<CFG> &refCFG) {
	ASSERT_EQ(toCompCFG->getNumberOfNodes(), refCFG->getNumberOfNodes()) <<
		"expected same number of nodes but in the compared CFG are `" <<
			toCompCFG->getNumberOfNodes() << "` nodes, "
		"and in the reference CFG are `" << refCFG->getNumberOfNodes() <<
			"` nodes";

	checkNodes(toCompCFG->getEntryNode(), refCFG->getEntryNode());
}

/**
* @brief Checks number of statements, number of predecessors and successors also
*        checks if statements are equal.
*
* @param[in] nodeOfCompCFG Node to compare.
* @param[in] nodeOfRefCFG Reference node.
*/
void NonRecursiveCFGBuilderTests::checkNodes(ShPtr<CFG::Node> nodeOfCompCFG,
		ShPtr<CFG::Node> nodeOfRefCFG) {
	if (hasItem(visitedNodes, nodeOfCompCFG)) {
		return;
	}
	visitedNodes.push_back(nodeOfCompCFG);

	if (nodeOfCompCFG->getNumberOfPreds() != nodeOfRefCFG->getNumberOfPreds()) {
		printNode(nodeOfCompCFG);
	}
	ASSERT_EQ(nodeOfCompCFG->getNumberOfPreds(), nodeOfRefCFG->getNumberOfPreds()) <<
		"expected same number of predecessors but in the compared node are `" <<
			nodeOfCompCFG->getNumberOfPreds() << "` predecessors, "
		"and in the reference node are  `" << nodeOfRefCFG->getNumberOfPreds() <<
			"` predecessors" << " actual node in CFG to compare is printed upper";

	if (nodeOfCompCFG->getNumberOfSuccs() != nodeOfRefCFG->getNumberOfSuccs()) {
		printNode(nodeOfCompCFG);
	}
	ASSERT_EQ(nodeOfCompCFG->getNumberOfSuccs(), nodeOfRefCFG->getNumberOfSuccs()) <<
		"expected same number of successors but in the compared node are `" <<
			nodeOfCompCFG->getNumberOfSuccs() << "` successors, "
		"and in the reference node are  `" << nodeOfRefCFG->getNumberOfSuccs() <<
			"` successors" << " actual node in CFG to compare is printed upper";

	if (nodeOfCompCFG->getNumberOfStmts() != nodeOfRefCFG->getNumberOfStmts()) {
		printNodes(nodeOfCompCFG, nodeOfRefCFG);
	}
	ASSERT_EQ(nodeOfCompCFG->getNumberOfStmts(), nodeOfRefCFG->getNumberOfStmts()) <<
		"expected same number of statements but in the compared node are `" <<
			nodeOfCompCFG->getNumberOfStmts() << "` statements, "
		"and in the reference node are  `" << nodeOfRefCFG->getNumberOfStmts() <<
			"` statements" << " both nodes are printed upper";

	auto compItStmt = nodeOfCompCFG->stmt_begin();
	for (auto refItI = nodeOfRefCFG->stmt_begin(),
			refItE = nodeOfRefCFG->stmt_end(); refItI != refItE; ++refItI) {
		ASSERT_EQ(*refItI, *compItStmt) <<
			"expected `" << *refItI << "`, "
			"got `" << *compItStmt << "`";
		compItStmt++;
	}

	auto compItSucc = nodeOfCompCFG->succ_begin();
	for (auto refItI = nodeOfRefCFG->succ_begin(),
			refItE = nodeOfRefCFG->succ_end(); refItI != refItE; ++refItI) {
		if ((*refItI)->getLabel()) {
			ASSERT_TRUE((*compItSucc)->getLabel()) <<
				"expected `" << (*refItI)->getLabel() << "`, "
				"got `null pointer`";
			ASSERT_EQ((*refItI)->getLabel()->getTextRepr(),
					(*compItSucc)->getLabel()->getTextRepr()) <<
				"expected `" << (*refItI)->getLabel() << "`, "
				"got `" << (*compItSucc)->getLabel() << "`";
		}
		checkNodes((*compItSucc)->getDst(), (*refItI)->getDst());
		compItSucc++;
	}
}

//
// Simple tests where are basic constructions of CFG.
//

TEST_F(NonRecursiveCFGBuilderTests,
OneNodeWithSimpleConnectionWithEntryAndExitNode) {
	// Simple creation of three nodes.
	// void func() {
	//
	// Input:
	//   int a;
	//   int b;
	//   a = b;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(assignStmtA);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeA(new CFG::Node());
	nodeA->addStmt(varDefStmtA);
	nodeA->addStmt(varDefStmtB);
	nodeA->addStmt(assignStmtA);
	refCFG->addNode(nodeA);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeA);
	refCFG->addEdge(nodeA, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
OneNodeWithSimpleConnectionWithEntryAndExitNodeButContainsEmptyStmt) {
	// Simple creation of three nodes. But int this case can't add EmptyStmt to
	// middle node.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   a = b;
	//   #EmptyStmt
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(assignStmtA);
	assignStmtA->setSuccessor(emptyStmt);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeA(new CFG::Node());
	nodeA->addStmt(varDefStmtA);
	nodeA->addStmt(varDefStmtB);
	nodeA->addStmt(assignStmtA);
	refCFG->addNode(nodeA);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeA);
	refCFG->addEdge(nodeA, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
OneNodeWithSimpleConnectionWithEntryAndExitNodeButContainsReturnInTheMiddleNode) {
	// Simple creation of three nodes. But int this case return statement causes
	// edge to exit node from this return.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   return;
	//   a = b;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(returnStmt);
	returnStmt->setSuccessor(assignStmtA);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeA(new CFG::Node());
	nodeA->addStmt(varDefStmtA);
	nodeA->addStmt(varDefStmtB);
	nodeA->addStmt(returnStmt);
	refCFG->addNode(nodeA);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeA);
	refCFG->addEdge(nodeA, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
OneNodeWithSimpleConnectionWithEntryAndExitNodeContainsUnreachableStmt) {
	// Simple creation of three nodes. Middle node has UnreachableStmt.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   #UnreachableStmt;
	//   a = b;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<UnreachableStmt> unreachableStmt(UnreachableStmt::create());
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(unreachableStmt);
	unreachableStmt->setSuccessor(assignStmtA);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeA(new CFG::Node());
	nodeA->addStmt(varDefStmtA);
	nodeA->addStmt(varDefStmtB);
	nodeA->addStmt(unreachableStmt);
	refCFG->addNode(nodeA);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeA);
	refCFG->addEdge(nodeA, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

//
// CFG for if statements.
//

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForSimpleIfStmtWithoutElseClause) {
	// If statement without else.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   if (a > b)
	//     a = b;
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varA, varB));
	ShPtr<IfStmt> ifStmt(IfStmt::create(gtOpExpr, assignStmtA));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(ifStmt);
	ifStmt->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeIf(new CFG::Node());
	nodeBeforeIf->addStmt(varDefStmtA);
	nodeBeforeIf->addStmt(varDefStmtB);
	nodeBeforeIf->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeIf);

	ShPtr<CFG::Node> nodeIf(new CFG::Node());
	nodeIf->addStmt(ifStmt);
	refCFG->addNode(nodeIf);

	ShPtr<CFG::Node> nodeTrueCondBody(new CFG::Node());
	nodeTrueCondBody->addStmt(assignStmtA);
	refCFG->addNode(nodeTrueCondBody);

	ShPtr<CFG::Node> nodeAfterIf(new CFG::Node());
	nodeAfterIf->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterIf);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeIf);
	refCFG->addEdge(nodeBeforeIf, nodeIf);
	refCFG->addEdge(nodeIf, nodeTrueCondBody, gtOpExpr);
	refCFG->addEdge(nodeTrueCondBody, nodeAfterIf);
	refCFG->addEdge(nodeIf, nodeAfterIf, ltEqOpExpr);
	refCFG->addEdge(nodeAfterIf, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForIfStmtWithNestedIfStmtWithElseClause) {
	// If statement with nested if statement with else clause.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   if (a > b)
	//     if (c > 2)
	//       a = b;
	//     else
	//       b = 2;
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(2, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExprA(GtOpExpr::create(varA, varB));
	ShPtr<GtOpExpr> gtOpExprC(GtOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<LtEqOpExpr> ltEqOpExprA(LtEqOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExprC(LtEqOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<IfStmt> ifStmtC(IfStmt::create(gtOpExprC, assignStmtA));
	ifStmtC->setElseClause(assignStmtB);
	ShPtr<IfStmt> ifStmtA(IfStmt::create(gtOpExprA, ifStmtC));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(ifStmtA);
	ifStmtA->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeIf(new CFG::Node());
	nodeBeforeIf->addStmt(varDefStmtA);
	nodeBeforeIf->addStmt(varDefStmtB);
	nodeBeforeIf->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeIf);

	ShPtr<CFG::Node> nodeIfA(new CFG::Node());
	nodeIfA->addStmt(ifStmtA);
	refCFG->addNode(nodeIfA);

	ShPtr<CFG::Node> nodeIfC(new CFG::Node());
	nodeIfC->addStmt(ifStmtC);
	refCFG->addNode(nodeIfC);

	ShPtr<CFG::Node> nodeTrueCondBodyIfC(new CFG::Node());
	nodeTrueCondBodyIfC->addStmt(assignStmtA);
	refCFG->addNode(nodeTrueCondBodyIfC);

	ShPtr<CFG::Node> nodeElseBodyIfC(new CFG::Node());
	nodeElseBodyIfC->addStmt(assignStmtB);
	refCFG->addNode(nodeElseBodyIfC);

	ShPtr<CFG::Node> nodeAfterIfA(new CFG::Node());
	nodeAfterIfA->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterIfA);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeIf);
	refCFG->addEdge(nodeBeforeIf, nodeIfA);
	refCFG->addEdge(nodeIfA, nodeIfC, gtOpExprA);
	refCFG->addEdge(nodeIfA, nodeAfterIfA, ltEqOpExprA);
	refCFG->addEdge(nodeIfC, nodeTrueCondBodyIfC, gtOpExprC);
	refCFG->addEdge(nodeIfC, nodeElseBodyIfC, ltEqOpExprC);
	refCFG->addEdge(nodeTrueCondBodyIfC, nodeAfterIfA);
	refCFG->addEdge(nodeElseBodyIfC, nodeAfterIfA);
	refCFG->addEdge(nodeAfterIfA, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForIfStmtWithNestedIfStmtWithElseClauseAndElseIfClause) {
	// If statement with nested if statement with else clause and else if clause.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   int d;
	//   int e;
	//   if (a > b) {
	//     d = a;
	//     if (c > 2)
	//       a = b;
	//     else if (c > 3)
	//       c = 1;
	//     else
	//       b = 2;
	//     e = 1;
	//   }
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<Variable> varD(Variable::create("d", IntType::create(16)));
	testFunc->addLocalVar(varD);
	ShPtr<Variable> varE(Variable::create("e", IntType::create(16)));
	testFunc->addLocalVar(varE);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtD(VarDefStmt::create(varD, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtE(VarDefStmt::create(varE, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(2, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtD(AssignStmt::create(varD, varA));
	ShPtr<AssignStmt> assignStmtE(AssignStmt::create(varE, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExprA(GtOpExpr::create(varA, varB));
	ShPtr<GtOpExpr> gtOpExprC1(GtOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<GtOpExpr> gtOpExprC2(GtOpExpr::create(varC, ConstInt::create(3, 64)));
	ShPtr<LtEqOpExpr> ltEqOpExprA(LtEqOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExprC1(LtEqOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<AndOpExpr> andOpExprC1(AndOpExpr::create(ltEqOpExprC1, gtOpExprC2));
	ShPtr<LtEqOpExpr> ltEqOpExprC2(LtEqOpExpr::create(varC, ConstInt::create(3, 64)));
	ShPtr<AndOpExpr> andOpExprC2(AndOpExpr::create(ltEqOpExprC1, ltEqOpExprC2));
	ShPtr<IfStmt> ifStmtA(IfStmt::create(gtOpExprA, assignStmtD));
	ShPtr<IfStmt> ifStmtC(IfStmt::create(gtOpExprC1, assignStmtA));
	ifStmtC->addClause(gtOpExprC2, assignStmtC);
	ifStmtC->setElseClause(assignStmtB);

	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(varDefStmtD);
	varDefStmtD->setSuccessor(varDefStmtE);
	varDefStmtE->setSuccessor(ifStmtA);
	assignStmtD->setSuccessor(ifStmtC);
	ifStmtC->setSuccessor(assignStmtE);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeIf(new CFG::Node());
	nodeBeforeIf->addStmt(varDefStmtA);
	nodeBeforeIf->addStmt(varDefStmtB);
	nodeBeforeIf->addStmt(varDefStmtC);
	nodeBeforeIf->addStmt(varDefStmtD);
	nodeBeforeIf->addStmt(varDefStmtE);
	refCFG->addNode(nodeBeforeIf);

	ShPtr<CFG::Node> nodeIfA(new CFG::Node());
	nodeIfA->addStmt(ifStmtA);
	refCFG->addNode(nodeIfA);

	ShPtr<CFG::Node> nodeD(new CFG::Node());
	nodeD->addStmt(assignStmtD);
	refCFG->addNode(nodeD);

	ShPtr<CFG::Node> nodeIfC(new CFG::Node());
	nodeIfC->addStmt(ifStmtC);
	refCFG->addNode(nodeIfC);

	ShPtr<CFG::Node> nodeTrueCondBodyIfC(new CFG::Node());
	nodeTrueCondBodyIfC->addStmt(assignStmtA);
	refCFG->addNode(nodeTrueCondBodyIfC);

	ShPtr<CFG::Node> nodeTrueCondBodyElseIfC(new CFG::Node());
	nodeTrueCondBodyElseIfC->addStmt(assignStmtC);
	refCFG->addNode(nodeTrueCondBodyElseIfC);

	ShPtr<CFG::Node> nodeElseBodyIfC(new CFG::Node());
	nodeElseBodyIfC->addStmt(assignStmtB);
	refCFG->addNode(nodeElseBodyIfC);

	ShPtr<CFG::Node> nodeE(new CFG::Node());
	nodeE->addStmt(assignStmtE);
	refCFG->addNode(nodeE);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeIf);
	refCFG->addEdge(nodeBeforeIf, nodeIfA);
	refCFG->addEdge(nodeIfA, nodeD, gtOpExprA);
	refCFG->addEdge(nodeD, nodeIfC);
	refCFG->addEdge(nodeIfC, nodeTrueCondBodyIfC, gtOpExprC1);
	refCFG->addEdge(nodeIfC, nodeTrueCondBodyElseIfC, andOpExprC1);
	refCFG->addEdge(nodeIfC, nodeElseBodyIfC, andOpExprC2);
	refCFG->addEdge(nodeTrueCondBodyIfC, nodeE);
	refCFG->addEdge(nodeTrueCondBodyElseIfC, nodeE);
	refCFG->addEdge(nodeElseBodyIfC, nodeE);
	refCFG->addEdge(nodeE, refCFG->getExitNode());
	refCFG->addEdge(nodeIfA, refCFG->getExitNode(), ltEqOpExprA);

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

//
// CFG for while loops.
//

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForSimpleWhileLoop) {
	// Simple while loop test.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   while (a > b)
	//     a = b;
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varA, varB));
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(gtOpExpr, assignStmtA));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(whileLoopStmt);
	whileLoopStmt->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeWhile(new CFG::Node());
	nodeBeforeWhile->addStmt(varDefStmtA);
	nodeBeforeWhile->addStmt(varDefStmtB);
	nodeBeforeWhile->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeWhile);

	ShPtr<CFG::Node> nodeWhile(new CFG::Node());
	nodeWhile->addStmt(whileLoopStmt);
	refCFG->addNode(nodeWhile);

	ShPtr<CFG::Node> nodeWhileBody(new CFG::Node());
	nodeWhileBody->addStmt(assignStmtA);
	refCFG->addNode(nodeWhileBody);

	ShPtr<CFG::Node> nodeAfterWhile(new CFG::Node());
	nodeAfterWhile->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterWhile);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeWhile);
	refCFG->addEdge(nodeBeforeWhile, nodeWhile);
	refCFG->addEdge(nodeWhile, nodeWhileBody, gtOpExpr);
	refCFG->addEdge(nodeWhileBody, nodeWhile);
	refCFG->addEdge(nodeWhile, nodeAfterWhile, ltEqOpExpr);
	refCFG->addEdge(nodeAfterWhile, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForWhileInWhileLoop) {
	// While loop with nested while loop statement.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   while (a > b) {
	//     b = 2;
	//     while (c > 2)
	//       a = b;
	//   }
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(2, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExprA(GtOpExpr::create(varA, varB));
	ShPtr<GtOpExpr> gtOpExprC(GtOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<LtEqOpExpr> ltEqOpExprA(LtEqOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExprC(LtEqOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<WhileLoopStmt> whileLoopStmtC(WhileLoopStmt::create(gtOpExprC, assignStmtA));
	ShPtr<WhileLoopStmt> whileLoopStmtA(WhileLoopStmt::create(gtOpExprA, assignStmtB));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(whileLoopStmtA);
	assignStmtB->setSuccessor(whileLoopStmtC);
	whileLoopStmtA->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeWhile(new CFG::Node());
	nodeBeforeWhile->addStmt(varDefStmtA);
	nodeBeforeWhile->addStmt(varDefStmtB);
	nodeBeforeWhile->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeWhile);

	ShPtr<CFG::Node> nodeWhileA(new CFG::Node());
	nodeWhileA->addStmt(whileLoopStmtA);
	refCFG->addNode(nodeWhileA);

	ShPtr<CFG::Node> nodeB(new CFG::Node());
	nodeB->addStmt(assignStmtB);
	refCFG->addNode(nodeB);

	ShPtr<CFG::Node> nodeWhileC(new CFG::Node());
	nodeWhileC->addStmt(whileLoopStmtC);
	refCFG->addNode(nodeWhileC);

	ShPtr<CFG::Node> nodeWhileBodyC(new CFG::Node());
	nodeWhileBodyC->addStmt(assignStmtA);
	refCFG->addNode(nodeWhileBodyC);

	ShPtr<CFG::Node> nodeAfterWhile(new CFG::Node());
	nodeAfterWhile->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterWhile);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeWhile);
	refCFG->addEdge(nodeBeforeWhile, nodeWhileA);
	refCFG->addEdge(nodeWhileA, nodeB, gtOpExprA);
	refCFG->addEdge(nodeB, nodeWhileC);
	refCFG->addEdge(nodeWhileA, nodeAfterWhile, ltEqOpExprA);
	refCFG->addEdge(nodeWhileC, nodeWhileBodyC, gtOpExprC);
	refCFG->addEdge(nodeWhileBodyC, nodeWhileC);
	refCFG->addEdge(nodeWhileC, nodeWhileA, ltEqOpExprC);
	refCFG->addEdge(nodeAfterWhile, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForWhileLoopWithIfStmtAndBreakInside) {
	// While loop with if condition with break inside. After break is useless
	// statement b = 1; This statement can't be added to CFG node.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   while (a > b) {
	//     if (c > 2) {
	//       break;
	//       b = 1;
	//     }
	//     a = b;
	//   }
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<BreakStmt> breakStmt(BreakStmt::create());
	ShPtr<GtOpExpr> gtOpExprA(GtOpExpr::create(varA, varB));
	ShPtr<GtOpExpr> gtOpExprC(GtOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<LtEqOpExpr> ltEqOpExprA(LtEqOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExprC(LtEqOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(gtOpExprC, breakStmt));
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(gtOpExprA, ifStmt));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(whileLoopStmt);
	ifStmt->setSuccessor(assignStmtA);
	breakStmt->setSuccessor(assignStmtB);
	whileLoopStmt->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeWhile(new CFG::Node());
	nodeBeforeWhile->addStmt(varDefStmtA);
	nodeBeforeWhile->addStmt(varDefStmtB);
	nodeBeforeWhile->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeWhile);

	ShPtr<CFG::Node> nodeWhile(new CFG::Node());
	nodeWhile->addStmt(whileLoopStmt);
	refCFG->addNode(nodeWhile);

	ShPtr<CFG::Node> nodeWhileBodyIf(new CFG::Node());
	nodeWhileBodyIf->addStmt(ifStmt);
	refCFG->addNode(nodeWhileBodyIf);

	ShPtr<CFG::Node> nodeIfBody(new CFG::Node());
	nodeIfBody->addStmt(breakStmt);
	refCFG->addNode(nodeIfBody);

	ShPtr<CFG::Node> nodeWhileBodyAssignA(new CFG::Node());
	nodeWhileBodyAssignA->addStmt(assignStmtA);
	refCFG->addNode(nodeWhileBodyAssignA);

	ShPtr<CFG::Node> nodeAfterWhile(new CFG::Node());
	nodeAfterWhile->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterWhile);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeWhile);
	refCFG->addEdge(nodeBeforeWhile, nodeWhile);
	refCFG->addEdge(nodeWhile, nodeWhileBodyIf, gtOpExprA);
	refCFG->addEdge(nodeWhile, nodeAfterWhile, ltEqOpExprA);
	refCFG->addEdge(nodeWhileBodyIf, nodeIfBody, gtOpExprC);
	refCFG->addEdge(nodeWhileBodyIf, nodeWhileBodyAssignA, ltEqOpExprC);
	refCFG->addEdge(nodeWhileBodyAssignA, nodeWhile);
	refCFG->addEdge(nodeIfBody, nodeAfterWhile);
	refCFG->addEdge(nodeAfterWhile, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForWhileLoopWithNestedWhileTrueLoop) {
	// While loop with nested while true loop statement.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   while (a > b) {
	//     while(true) {
	//       a = b;
	//     }
	//     b = 1;
	//   }
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varA, varB));
	ShPtr<WhileLoopStmt> whileLoopStmtTrue(WhileLoopStmt::create(
		ConstBool::create(true), assignStmtA));
	ShPtr<WhileLoopStmt> whileLoopStmtA(WhileLoopStmt::create(
		gtOpExpr, whileLoopStmtTrue));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(whileLoopStmtA);
	whileLoopStmtTrue->setSuccessor(assignStmtB);
	whileLoopStmtA->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeWhile(new CFG::Node());
	nodeBeforeWhile->addStmt(varDefStmtA);
	nodeBeforeWhile->addStmt(varDefStmtB);
	nodeBeforeWhile->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeWhile);

	ShPtr<CFG::Node> nodeWhileA(new CFG::Node());
	nodeWhileA->addStmt(whileLoopStmtA);
	refCFG->addNode(nodeWhileA);

	ShPtr<CFG::Node> nodeWhileTrue(new CFG::Node());
	nodeWhileTrue->addStmt(whileLoopStmtTrue);
	refCFG->addNode(nodeWhileTrue);

	ShPtr<CFG::Node> nodeWhileTrueBody(new CFG::Node());
	nodeWhileTrueBody->addStmt(assignStmtA);
	refCFG->addNode(nodeWhileTrueBody);

	ShPtr<CFG::Node> nodeAfterWhileA(new CFG::Node());
	nodeAfterWhileA->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterWhileA);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeWhile);
	refCFG->addEdge(nodeBeforeWhile, nodeWhileA);
	refCFG->addEdge(nodeWhileA, nodeWhileTrue, gtOpExpr);
	refCFG->addEdge(nodeWhileA, nodeAfterWhileA, ltEqOpExpr);
	refCFG->addEdge(nodeWhileTrue, nodeWhileTrueBody, ConstBool::create(true));
	refCFG->addEdge(nodeWhileTrueBody, nodeWhileTrue);
	refCFG->addEdge(nodeAfterWhileA, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForSimpleWhileTrueLoop) {
	// Simple while loop test where condition is true.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   while (true)
	//     a = b;
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<WhileLoopStmt> whileLoopStmtTrue(WhileLoopStmt::create(
		ConstBool::create(true), assignStmtA));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(whileLoopStmtTrue);
	whileLoopStmtTrue->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeWhile(new CFG::Node());
	nodeBeforeWhile->addStmt(varDefStmtA);
	nodeBeforeWhile->addStmt(varDefStmtB);
	nodeBeforeWhile->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeWhile);

	ShPtr<CFG::Node> nodeWhileTrue(new CFG::Node());
	nodeWhileTrue->addStmt(whileLoopStmtTrue);
	refCFG->addNode(nodeWhileTrue);

	ShPtr<CFG::Node> nodeWhileBody(new CFG::Node());
	nodeWhileBody->addStmt(assignStmtA);
	refCFG->addNode(nodeWhileBody);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeWhile);
	refCFG->addEdge(nodeBeforeWhile, nodeWhileTrue);
	refCFG->addEdge(nodeWhileTrue, nodeWhileBody, ConstBool::create(true));
	refCFG->addEdge(nodeWhileBody, nodeWhileTrue);

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

//
// CFG for for loops.
//

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForSimpleForLoop) {
	// Simple for loop test.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   for a in range(1,1)
	//     a = b;
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<ConstInt> oneConstInt(ConstInt::create(1, 64));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<ForLoopStmt> forLoopStmt(ForLoopStmt::create(varA, oneConstInt,
		oneConstInt, oneConstInt, assignStmtA));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(forLoopStmt);
	forLoopStmt->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeFor(new CFG::Node());
	nodeBeforeFor->addStmt(varDefStmtA);
	nodeBeforeFor->addStmt(varDefStmtB);
	nodeBeforeFor->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeFor);

	ShPtr<CFG::Node> nodeFor(new CFG::Node());
	nodeFor->addStmt(forLoopStmt);
	refCFG->addNode(nodeFor);

	ShPtr<CFG::Node> nodeForBody(new CFG::Node());
	nodeForBody->addStmt(assignStmtA);
	refCFG->addNode(nodeForBody);

	ShPtr<CFG::Node> nodeAfterFor(new CFG::Node());
	nodeAfterFor->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterFor);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeFor);
	refCFG->addEdge(nodeBeforeFor, nodeFor);
	refCFG->addEdge(nodeFor, nodeForBody);
	refCFG->addEdge(nodeForBody, nodeFor);
	refCFG->addEdge(nodeFor, nodeAfterFor);
	refCFG->addEdge(nodeAfterFor, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForForInForLoop) {
	// For loop with nested for loop statement.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   for a in range(1,1) {
	//     b = 2;
	//     for a in range(2,2)
	//       a = b;
	//   }
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<ConstInt> oneConstInt(ConstInt::create(1, 64));
	ShPtr<ConstInt> twoConstInt(ConstInt::create(2, 64));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(2, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<ForLoopStmt> forLoopStmtFirst(ForLoopStmt::create(varA, oneConstInt,
		oneConstInt, oneConstInt, assignStmtB));
	ShPtr<ForLoopStmt> forLoopStmtSec(ForLoopStmt::create(varA, twoConstInt,
		twoConstInt, twoConstInt, assignStmtA));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(forLoopStmtFirst);
	assignStmtB->setSuccessor(forLoopStmtSec);
	forLoopStmtFirst->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeFor(new CFG::Node());
	nodeBeforeFor->addStmt(varDefStmtA);
	nodeBeforeFor->addStmt(varDefStmtB);
	nodeBeforeFor->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeFor);

	ShPtr<CFG::Node> nodeForFirst(new CFG::Node());
	nodeForFirst->addStmt(forLoopStmtFirst);
	refCFG->addNode(nodeForFirst);

	ShPtr<CFG::Node> nodeB(new CFG::Node());
	nodeB->addStmt(assignStmtB);
	refCFG->addNode(nodeB);

	ShPtr<CFG::Node> nodeForSec(new CFG::Node());
	nodeForSec->addStmt(forLoopStmtSec);
	refCFG->addNode(nodeForSec);

	ShPtr<CFG::Node> nodeForBodySec(new CFG::Node());
	nodeForBodySec->addStmt(assignStmtA);
	refCFG->addNode(nodeForBodySec);

	ShPtr<CFG::Node> nodeAfterFor(new CFG::Node());
	nodeAfterFor->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterFor);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeFor);
	refCFG->addEdge(nodeBeforeFor, nodeForFirst);
	refCFG->addEdge(nodeForFirst, nodeB);
	refCFG->addEdge(nodeForFirst, nodeAfterFor);
	refCFG->addEdge(nodeB, nodeForSec);
	refCFG->addEdge(nodeForSec, nodeForBodySec);
	refCFG->addEdge(nodeForSec, nodeForFirst);
	refCFG->addEdge(nodeForBodySec, nodeForSec);
	refCFG->addEdge(nodeAfterFor, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForForLoopWithIfStmtAndContinueInside) {
	// For loop with if condition with continue inside. After continue is
	// useless statement b = 1; This statement can't be added to CFG node.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   for a in range(1,1) {
	//     if (c > 2) {
	//       continue;
	//       b = 1;
	//     }
	//     a = b;
	//   }
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<ConstInt> oneConstInt(ConstInt::create(1, 64));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<ContinueStmt> continueStmt(ContinueStmt::create());
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(gtOpExpr, continueStmt));
	ShPtr<ForLoopStmt> forLoopStmt(ForLoopStmt::create(varA, oneConstInt,
		oneConstInt, oneConstInt, ifStmt));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(forLoopStmt);
	ifStmt->setSuccessor(assignStmtA);
	continueStmt->setSuccessor(assignStmtB);
	forLoopStmt->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeFor(new CFG::Node());
	nodeBeforeFor->addStmt(varDefStmtA);
	nodeBeforeFor->addStmt(varDefStmtB);
	nodeBeforeFor->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeFor);

	ShPtr<CFG::Node> nodeFor(new CFG::Node());
	nodeFor->addStmt(forLoopStmt);
	refCFG->addNode(nodeFor);

	ShPtr<CFG::Node> nodeForBodyIf(new CFG::Node());
	nodeForBodyIf->addStmt(ifStmt);
	refCFG->addNode(nodeForBodyIf);

	ShPtr<CFG::Node> nodeIfBody(new CFG::Node());
	nodeIfBody->addStmt(continueStmt);
	refCFG->addNode(nodeIfBody);

	ShPtr<CFG::Node> nodeForBodyAssignA(new CFG::Node());
	nodeForBodyAssignA->addStmt(assignStmtA);
	refCFG->addNode(nodeForBodyAssignA);

	ShPtr<CFG::Node> nodeAfterFor(new CFG::Node());
	nodeAfterFor->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterFor);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeFor);
	refCFG->addEdge(nodeBeforeFor, nodeFor);
	refCFG->addEdge(nodeFor, nodeForBodyIf);
	refCFG->addEdge(nodeFor, nodeAfterFor);
	refCFG->addEdge(nodeForBodyIf, nodeIfBody, gtOpExpr);
	refCFG->addEdge(nodeForBodyIf, nodeForBodyAssignA, ltEqOpExpr);
	refCFG->addEdge(nodeForBodyAssignA, nodeFor);
	refCFG->addEdge(nodeIfBody, nodeFor);
	refCFG->addEdge(nodeAfterFor, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForForLoopWithIfStmtAndReturnInside) {
	// For loop with if condition with return inside. After return is useless
	// statement b = 1; This statement can't be added to CFG node.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   for a in range(1,1) {
	//     if (c > 2) {
	//       return;
	//       b = 1;
	//     }
	//     a = b;
	//   }
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<ConstInt> oneConstInt(ConstInt::create(1, 64));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varC, ConstInt::create(2, 64)));
	ShPtr<IfStmt> ifStmt(IfStmt::create(gtOpExpr, returnStmt));
	ShPtr<ForLoopStmt> forLoopStmt(ForLoopStmt::create(varA, oneConstInt,
		oneConstInt, oneConstInt, ifStmt));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(forLoopStmt);
	ifStmt->setSuccessor(assignStmtA);
	returnStmt->setSuccessor(assignStmtB);
	forLoopStmt->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeFor(new CFG::Node());
	nodeBeforeFor->addStmt(varDefStmtA);
	nodeBeforeFor->addStmt(varDefStmtB);
	nodeBeforeFor->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeFor);

	ShPtr<CFG::Node> nodeFor(new CFG::Node());
	nodeFor->addStmt(forLoopStmt);
	refCFG->addNode(nodeFor);

	ShPtr<CFG::Node> nodeForBodyIf(new CFG::Node());
	nodeForBodyIf->addStmt(ifStmt);
	refCFG->addNode(nodeForBodyIf);

	ShPtr<CFG::Node> nodeIfBody(new CFG::Node());
	nodeIfBody->addStmt(returnStmt);
	refCFG->addNode(nodeIfBody);

	ShPtr<CFG::Node> nodeForBodyAssignA(new CFG::Node());
	nodeForBodyAssignA->addStmt(assignStmtA);
	refCFG->addNode(nodeForBodyAssignA);

	ShPtr<CFG::Node> nodeAfterFor(new CFG::Node());
	nodeAfterFor->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterFor);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeFor);
	refCFG->addEdge(nodeBeforeFor, nodeFor);
	refCFG->addEdge(nodeFor, nodeForBodyIf);
	refCFG->addEdge(nodeFor, nodeAfterFor);
	refCFG->addEdge(nodeForBodyIf, nodeIfBody, gtOpExpr);
	refCFG->addEdge(nodeForBodyIf, nodeForBodyAssignA, ltEqOpExpr);
	refCFG->addEdge(nodeForBodyAssignA, nodeFor);
	refCFG->addEdge(nodeIfBody, refCFG->getExitNode());
	refCFG->addEdge(nodeAfterFor, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

//
// CFG for switch statements.
//

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForSimpleSwitchStatementWithDefaultClause) {
	// Switch statement with default clause.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   switch(a) {
	//     case a:
	//       a = b;
	//       break;
	//     case b:
	//       b = 1;
	//       break;
	//     default:
	//       break;
	//   }
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<EqOpExpr> eqOpExprA(EqOpExpr::create(varA, varA));
	ShPtr<EqOpExpr> eqOpExprB(EqOpExpr::create(varA, varB));
	ShPtr<NeqOpExpr> neqOpExprA(NeqOpExpr::create(varA, varA));
	ShPtr<NeqOpExpr> neqOpExprB(NeqOpExpr::create(varA, varB));
	ShPtr<AndOpExpr> andOpExpr(AndOpExpr::create(neqOpExprA, neqOpExprB));
	ShPtr<BreakStmt> breakStmtA(BreakStmt::create());
	ShPtr<BreakStmt> breakStmtB(BreakStmt::create());
	ShPtr<BreakStmt> breakStmtDef(BreakStmt::create());
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(varA));
	switchStmt->addClause(varA, assignStmtA);
	switchStmt->addClause(varB, assignStmtB);
	switchStmt->addDefaultClause(breakStmtDef);
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(switchStmt);
	assignStmtA->setSuccessor(breakStmtA);
	assignStmtB->setSuccessor(breakStmtB);
	switchStmt->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeSwitch(new CFG::Node());
	nodeBeforeSwitch->addStmt(varDefStmtA);
	nodeBeforeSwitch->addStmt(varDefStmtB);
	nodeBeforeSwitch->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeSwitch);

	ShPtr<CFG::Node> nodeSwitch(new CFG::Node());
	nodeSwitch->addStmt(switchStmt);
	refCFG->addNode(nodeSwitch);

	ShPtr<CFG::Node> nodeClauseA(new CFG::Node());
	nodeClauseA->addStmt(assignStmtA);
	nodeClauseA->addStmt(breakStmtA);
	refCFG->addNode(nodeClauseA);

	ShPtr<CFG::Node> nodeClauseB(new CFG::Node());
	nodeClauseB->addStmt(assignStmtB);
	nodeClauseB->addStmt(breakStmtB);
	refCFG->addNode(nodeClauseB);

	ShPtr<CFG::Node> nodeClauseDef(new CFG::Node());
	nodeClauseDef->addStmt(breakStmtDef);
	refCFG->addNode(nodeClauseDef);

	ShPtr<CFG::Node> nodeAfterSwitch(new CFG::Node());
	nodeAfterSwitch->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterSwitch);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeSwitch);
	refCFG->addEdge(nodeBeforeSwitch, nodeSwitch);
	refCFG->addEdge(nodeSwitch, nodeClauseA, eqOpExprA);
	refCFG->addEdge(nodeSwitch, nodeClauseB, eqOpExprB);
	refCFG->addEdge(nodeSwitch, nodeClauseDef, andOpExpr);
	refCFG->addEdge(nodeClauseA, nodeAfterSwitch);
	refCFG->addEdge(nodeClauseB, nodeAfterSwitch);
	refCFG->addEdge(nodeClauseDef, nodeAfterSwitch);
	refCFG->addEdge(nodeAfterSwitch, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForSimpleSwitchStatementWithoutDefaultClause) {
	// Switch statement without default clause.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   switch(a) {
	//     case a:
	//       a = b;
	//       break;
	//     case b:
	//       b = 1;
	//       break;
	//   }
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<EqOpExpr> eqOpExprA(EqOpExpr::create(varA, varA));
	ShPtr<EqOpExpr> eqOpExprB(EqOpExpr::create(varA, varB));
	ShPtr<NeqOpExpr> neqOpExprA(NeqOpExpr::create(varA, varA));
	ShPtr<NeqOpExpr> neqOpExprB(NeqOpExpr::create(varA, varB));
	ShPtr<AndOpExpr> andOpExpr(AndOpExpr::create(neqOpExprA, neqOpExprB));
	ShPtr<BreakStmt> breakStmtA(BreakStmt::create());
	ShPtr<BreakStmt> breakStmtB(BreakStmt::create());
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(varA));
	switchStmt->addClause(varA, assignStmtA);
	switchStmt->addClause(varB, assignStmtB);
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(switchStmt);
	assignStmtA->setSuccessor(breakStmtA);
	assignStmtB->setSuccessor(breakStmtB);
	switchStmt->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeSwitch(new CFG::Node());
	nodeBeforeSwitch->addStmt(varDefStmtA);
	nodeBeforeSwitch->addStmt(varDefStmtB);
	nodeBeforeSwitch->addStmt(varDefStmtC);
	refCFG->addNode(nodeBeforeSwitch);

	ShPtr<CFG::Node> nodeSwitch(new CFG::Node());
	nodeSwitch->addStmt(switchStmt);
	refCFG->addNode(nodeSwitch);

	ShPtr<CFG::Node> nodeClauseA(new CFG::Node());
	nodeClauseA->addStmt(assignStmtA);
	nodeClauseA->addStmt(breakStmtA);
	refCFG->addNode(nodeClauseA);

	ShPtr<CFG::Node> nodeClauseB(new CFG::Node());
	nodeClauseB->addStmt(assignStmtB);
	nodeClauseB->addStmt(breakStmtB);
	refCFG->addNode(nodeClauseB);

	ShPtr<CFG::Node> nodeAfterSwitch(new CFG::Node());
	nodeAfterSwitch->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterSwitch);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeSwitch);
	refCFG->addEdge(nodeBeforeSwitch, nodeSwitch);
	refCFG->addEdge(nodeSwitch, nodeClauseA, eqOpExprA);
	refCFG->addEdge(nodeSwitch, nodeClauseB, eqOpExprB);
	refCFG->addEdge(nodeSwitch, nodeAfterSwitch);
	refCFG->addEdge(nodeClauseA, nodeAfterSwitch);
	refCFG->addEdge(nodeClauseB, nodeAfterSwitch);
	refCFG->addEdge(nodeAfterSwitch, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForSimpleSwitchStatementWithDefaultClauseWithoutBreakStmts) {
	// Switch statement with default clause and all clauses haven't break
	// statements.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   int d;
	//   switch(a) {
	//     case a:
	//       a = b;
	//     case b:
	//       b = 1;
	//     default:
	//       d = 1;
	//   }
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<Variable> varD(Variable::create("d", IntType::create(16)));
	testFunc->addLocalVar(varD);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtD(VarDefStmt::create(varD, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtD(AssignStmt::create(varD, ConstInt::create(1, 64)));
	ShPtr<EqOpExpr> eqOpExprA(EqOpExpr::create(varA, varA));
	ShPtr<EqOpExpr> eqOpExprB(EqOpExpr::create(varA, varB));
	ShPtr<NeqOpExpr> neqOpExprA(NeqOpExpr::create(varA, varA));
	ShPtr<NeqOpExpr> neqOpExprB(NeqOpExpr::create(varA, varB));
	ShPtr<AndOpExpr> andOpExpr(AndOpExpr::create(neqOpExprA, neqOpExprB));
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(varA));
	switchStmt->addClause(varA, assignStmtA);
	switchStmt->addClause(varB, assignStmtB);
	switchStmt->addDefaultClause(assignStmtD);
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(varDefStmtD);
	varDefStmtD->setSuccessor(switchStmt);
	switchStmt->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeSwitch(new CFG::Node());
	nodeBeforeSwitch->addStmt(varDefStmtA);
	nodeBeforeSwitch->addStmt(varDefStmtB);
	nodeBeforeSwitch->addStmt(varDefStmtC);
	nodeBeforeSwitch->addStmt(varDefStmtD);
	refCFG->addNode(nodeBeforeSwitch);

	ShPtr<CFG::Node> nodeSwitch(new CFG::Node());
	nodeSwitch->addStmt(switchStmt);
	refCFG->addNode(nodeSwitch);

	ShPtr<CFG::Node> nodeClauseA(new CFG::Node());
	nodeClauseA->addStmt(assignStmtA);
	refCFG->addNode(nodeClauseA);

	ShPtr<CFG::Node> nodeClauseB(new CFG::Node());
	nodeClauseB->addStmt(assignStmtB);
	refCFG->addNode(nodeClauseB);

	ShPtr<CFG::Node> nodeClauseDef(new CFG::Node());
	nodeClauseDef->addStmt(assignStmtD);
	refCFG->addNode(nodeClauseDef);

	ShPtr<CFG::Node> nodeAfterSwitch(new CFG::Node());
	nodeAfterSwitch->addStmt(assignStmtC);
	refCFG->addNode(nodeAfterSwitch);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeSwitch);
	refCFG->addEdge(nodeBeforeSwitch, nodeSwitch);
	refCFG->addEdge(nodeSwitch, nodeClauseA, eqOpExprA);
	refCFG->addEdge(nodeSwitch, nodeClauseB, eqOpExprB);
	refCFG->addEdge(nodeSwitch, nodeClauseDef, andOpExpr);
	refCFG->addEdge(nodeClauseA, nodeClauseB);
	refCFG->addEdge(nodeClauseB, nodeClauseDef);
	refCFG->addEdge(nodeClauseDef, nodeAfterSwitch);
	refCFG->addEdge(nodeAfterSwitch, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForSwitchStatementWithNestedSwitchStmtWithDefaultClause) {
	// Switch statement with nested switch statement with default clause.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   int d;
	//   switch(a) {
	//     case a:
	//       switch(b) {
	//         case b:
	//           b = 1;
	//           break;
	//         default:
	//           c = 1;
	//           break;
	//       }
	//       d = 1;
	//   }
	//   a = b;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<Variable> varD(Variable::create("d", IntType::create(16)));
	testFunc->addLocalVar(varD);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtD(VarDefStmt::create(varD, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtD(AssignStmt::create(varD, ConstInt::create(1, 64)));
	ShPtr<BreakStmt> breakStmtB(BreakStmt::create());
	ShPtr<BreakStmt> breakStmtDef(BreakStmt::create());
	ShPtr<EqOpExpr> eqOpExprA(EqOpExpr::create(varA, varA));
	ShPtr<EqOpExpr> eqOpExprB(EqOpExpr::create(varB, varB));
	ShPtr<NeqOpExpr> neqOpExprB(NeqOpExpr::create(varB, varB));
	ShPtr<SwitchStmt> switchStmtB(SwitchStmt::create(varB));
	ShPtr<SwitchStmt> switchStmtA(SwitchStmt::create(varA));
	switchStmtA->addClause(varA, switchStmtB);
	switchStmtB->addClause(varB, assignStmtB);
	switchStmtB->addDefaultClause(assignStmtC);
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(varDefStmtD);
	varDefStmtD->setSuccessor(switchStmtA);
	switchStmtA->setSuccessor(assignStmtA);
	assignStmtB->setSuccessor(breakStmtB);
	assignStmtC->setSuccessor(breakStmtDef);
	switchStmtB->setSuccessor(assignStmtD);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeSwitch(new CFG::Node());
	nodeBeforeSwitch->addStmt(varDefStmtA);
	nodeBeforeSwitch->addStmt(varDefStmtB);
	nodeBeforeSwitch->addStmt(varDefStmtC);
	nodeBeforeSwitch->addStmt(varDefStmtD);
	refCFG->addNode(nodeBeforeSwitch);

	ShPtr<CFG::Node> nodeSwitchA(new CFG::Node());
	nodeSwitchA->addStmt(switchStmtA);
	refCFG->addNode(nodeSwitchA);

	ShPtr<CFG::Node> nodeSwitchB(new CFG::Node());
	nodeSwitchB->addStmt(switchStmtB);
	refCFG->addNode(nodeSwitchB);

	ShPtr<CFG::Node> nodeClauseB(new CFG::Node());
	nodeClauseB->addStmt(assignStmtB);
	nodeClauseB->addStmt(breakStmtB);
	refCFG->addNode(nodeClauseB);

	ShPtr<CFG::Node> nodeClauseDef(new CFG::Node());
	nodeClauseDef->addStmt(assignStmtC);
	nodeClauseDef->addStmt(breakStmtDef);
	refCFG->addNode(nodeClauseDef);

	ShPtr<CFG::Node> nodeAfterSwitchB(new CFG::Node());
	nodeAfterSwitchB->addStmt(assignStmtD);
	refCFG->addNode(nodeAfterSwitchB);

	ShPtr<CFG::Node> nodeAfterSwitchA(new CFG::Node());
	nodeAfterSwitchA->addStmt(assignStmtA);
	refCFG->addNode(nodeAfterSwitchA);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeSwitch);
	refCFG->addEdge(nodeBeforeSwitch, nodeSwitchA);
	refCFG->addEdge(nodeSwitchA, nodeSwitchB, eqOpExprA);
	refCFG->addEdge(nodeSwitchA, nodeAfterSwitchA);
	refCFG->addEdge(nodeSwitchB, nodeClauseB, eqOpExprB);
	refCFG->addEdge(nodeSwitchB, nodeClauseDef, neqOpExprB);
	refCFG->addEdge(nodeClauseB, nodeAfterSwitchB);
	refCFG->addEdge(nodeClauseDef, nodeAfterSwitchB);
	refCFG->addEdge(nodeAfterSwitchB, nodeAfterSwitchA);
	refCFG->addEdge(nodeAfterSwitchA, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

//
// CFG with goto statements.
//

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForSimpleGotoJumpBackward) {
	// Simple goto jump backward.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   b = 1
	//   c = 1;
	//   goto c = 1;
	//   a = b;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(assignStmtC));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(assignStmtB);
	assignStmtB->setSuccessor(assignStmtC);
	assignStmtC->setSuccessor(gotoStmt);
	gotoStmt->setSuccessor(assignStmtA);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeGotoTarg(new CFG::Node());
	nodeBeforeGotoTarg->addStmt(varDefStmtA);
	nodeBeforeGotoTarg->addStmt(varDefStmtB);
	nodeBeforeGotoTarg->addStmt(varDefStmtC);
	nodeBeforeGotoTarg->addStmt(assignStmtB);
	refCFG->addNode(nodeBeforeGotoTarg);

	ShPtr<CFG::Node> targetGotoNode(new CFG::Node());
	targetGotoNode->addStmt(assignStmtC);
	targetGotoNode->addStmt(gotoStmt);
	refCFG->addNode(targetGotoNode);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeGotoTarg);
	refCFG->addEdge(nodeBeforeGotoTarg, targetGotoNode);
	refCFG->addEdge(targetGotoNode, targetGotoNode);

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForSimpleGotoJumpForward) {
	// Simple goto jump forward.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   b = 1
	//   goto c = 1;
	//   a = b;
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(assignStmtC));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(assignStmtB);
	assignStmtB->setSuccessor(gotoStmt);
	gotoStmt->setSuccessor(assignStmtA);
	assignStmtA->setSuccessor(assignStmtC);

	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeWithGoto(new CFG::Node());
	nodeWithGoto->addStmt(varDefStmtA);
	nodeWithGoto->addStmt(varDefStmtB);
	nodeWithGoto->addStmt(varDefStmtC);
	nodeWithGoto->addStmt(assignStmtB);
	nodeWithGoto->addStmt(gotoStmt);
	refCFG->addNode(nodeWithGoto);

	ShPtr<CFG::Node> targetGotoNode(new CFG::Node());
	targetGotoNode->addStmt(assignStmtC);
	refCFG->addNode(targetGotoNode);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeWithGoto);
	refCFG->addEdge(nodeWithGoto, targetGotoNode);
	refCFG->addEdge(targetGotoNode, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForTwoGotoJumpBackwardFromIfStmt) {
	// Two goto statements jump backward from if statement.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   b = 1
	//   c = 1;
	//   if (a > b)
	//     goto c = 1;
	//   else
	//     goto c = 1;
	//   a = b;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varA, varB));
	ShPtr<GotoStmt> gotoStmtFirst(GotoStmt::create(assignStmtC));
	ShPtr<GotoStmt> gotoStmtSec(GotoStmt::create(assignStmtC));
	ShPtr<IfStmt> ifStmt(IfStmt::create(gtOpExpr, gotoStmtFirst));
	ifStmt->setElseClause(gotoStmtSec);
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(assignStmtB);
	assignStmtB->setSuccessor(assignStmtC);
	assignStmtC->setSuccessor(ifStmt);
	ifStmt->setSuccessor(assignStmtA);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeGotoTarg(new CFG::Node());
	nodeBeforeGotoTarg->addStmt(varDefStmtA);
	nodeBeforeGotoTarg->addStmt(varDefStmtB);
	nodeBeforeGotoTarg->addStmt(varDefStmtC);
	nodeBeforeGotoTarg->addStmt(assignStmtB);
	refCFG->addNode(nodeBeforeGotoTarg);

	ShPtr<CFG::Node> targetGotoNode(new CFG::Node());
	targetGotoNode->addStmt(assignStmtC);
	refCFG->addNode(targetGotoNode);

	ShPtr<CFG::Node> nodeIf(new CFG::Node());
	nodeIf->addStmt(ifStmt);
	refCFG->addNode(nodeIf);

	ShPtr<CFG::Node> nodeIfBody(new CFG::Node());
	nodeIfBody->addStmt(gotoStmtFirst);
	refCFG->addNode(nodeIfBody);

	ShPtr<CFG::Node> nodeElseBody(new CFG::Node());
	nodeElseBody->addStmt(gotoStmtSec);
	refCFG->addNode(nodeElseBody);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeGotoTarg);
	refCFG->addEdge(nodeBeforeGotoTarg, targetGotoNode);
	refCFG->addEdge(targetGotoNode, nodeIf);
	refCFG->addEdge(nodeIf, nodeIfBody, gtOpExpr);
	refCFG->addEdge(nodeIf, nodeElseBody, ltEqOpExpr);
	refCFG->addEdge(nodeIfBody, targetGotoNode);
	refCFG->addEdge(nodeElseBody, targetGotoNode);

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForTwoGotoJumpForwardFromIfStmt) {
	// Two goto statements jump forward from if statement.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   b = 1
	//   if (a > b)
	//     goto c = 1;
	//   else
	//     goto c = 1;
	//   a = b;
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varA, varB));
	ShPtr<GotoStmt> gotoStmtFirst(GotoStmt::create(assignStmtC));
	ShPtr<GotoStmt> gotoStmtSec(GotoStmt::create(assignStmtC));
	ShPtr<IfStmt> ifStmt(IfStmt::create(gtOpExpr, gotoStmtFirst));
	ifStmt->setElseClause(gotoStmtSec);
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(assignStmtB);
	assignStmtB->setSuccessor(ifStmt);
	ifStmt->setSuccessor(assignStmtA);
	assignStmtA->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeIf(new CFG::Node());
	nodeBeforeIf->addStmt(varDefStmtA);
	nodeBeforeIf->addStmt(varDefStmtB);
	nodeBeforeIf->addStmt(varDefStmtC);
	nodeBeforeIf->addStmt(assignStmtB);
	refCFG->addNode(nodeBeforeIf);

	ShPtr<CFG::Node> nodeIf(new CFG::Node());
	nodeIf->addStmt(ifStmt);
	refCFG->addNode(nodeIf);

	ShPtr<CFG::Node> nodeIfBody(new CFG::Node());
	nodeIfBody->addStmt(gotoStmtFirst);
	refCFG->addNode(nodeIfBody);

	ShPtr<CFG::Node> nodeElseBody(new CFG::Node());
	nodeElseBody->addStmt(gotoStmtSec);
	refCFG->addNode(nodeElseBody);

	ShPtr<CFG::Node> targetGotoNode(new CFG::Node());
	targetGotoNode->addStmt(assignStmtC);
	refCFG->addNode(targetGotoNode);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeIf);
	refCFG->addEdge(nodeBeforeIf, nodeIf);
	refCFG->addEdge(nodeIf, nodeIfBody, gtOpExpr);
	refCFG->addEdge(nodeIf, nodeElseBody, ltEqOpExpr);
	refCFG->addEdge(nodeIfBody, targetGotoNode);
	refCFG->addEdge(nodeElseBody, targetGotoNode);
	refCFG->addEdge(targetGotoNode, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForTwoGotoOneJumpForwardSecondOneBackwardFromIfStmt) {
	// Two goto statements one jump forward the second one jump bacward.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int d;
	//   goto d = 3;
	//   if (a > b) {
	//     a = b;
	//     d = 3;
	//     goto if;
	//   }
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varD(Variable::create("d", IntType::create(16)));
	testFunc->addLocalVar(varD);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtD(VarDefStmt::create(varD, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtD(AssignStmt::create(varD, ConstInt::create(3, 64)));
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varA, varB));
	ShPtr<IfStmt> ifStmt(IfStmt::create(gtOpExpr, assignStmtA));
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(assignStmtD));
	ShPtr<GotoStmt> gotoStmt1(GotoStmt::create(ifStmt));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtD);
	varDefStmtD->setSuccessor(gotoStmt);
	gotoStmt->setSuccessor(ifStmt);
	assignStmtA->setSuccessor(assignStmtD);
	assignStmtD->setSuccessor(gotoStmt1);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> varDefNodeWithFirstGoto(new CFG::Node());
	varDefNodeWithFirstGoto->addStmt(varDefStmtA);
	varDefNodeWithFirstGoto->addStmt(varDefStmtB);
	varDefNodeWithFirstGoto->addStmt(varDefStmtD);
	varDefNodeWithFirstGoto->addStmt(gotoStmt);
	refCFG->addNode(varDefNodeWithFirstGoto);

	ShPtr<CFG::Node> firstGotoTargetNode(new CFG::Node());
	firstGotoTargetNode->addStmt(assignStmtD);
	firstGotoTargetNode->addStmt(gotoStmt1);
	refCFG->addNode(firstGotoTargetNode);

	ShPtr<CFG::Node> nodeIfAlsoSecondGotoTarget(new CFG::Node());
	nodeIfAlsoSecondGotoTarget->addStmt(ifStmt);
	refCFG->addNode(nodeIfAlsoSecondGotoTarget);

	ShPtr<CFG::Node> nodeIfBody(new CFG::Node());
	nodeIfBody->addStmt(assignStmtA);
	refCFG->addNode(nodeIfBody);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), varDefNodeWithFirstGoto);
	refCFG->addEdge(varDefNodeWithFirstGoto, firstGotoTargetNode);
	refCFG->addEdge(firstGotoTargetNode, nodeIfAlsoSecondGotoTarget);
	refCFG->addEdge(nodeIfAlsoSecondGotoTarget, nodeIfBody, gtOpExpr);
	refCFG->addEdge(nodeIfBody, firstGotoTargetNode);
	refCFG->addEdge(nodeIfAlsoSecondGotoTarget, refCFG->getExitNode(), ltEqOpExpr);

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(refCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForGotoToGotoForwardJumps) {
	// Goto to goto forward jumps.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   int d;
	//   b = 1
	//   goto A;
	//   a = b;
	//   A: goto c = 1;
	//   d = 2;
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<Variable> varD(Variable::create("d", IntType::create(16)));
	testFunc->addLocalVar(varD);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtD(VarDefStmt::create(varD, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtD(AssignStmt::create(varD, ConstInt::create(2, 64)));
	ShPtr<GotoStmt> gotoStmtSec(GotoStmt::create(assignStmtC));
	ShPtr<GotoStmt> gotoStmtFirst(GotoStmt::create(gotoStmtSec));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(varDefStmtD);
	varDefStmtD->setSuccessor(assignStmtB);
	assignStmtB->setSuccessor(gotoStmtFirst);
	gotoStmtFirst->setSuccessor(assignStmtA);
	assignStmtA->setSuccessor(gotoStmtSec);
	gotoStmtSec->setSuccessor(assignStmtD);
	assignStmtD->setSuccessor(assignStmtC);

	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeWithFirstGoto(new CFG::Node());
	nodeWithFirstGoto->addStmt(varDefStmtA);
	nodeWithFirstGoto->addStmt(varDefStmtB);
	nodeWithFirstGoto->addStmt(varDefStmtC);
	nodeWithFirstGoto->addStmt(varDefStmtD);
	nodeWithFirstGoto->addStmt(assignStmtB);
	nodeWithFirstGoto->addStmt(gotoStmtFirst);
	refCFG->addNode(nodeWithFirstGoto);

	ShPtr<CFG::Node> nodeWithSecGoto(new CFG::Node());
	nodeWithSecGoto->addStmt(gotoStmtSec);
	refCFG->addNode(nodeWithSecGoto);

	ShPtr<CFG::Node> targetGotoNode(new CFG::Node());
	targetGotoNode->addStmt(assignStmtC);
	refCFG->addNode(targetGotoNode);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeWithFirstGoto);
	refCFG->addEdge(nodeWithFirstGoto, nodeWithSecGoto);
	refCFG->addEdge(nodeWithSecGoto, targetGotoNode);
	refCFG->addEdge(targetGotoNode, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForWhileWithGotoJumpForward) {
	// Goto statement jump forward from body of while loop statement.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   b = 1
	//   while (a > b)
	//     goto c = 1;
	//   a = b;
	//   c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varA, varB));
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(assignStmtC));
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(gtOpExpr, gotoStmt));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(assignStmtB);
	assignStmtB->setSuccessor(whileLoopStmt);
	whileLoopStmt->setSuccessor(assignStmtA);
	assignStmtA->setSuccessor(assignStmtC);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeBeforeWhile(new CFG::Node());
	nodeBeforeWhile->addStmt(varDefStmtA);
	nodeBeforeWhile->addStmt(varDefStmtB);
	nodeBeforeWhile->addStmt(varDefStmtC);
	nodeBeforeWhile->addStmt(assignStmtB);
	refCFG->addNode(nodeBeforeWhile);

	ShPtr<CFG::Node> nodeWhile(new CFG::Node());
	nodeWhile->addStmt(whileLoopStmt);
	refCFG->addNode(nodeWhile);

	ShPtr<CFG::Node> nodeWhileBody(new CFG::Node());
	nodeWhileBody->addStmt(gotoStmt);
	refCFG->addNode(nodeWhileBody);

	ShPtr<CFG::Node> nodeA(new CFG::Node());
	nodeA->addStmt(assignStmtA);
	refCFG->addNode(nodeA);

	ShPtr<CFG::Node> targetGotoNode(new CFG::Node());
	targetGotoNode->addStmt(assignStmtC);
	refCFG->addNode(targetGotoNode);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeBeforeWhile);
	refCFG->addEdge(nodeBeforeWhile, nodeWhile);
	refCFG->addEdge(nodeWhile, nodeWhileBody, gtOpExpr);
	refCFG->addEdge(nodeWhile, nodeA, ltEqOpExpr);
	refCFG->addEdge(nodeWhileBody, targetGotoNode);
	refCFG->addEdge(nodeA, targetGotoNode);
	refCFG->addEdge(targetGotoNode, refCFG->getExitNode());

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForGotoJumpToBodyOfWhile) {
	// Goto statement jump forward to body of while loop statement.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   b = 1
	//   goto c = 1;
	//   a = b;
	//   while (a > b)
	//		c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varA, varB));
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(assignStmtC));
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(gtOpExpr, assignStmtC));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(assignStmtB);
	assignStmtB->setSuccessor(gotoStmt);
	gotoStmt->setSuccessor(assignStmtA);
	assignStmtA->setSuccessor(whileLoopStmt);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeWithGoto(new CFG::Node());
	nodeWithGoto->addStmt(varDefStmtA);
	nodeWithGoto->addStmt(varDefStmtB);
	nodeWithGoto->addStmt(varDefStmtC);
	nodeWithGoto->addStmt(assignStmtB);
	nodeWithGoto->addStmt(gotoStmt);
	refCFG->addNode(nodeWithGoto);

	ShPtr<CFG::Node> nodeWhile(new CFG::Node());
	nodeWhile->addStmt(whileLoopStmt);
	refCFG->addNode(nodeWhile);

	ShPtr<CFG::Node> nodeWhileBody(new CFG::Node());
	nodeWhileBody->addStmt(assignStmtC);
	refCFG->addNode(nodeWhileBody);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeWithGoto);
	refCFG->addEdge(nodeWithGoto, nodeWhileBody);
	refCFG->addEdge(nodeWhile, nodeWhileBody, gtOpExpr);
	refCFG->addEdge(nodeWhile, refCFG->getExitNode(), ltEqOpExpr);
	refCFG->addEdge(nodeWhileBody, nodeWhile);

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

TEST_F(NonRecursiveCFGBuilderTests,
CFGCreatedForGotoJumpToWhile) {
	// Goto statement jump forward to while loop statement.
	//
	// Input:
	// void func() {
	//   int a;
	//   int b;
	//   int c;
	//   b = 1
	//   goto while (a > b);
	//   a = b;
	//   while (a > b)
	//		c = 1;
	// }
	//

	// Creating body of function to create CFG.
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	testFunc->addLocalVar(varC);
	ShPtr<VarDefStmt> varDefStmtA(VarDefStmt::create(varA, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtB(VarDefStmt::create(varB, ShPtr<Expression>()));
	ShPtr<VarDefStmt> varDefStmtC(VarDefStmt::create(varC, ShPtr<Expression>()));
	ShPtr<AssignStmt> assignStmtA(AssignStmt::create(varA, varB));
	ShPtr<AssignStmt> assignStmtB(AssignStmt::create(varB, ConstInt::create(1, 64)));
	ShPtr<AssignStmt> assignStmtC(AssignStmt::create(varC, ConstInt::create(1, 64)));
	ShPtr<GtOpExpr> gtOpExpr(GtOpExpr::create(varA, varB));
	ShPtr<LtEqOpExpr> ltEqOpExpr(LtEqOpExpr::create(varA, varB));
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(gtOpExpr, assignStmtC));
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(whileLoopStmt));
	varDefStmtA->setSuccessor(varDefStmtB);
	varDefStmtB->setSuccessor(varDefStmtC);
	varDefStmtC->setSuccessor(assignStmtB);
	assignStmtB->setSuccessor(gotoStmt);
	gotoStmt->setSuccessor(assignStmtA);
	assignStmtA->setSuccessor(whileLoopStmt);
	testFunc->setBody(varDefStmtA);

	// Creating a reference CFG.
	ShPtr<CFG> refCFG(ShPtr<CFG>(new CFG(testFunc)));

	refCFG->addEntryNode(ShPtr<CFG::Node>(new CFG::Node("entry")));

	ShPtr<CFG::Node> nodeWithGoto(new CFG::Node());
	nodeWithGoto->addStmt(varDefStmtA);
	nodeWithGoto->addStmt(varDefStmtB);
	nodeWithGoto->addStmt(varDefStmtC);
	nodeWithGoto->addStmt(assignStmtB);
	nodeWithGoto->addStmt(gotoStmt);
	refCFG->addNode(nodeWithGoto);

	ShPtr<CFG::Node> nodeWhile(new CFG::Node());
	nodeWhile->addStmt(whileLoopStmt);
	refCFG->addNode(nodeWhile);

	ShPtr<CFG::Node> nodeWhileBody(new CFG::Node());
	nodeWhileBody->addStmt(assignStmtC);
	refCFG->addNode(nodeWhileBody);

	refCFG->addExitNode(ShPtr<CFG::Node>(new CFG::Node("exit")));

	refCFG->addEdge(refCFG->getEntryNode(), nodeWithGoto);
	refCFG->addEdge(nodeWithGoto, nodeWhile);
	refCFG->addEdge(nodeWhile, nodeWhileBody, gtOpExpr);
	refCFG->addEdge(nodeWhile, refCFG->getExitNode(), ltEqOpExpr);
	refCFG->addEdge(nodeWhileBody, nodeWhile);

	// Check difference.
	ShPtr<retdec::llvmir2hll::CFGBuilder> cfgBuilder(retdec::llvmir2hll::NonRecursiveCFGBuilder::create());
	ShPtr<CFG> compCFG(cfgBuilder->getCFG(testFunc));
	checkEquivalenceOfCFGs(compCFG, refCFG);

	// If want to emit CFG, set to 1
	#if 0
	emitCFG(compCFG);
	#endif
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
