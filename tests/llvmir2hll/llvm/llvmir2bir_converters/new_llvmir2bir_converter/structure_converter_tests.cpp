/**
* @file tests/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/structure_converter_tests.cpp
* @brief Tests for the @c structure_converter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "llvmir2hll/ir/assertions.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter_tests/base_tests.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/utils/ir.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c structure_converter module.
*/
class StructureConverterTests: public NewLLVMIR2BIRConverterBaseTests {
protected:
	template<class T>
	AssertionResult isComparison(ShPtr<Expression> expr, ShPtr<Variable> var,
		int num);
	template<class T>
	AssertionResult isComparison(ShPtr<Expression> expr, ShPtr<Variable> var1,
		ShPtr<Variable> var2);

	template<class T = BreakStmt>
	AssertionResult isTerminatingSwitchClause(const SwitchStmt::SwitchClause &clause,
		int cond, int funcParam);
	AssertionResult isNonTerminatingSwitchClause(const SwitchStmt::SwitchClause &clause,
		int cond, int funcParam);

	void testPredefinedDoWhileLoop(ShPtr<Statement> statement,
		ShPtr<Variable> varX, ShPtr<Variable> varY,
		ShPtr<Variable> varLoopCond);
};

/**
* @brief Assertion that the given BIR expression @a expr is a comparison
*        expression of the variable @a var and the integer constant @a num.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
AssertionResult StructureConverterTests::isComparison(ShPtr<Expression> expr,
		ShPtr<Variable> var, int num) {
	auto compExpr = cast<T>(expr);
	if (!compExpr) {
		return AssertionFailure() << expr
			<< " is not a comparison of expected type";
	}

	if (compExpr->getFirstOperand() != var) {
		return AssertionFailure() << expr
			<< " does not have first operand " << var;
	}

	if (!isConstInt(compExpr->getSecondOperand(), num)) {
		return AssertionFailure() << expr
			<< " does not have second operand " << num;
	}

	return AssertionSuccess() << expr << " is comparion of expected type of "
		<< var << " and " << num;
}

/**
* @brief Assertion that the given BIR expression @a expr is a comparison
*        expression of the variable @a var1 and the variable @a var2.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
AssertionResult StructureConverterTests::isComparison(ShPtr<Expression> expr,
		ShPtr<Variable> var1, ShPtr<Variable> var2) {
	auto compExpr = cast<T>(expr);
	if (!compExpr) {
		return AssertionFailure() << expr
			<< " is not a comparison of expected type";
	}

	if (compExpr->getFirstOperand() != var1) {
		return AssertionFailure() << expr
			<< " does not have first operand " << var1;
	}

	if (compExpr->getSecondOperand() != var2) {
		return AssertionFailure() << expr
			<< " does not have second operand " << var2;
	}

	return AssertionSuccess() << expr << " is comparion of expected type of "
		<< var1 << " and " << var2;
}

/**
* @brief Assertion that the given BIR switch clause @a clause has condition
*        @a cond and body calls function test with parameter @a funcParam.
*
* @tparam T Class that represents a statement in BIR, which must be at the end
*           of the clause body.
*/
template<class T>
AssertionResult StructureConverterTests::isTerminatingSwitchClause(
		const SwitchStmt::SwitchClause &clause, int cond, int funcParam) {
	if (!isConstInt(clause.first, cond)) {
		return AssertionFailure()
			<< "This clause does not have condition " << cond;
	}

	auto clauseBody = skipEmptyStmts(clause.second);
	if (!isCallOfFuncTest(clauseBody, funcParam)) {
		return AssertionFailure()
			<< "This clause does not call function test("
			<< funcParam << ")";
	}

	if (!isa<T>(getFirstNonEmptySuccOf(clauseBody))) {
		return AssertionFailure()
			<< "This clause is not terminated correctly";
	}

	return AssertionSuccess() << "This clause is switch clause with condition "
		<< cond << " and body is call of function test(" <<  funcParam
		<< ") and it is terminated correctly";
}

/**
* @brief Assertion that the given BIR switch clause @a clause has condition
*        @a cond and body calls function test with parameter @a funcParam.
*
* The given clause @a clause cannot be terminated by any statement. It means
* that the clause must fall through to the following clause.
*/
AssertionResult StructureConverterTests::isNonTerminatingSwitchClause(
		const SwitchStmt::SwitchClause &clause, int cond, int funcParam) {
	if (!isConstInt(clause.first, cond)) {
		return AssertionFailure()
			<< "This clause does not have condition " << cond;
	}

	auto clauseBody = skipEmptyStmts(clause.second);
	if (!isCallOfFuncTest(clauseBody, funcParam)) {
		return AssertionFailure()
			<< "This clause does not call function test("
			<< funcParam << ")";
	}

	auto successor = getFirstNonEmptySuccOf(clauseBody);
	if (successor) {
		return AssertionFailure()
			<< "This clause does not fall through to the next clause";
	}

	return AssertionSuccess() << "This clause is switch clause with condition "
		<< cond << " and body is call of function test(" <<  funcParam
		<< ") and it falls through to the next clause";
}

/**
* @brief Assertion that the given BIR statement @a statement is a do-while loop
*        with predefined body.
*
* Predefined body must match this code:
* @code
* while (true) {
*     test(x);
*     y = x + 1;
*     if (y == val) {
*         break;
*     }
*     x = y;
* }
* @endcode
*
* @param[in] statement Tested statement in BIR.
* @param[in] varX Integer variable "x".
* @param[in] varY Integer variable "y".
* @param[in] varVal Integer variable "val".
*/
void StructureConverterTests::testPredefinedDoWhileLoop(
		ShPtr<Statement> statement, ShPtr<Variable> varX,
		ShPtr<Variable> varY, ShPtr<Variable> varVal) {
	auto whileStmt = cast<WhileLoopStmt>(statement);
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());

	ASSERT_TRUE(isCallOfFuncTest(whileBody, varX));

	auto assignStmt = getFirstNonEmptySuccOf(whileBody);
	ASSERT_TRUE(isAssignOfAddExprToVar(assignStmt, varY, varX, 1));

	auto ifBreak = cast<IfStmt>(getFirstNonEmptySuccOf(assignStmt));
	ASSERT_TRUE(ifBreak);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak->getFirstIfCond(), varY, varVal));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak->getFirstIfBody()));
	ASSERT_EQ("break -> after"s, ifBreak->getFirstIfBody()->getMetadata());
	ASSERT_FALSE(ifBreak->hasElseClause());

	auto assignStmt2 = getFirstNonEmptySuccOf(ifBreak);
	ASSERT_TRUE(isAssignOfVarToVar(assignStmt2, varX, varY));

	auto continueStmt = cast<EmptyStmt>(assignStmt2->getSuccessor());
	ASSERT_TRUE(continueStmt);
	ASSERT_EQ("continue -> loop"s, continueStmt->getMetadata());
}

//
// Tests for if/else conditions
//

TEST_F(StructureConverterTests,
IfElseConditionIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			call void @test(i32 1)
			br label %after
		iffalse:
			call void @test(i32 2)
			br label %after
		after:
			call void @test(i32 3)
			ret void
		}
	)");

	//
	// // entry
	// if (val == 1) {
	//     // iftrue
	//     test(1);
	//     // branch -> after
	// } else {
	//     // iffalse
	//     test(2);
	//     // branch ->after
	// }
	// // after
	// test(3);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto body = f->getBody();
	ASSERT_TRUE(body);
	ASSERT_EQ("entry"s, body->getMetadata());
	auto ifStmt = cast<IfStmt>(skipEmptyStmts(body));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	auto trueBody = ifStmt->getFirstIfBody();
	ASSERT_EQ("iftrue"s, trueBody->getMetadata());
	ASSERT_TRUE(isCallOfFuncTest(trueBody, 1));
	auto trueBodySucc = trueBody->getSuccessor();
	ASSERT_TRUE(trueBodySucc);
	ASSERT_EQ("branch -> after"s, trueBodySucc->getMetadata());
	auto falseBody = ifStmt->getElseClause();
	ASSERT_EQ("iffalse"s, falseBody->getMetadata());
	ASSERT_TRUE(isCallOfFuncTest(falseBody, 2));
	auto falseBodySucc = falseBody->getSuccessor();
	ASSERT_TRUE(falseBodySucc);
	ASSERT_EQ("branch -> after"s, falseBodySucc->getMetadata());
	auto after = ifStmt->getSuccessor();
	ASSERT_EQ("after"s, after->getMetadata());
	ASSERT_TRUE(isCallOfFuncTest(after, 3));
}

TEST_F(StructureConverterTests,
IfElseConditionWithPhiNodeAfterIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			call void @test(i32 1)
			br label %after
		iffalse:
			call void @test(i32 2)
			br label %after
		after:
			%x = phi i32 [ 1, %iftrue ], [ 2, %iffalse ]
			call void @test(i32 %x)
			ret void
		}
	)");

	//
	// int x;
	// if (val == 1) {
	//     test(1);
	//     x = 1;
	// } else {
	//     test(2);
	//     x = 2;
	// }
	// test(x);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto ifStmt = cast<IfStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	auto ifTrue = ifStmt->getFirstIfBody();
	ASSERT_TRUE(isCallOfFuncTest(ifTrue, 1));
	ASSERT_TRUE(isAssignOfConstIntToVar(getFirstNonEmptySuccOf(ifTrue), varX, 1));
	auto ifFalse = ifStmt->getElseClause();
	ASSERT_TRUE(isCallOfFuncTest(ifFalse, 2));
	ASSERT_TRUE(isAssignOfConstIntToVar(getFirstNonEmptySuccOf(ifFalse), varX, 2));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(ifStmt), varX));
}

TEST_F(StructureConverterTests,
IfConditionOnlyWithTrueBranchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %after
		iftrue:
			call void @test(i32 1)
			br label %after
		after:
			call void @test(i32 2)
			ret void
		}
	)");

	//
	// if (val == 1) {
	//     test(1);
	// }
	// test(2);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto ifStmt = cast<IfStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt->getFirstIfBody(), 1));
	ASSERT_FALSE(ifStmt->hasElseClause());
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(ifStmt), 2));
}

TEST_F(StructureConverterTests,
IfConditionOnlyWithTrueBranchAndWithPhiNodeAfterIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %after
		iftrue:
			call void @test(i32 1)
			br label %after
		after:
			%x = phi i32 [ 1, %iftrue ], [ 2, %entry ]
			call void @test(i32 %x)
			ret void
		}
	)");

	//
	// int x;
	// if (val == 1) {
	//     test(1);
	//     x = 1;
	// } else {
	//     x = 2;
	// }
	// test(x);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto ifStmt = cast<IfStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	auto ifTrue = ifStmt->getFirstIfBody();
	ASSERT_TRUE(isCallOfFuncTest(ifTrue, 1));
	ASSERT_TRUE(isAssignOfConstIntToVar(getFirstNonEmptySuccOf(ifTrue), varX, 1));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt->getFirstIfBody(), 1));
	ASSERT_TRUE(isAssignOfConstIntToVar(ifStmt->getElseClause(), varX, 2));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(ifStmt), varX));
}

TEST_F(StructureConverterTests,
IfConditionOnlyWithFalseBranchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %after, label %iffalse
		iffalse:
			call void @test(i32 1)
			br label %after
		after:
			call void @test(i32 2)
			ret void
		}
	)");

	//
	// if (val != 1) {
	//     test(1);
	// }
	// test(2);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto ifStmt = cast<IfStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<NeqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt->getFirstIfBody(), 1));
	ASSERT_FALSE(ifStmt->hasElseClause());
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(ifStmt), 2));
}

TEST_F(StructureConverterTests,
IfConditionOnlyWithFalseBranchAndWithPhiNodeAfterIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %after, label %iftrue
		iftrue:
			call void @test(i32 1)
			br label %after
		after:
			%x = phi i32 [ 1, %iftrue ], [ 2, %entry ]
			call void @test(i32 %x)
			ret void
		}
	)");

	//
	// int x;
	// if (val != 1) {
	//     test(1);
	//     x = 1;
	// } else {
	//     x = 2;
	// }
	// test(x);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto ifStmt = cast<IfStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<NeqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	auto ifTrue = ifStmt->getFirstIfBody();
	ASSERT_TRUE(isCallOfFuncTest(ifTrue, 1));
	ASSERT_TRUE(isAssignOfConstIntToVar(getFirstNonEmptySuccOf(ifTrue), varX, 1));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt->getFirstIfBody(), 1));
	ASSERT_TRUE(isAssignOfConstIntToVar(ifStmt->getElseClause(), varX, 2));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(ifStmt), varX));
}

TEST_F(StructureConverterTests,
IfElseConditionWithReturnInTrueBranchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define i32 @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			ret i32 1
		iffalse:
			call void @test(i32 1)
			br label %after
		after:
			call void @test(i32 2)
			ret i32 0
		}
	)");

	//
	// if (val == 1) {
	//     return 1;
	// }
	// test(1);
	// test(2);
	// return 0;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto ifStmt = cast<IfStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	ASSERT_TRUE(isIntReturn(ifStmt->getFirstIfBody(), 1));
	ASSERT_FALSE(ifStmt->hasElseClause());
	auto callStmt1 = getFirstNonEmptySuccOf(ifStmt);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto callStmt2 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 2));
	ASSERT_TRUE(isIntReturn(getFirstNonEmptySuccOf(callStmt2), 0));
}

TEST_F(StructureConverterTests,
IfElseConditionWithReturnInFalseBranchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define i32 @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			call void @test(i32 1)
			br label %after
		iffalse:
			ret i32 1
		after:
			call void @test(i32 2)
			ret i32 0
		}
	)");

	//
	// if (val != 1) {
	//     return 1;
	// }
	// test(1);
	// test(2);
	// return 0;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto ifStmt = cast<IfStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<NeqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	ASSERT_TRUE(isIntReturn(ifStmt->getFirstIfBody(), 1));
	ASSERT_FALSE(ifStmt->hasElseClause());
	auto callStmt1 = getFirstNonEmptySuccOf(ifStmt);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto callStmt2 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 2));
	ASSERT_TRUE(isIntReturn(getFirstNonEmptySuccOf(callStmt2), 0));
}

TEST_F(StructureConverterTests,
IfElseConditionWithReturnsInBothBranchesIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		define i32 @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			ret i32 1
		iffalse:
			ret i32 0
		}
	)");

	//
	// if (val == 1) {
	//     return 1;
	// }
	// return 0;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto ifStmt = cast<IfStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	ASSERT_TRUE(isIntReturn(ifStmt->getFirstIfBody(), 1));
	ASSERT_FALSE(ifStmt->hasElseClause());
	ASSERT_TRUE(isIntReturn(getFirstNonEmptySuccOf(ifStmt), 0));
}

TEST_F(StructureConverterTests,
IfConditionWithEmptyTrueBranchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %after
		iftrue:
			br label %after
		after:
			call void @test(i32 1)
			ret void
		}
	)");

	//
	// test(1);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_TRUE(isCallOfFuncTest(skipEmptyStmts(f->getBody()), 1));
}

TEST_F(StructureConverterTests,
IfConditionWithEmptyFalseBranchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %after, label %iffalse
		iffalse:
			br label %after
		after:
			call void @test(i32 1)
			ret void
		}
	)");

	//
	// test(1);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_TRUE(isCallOfFuncTest(skipEmptyStmts(f->getBody()), 1));
}

TEST_F(StructureConverterTests,
IfElseConditionWithEmptyTrueBranchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			br label %after
		iffalse:
			call void @test(i32 1)
			br label %after
		after:
			call void @test(i32 2)
			ret void
		}
	)");

	//
	// if (val != 1) {
	//     test(1);
	// }
	// test(2);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto ifStmt = cast<IfStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<NeqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt->getFirstIfBody(), 1));
	ASSERT_FALSE(ifStmt->hasElseClause());
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(ifStmt), 2));
}

TEST_F(StructureConverterTests,
IfElseConditionWithEmptyFalseBranchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			call void @test(i32 1)
			br label %after
		iffalse:
			br label %after
		after:
			call void @test(i32 2)
			ret void
		}
	)");

	//
	// if (val == 1) {
	//     test(1);
	// }
	// test(2);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto ifStmt = cast<IfStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(ifStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt->getFirstIfCond(), f->getParam(1), 1));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt->getFirstIfBody(), 1));
	ASSERT_FALSE(ifStmt->hasElseClause());
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(ifStmt), 2));
}

TEST_F(StructureConverterTests,
IfElseConditionWithBothBranchesEmptyIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			br label %after
		iffalse:
			br label %after
		after:
			call void @test(i32 1)
			ret void
		}
	)");

	//
	// test(1);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_TRUE(isCallOfFuncTest(skipEmptyStmts(f->getBody()), 1));
}

TEST_F(StructureConverterTests,
TwoIfElseConditionsInSequenceAreConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
			%cond1 = icmp eq i32 %val, 1
			br i1 %cond1, label %iftrue1, label %iffalse1
		iftrue1:
			call void @test(i32 1)
			br label %between
		iffalse1:
			call void @test(i32 2)
			br label %between
		between:
			call void @test(i32 3)
			%cond2 = icmp eq i32 %val, 2
			br i1 %cond2, label %iftrue2, label %iffalse2
		iftrue2:
			call void @test(i32 4)
			br label %after
		iffalse2:
			call void @test(i32 5)
			br label %after
		after:
			call void @test(i32 6)
			ret void
		}
	)");

	//
	// if (val == 1) {
	//     test(1);
	// } else {
	//     test(2);
	// }
	// test(3);
	// if (val == 2) {
	//     test(4);
	// } else {
	//     test(5);
	// }
	// test(6);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto ifStmt1 = cast<IfStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(ifStmt1);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt1->getFirstIfCond(), f->getParam(1), 1));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt1->getFirstIfBody(), 1));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt1->getElseClause(), 2));
	auto callStmt1 = getFirstNonEmptySuccOf(ifStmt1);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 3));
	auto ifStmt2 = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt1));
	ASSERT_TRUE(ifStmt2);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt2->getFirstIfCond(), f->getParam(1), 2));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt2->getFirstIfBody(), 4));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt2->getElseClause(), 5));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(ifStmt2), 6));
}

TEST_F(StructureConverterTests,
IfElseConditionWithNestedIfElseConsitionIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
			%cond1 = icmp ne i32 %val, 1
			br i1 %cond1, label %iftrue1, label %iffalse1
		iftrue1:
			call void @test(i32 1)
			%cond2 = icmp eq i32 %val, 2
			br i1 %cond2, label %iftrue2, label %iffalse2
		iftrue2:
			call void @test(i32 2)
			br label %after1
		iffalse2:
			call void @test(i32 3)
			br label %after1
		after1:
			call void @test(i32 4)
			br label %after2
		iffalse1:
			call void @test(i32 5)
			br label %after2
		after2:
			call void @test(i32 6)
		; code below is only to prevent optimizations with return
			br i1 %cond1, label %true, label %false
		true:
			call void @test(i32 0)
			br label %last
		false:
			call void @test(i32 0)
			br label %last
		last:
			ret void
		}
	)");

	//
	// if (val != 1) {
	//     test(1);
	//     if (val == 2) {
	//         test(2);
	//     } else {
	//         test(3);
	//     }
	//     test(4);
	// } else {
	//     test(5);
	// }
	// test(6);
	// // ...
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto ifStmt1 = cast<IfStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(ifStmt1);
	ASSERT_TRUE(isComparison<NeqOpExpr>(ifStmt1->getFirstIfCond(), f->getParam(1), 1));
	auto ifBody = ifStmt1->getFirstIfBody();
	ASSERT_TRUE(isCallOfFuncTest(ifBody, 1));
	auto ifStmt2 = cast<IfStmt>(getFirstNonEmptySuccOf(ifBody));
	ASSERT_TRUE(ifStmt2);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt2->getFirstIfCond(), f->getParam(1), 2));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt2->getFirstIfBody(), 2));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt2->getElseClause(), 3));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(ifStmt2), 4));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt1->getElseClause(), 5));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(ifStmt1), 6));
}

TEST_F(StructureConverterTests,
IfElseConditionWithClonedBlockWithReturnIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
			%cond1 = icmp ne i32 %val, 1
			br i1 %cond1, label %iftrue1, label %iffalse1
		iftrue1:
			call void @test(i32 1)
			%cond2 = icmp eq i32 %val, 2
			br i1 %cond2, label %iftrue2, label %iffalse2
		iftrue2:
			call void @test(i32 2)
			br label %after1
		iffalse2:
			call void @test(i32 3)
			br label %after1
		after1:
			call void @test(i32 4)
			br label %after2
		iffalse1:
			call void @test(i32 5)
			br label %after2
		after2:
			call void @test(i32 6)
			ret void
		}
	)");

	//
	// if (val == 1) {
	//     test(5);
	//     test(6);
	//     return;
	// }
	// test(1);
	// if (val == 2) {
	//     test(2);
	// } else {
	//     test(3);
	// }
	// test(4);
	// test(6);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto ifStmt1 = cast<IfStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(ifStmt1);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt1->getFirstIfCond(), f->getParam(1), 1));
	auto ifBody = ifStmt1->getFirstIfBody();
	ASSERT_TRUE(isCallOfFuncTest(ifBody, 5));
	auto callStmt2 = getFirstNonEmptySuccOf(ifBody);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 6));
	auto ret1 = getFirstNonEmptySuccOf(callStmt2);
	ASSERT_TRUE(isa<ReturnStmt>(ret1));
	ASSERT_FALSE(ifStmt1->hasElseClause());
	auto callStmt3 = getFirstNonEmptySuccOf(ifStmt1);
	ASSERT_TRUE(isCallOfFuncTest(callStmt3, 1));
	auto ifStmt2 = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt3));
	ASSERT_TRUE(ifStmt2);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifStmt2->getFirstIfCond(), f->getParam(1), 2));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt2->getFirstIfBody(), 2));
	ASSERT_TRUE(isCallOfFuncTest(ifStmt2->getElseClause(), 3));
	auto callStmt6 = getFirstNonEmptySuccOf(ifStmt2);
	ASSERT_TRUE(isCallOfFuncTest(callStmt6, 4));
	auto callStmt7 = getFirstNonEmptySuccOf(callStmt6);
	ASSERT_TRUE(isCallOfFuncTest(callStmt7, 6));
	auto ret2 = getFirstNonEmptySuccOf(callStmt7);
	ASSERT_TRUE(isa<ReturnStmt>(ret2));
	ASSERT_NE(callStmt3, callStmt7)
		<< "Call statements test(6) are not cloned.";
	ASSERT_NE(ret1, ret2)
		<< "Returns are not cloned.";
}

//
// Tests for loops
//

TEST_F(StructureConverterTests,
SimpleDoWhileLoopIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			%x = phi i32 [ %y, %loop ], [ 0, %entry ]
			call void @test(i32 %x)
			%y = add i32 %x, 1
			%cond = icmp eq i32 %y, %val
			br i1 %cond, label %after, label %loop
		after:
			call void @test(i32 2)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// // entry (metadata not tested)
	// test(1);
	// x = 0;
	// while (true) {
	//     // loop (metadata not tested)
	//     test(x);
	//     y = x + 1;
	//     if (y == val) {
	//         // break -> after
	//         break;
	//     }
	//     x = y;
	//     // continue -> loop
	// }
	// // after (metadata not tested)
	// test(2);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto callStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto assignStmt1 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varX, 0));
	auto whileStmt = getFirstNonEmptySuccOf(assignStmt1);
	{
		SCOPED_TRACE("Test for do-while loop");
		testPredefinedDoWhileLoop(whileStmt, varX, varY, f->getParam(1));
		if (HasFatalFailure()) {
			return;
		}
	}
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 2));
}

TEST_F(StructureConverterTests,
SimpleDoWhileLoopWithBackEdgeInFalseBranchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			%x = phi i32 [ %y, %loop ], [ 0, %entry ]
			call void @test(i32 %x)
			%y = add i32 %x, 1
			%cond = icmp ne i32 %y, %val
			br i1 %cond, label %loop, label %after
		after:
			call void @test(i32 2)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// test(1);
	// x = 0;
	// while (true) {
	//     test(x);
	//     y = x + 1;
	//     if (y == val) {
	//         break;
	//     }
	//     x = y;
	// }
	// test(2);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto callStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto assignStmt1 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varDefX->getVar(), 0));
	auto whileStmt = getFirstNonEmptySuccOf(assignStmt1);
	{
		SCOPED_TRACE("Test for do-while loop");
		testPredefinedDoWhileLoop(whileStmt, varX, varY, f->getParam(1));
		if (HasFatalFailure()) {
			return;
		}
	}
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 2));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithIfElseConditionInsideIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val1, i32 %val2) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			%x = phi i32 [ %y, %afterInside ], [ 0, %entry ]
			%y = add i32 %x, 1
			call void @test(i32 2)
			%cond = icmp eq i32 %y, %val1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			call void @test(i32 3)
			br label %afterInside
		iffalse:
			call void @test(i32 4)
			br label %afterInside
		afterInside:
			call void @test(i32 5)
			%cond2 = icmp eq i32 %y, %val2
			br i1 %cond2, label %after, label %loop
		after:
			call void @test(i32 6)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// test(1);
	// x = 0;
	// while (true) {
	//     y = x + 1
	//     test(2);
	//     if (y == val1) {
	//         test(3);
	//     } else {
	//         test(4);
	//     }
	//     test(5);
	//     if (y == val2) {
	//         break;
	//     }
	//     x = y;
	// }
	// test(6);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto callStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto assignStmt1 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varX, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());
	ASSERT_TRUE(isAssignOfAddExprToVar(whileBody, varY, varX, 1));
	auto callStmt2 = getFirstNonEmptySuccOf(whileBody);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 2));
	auto innerIfStmt = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt2));
	ASSERT_TRUE(innerIfStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(innerIfStmt->getFirstIfCond(), varY,
		f->getParam(1)));
	ASSERT_TRUE(isCallOfFuncTest(innerIfStmt->getFirstIfBody(), 3));
	ASSERT_TRUE(isCallOfFuncTest(innerIfStmt->getElseClause(), 4));
	auto afterInnerIf = getFirstNonEmptySuccOf(innerIfStmt);
	ASSERT_TRUE(isCallOfFuncTest(afterInnerIf, 5));
	auto ifBreak = cast<IfStmt>(getFirstNonEmptySuccOf(afterInnerIf));
	ASSERT_TRUE(ifBreak);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak->getFirstIfCond(), varY,
		f->getParam(2)));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak->getFirstIfBody()));
	ASSERT_FALSE(ifBreak->hasElseClause());
	ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak), varX, varY));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 6));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithIfConditionOnlyWithTrueBranchInsideIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val1, i32 %val2) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			%x = phi i32 [ %y, %afterInside ], [ 0, %entry ]
			%y = add i32 %x, 1
			call void @test(i32 2)
			%cond = icmp eq i32 %y, %val1
			br i1 %cond, label %iftrue, label %afterInside
		iftrue:
			call void @test(i32 3)
			br label %afterInside
		afterInside:
			call void @test(i32 4)
			%cond2 = icmp eq i32 %y, %val2
			br i1 %cond2, label %after, label %loop
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// test(1);
	// x = 0;
	// while (true) {
	//     y = x + 1
	//     test(2);
	//     if (y == val1) {
	//         test(3);
	//     }
	//     test(4);
	//     if (y == val2) {
	//         break;
	//     }
	//     x = y;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto callStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto assignStmt1 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varX, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());
	ASSERT_TRUE(isAssignOfAddExprToVar(whileBody, varY, varX, 1));
	auto callStmt2 = getFirstNonEmptySuccOf(whileBody);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 2));
	auto innerIfStmt = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt2));
	ASSERT_TRUE(innerIfStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(innerIfStmt->getFirstIfCond(), varY,
		f->getParam(1)));
	ASSERT_TRUE(isCallOfFuncTest(innerIfStmt->getFirstIfBody(), 3));
	ASSERT_FALSE(innerIfStmt->hasElseClause());
	auto afterInnerIf = getFirstNonEmptySuccOf(innerIfStmt);
	ASSERT_TRUE(isCallOfFuncTest(afterInnerIf, 4));
	auto ifBreak = cast<IfStmt>(getFirstNonEmptySuccOf(afterInnerIf));
	ASSERT_TRUE(ifBreak);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak->getFirstIfCond(), varY,
		f->getParam(2)));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak->getFirstIfBody()));
	ASSERT_FALSE(ifBreak->hasElseClause());
	ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak), varX, varY));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 5));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithIfConditionOnlyWithFalseBranchInsideIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val1, i32 %val2) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			%x = phi i32 [ %y, %afterInside ], [ 0, %entry ]
			%y = add i32 %x, 1
			call void @test(i32 2)
			%cond = icmp eq i32 %y, %val1
			br i1 %cond, label %afterInside, label %iftrue
		iftrue:
			call void @test(i32 3)
			br label %afterInside
		afterInside:
			call void @test(i32 4)
			%cond2 = icmp eq i32 %y, %val2
			br i1 %cond2, label %after, label %loop
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// test(1);
	// x = 0;
	// while (true) {
	//     y = x + 1
	//     test(2);
	//     if (y != val1) {
	//         test(3);
	//     }
	//     test(4);
	//     if (y == val2) {
	//         break;
	//     }
	//     x = y;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto callStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto assignStmt1 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varX, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());
	ASSERT_TRUE(isAssignOfAddExprToVar(whileBody, varY, varX, 1));
	auto callStmt2 = getFirstNonEmptySuccOf(whileBody);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 2));
	auto innerIfStmt = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt2));
	ASSERT_TRUE(innerIfStmt);
	ASSERT_TRUE(isComparison<NeqOpExpr>(innerIfStmt->getFirstIfCond(), varY,
		f->getParam(1)));
	ASSERT_TRUE(isCallOfFuncTest(innerIfStmt->getFirstIfBody(), 3));
	ASSERT_FALSE(innerIfStmt->hasElseClause());
	auto afterInnerIf = getFirstNonEmptySuccOf(innerIfStmt);
	ASSERT_TRUE(isCallOfFuncTest(afterInnerIf, 4));
	auto ifBreak = cast<IfStmt>(getFirstNonEmptySuccOf(afterInnerIf));
	ASSERT_TRUE(ifBreak);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak->getFirstIfCond(), varY,
		f->getParam(2)));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak->getFirstIfBody()));
	ASSERT_FALSE(ifBreak->hasElseClause());
	ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak), varX, varY));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 5));
}

TEST_F(StructureConverterTests,
SimpleWhileTrueLoopConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function() {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			call void @test(i32 2)
			br label %loop
		}
	)");

	//
	// test(1);
	// while (true) {
	//     test(2);
	// }
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto callStmt1 = skipEmptyStmts(f->getBody());
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(callStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	ASSERT_TRUE(isCallOfFuncTest(skipEmptyStmts(whileStmt->getBody()), 2));
}

TEST_F(StructureConverterTests,
WhileTrueLoopWithIfElseConditionInsideConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			call void @test(i32 2)
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			call void @test(i32 3)
			br label %afterInside
		iffalse:
			call void @test(i32 4)
			br label %afterInside
		afterInside:
			call void @test(i32 5)
			br label %loop
		}
	)");

	//
	// test(1);
	// while (true) {
	//     test(2);
	//     if (val == 1) {
	//         test(3);
	//     } else {
	//         test(4);
	//     }
	//     test(5);
	// }
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto callStmt1 = skipEmptyStmts(f->getBody());
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(callStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());
	ASSERT_TRUE(isCallOfFuncTest(whileBody, 2));
	auto innerIfStmt = cast<IfStmt>(getFirstNonEmptySuccOf(whileBody));
	ASSERT_TRUE(innerIfStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(innerIfStmt->getFirstIfCond(), f->getParam(1), 1));
	ASSERT_TRUE(isCallOfFuncTest(innerIfStmt->getFirstIfBody(), 3));
	ASSERT_TRUE(isCallOfFuncTest(innerIfStmt->getElseClause(), 4));
	auto afterInnerIf = getFirstNonEmptySuccOf(innerIfStmt);
	ASSERT_TRUE(isCallOfFuncTest(afterInnerIf, 5));
}

TEST_F(StructureConverterTests,
WhileTrueLoopWithIfElseConditionHavingLoopHeaderBBAfterInsideConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			call void @test(i32 2)
			%cond = icmp eq i32 %val, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			call void @test(i32 3)
			br label %loop
		iffalse:
			call void @test(i32 4)
			br label %loop
		}
	)");

	//
	// test(1);
	// while (true) {
	//     test(2);
	//     if (val == 1) {
	//         test(3);
	//     } else {
	//         test(4);
	//     }
	// }
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto callStmt1 = skipEmptyStmts(f->getBody());
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(callStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());
	ASSERT_TRUE(isCallOfFuncTest(whileBody, 2));
	auto innerIfStmt = cast<IfStmt>(getFirstNonEmptySuccOf(whileBody));
	ASSERT_TRUE(innerIfStmt);
	ASSERT_TRUE(isComparison<EqOpExpr>(innerIfStmt->getFirstIfCond(), f->getParam(1), 1));
	ASSERT_TRUE(isCallOfFuncTest(innerIfStmt->getFirstIfBody(), 3));
	ASSERT_TRUE(isCallOfFuncTest(innerIfStmt->getElseClause(), 4));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithIfInTrueBranchOnlyWithBreakInsideIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val1, i32 %val2) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			%x = phi i32 [ %y, %afterInside ], [ 0, %entry ]
			%y = add i32 %x, 1
			call void @test(i32 2)
			%cond1 = icmp eq i32 %y, %val1
			br i1 %cond1, label %after, label %afterInside
		afterInside:
			call void @test(i32 3)
			%cond2 = icmp eq i32 %y, %val2
			br i1 %cond2, label %after, label %loop
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// test(1);
	// x = 0;
	// while (true) {
	//     y = x + 1
	//     test(2);
	//     if (y == val1) {
	//         break;
	//     }
	//     test(3);
	//     if (y == val2) {
	//         break;
	//     }
	//     x = y;
	// }
	// test(4);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto callStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto assignStmt1 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varX, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());
	ASSERT_TRUE(isAssignOfAddExprToVar(whileBody, varY, varX, 1));
	auto callStmt2 = getFirstNonEmptySuccOf(whileBody);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 2));
	auto ifBreak1 = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt2));
	ASSERT_TRUE(ifBreak1);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak1->getFirstIfCond(), varY,
		f->getParam(1)));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak1->getFirstIfBody()));
	ASSERT_FALSE(ifBreak1->hasElseClause());
	auto afterInnerIf = getFirstNonEmptySuccOf(ifBreak1);
	ASSERT_TRUE(isCallOfFuncTest(afterInnerIf, 3));
	auto ifBreak2 = cast<IfStmt>(getFirstNonEmptySuccOf(afterInnerIf));
	ASSERT_TRUE(ifBreak2);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak2->getFirstIfCond(), varY,
		f->getParam(2)));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak2->getFirstIfBody()));
	ASSERT_FALSE(ifBreak2->hasElseClause());
	ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak2), varX, varY));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 4));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithIfInFalseBranchOnlyWithBreakInsideIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val1, i32 %val2) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			%x = phi i32 [ %y, %afterInside ], [ 0, %entry ]
			%y = add i32 %x, 1
			call void @test(i32 2)
			%cond1 = icmp eq i32 %y, %val1
			br i1 %cond1, label %afterInside, label %after
		afterInside:
			call void @test(i32 3)
			%cond2 = icmp eq i32 %y, %val2
			br i1 %cond2, label %after, label %loop
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// test(1);
	// x = 0;
	// while (true) {
	//     y = x + 1
	//     test(2);
	//     if (y != val1) {
	//         break;
	//     }
	//     test(3);
	//     if (y == val2) {
	//         break;
	//     }
	//     x = y;
	// }
	// test(4);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto callStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto assignStmt1 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varX, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());
	ASSERT_TRUE(isAssignOfAddExprToVar(whileBody, varY, varX, 1));
	auto callStmt2 = getFirstNonEmptySuccOf(whileBody);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 2));
	auto ifBreak1 = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt2));
	ASSERT_TRUE(ifBreak1);
	ASSERT_TRUE(isComparison<NeqOpExpr>(ifBreak1->getFirstIfCond(), varY,
		f->getParam(1)));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak1->getFirstIfBody()));
	ASSERT_FALSE(ifBreak1->hasElseClause());
	auto afterInnerIf = getFirstNonEmptySuccOf(ifBreak1);
	ASSERT_TRUE(isCallOfFuncTest(afterInnerIf, 3));
	auto ifBreak2 = cast<IfStmt>(getFirstNonEmptySuccOf(afterInnerIf));
	ASSERT_TRUE(ifBreak2);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak2->getFirstIfCond(), varY,
		f->getParam(2)));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak2->getFirstIfBody()));
	ASSERT_FALSE(ifBreak2->hasElseClause());
	ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak2), varX, varY));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 4));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithIfInTrueBranchOnlyWithContinueInsideIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val1, i32 %val2) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			%x = phi i32 [ %y, %loop ], [ %y, %afterInside ], [ 0, %entry ]
			%y = add i32 %x, 1
			call void @test(i32 2)
			%cond1 = icmp eq i32 %y, %val1
			br i1 %cond1, label %loop, label %afterInside
		afterInside:
			call void @test(i32 3)
			%cond2 = icmp eq i32 %y, %val2
			br i1 %cond2, label %after, label %loop
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// // entry (metadata not tested)
	// test(1);
	// x = 0;
	// while (true) {
	//     // loop (metadata not tested)
	//     y = x + 1
	//     test(2);
	//     if (y == val1) {
	//         x = y;
	//         // continue -> loop
	//         continue;
	//     }
	//     // afterInside (metadata not tested)
	//     test(3);
	//     if (y == val2) {
	//         // break -> after (metadata not tested)
	//         break;
	//     }
	//     x = y;
	//     // continue -> loop (metadata not tested)
	// }
	// // after (metadata not tested)
	// test(4);
	// return;
	//

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto callStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto assignStmt1 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varX, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());
	ASSERT_TRUE(isAssignOfAddExprToVar(whileBody, varY, varX, 1));
	auto callStmt2 = getFirstNonEmptySuccOf(whileBody);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 2));
	auto ifBreak1 = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt2));
	ASSERT_TRUE(ifBreak1);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak1->getFirstIfCond(), varY,
		f->getParam(1)));
	auto continueBranch = ifBreak1->getFirstIfBody();
	ASSERT_TRUE(isAssignOfVarToVar(continueBranch, varX, varY));
	auto continueStmt = cast<ContinueStmt>(getFirstNonEmptySuccOf(continueBranch));
	ASSERT_TRUE(continueStmt);
	ASSERT_EQ("continue -> loop"s, continueStmt->getMetadata());
	ASSERT_FALSE(ifBreak1->hasElseClause());
	auto afterInnerIf = getFirstNonEmptySuccOf(ifBreak1);
	ASSERT_TRUE(isCallOfFuncTest(afterInnerIf, 3));
	auto ifBreak2 = cast<IfStmt>(getFirstNonEmptySuccOf(afterInnerIf));
	ASSERT_TRUE(ifBreak2);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak2->getFirstIfCond(), varY,
		f->getParam(2)));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak2->getFirstIfBody()));
	ASSERT_FALSE(ifBreak2->hasElseClause());
	ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak2), varX, varY));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 4));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithIfInFalseBranchOnlyWithContinueInsideIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val1, i32 %val2) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			%x = phi i32 [ %y, %loop ], [ %y, %afterInside ], [ 0, %entry ]
			%y = add i32 %x, 1
			call void @test(i32 2)
			%cond1 = icmp eq i32 %y, %val1
			br i1 %cond1, label %afterInside, label %loop
		afterInside:
			call void @test(i32 3)
			%cond2 = icmp eq i32 %y, %val2
			br i1 %cond2, label %after, label %loop
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// test(1);
	// x = 0;
	// while (true) {
	//     y = x + 1
	//     test(2);
	//     if (y != val1) {
	//         x = y;
	//         continue;
	//     }
	//     test(3);
	//     if (y == val2) {
	//         break;
	//     }
	//     x = y;
	// }
	// test(4);
	// return;
	//

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto callStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto assignStmt1 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varX, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());
	ASSERT_TRUE(isAssignOfAddExprToVar(whileBody, varY, varX, 1));
	auto callStmt2 = getFirstNonEmptySuccOf(whileBody);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 2));
	auto ifBreak1 = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt2));
	ASSERT_TRUE(ifBreak1);
	ASSERT_TRUE(isComparison<NeqOpExpr>(ifBreak1->getFirstIfCond(), varY,
		f->getParam(1)));
	auto continueBranch = ifBreak1->getFirstIfBody();
	ASSERT_TRUE(isAssignOfVarToVar(continueBranch, varX, varY));
	ASSERT_TRUE(isa<ContinueStmt>(getFirstNonEmptySuccOf(continueBranch)));
	ASSERT_FALSE(ifBreak1->hasElseClause());
	auto afterInnerIf = getFirstNonEmptySuccOf(ifBreak1);
	ASSERT_TRUE(isCallOfFuncTest(afterInnerIf, 3));
	auto ifBreak2 = cast<IfStmt>(getFirstNonEmptySuccOf(afterInnerIf));
	ASSERT_TRUE(ifBreak2);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak2->getFirstIfCond(), varY,
		f->getParam(2)));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak2->getFirstIfBody()));
	ASSERT_FALSE(ifBreak2->hasElseClause());
	ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak2), varX, varY));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 4));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithIfInTrueBranchTerminatedByContinueIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val1, i32 %val2) {
		entry:
			call void @test(i32 1)
			br label %loop
		loop:
			%x = phi i32 [ %y, %continueBranch ], [ %y, %afterInside ], [ 0, %entry ]
			%y = add i32 %x, 1
			call void @test(i32 2)
			%cond1 = icmp eq i32 %y, %val1
			br i1 %cond1, label %continueBranch, label %afterInside
		continueBranch:
			call void @test(i32 3)
			br label %loop
		afterInside:
			call void @test(i32 4)
			%cond2 = icmp eq i32 %y, %val2
			br i1 %cond2, label %after, label %loop
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// // entry (metadata not tested)
	// test(1);
	// x = 0;
	// while (true) {
	//     // loop (metadata not tested)
	//     y = x + 1
	//     test(2);
	//     if (y == val1) {
	//         // continueBranch (metadata not tested)
	//         test(3);
	//         x = y;
	//         // continue -> loop
	//         continue;
	//     }
	//     // afterInside (metadata not tested)
	//     test(4);
	//     if (y == val2) {
	//         // break -> after (metadata not tested)
	//         break;
	//     }
	//     x = y;
	//     // continue -> loop (metadata not tested)
	// }
	// // after (metadata not tested)
	// test(5);
	// return;
	//

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto callStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isCallOfFuncTest(callStmt1, 1));
	auto assignStmt1 = getFirstNonEmptySuccOf(callStmt1);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varX, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	auto whileCond = cast<ConstBool>(whileStmt->getCondition());
	ASSERT_TRUE(whileCond);
	ASSERT_TRUE(whileCond->getValue());
	auto whileBody = skipEmptyStmts(whileStmt->getBody());
	ASSERT_TRUE(isAssignOfAddExprToVar(whileBody, varY, varX, 1));
	auto callStmt2 = getFirstNonEmptySuccOf(whileBody);
	ASSERT_TRUE(isCallOfFuncTest(callStmt2, 2));
	auto ifBreak1 = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt2));
	ASSERT_TRUE(ifBreak1);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak1->getFirstIfCond(), varY,
		f->getParam(1)));
	auto callStmt3 = ifBreak1->getFirstIfBody();
	ASSERT_TRUE(isCallOfFuncTest(callStmt3, 3));
	auto continueBranch = getFirstNonEmptySuccOf(callStmt3);
	ASSERT_TRUE(isAssignOfVarToVar(continueBranch, varX, varY));
	auto continueStmt = cast<ContinueStmt>(getFirstNonEmptySuccOf(continueBranch));
	ASSERT_TRUE(continueStmt);
	ASSERT_EQ("continue -> loop"s, continueStmt->getMetadata());
	ASSERT_FALSE(ifBreak1->hasElseClause());
	auto afterInnerIf = getFirstNonEmptySuccOf(ifBreak1);
	ASSERT_TRUE(isCallOfFuncTest(afterInnerIf, 4));
	auto ifBreak2 = cast<IfStmt>(getFirstNonEmptySuccOf(afterInnerIf));
	ASSERT_TRUE(ifBreak2);
	ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak2->getFirstIfCond(), varY,
		f->getParam(2)));
	ASSERT_TRUE(isa<BreakStmt>(ifBreak2->getFirstIfBody()));
	ASSERT_FALSE(ifBreak2->hasElseClause());
	ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak2), varX, varY));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 5));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithNestedDoWhileLoopIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			br label %outsideLoop
		outsideLoop:
			%i = phi i32 [ 0, %entry ], [ %i2, %outsideLoop2 ]
			call void @test(i32 1)
			br label %insideLoop
		insideLoop:
			%j = phi i32 [ 0, %outsideLoop ], [ %j2, %insideLoop ]
			call void @test(i32 2)
			%j2 = add i32 %j, 1
			%insideCond = icmp slt i32 %j, %i
			br i1 %insideCond, label %insideLoop, label %outsideLoop2
		outsideLoop2:
			call void @test(i32 3)
			%i2 = add i32 %i, 1
			%outsideCond = icmp eq i32 %i, %val
			br i1 %outsideCond, label %after, label %outsideLoop
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// int i;
	// int i2;
	// int j;
	// i = 0;
	// while (true) {
	//     test(1);
	//     j = 0;
	//     while (true) {
	//         test(2);
	//         if (j >= i) {
	//             break;
	//         }
	//         j = j + 1;
	//     }
	//     test(3);
	//     i2 = i + 1;
	//     if (i == val) {
	//         break;
	//     }
	//     i = i2;
	// }
	// test(4);
	// return;
	//

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefI = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefI, "i"));
	auto varI = varDefI->getVar();
	auto varDefI2 = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI));
	ASSERT_TRUE(isVarDef<IntType>(varDefI2, "i2"));
	auto varI2 = varDefI2->getVar();
	auto varDefJ = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI2));
	ASSERT_TRUE(isVarDef<IntType>(varDefJ, "j"));
	auto varJ = varDefJ->getVar();
	auto assignStmt1 = getFirstNonEmptySuccOf(varDefJ);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varI, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	{
		SCOPED_TRACE("Testing outer loop");
		auto whileCond = cast<ConstBool>(whileStmt->getCondition());
		ASSERT_TRUE(whileCond->getValue());
		ASSERT_TRUE(whileCond);
		auto whileBody = skipEmptyStmts(whileStmt->getBody());
		ASSERT_TRUE(isCallOfFuncTest(whileBody, 1));
		auto assignStmt2 = getFirstNonEmptySuccOf(whileBody);
		ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt2, varJ, 0));
		auto innerWhileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt2));
		ASSERT_TRUE(innerWhileStmt);
		{
			SCOPED_TRACE("Testing inner loop");
			auto innerWhileCond = cast<ConstBool>(
				innerWhileStmt->getCondition());
			ASSERT_TRUE(innerWhileCond->getValue());
			ASSERT_TRUE(innerWhileCond);
			auto innerBody = skipEmptyStmts(innerWhileStmt->getBody());
			ASSERT_TRUE(isCallOfFuncTest(innerBody, 2));
			auto assignStmt3 = getFirstNonEmptySuccOf(innerBody);
			auto ifBreak1 = cast<IfStmt>(assignStmt3);
			ASSERT_TRUE(ifBreak1);
			ASSERT_TRUE(isComparison<GtEqOpExpr>(
				ifBreak1->getFirstIfCond(), varJ, varI));
			ASSERT_TRUE(isa<BreakStmt>(ifBreak1->getFirstIfBody()));
			ASSERT_FALSE(ifBreak1->hasElseClause());
			ASSERT_TRUE(isAssignOfAddExprToVar(getFirstNonEmptySuccOf(ifBreak1),
				varJ, varJ, 1));
		}
		auto afterInnerWhile = getFirstNonEmptySuccOf(innerWhileStmt);
		ASSERT_TRUE(isCallOfFuncTest(afterInnerWhile, 3));
		auto assignStmt4 = getFirstNonEmptySuccOf(afterInnerWhile);
		ASSERT_TRUE(isAssignOfAddExprToVar(assignStmt4, varI2, varI, 1));
		auto ifBreak2 = cast<IfStmt>(getFirstNonEmptySuccOf(assignStmt4));
		ASSERT_TRUE(ifBreak2);
		ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak2->getFirstIfCond(),
			varI, f->getParam(1)));
		ASSERT_TRUE(isa<BreakStmt>(ifBreak2->getFirstIfBody()));
		ASSERT_FALSE(ifBreak2->hasElseClause());
		ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak2), varI, varI2));
	}
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 4));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithNestedDoWhileLoopWithContinueToParentInHeaderIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			br label %outsideLoop
		outsideLoop:
			%i = phi i32 [ 0, %entry ], [ %i2, %insideLoop ]
			%i2 = add i32 %i, 1
			call void @test(i32 1)
			br label %insideLoop
		insideLoop:
			%j = phi i32 [ 0, %outsideLoop ], [ %j2, %insideLoop2 ]
			call void @test(i32 2)
			%j2 = add i32 %j, 1
			%insideCond = icmp slt i32 %j, %i
			br i1 %insideCond, label %outsideLoop, label %insideLoop2
		insideLoop2:
			call void @test(i32 3)
			%outsideCond = icmp eq i32 %i, %val
			br i1 %outsideCond, label %insideLoop, label %after
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// int i;
	// int j;
	// // entry (metadata not tested)
	// i = 0;
	// while (true) {
	//     // outsideLoop (metadata not tested)
	//     test(1);
	//     j = 0;
	//     while (true) {
	//         // insideLoop (metadata not tested)
	//         test(2);
	//         if (j < i) {
	//             i++;
	//             // break -> outsideLoop
	//             break;
	//         }
	//         // insideLoop2 (metadata not tested)
	//         test(3);
	//         if (i != val) {
	//             // break (via goto) -> after
	//             goto after;
	//         }
	//         j++;
	//         // continue -> insideLoop (metadata not tested)
	//     }
	//     // continue -> loop (metadata not tested)
	// }
	// lab_after:
	// // after (metadata not tested)
	// test(4);
	// return;
	//

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefI = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefI, "i"));
	auto varI = varDefI->getVar();
	auto varDefJ = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI));
	ASSERT_TRUE(isVarDef<IntType>(varDefJ, "j"));
	auto varJ = varDefJ->getVar();
	auto assignStmt1 = getFirstNonEmptySuccOf(varDefJ);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varI, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	{
		SCOPED_TRACE("Testing outer loop");
		auto whileCond = cast<ConstBool>(whileStmt->getCondition());
		ASSERT_TRUE(whileCond->getValue());
		ASSERT_TRUE(whileCond);
		auto whileBody = skipEmptyStmts(whileStmt->getBody());
		ASSERT_TRUE(isCallOfFuncTest(whileBody, 1));
		auto assignStmt2 = getFirstNonEmptySuccOf(whileBody);
		ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt2, varJ, 0));
		auto innerWhileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt2));
		ASSERT_TRUE(innerWhileStmt);
		{
			SCOPED_TRACE("Testing inner loop");
			auto innerWhileCond = cast<ConstBool>(
				innerWhileStmt->getCondition());
			ASSERT_TRUE(innerWhileCond->getValue());
			ASSERT_TRUE(innerWhileCond);
			auto innerBody = skipEmptyStmts(innerWhileStmt->getBody());
			ASSERT_TRUE(isCallOfFuncTest(innerBody, 2));
			auto ifBreak1 = cast<IfStmt>(getFirstNonEmptySuccOf(innerBody));
			ASSERT_TRUE(ifBreak1);
			ASSERT_TRUE(isComparison<LtOpExpr>(
				ifBreak1->getFirstIfCond(), varJ, varI));
			auto assignStmt3 = ifBreak1->getFirstIfBody();
			ASSERT_TRUE(isAssignOfAddExprToVar(assignStmt3, varI, varI, 1));
			auto breakStmt = cast<BreakStmt>(getFirstNonEmptySuccOf(assignStmt3));
			ASSERT_TRUE(breakStmt);
			ASSERT_EQ("break -> outsideLoop"s, breakStmt->getMetadata());
			ASSERT_FALSE(ifBreak1->hasElseClause());
			auto callStmt3 = getFirstNonEmptySuccOf(ifBreak1);
			ASSERT_TRUE(isCallOfFuncTest(callStmt3, 3));
			auto ifBreak2 = cast<IfStmt>(getFirstNonEmptySuccOf(callStmt3));
			ASSERT_TRUE(ifBreak2);
			ASSERT_TRUE(isComparison<NeqOpExpr>(
				ifBreak2->getFirstIfCond(), varI, f->getParam(1)));
			auto gotoStmt = cast<GotoStmt>(ifBreak2->getFirstIfBody());
			ASSERT_TRUE(gotoStmt);
			ASSERT_BIR_EQ(getFirstNonEmptySuccOf(whileStmt), gotoStmt->getTarget());
			ASSERT_EQ("break (via goto) -> after"s, gotoStmt->getMetadata());
			ASSERT_FALSE(ifBreak2->hasElseClause());
			ASSERT_TRUE(isAssignOfAddExprToVar(getFirstNonEmptySuccOf(ifBreak2),
				varJ, varJ, 1));
		}
		auto innerWhileSucc = cast<EmptyStmt>(innerWhileStmt->getSuccessor());
		ASSERT_TRUE(innerWhileSucc);
	}
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 4));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithNestedDoWhileLoopInIfStatementIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val, i32 %val2) {
		entry:
			br label %outsideLoop
		outsideLoop:
			%i = phi i32 [ 0, %entry ], [ %i2, %outsideLoop2 ]
			call void @test(i32 1)
			%cond = icmp slt i32 %i, %val
			br i1 %cond, label %insideLoop, label %outsideLoop2
		insideLoop:
			%j = phi i32 [ 0, %outsideLoop ], [ %j2, %insideLoop ]
			call void @test(i32 2)
			%j2 = add i32 %j, 1
			%insideCond = icmp slt i32 %j, %i
			br i1 %insideCond, label %insideLoop, label %outsideLoop2
		outsideLoop2:
			call void @test(i32 3)
			%i2 = add i32 %i, 1
			%outsideCond = icmp eq i32 %i, %val2
			br i1 %outsideCond, label %after, label %outsideLoop
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// int i;
	// int i2;
	// int j;
	// i = 0;
	// while (true) {
	//     test(1);
	//     if (i < val) {
	//         j = 0;
	//         while (true) {
	//             test(2);
	//             if (j >= i) {
	//                 break;
	//             }
	//             j = j + 1;
	//         }
	//     }
	//     test(3);
	//     i2 = i + 1;
	//     if (i == val2) {
	//         break;
	//     }
	//     i = i2;
	// }
	// test(4);
	// return;
	//

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefI = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefI, "i"));
	auto varI = varDefI->getVar();
	auto varDefI2 = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI));
	ASSERT_TRUE(isVarDef<IntType>(varDefI2, "i2"));
	auto varI2 = varDefI2->getVar();
	auto varDefJ = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI2));
	ASSERT_TRUE(isVarDef<IntType>(varDefJ, "j"));
	auto varJ = varDefJ->getVar();
	auto assignStmt1 = getFirstNonEmptySuccOf(varDefJ);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varI, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	{
		SCOPED_TRACE("Testing outer loop");
		auto whileCond = cast<ConstBool>(whileStmt->getCondition());
		ASSERT_TRUE(whileCond->getValue());
		ASSERT_TRUE(whileCond);
		auto whileBody = skipEmptyStmts(whileStmt->getBody());
		ASSERT_TRUE(isCallOfFuncTest(whileBody, 1));
		auto innerIfStmt = cast<IfStmt>(getFirstNonEmptySuccOf(whileBody));
		ASSERT_TRUE(innerIfStmt);
		ASSERT_TRUE(isComparison<LtOpExpr>(innerIfStmt->getFirstIfCond(),
			varI, f->getParam(1)));
		ASSERT_FALSE(innerIfStmt->hasElseClause());
		auto assignStmt2 = innerIfStmt->getFirstIfBody();
		ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt2, varJ, 0));
		auto innerWhileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt2));
		ASSERT_TRUE(innerWhileStmt);
		{
			SCOPED_TRACE("Testing inner loop");
			auto innerWhileCond = cast<ConstBool>(
				innerWhileStmt->getCondition());
			ASSERT_TRUE(innerWhileCond->getValue());
			ASSERT_TRUE(innerWhileCond);
			auto innerBody = skipEmptyStmts(innerWhileStmt->getBody());
			ASSERT_TRUE(isCallOfFuncTest(innerBody, 2));
			auto ifBreak1 = cast<IfStmt>(getFirstNonEmptySuccOf(innerBody));
			ASSERT_TRUE(ifBreak1);
			ASSERT_TRUE(isComparison<GtEqOpExpr>(
				ifBreak1->getFirstIfCond(), varJ, varI));
			ASSERT_TRUE(isa<BreakStmt>(ifBreak1->getFirstIfBody()));
			ASSERT_FALSE(ifBreak1->hasElseClause());
			ASSERT_TRUE(isAssignOfAddExprToVar(getFirstNonEmptySuccOf(ifBreak1),
				varJ, varJ, 1));
		}
		auto afterInnerWhile = getFirstNonEmptySuccOf(innerIfStmt);
		ASSERT_TRUE(isCallOfFuncTest(afterInnerWhile, 3));
		auto assignStmt3 = getFirstNonEmptySuccOf(afterInnerWhile);
		ASSERT_TRUE(isAssignOfAddExprToVar(assignStmt3, varI2, varI, 1));
		auto ifBreak2 = cast<IfStmt>(getFirstNonEmptySuccOf(assignStmt3));
		ASSERT_TRUE(ifBreak2);
		ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak2->getFirstIfCond(),
			varI, f->getParam(2)));
		ASSERT_TRUE(isa<BreakStmt>(ifBreak2->getFirstIfBody()));
		ASSERT_FALSE(ifBreak2->hasElseClause());
		ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak2), varI, varI2));
	}
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 4));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithNestedDoWhileLoopWithBreakForParentLoopIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val, i32 %val2) {
		entry:
			br label %outsideLoop
		outsideLoop:
			%i = phi i32 [ 0, %entry ], [ %i2, %outsideLoop2 ]
			call void @test(i32 1)
			br label %insideLoop
		insideLoop:
			%j = phi i32 [ 0, %outsideLoop ], [ %j2, %insideLoop2 ]
			call void @test(i32 2)
			%insideCond = icmp eq i32 %j, %val2
			br i1 %insideCond, label %after, label %insideLoop2
		insideLoop2:
			%j2 = add i32 %j, 1
			%insideCond2 = icmp slt i32 %j, %i
			br i1 %insideCond2, label %insideLoop, label %outsideLoop2
		outsideLoop2:
			call void @test(i32 3)
			%i2 = add i32 %i, 1
			%outsideCond = icmp eq i32 %i, %val
			br i1 %outsideCond, label %after, label %outsideLoop
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// int i;
	// int i2;
	// int j;
	// int j2;
	// i = 0;
	// while (true) {
	//     test(1);
	//     j = 0;
	//     while (true) {
	//         test(2);
	//         if (j == val) {
	//             goto lab_after;
	//         }
	//         j2 = j + 1
	//         if (j >= i) {
	//             break;
	//         }
	//         j = j2;
	//     }
	//     test(3);
	//     i2 = i + 1;
	//     if (i == val) {
	//         break;
	//     }
	//     i = i2;
	// }
	// lab_after:
	// test(4);
	// return;
	//

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefI = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefI, "i"));
	auto varI = varDefI->getVar();
	auto varDefI2 = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI));
	ASSERT_TRUE(isVarDef<IntType>(varDefI2, "i2"));
	auto varI2 = varDefI2->getVar();
	auto varDefJ = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI2));
	ASSERT_TRUE(isVarDef<IntType>(varDefJ, "j"));
	auto varJ = varDefJ->getVar();
	auto varDefJ2 = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefJ));
	ASSERT_TRUE(isVarDef<IntType>(varDefJ2, "j2"));
	auto varJ2 = varDefJ2->getVar();
	auto assignStmt1 = getFirstNonEmptySuccOf(varDefJ2);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varI, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	{
		SCOPED_TRACE("Testing outer loop");
		auto whileCond = cast<ConstBool>(whileStmt->getCondition());
		ASSERT_TRUE(whileCond->getValue());
		ASSERT_TRUE(whileCond);
		auto whileBody = skipEmptyStmts(whileStmt->getBody());
		ASSERT_TRUE(isCallOfFuncTest(whileBody, 1));
		auto assignStmt2 = getFirstNonEmptySuccOf(whileBody);
		ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt2, varJ, 0));
		auto innerWhileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt2));
		ASSERT_TRUE(innerWhileStmt);
		{
			SCOPED_TRACE("Testing inner loop");
			auto innerWhileCond = cast<ConstBool>(
				innerWhileStmt->getCondition());
			ASSERT_TRUE(innerWhileCond->getValue());
			ASSERT_TRUE(innerWhileCond);
			auto innerBody = skipEmptyStmts(innerWhileStmt->getBody());
			ASSERT_TRUE(isCallOfFuncTest(innerBody, 2));
			auto ifBreak1 = cast<IfStmt>(getFirstNonEmptySuccOf(innerBody));
			ASSERT_TRUE(ifBreak1);
			ASSERT_TRUE(isComparison<EqOpExpr>(
				ifBreak1->getFirstIfCond(), varJ, f->getParam(2)));
			auto gotoStmt = cast<GotoStmt>(ifBreak1->getFirstIfBody());
			ASSERT_TRUE(gotoStmt);
			ASSERT_BIR_EQ(getFirstNonEmptySuccOf(whileStmt), gotoStmt->getTarget());
			ASSERT_FALSE(ifBreak1->hasElseClause());
			auto assignStmt3 = getFirstNonEmptySuccOf(ifBreak1);
			ASSERT_TRUE(isAssignOfAddExprToVar(assignStmt3, varJ2, varJ, 1));
			auto ifBreak2 = cast<IfStmt>(getFirstNonEmptySuccOf(assignStmt3));
			ASSERT_TRUE(ifBreak2);
			ASSERT_TRUE(isComparison<GtEqOpExpr>(
				ifBreak2->getFirstIfCond(), varJ, varI));
			ASSERT_TRUE(isa<BreakStmt>(ifBreak2->getFirstIfBody()));
			ASSERT_FALSE(ifBreak2->hasElseClause());
			ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak2),
				varJ, varJ2));
		}
		auto afterInnerWhile = getFirstNonEmptySuccOf(innerWhileStmt);
		ASSERT_TRUE(isCallOfFuncTest(afterInnerWhile, 3));
		auto assignStmt4 = getFirstNonEmptySuccOf(afterInnerWhile);
		ASSERT_TRUE(isAssignOfAddExprToVar(assignStmt4, varI2, varI, 1));
		auto ifBreak3 = cast<IfStmt>(getFirstNonEmptySuccOf(assignStmt4));
		ASSERT_TRUE(ifBreak3);
		ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak3->getFirstIfCond(),
			varI, f->getParam(1)));
		ASSERT_TRUE(isa<BreakStmt>(ifBreak3->getFirstIfBody()));
		ASSERT_FALSE(ifBreak3->hasElseClause());
		ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak3), varI, varI2));
	}
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 4));
}

TEST_F(StructureConverterTests,
GoToJumpToEmptyBodyIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val, i32 %val2) {
		entry:
			br label %outsideLoop
		outsideLoop:
			%i = phi i32 [ 0, %entry ], [ %i2, %outsideLoop2 ]
			call void @test(i32 1)
			br label %insideLoop
		insideLoop:
			%j = phi i32 [ 0, %outsideLoop ], [ %j2, %insideLoop2 ]
			call void @test(i32 2)
			%insideCond = icmp eq i32 %j, %val2
			br i1 %insideCond, label %after, label %insideLoop2
		insideLoop2:
			%j2 = add i32 %j, 1
			%insideCond2 = icmp slt i32 %j, %i
			br i1 %insideCond2, label %insideLoop, label %outsideLoop2
		outsideLoop2:
			call void @test(i32 3)
			%i2 = add i32 %i, 1
			%outsideCond = icmp eq i32 %i, %val
			br i1 %outsideCond, label %after, label %outsideLoop
		after:
			br label %after2
		after2:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// int i;
	// int i2;
	// int j;
	// int j2;
	// i = 0;
	// while (true) {
	//     // body not tested
	// }
	// lab_after:
	// test(4);
	// return;
	//

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefI = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefI, "i"));
	auto varDefI2 = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI));
	ASSERT_TRUE(isVarDef<IntType>(varDefI2, "i2"));
	auto varDefJ = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI2));
	ASSERT_TRUE(isVarDef<IntType>(varDefJ, "j"));
	auto varDefJ2 = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefJ));
	ASSERT_TRUE(isVarDef<IntType>(varDefJ2, "j2"));
	auto assignStmt1 = getFirstNonEmptySuccOf(varDefJ2);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varDefI->getVar(), 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 4));
}

TEST_F(StructureConverterTests,
DoWhileLoopWithNestedDoWhileLoopWithContinueToParentLoopIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val, i32 %val2) {
		entry:
			br label %outsideLoop
		outsideLoop:
			%i = phi i32 [ 0, %entry ], [ %i, %insideLoop ], [ %i2, %outsideLoop2 ]
			call void @test(i32 1)
			br label %insideLoop
		insideLoop:
			%j = phi i32 [ 0, %outsideLoop ], [ %j2, %insideLoop2 ]
			call void @test(i32 2)
			%insideCond = icmp eq i32 %j, %val2
			br i1 %insideCond, label %outsideLoop, label %insideLoop2
		insideLoop2:
			%j2 = add i32 %j, 1
			%insideCond2 = icmp slt i32 %j, %i
			br i1 %insideCond2, label %insideLoop, label %outsideLoop2
		outsideLoop2:
			call void @test(i32 3)
			%i2 = add i32 %i, 1
			%outsideCond = icmp eq i32 %i, %val
			br i1 %outsideCond, label %after, label %outsideLoop
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// int i;
	// int i2;
	// int j;
	// int j2;
	// // entry (metadata not tested)
	// i = 0;
	// while (true) {
	//     lab_outsideLoop:
	//     // outsideLoop (metadata not tested)
	//     test(1);
	//     j = 0;
	//     while (true) {
	//         // insideLoop (metadata not tested)
	//         test(2);
	//         if (j == val) {
	//             i = i;
	//             // continue (via goto) -> outsideLoop
	//             goto lab_outsideLoop;
	//         }
	//         // insideLoop2 (metadata not tested)
	//         j2 = j + 1
	//         if (j >= i) {
	//             // break -> outsideLoop2 (metadata not tested)
	//             break;
	//         }
	//         j = j2;
	//         // continue -> insideLoop (metadata not tested)
	//     }
	//     // outsideLoop2 (metadata not tested)
	//     test(3);
	//     i2 = i + 1;
	//     if (i == val) {
	//         // break -> after (metadata not tested)
	//         break;
	//     }
	//     i = i2;
	//     // continue -> outsideLoop (metadata not tested)
	// }
	// lab_after:
	// // after (metadata not tested)
	// test(4);
	// return;
	//

	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefI = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefI, "i"));
	auto varI = varDefI->getVar();
	auto varDefI2 = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI));
	ASSERT_TRUE(isVarDef<IntType>(varDefI2, "i2"));
	auto varI2 = varDefI2->getVar();
	auto varDefJ = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI2));
	ASSERT_TRUE(isVarDef<IntType>(varDefJ, "j"));
	auto varJ = varDefJ->getVar();
	auto varDefJ2 = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefJ));
	ASSERT_TRUE(isVarDef<IntType>(varDefJ2, "j2"));
	auto varJ2 = varDefJ2->getVar();
	auto assignStmt1 = getFirstNonEmptySuccOf(varDefJ2);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varI, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	{
		SCOPED_TRACE("Testing outer loop");
		auto whileCond = cast<ConstBool>(whileStmt->getCondition());
		ASSERT_TRUE(whileCond->getValue());
		ASSERT_TRUE(whileCond);
		auto whileBody = skipEmptyStmts(whileStmt->getBody());
		ASSERT_TRUE(isCallOfFuncTest(whileBody, 1));
		auto assignStmt2 = getFirstNonEmptySuccOf(whileBody);
		ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt2, varJ, 0));
		auto innerWhileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt2));
		ASSERT_TRUE(innerWhileStmt);
		{
			SCOPED_TRACE("Testing inner loop");
			auto innerWhileCond = cast<ConstBool>(
				innerWhileStmt->getCondition());
			ASSERT_TRUE(innerWhileCond->getValue());
			ASSERT_TRUE(innerWhileCond);
			auto innerBody = skipEmptyStmts(innerWhileStmt->getBody());
			ASSERT_TRUE(isCallOfFuncTest(innerBody, 2));
			auto ifBreak1 = cast<IfStmt>(getFirstNonEmptySuccOf(innerBody));
			ASSERT_TRUE(ifBreak1);
			ASSERT_TRUE(isComparison<EqOpExpr>(
				ifBreak1->getFirstIfCond(), varJ, f->getParam(2)));
			auto ifBreak1Body = ifBreak1->getFirstIfBody();
			ASSERT_TRUE(isAssignOfVarToVar(ifBreak1Body, varI, varI));
			auto gotoStmt = cast<GotoStmt>(getFirstNonEmptySuccOf(ifBreak1Body));
			ASSERT_TRUE(gotoStmt);
			ASSERT_BIR_EQ(whileBody, gotoStmt->getTarget());
			ASSERT_EQ("continue (via goto) -> outsideLoop"s, gotoStmt->getMetadata());
			ASSERT_FALSE(ifBreak1->hasElseClause());
			auto assignStmt3 = getFirstNonEmptySuccOf(ifBreak1);
			ASSERT_TRUE(isAssignOfAddExprToVar(assignStmt3, varJ2, varJ, 1));
			auto ifBreak2 = cast<IfStmt>(getFirstNonEmptySuccOf(assignStmt3));
			ASSERT_TRUE(ifBreak2);
			ASSERT_TRUE(isComparison<GtEqOpExpr>(
				ifBreak2->getFirstIfCond(), varJ, varI));
			ASSERT_TRUE(isa<BreakStmt>(ifBreak2->getFirstIfBody()));
			ASSERT_FALSE(ifBreak2->hasElseClause());
			ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak2),
				varJ, varJ2));
		}
		auto afterInnerWhile = getFirstNonEmptySuccOf(innerWhileStmt);
		ASSERT_TRUE(isCallOfFuncTest(afterInnerWhile, 3));
		auto assignStmt4 = getFirstNonEmptySuccOf(afterInnerWhile);
		ASSERT_TRUE(isAssignOfAddExprToVar(assignStmt4, varI2, varI, 1));
		auto ifBreak3 = cast<IfStmt>(getFirstNonEmptySuccOf(assignStmt4));
		ASSERT_TRUE(ifBreak3);
		ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak3->getFirstIfCond(),
			varI, f->getParam(1)));
		ASSERT_TRUE(isa<BreakStmt>(ifBreak3->getFirstIfBody()));
		ASSERT_FALSE(ifBreak3->hasElseClause());
		ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak3), varI, varI2));
	}
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 4));
}

TEST_F(StructureConverterTests,
SimpleForLoopIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function() {
		entry:
			br label %loop
		loop:
			%i = phi i32 [ %add, %loop ], [ 0, %entry ]
			call void @test(i32 %i)
			%add = add i32 %i, 1
			%cond = icmp eq i32 %add, 10
			br i1 %cond, label %after, label %loop
		after:
			ret void
		}
	)");

	//
	// int add;
	// int i;
	// // entry (metadata not tested)
	// for (i = 0; i < 10; i++) {
	//     // loop (metadata not tested)
	//     test(i);
	//     add = i + 1;
	//     // continue -> loop
	// }
	// // after (metadata not tested)
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefAdd = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefAdd, "add"));
	auto varAdd = varDefAdd->getVar();
	auto varDefI = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefAdd));
	ASSERT_TRUE(isVarDef<IntType>(varDefI, "i"));
	auto varI = varDefI->getVar();
	auto forLoopStmt = cast<ForLoopStmt>(getFirstNonEmptySuccOf(varDefI));
	ASSERT_TRUE(forLoopStmt);
	ASSERT_BIR_EQ(varI, forLoopStmt->getIndVar());
	ASSERT_TRUE(isConstInt(forLoopStmt->getStartValue(), 0));
	auto comparison = cast<LtOpExpr>(forLoopStmt->getEndCond());
	ASSERT_TRUE(isComparison<LtOpExpr>(comparison, varI, 10));
	ASSERT_EQ(LtOpExpr::Variant::SCmp, comparison->getVariant());
	ASSERT_TRUE(isConstInt(forLoopStmt->getStep(), 1));
	auto loopBody = skipEmptyStmts(forLoopStmt->getBody());
	ASSERT_TRUE(isCallOfFuncTest(loopBody, varI));
	auto addStmt = getFirstNonEmptySuccOf(loopBody);
	ASSERT_TRUE(isAssignOfAddExprToVar(addStmt, varAdd, varI, 1));
	auto loopEnd = cast<EmptyStmt>(addStmt->getSuccessor());
	ASSERT_TRUE(loopEnd);
	ASSERT_EQ("continue -> loop"s, loopEnd->getMetadata());
}

TEST_F(StructureConverterTests,
SimpleForLoopWithPhiNodesIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %start) {
		entry:
			br label %loop
		loop:
			%i = phi i32 [ %add, %loop ], [ 0, %entry ]
			%x = phi i32 [ %mul, %loop ], [ %start, %entry ]
			%mul = mul i32 %x, 2
			%add = add i32 %i, 1
			%cond = icmp eq i32 %add, 10
			br i1 %cond, label %after, label %loop
		after:
			call void @test(i32 %mul)
			ret void
		}
	)");

	//
	// int add;
	// int i;
	// int mul;
	// int x;
	// x = start;
	// for (i = 0; i < 10; i++) {
	//     mul = x * 2;
	//     add = i + 1;
	//     x = mul;
	// }
	// test(mul);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefAdd = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefAdd, "add"));
	auto varAdd = varDefAdd->getVar();
	auto varDefI = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefAdd));
	ASSERT_TRUE(isVarDef<IntType>(varDefI, "i"));
	auto varI = varDefI->getVar();
	auto varDefMul = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefI));
	ASSERT_TRUE(isVarDef<IntType>(varDefMul, "mul"));
	auto varMul = varDefMul->getVar();
	auto varDefX = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefMul));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto assignStmt = getFirstNonEmptySuccOf(varDefX);
	ASSERT_TRUE(isAssignOfVarToVar(assignStmt, varX, f->getParam(1)));
	auto forLoopStmt = cast<ForLoopStmt>(getFirstNonEmptySuccOf(assignStmt));
	ASSERT_TRUE(forLoopStmt);
	ASSERT_BIR_EQ(varI, forLoopStmt->getIndVar());
	ASSERT_TRUE(isConstInt(forLoopStmt->getStartValue(), 0));
	ASSERT_TRUE(isComparison<LtOpExpr>(forLoopStmt->getEndCond(), varI, 10));
	ASSERT_TRUE(isConstInt(forLoopStmt->getStep(), 1));
	auto loopBody = skipEmptyStmts(forLoopStmt->getBody());
	ASSERT_TRUE(isAssignOfMulExprToVar(loopBody, varMul, varX, 2));
	auto addStmt = getFirstNonEmptySuccOf(loopBody);
	ASSERT_TRUE(isAssignOfAddExprToVar(addStmt, varAdd, varI, 1));
	auto phiNode = getFirstNonEmptySuccOf(addStmt);
	ASSERT_TRUE(isAssignOfVarToVar(phiNode, varX, varMul));
	auto loopEnd = cast<EmptyStmt>(phiNode->getSuccessor());
	ASSERT_TRUE(loopEnd);
}

//
// Tests for switch statement
//

TEST_F(StructureConverterTests,
SwitchWithDefaultClauseAndWithAllClausesTerminatedByBreakIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %after
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// // entry (metadata not tested)
	// switch (val) {
	// case 1:
	//     // case1 (metadata not tested)
	//     test(1);
	//     // break -> after
	//     break;
	// case 2:
	//     // case2 (metadata not tested)
	//     test(2);
	//     // break -> after
	//     break;
	// case 3:
	//     // case3 (metadata not tested)
	//     test(3);
	//     // break -> after
	//     break;
	// default:
	//     // default (metadata not tested)
	//     test(4);
	//     // break -> after
	//     break;
	// }
	// // after (metadata not tested)
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	ASSERT_EQ("break -> after"s, Statement::getLastStatement(case1->second)->getMetadata());
	auto case2 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	ASSERT_EQ("break -> after"s, Statement::getLastStatement(case2->second)->getMetadata());
	auto case3 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	ASSERT_EQ("break -> after"s, Statement::getLastStatement(case3->second)->getMetadata());
	auto defaultClause = std::next(case3);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	auto defaultBreak = cast<BreakStmt>(getFirstNonEmptySuccOf(defaultBody));
	ASSERT_TRUE(defaultBreak);
	ASSERT_EQ("break -> after"s, defaultBreak->getMetadata());
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithoutDefaultClauseAndWithAllClausesTerminatedByBreakIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %after [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	//     break;
	// case 2:
	//     test(2);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// }
	// test(4);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	ASSERT_FALSE(switchStmt->hasDefaultClause());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	auto case2 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	auto case3 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 4));
}

TEST_F(StructureConverterTests,
SwitchWithDefaultClauseAndWithFallThroughFromCase1ToCase2IsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %case2
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %after
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// // entry (metadata not tested)
	// switch (val) {
	// case 1:
	//     // case1 (metadata not tested)
	//     test(1);
	//     // branch -> case2
	// case 2:
	//     // case2 (metadata not tested)
	//     test(2);
	//     // break -> after (metadata not tested)
	//     break;
	// case 3:
	//     // case3 (metadata not tested)
	//     test(3);
	//     // break -> after (metadata not tested)
	//     break;
	// default:
	//     // default (metadata not tested)
	//     test(4);
	//     // break -> after (metadata not tested)
	//     break;
	// }
	// // after (metadata not tested)
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case1, 1, 1));
	ASSERT_EQ("branch -> case2"s, Statement::getLastStatement(case1->second)->getMetadata());
	auto case2 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	auto case3 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	auto defaultClause = std::next(case3);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(defaultBody)));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithoutDefaultClauseAndWithFallThroughFromCase1ToCase2IsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %after [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %case2
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	// case 2:
	//     test(2);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// }
	// test(4);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	ASSERT_FALSE(switchStmt->hasDefaultClause());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case1, 1, 1));
	auto case2 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	auto case3 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 4));
}

TEST_F(StructureConverterTests,
SwitchWithoutDefaultClauseAndWithNonTerminatingBBAfterIsCovertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %after [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		after:
			br label %after2
		after2:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// switch (val) {
	// // ... (switch body not tested)
	// }
	// test(4);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 4));
}

TEST_F(StructureConverterTests,
SwitchWithDefaultClauseAndWithFallThroughFromCase2ToCase1IsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %case1
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %after
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 2:
	//     test(2);
	// case 1:
	//     test(1);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// default:
	//     test(4);
	//     break;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case2 = switchStmt->clause_begin();
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case2, 2, 2));
	auto case1 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	auto case3 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	auto defaultClause = std::next(case3);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(defaultBody)));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithoutDefaultClauseAndWithFallThroughFromCase2ToCase1IsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %after [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %case1
		case3:
			call void @test(i32 3)
			br label %after
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 2:
	//     test(2);
	// case 1:
	//     test(1);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// }
	// test(4);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	ASSERT_FALSE(switchStmt->hasDefaultClause());
	auto case2 = switchStmt->clause_begin();
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case2, 2, 2));
	auto case1 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	auto case3 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 4));
}

TEST_F(StructureConverterTests,
SwitchWithDefaultClauseAndWithFallThroughFromCase1ToCase3IsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %case3
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %after
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	// case 3:
	//     test(3);
	//     break;
	// case 2:
	//     test(2);
	//     break;
	// default:
	//     test(4);
	//     break;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case1, 1, 1));
	auto case3 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	auto case2 = std::next(case3);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	auto defaultClause = std::next(case2);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(defaultBody)));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithDefaultClauseAndWithFallThroughFromCase3ToCase1IsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %case1
		default:
			call void @test(i32 4)
			br label %after
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 2:
	//     test(2);
	//     break;
	// case 3:
	//     test(3);
	// case 1:
	//     test(1);
	//     break;
	// default:
	//     test(4);
	//     break;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case2 = switchStmt->clause_begin();
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	auto case3 = std::next(case2);
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case3, 3, 3));
	auto case1 = std::next(case3);
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	auto defaultClause = std::next(case1);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(defaultBody)));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithFallThroughFromCase2ToDefaultIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %default
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %after
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	//     break;
	// case 2:
	//     test(2);
	// default:
	//     test(4);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	auto case2 = std::next(case1);
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case2, 2, 2));
	auto defaultClause = std::next(case2);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(defaultBody)));
	auto case3 = std::next(defaultClause);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithFallThroughFromDefaultToCase2IsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %case2
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// default:
	//     test(4);
	// case 2:
	//     test(2);
	//     break;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	auto case3 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	auto defaultClause = std::next(case3);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_FALSE(getFirstNonEmptySuccOf(defaultBody)) << "There must be a fall through.";
	auto case2 = std::next(defaultClause);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithoutDefaultClauseAndWithFallThroughAllCasesInMixedOrderIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %after [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %case1
		case3:
			call void @test(i32 3)
			br label %case2
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 3:
	//     test(3);
	// case 2:
	//     test(2);
	// case 1:
	//     test(1);
	//     break;
	// }
	// test(4);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	ASSERT_FALSE(switchStmt->hasDefaultClause());
	auto case3 = switchStmt->clause_begin();
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case3, 3, 3));
	auto case2 = std::next(case3);
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case2, 2, 2));
	auto case1 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 4));
}

TEST_F(StructureConverterTests,
SwitchWithFallThroughFromDefaultAndTenThroughAllCasesInMixedOrderIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %case3
		case2:
			call void @test(i32 2)
			br label %case1
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %case2
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// switch (val) {
	// default:
	//     test(4);
	// case 2:
	//     test(2);
	// case 1:
	//     test(1);
	// case 3:
	//     test(3);
	//     break;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto defaultClause = switchStmt->clause_begin();
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_FALSE(getFirstNonEmptySuccOf(defaultBody)) << "There must be a fall through.";
	auto case2 = std::next(defaultClause);
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case2, 2, 2));
	auto case1 = std::next(case2);
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case1, 1, 1));
	auto case3 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithFallThroughFromCase1ToDefaultAndThenToCase2TerminatedByReturnIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
			]
		case1:
			call void @test(i32 1)
			br label %default
		default:
			call void @test(i32 0)
			br label %case2
		case2:
			call void @test(i32 2)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	// default:
	//     test(0);
	// case 2:
	//     test(2);
	//     return;
	// }
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case1, 1, 1));
	auto defaultClause = std::next(case1);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 0));
	ASSERT_FALSE(getFirstNonEmptySuccOf(defaultBody)) << "There must be a fall through.";
	auto case2 = std::next(defaultClause);
	ASSERT_TRUE(isTerminatingSwitchClause<ReturnStmt>(*case2, 2, 2));
	ASSERT_FALSE(getFirstNonEmptySuccOf(switchStmt));
}

TEST_F(StructureConverterTests,
SwitchWithDefaultClauseAndWithCase1TerminatedByReturnIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			ret void
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %after
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	//     return;
	// case 2:
	//     test(2);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// default:
	//     test(4);
	//     break;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isTerminatingSwitchClause<ReturnStmt>(*case1, 1, 1));
	auto case2 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	auto case3 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	auto defaultClause = std::next(case3);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(defaultBody)));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithDefaultClauseTerminatedByReturnIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			ret void
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	//     break;
	// case 2:
	//     test(2);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// default:
	//     test(4);
	//     return;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	auto case2 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	auto case3 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	auto defaultClause = std::next(case3);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_TRUE(isa<ReturnStmt>(getFirstNonEmptySuccOf(defaultBody)));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithAllClausesTerminatedByReturnIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %after [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			ret void
		case2:
			call void @test(i32 2)
			ret void
		case3:
			call void @test(i32 3)
			ret void
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	//     return;
	// case 2:
	//     test(2);
	//     return;
	// case 3:
	//     test(3);
	//     return;
	// }
	// test(4);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	ASSERT_FALSE(switchStmt->hasDefaultClause());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isTerminatingSwitchClause<ReturnStmt>(*case1, 1, 1));
	auto case2 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause<ReturnStmt>(*case2, 2, 2));
	auto case3 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause<ReturnStmt>(*case3, 3, 3));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 4));
}

TEST_F(StructureConverterTests,
SwitchWithEmptyCase1WhichFallThroughToCase2IsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			br label %case2
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %after
		after:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	// case 2:
	//     test(2);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// default:
	//     test(4);
	//     break;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isConstInt(case1->first, 1));
	auto case1Body = skipEmptyStmts(case1->second);
	ASSERT_FALSE(case1Body)
		<< "This clause does not fall through to the next clause";
	auto case2 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	auto case3 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	auto defaultClause = std::next(case3);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(defaultBody)));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithoutDefaultAndWithIfElseStatementInsideIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val, i32 %val2) {
		entry:
			switch i32 %val, label %after [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			%cond = icmp eq i32 %val2, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			call void @test(i32 2)
			br label %case1After
		iffalse:
			call void @test(i32 3)
			br label %case1After
		case1After:
			call void @test(i32 4)
			br label %after
		case2:
			call void @test(i32 5)
			br label %after
		case3:
			call void @test(i32 6)
			br label %after
		after:
			call void @test(i32 7)
		; code below is only to prevent optimizations with return
			%lastCond = icmp eq i32 %val, 1
			br i1 %lastCond, label %true, label %false
		true:
			call void @test(i32 0)
			br label %last
		false:
			call void @test(i32 0)
			br label %last
		last:
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	//     if (val2 == 1) {
	//         test(2);
	//     } else {
	//         test(3);
	//     }
	//     test(4);
	//     break;
	// case 2:
	//     test(5);
	//     break;
	// case 3:
	//     test(6);
	//     break;
	// }
	// test(7);
	// // ...
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	ASSERT_FALSE(switchStmt->hasDefaultClause());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isConstInt(case1->first, 1));
	auto case1Body = skipEmptyStmts(case1->second);
	ASSERT_TRUE(isCallOfFuncTest(case1Body, 1));
	auto nestedIf = cast<IfStmt>(getFirstNonEmptySuccOf(case1Body));
	ASSERT_TRUE(nestedIf);
	ASSERT_TRUE(isComparison<EqOpExpr>(nestedIf->getFirstIfCond(), f->getParam(2), 1));
	ASSERT_TRUE(isCallOfFuncTest(nestedIf->getFirstIfBody(), 2));
	ASSERT_TRUE(isCallOfFuncTest(nestedIf->getElseClause(), 3));
	auto afterNestedIf = getFirstNonEmptySuccOf(nestedIf);
	ASSERT_TRUE(isCallOfFuncTest(afterNestedIf, 4));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(afterNestedIf)));
	auto case2 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 5));
	auto case3 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 6));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 7));
}

TEST_F(StructureConverterTests,
SwitchWithoutDefaultAndWithIfElseStatementInsideWithTheSameBBAfterAsSwitchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val, i32 %val2) {
		entry:
			switch i32 %val, label %after [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			%cond = icmp eq i32 %val2, 1
			br i1 %cond, label %iftrue, label %iffalse
		iftrue:
			call void @test(i32 2)
			br label %after
		iffalse:
			call void @test(i32 3)
			br label %after
		case2:
			call void @test(i32 4)
			br label %after
		case3:
			call void @test(i32 5)
			br label %after
		after:
			call void @test(i32 6)
		; code below is only to prevent optimizations with return
			%lastCond = icmp eq i32 %val, 1
			br i1 %lastCond, label %true, label %false
		true:
			call void @test(i32 0)
			br label %last
		false:
			call void @test(i32 0)
			br label %last
		last:
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	//     test(1);
	//     if (val2 == 1) {
	//         test(2);
	//     } else {
	//         test(3);
	//     }
	//     break;
	// case 2:
	//     test(4);
	//     break;
	// case 3:
	//     test(5);
	//     break;
	// }
	// test(6);
	// // ...
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	ASSERT_FALSE(switchStmt->hasDefaultClause());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isConstInt(case1->first, 1));
	auto case1Body = skipEmptyStmts(case1->second);
	ASSERT_TRUE(isCallOfFuncTest(case1Body, 1));
	auto nestedIf = cast<IfStmt>(getFirstNonEmptySuccOf(case1Body));
	ASSERT_TRUE(nestedIf);
	ASSERT_TRUE(isComparison<EqOpExpr>(nestedIf->getFirstIfCond(), f->getParam(2), 1));
	ASSERT_TRUE(isCallOfFuncTest(nestedIf->getFirstIfBody(), 2));
	ASSERT_TRUE(isCallOfFuncTest(nestedIf->getElseClause(), 3));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(nestedIf)));
	auto case2 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 4));
	auto case3 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 5));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 6));
}

TEST_F(StructureConverterTests,
SwitchWithMoreConditionsForOneCaseIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %after [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case1
				i32 4, label %case3
				i32 5, label %case1
				i32 6, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 2)
			br label %after
		case3:
			call void @test(i32 3)
			br label %after
		after:
			call void @test(i32 4)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 1:
	// case 3:
	// case 5:
	//     test(1);
	//     break;
	// case 2:
	//     test(2);
	//     break;
	// case 4:
	// case 6:
	//     test(3);
	//     break;
	// }
	// test(4);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	ASSERT_FALSE(switchStmt->hasDefaultClause());
	auto case1 = switchStmt->clause_begin();
	ASSERT_TRUE(isConstInt(case1->first, 1));
	ASSERT_TRUE(isa<EmptyStmt>(case1->second));
	auto case3 = std::next(case1);
	ASSERT_TRUE(isConstInt(case3->first, 3));
	ASSERT_TRUE(isa<EmptyStmt>(case3->second));
	auto case5 = std::next(case3);
	ASSERT_TRUE(isTerminatingSwitchClause(*case5, 5, 1));
	auto case2 = std::next(case5);
	ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
	auto case4 = std::next(case2);
	ASSERT_TRUE(isConstInt(case4->first, 4));
	ASSERT_TRUE(isa<EmptyStmt>(case4->second));
	auto case6 = std::next(case4);
	ASSERT_TRUE(isTerminatingSwitchClause(*case6, 6, 3));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 4));
}

TEST_F(StructureConverterTests,
SwitchWithNoCaseIsConvertedCorrectlyAsUnconditionalJump) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %after [
			]
		after:
			call void @test(i32 1)
			ret void
		}
	)");

	//
	// test(1);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	ASSERT_TRUE(isCallOfFuncTest(skipEmptyStmts(f->getBody()), 1));
}

TEST_F(StructureConverterTests,
SwitchWithNestedSwitchIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val, i32 %val2) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 21)
			switch i32 %val2, label %afterInner [
				i32 1, label %innerCase1
				i32 2, label %innerCase2
				i32 3, label %innerCase3
			]
		innerCase1:
			call void @test(i32 201)
			br label %afterInner
		innerCase2:
			call void @test(i32 202)
			br label %afterInner
		innerCase3:
			call void @test(i32 203)
			br label %innerCase1
		afterInner:
			call void @test(i32 22)
			br label %case1
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %after
		after:
			call void @test(i32 5)
		; code below is only to prevent optimizations with return
			%lastCond = icmp eq i32 %val, 1
			br i1 %lastCond, label %true, label %false
		true:
			call void @test(i32 0)
			br label %last
		false:
			call void @test(i32 0)
			br label %last
		last:
			ret void
		}
	)");

	//
	// switch (val) {
	// case 2:
	//     test(21);
	//     switch(val2) {
	//     case 2:
	//         test(202);
	//         break;
	//     case 3:
	//         test(203);
	//     case 1:
	//         test(201);
	//         break;
	//     }
	//     test(22);
	// case 1:
	//     test(1);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// default:
	//     test(4);
	//     break;
	// }
	// test(5);
	// // ...
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case2 = switchStmt->clause_begin();
	ASSERT_TRUE(isConstInt(case2->first, 2));
	auto case2Body = skipEmptyStmts(case2->second);
	ASSERT_TRUE(isCallOfFuncTest(case2Body, 21));
	auto innerSwitch = cast<SwitchStmt>(case2Body->getSuccessor());
	ASSERT_TRUE(innerSwitch);
	{
		SCOPED_TRACE("Testing inner switch");
		ASSERT_BIR_EQ(f->getParam(2), innerSwitch->getControlExpr());
		ASSERT_FALSE(innerSwitch->hasDefaultClause());
		auto innerCase2 = innerSwitch->clause_begin();
		ASSERT_TRUE(isTerminatingSwitchClause(*innerCase2, 2, 202));
		auto innerCase3 = std::next(innerCase2);
		ASSERT_TRUE(isNonTerminatingSwitchClause(*innerCase3, 3, 203));
		auto innerCase1 = std::next(innerCase3);
		ASSERT_TRUE(isTerminatingSwitchClause(*innerCase1, 1, 201));
	}
	auto innerSwitchSucc = getFirstNonEmptySuccOf(innerSwitch);
	ASSERT_TRUE(isCallOfFuncTest(innerSwitchSucc, 22));
	auto case2end = getFirstNonEmptySuccOf(innerSwitchSucc);
	ASSERT_FALSE(case2end)
		<< "This clause does not fall through to the next clause";
	auto case1 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	auto case3 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	auto defaultClause = std::next(case3);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(defaultBody)));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWithNestedSwitchWithTheSameBBAfterIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val, i32 %val2) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %after
		case2:
			call void @test(i32 21)
			switch i32 %val2, label %case1 [
				i32 1, label %innerCase1
				i32 2, label %innerCase2
				i32 3, label %innerCase3
			]
		innerCase1:
			call void @test(i32 201)
			br label %case1
		innerCase2:
			call void @test(i32 202)
			br label %case1
		innerCase3:
			call void @test(i32 203)
			br label %innerCase1
		case3:
			call void @test(i32 3)
			br label %after
		default:
			call void @test(i32 4)
			br label %after
		after:
			br label %after2
		after2:
			call void @test(i32 5)
			ret void
		}
	)");

	//
	// switch (val) {
	// case 2:
	//     test(21);
	//     switch(val2) {
	//     case 2:
	//         test(202);
	//         break;
	//     case 3:
	//         test(203);
	//     case 1:
	//         test(201);
	//         break;
	//     }
	// case 1:
	//     test(1);
	//     break;
	// case 3:
	//     test(3);
	//     break;
	// default:
	//     test(4);
	//     break;
	// }
	// test(5);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case2 = switchStmt->clause_begin();
	ASSERT_TRUE(isConstInt(case2->first, 2));
	auto case2Body = skipEmptyStmts(case2->second);
	ASSERT_TRUE(isCallOfFuncTest(case2Body, 21));
	auto innerSwitch = cast<SwitchStmt>(case2Body->getSuccessor());
	ASSERT_TRUE(innerSwitch);
	{
		SCOPED_TRACE("Testing inner switch");
		ASSERT_BIR_EQ(f->getParam(2), innerSwitch->getControlExpr());
		ASSERT_FALSE(innerSwitch->hasDefaultClause());
		auto innerCase2 = innerSwitch->clause_begin();
		ASSERT_TRUE(isTerminatingSwitchClause(*innerCase2, 2, 202));
		auto innerCase3 = std::next(innerCase2);
		ASSERT_TRUE(isNonTerminatingSwitchClause(*innerCase3, 3, 203));
		auto innerCase1 = std::next(innerCase3);
		ASSERT_TRUE(isTerminatingSwitchClause(*innerCase1, 1, 201));
	}
	auto case2end = getFirstNonEmptySuccOf(innerSwitch);
	ASSERT_FALSE(case2end)
		<< "This clause does not fall through to the next clause";
	auto case1 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
	auto case3 = std::next(case1);
	ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
	auto defaultClause = std::next(case3);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
	ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(defaultBody)));
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(switchStmt), 5));
}

TEST_F(StructureConverterTests,
SwitchWhichMustBeStructuredAlsoUsingGotoIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			switch i32 %val, label %default [
				i32 1, label %case1
				i32 2, label %case2
			]
		case1:
			call void @test(i32 1)
			ret void
		case2:
			call void @test(i32 2)
			br label %case1
		default:
			call void @test(i32 3)
			br label %case1
		}
	)");

	//
	// switch (val) {
	// case 2:
	//     test(2);
	// case 1:
	//   lab_case1:
	//     test(1);
	//     return;
	// default:
	//     test(3);
	//     goto lab_case1;
	// }
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto switchStmt = cast<SwitchStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(switchStmt);
	ASSERT_BIR_EQ(f->getParam(1), switchStmt->getControlExpr());
	auto case2 = switchStmt->clause_begin();
	ASSERT_TRUE(isNonTerminatingSwitchClause(*case2, 2, 2));
	auto case1 = std::next(case2);
	ASSERT_TRUE(isTerminatingSwitchClause<ReturnStmt>(*case1, 1, 1));
	auto defaultClause = std::next(case1);
	ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
	auto defaultBody = skipEmptyStmts(defaultClause->second);
	ASSERT_TRUE(isCallOfFuncTest(defaultBody, 3));
	auto gotoStmt = cast<GotoStmt>(getFirstNonEmptySuccOf(defaultBody));
	ASSERT_TRUE(gotoStmt);
	ASSERT_BIR_EQ(case1->second, gotoStmt->getTarget());
}

//
// Tests for switches inside loops
//

TEST_F(StructureConverterTests,
SwitchInLoopWithDefaultClauseAndWithAllClausesTerminatedByBreakIsConvertedCorrectly) {
	auto module = convertLLVMIR2BIR(R"(
		declare void @test(i32)

		define void @function(i32 %val) {
		entry:
			br label %loop
		loop:
			%x = phi i32 [ %y, %afterSwitch ], [ 0, %entry ]
			call void @test(i32 0)
			switch i32 %x, label %default [
				i32 1, label %case1
				i32 2, label %case2
				i32 3, label %case3
			]
		case1:
			call void @test(i32 1)
			br label %afterSwitch
		case2:
			call void @test(i32 2)
			br label %afterSwitch
		case3:
			call void @test(i32 3)
			br label %afterSwitch
		default:
			call void @test(i32 4)
			br label %afterSwitch
		afterSwitch:
			call void @test(i32 5)
			%y = add i32 %x, 1
			%cond = icmp eq i32 %y, %val
			br i1 %cond, label %after, label %loop
		after:
			call void @test(i32 6)
			ret void
		}
	)");

	//
	// int x;
	// int y;
	// x = 0;
	// while (true) {
	//     test(0);
	//     switch (val) {
	//     case 1:
	//         test(1);
	//         break;
	//     case 2:
	//         test(2);
	//         break;
	//     case 3:
	//         test(3);
	//         break;
	//     default:
	//         test(4);
	//         break;
	//     }
	//     test(5);
	//     y = x + 1;
	//     if (y == val) {
	//         break;
	//     }
	//     x = y;
	// }
	// test(6);
	// return;
	//
	auto f = module->getFuncByName("function");
	ASSERT_TRUE(f);
	auto varDefX = cast<VarDefStmt>(skipEmptyStmts(f->getBody()));
	ASSERT_TRUE(isVarDef<IntType>(varDefX, "x"));
	auto varX = varDefX->getVar();
	auto varDefY = cast<VarDefStmt>(getFirstNonEmptySuccOf(varDefX));
	ASSERT_TRUE(isVarDef<IntType>(varDefY, "y"));
	auto varY = varDefY->getVar();
	auto assignStmt1 = getFirstNonEmptySuccOf(varDefY);
	ASSERT_TRUE(isAssignOfConstIntToVar(assignStmt1, varX, 0));
	auto whileStmt = cast<WhileLoopStmt>(getFirstNonEmptySuccOf(assignStmt1));
	ASSERT_TRUE(whileStmt);
	{
		SCOPED_TRACE("Testing loop");
		auto whileCond = cast<ConstBool>(whileStmt->getCondition());
		ASSERT_TRUE(whileCond->getValue());
		ASSERT_TRUE(whileCond);
		auto whileBody = skipEmptyStmts(whileStmt->getBody());
		ASSERT_TRUE(isCallOfFuncTest(whileBody, 0));
		auto switchStmt = cast<SwitchStmt>(getFirstNonEmptySuccOf(whileBody));
		ASSERT_TRUE(switchStmt);
		ASSERT_BIR_EQ(varX, switchStmt->getControlExpr());
		auto case1 = switchStmt->clause_begin();
		ASSERT_TRUE(isTerminatingSwitchClause(*case1, 1, 1));
		auto case2 = std::next(case1);
		ASSERT_TRUE(isTerminatingSwitchClause(*case2, 2, 2));
		auto case3 = std::next(case2);
		ASSERT_TRUE(isTerminatingSwitchClause(*case3, 3, 3));
		auto defaultClause = std::next(case3);
		ASSERT_FALSE(defaultClause->first) << "This is not a default clause.";
		auto defaultBody = skipEmptyStmts(defaultClause->second);
		ASSERT_TRUE(isCallOfFuncTest(defaultBody, 4));
		ASSERT_TRUE(isa<BreakStmt>(getFirstNonEmptySuccOf(defaultBody)));
		auto switchSucc = getFirstNonEmptySuccOf(switchStmt);
		ASSERT_TRUE(isCallOfFuncTest(switchSucc, 5));
		auto assignStmt2 = getFirstNonEmptySuccOf(switchSucc);
		ASSERT_TRUE(isAssignOfAddExprToVar(assignStmt2, varY, varX, 1));
		auto ifBreak = cast<IfStmt>(getFirstNonEmptySuccOf(assignStmt2));
		ASSERT_TRUE(ifBreak);
		ASSERT_TRUE(isComparison<EqOpExpr>(ifBreak->getFirstIfCond(),
			varY, f->getParam(1)));
		ASSERT_TRUE(isa<BreakStmt>(ifBreak->getFirstIfBody()));
		ASSERT_FALSE(ifBreak->hasElseClause());
		ASSERT_TRUE(isAssignOfVarToVar(getFirstNonEmptySuccOf(ifBreak), varX, varY));
	}
	ASSERT_TRUE(isCallOfFuncTest(getFirstNonEmptySuccOf(whileStmt), 6));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
