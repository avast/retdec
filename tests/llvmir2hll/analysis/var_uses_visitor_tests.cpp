/**
* @file tests/llvmir2hll/analysis/var_uses_visitor_tests.cpp
* @brief Tests for the @c var_uses_visitor module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <map>

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analysis.h"
#include "llvmir2hll/analysis/tests_with_value_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/analysis/var_uses_visitor.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/types.h"

/**
* @brief Runs the code after the macro for all variants of VarUsesVisitor.
*
* This macro runs the code specified after the macro for every variant of
* VarUsesVisitor (caching enabled/disabled, precomputation enabled/disabled).
* The currently instantiated VarUsesVisitor is accessible in the variable @c
* vuv, its description in a string @c vuvDesc.
*
* The macro INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS from
* TestsWithValueAnalysis.h has to be used before this macro.
*
* Example of usage:
* @code
* INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
* FOR_EVERY_VAR_USES_VISITOR_VARIANT {
*   // Tests
*   // ...
* }
* @endcode
*/
#define FOR_EVERY_VAR_USES_VISITOR_VARIANT \
	using VAVMap = std::map<std::string, ShPtr<VarUsesVisitor>>; \
	VAVMap vuvMap; \
	vuvMap.insert(std::make_pair("-----> VUV: cache OFF, precomputation OFF", \
		VarUsesVisitor::create(va, false))); \
	vuvMap.insert(std::make_pair("-----> VUV: cache ON, precomputation OFF", \
		VarUsesVisitor::create(va, true))); \
	vuvMap.insert(std::make_pair("-----> VUV: cache ON, precomputation ON", \
		VarUsesVisitor::create(va, true, module))); \
	std::string vuvDesc; \
	ShPtr<VarUsesVisitor> vuv; \
	for (auto vuvMapI = vuvMap.begin(), vuvMapE = vuvMap.end(); \
		vuvMapI != vuvMapE && (vuvDesc = vuvMapI->first, true) && (vuv = vuvMapI->second); \
		++vuvMapI)

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c var_uses_visitor module.
*/
class VarUsesVisitorTests: public TestsWithModule {};

TEST_F(VarUsesVisitorTests,
VariableIsNotUsedAtAll) {
	// Set-up the module.
	//
	// def test():
	//    return
	//
	ShPtr<Variable> dummyVar(Variable::create("dummy", IntType::create(32)));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	testFunc->setBody(returnStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	FOR_EVERY_VAR_USES_VISITOR_VARIANT {
		// isUsed()
		EXPECT_FALSE(vuv->isUsed(dummyVar, testFunc, false)) << vuvDesc;
		EXPECT_FALSE(vuv->isUsed(dummyVar, testFunc, true)) << vuvDesc;

		// getUses()
		ShPtr<VarUses> dummyVarUses(vuv->getUses(dummyVar, testFunc));
		EXPECT_EQ(dummyVar, dummyVarUses->var) << vuvDesc;
		EXPECT_EQ(testFunc, dummyVarUses->func) << vuvDesc;
		EXPECT_TRUE(dummyVarUses->dirUses.empty()) << vuvDesc;
	}
}

TEST_F(VarUsesVisitorTests,
GlobalVariableIsDirectlyUsedOnce) {
	// Set-up the module.
	//
	// a
	//
	// def test():
	//    return a
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	testFunc->setBody(returnA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	FOR_EVERY_VAR_USES_VISITOR_VARIANT {
		// isUsed()
		EXPECT_TRUE(vuv->isUsed(varA, testFunc, false)) << vuvDesc;
		EXPECT_FALSE(vuv->isUsed(varA, testFunc, true)) << vuvDesc;

		// getUses()
		ShPtr<VarUses> varAUses(vuv->getUses(varA, testFunc));
		EXPECT_EQ(varA, varAUses->var) << vuvDesc;
		EXPECT_EQ(testFunc, varAUses->func) << vuvDesc;
		StmtSet refVarAUses;
		refVarAUses.insert(returnA);
		EXPECT_EQ(refVarAUses, varAUses->dirUses) << vuvDesc;
	}
}

TEST_F(VarUsesVisitorTests,
GlobalVariableIsDirectlyUsedTwice) {
	// Set-up the module.
	//
	// a
	//
	// def test():
	//    a = 1
	//    return a
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(varA,
		ConstInt::create(1, 32), returnA));
	testFunc->setBody(assignA1);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	FOR_EVERY_VAR_USES_VISITOR_VARIANT {
		// isUsed()
		EXPECT_TRUE(vuv->isUsed(varA, testFunc, false)) << vuvDesc;
		EXPECT_TRUE(vuv->isUsed(varA, testFunc, true)) << vuvDesc;

		// getUses()
		ShPtr<VarUses> varAUses(vuv->getUses(varA, testFunc));
		EXPECT_EQ(varA, varAUses->var) << vuvDesc;
		EXPECT_EQ(testFunc, varAUses->func) << vuvDesc;
		StmtSet refVarAUses;
		refVarAUses.insert(assignA1);
		refVarAUses.insert(returnA);
		EXPECT_EQ(refVarAUses, varAUses->dirUses) << vuvDesc;
	}
}

TEST_F(VarUsesVisitorTests,
LocalVariableIsDirectlyUsedTwice) {
	// Set-up the module.
	//
	// def test():
	//    a = 1
	//    return a
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	ShPtr<VarDefStmt> varADef(VarDefStmt::create(varA,
		ConstInt::create(1, 32), returnA));
	testFunc->setBody(varADef);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	FOR_EVERY_VAR_USES_VISITOR_VARIANT {
		// isUsed()
		EXPECT_TRUE(vuv->isUsed(varA, testFunc, false)) << vuvDesc;
		EXPECT_TRUE(vuv->isUsed(varA, testFunc, true)) << vuvDesc;

		// getUses()
		ShPtr<VarUses> varAUses(vuv->getUses(varA, testFunc));
		EXPECT_EQ(varA, varAUses->var) << vuvDesc;
		EXPECT_EQ(testFunc, varAUses->func);
		StmtSet refVarAUses;
		refVarAUses.insert(varADef);
		refVarAUses.insert(returnA);
		EXPECT_EQ(refVarAUses, varAUses->dirUses) << vuvDesc;
	}
}

TEST_F(VarUsesVisitorTests,
GlobalVariableIsIndirectlyUsedMust) {
	// Set-up the module.
	//
	// a
	//
	// def test():
	//    p = &a
	//    return *p
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p", PointerType::create(
		IntType::create(32))));
	ShPtr<ReturnStmt> returnP(ReturnStmt::create(DerefOpExpr::create(varP)));
	ShPtr<VarDefStmt> varPDef(VarDefStmt::create(varP,
		AddressOpExpr::create(varA), returnP));
	testFunc->setBody(varPDef);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	// Set-up more specific default actions.
	ON_CALL(*aliasAnalysisMock, pointsTo(varP))
		.WillByDefault(Return(varA));

	FOR_EVERY_VAR_USES_VISITOR_VARIANT {
		// isUsed()
		EXPECT_TRUE(vuv->isUsed(varA, testFunc, false)) << vuvDesc;
		EXPECT_TRUE(vuv->isUsed(varA, testFunc, true)) << vuvDesc;

		// getUses()
		ShPtr<VarUses> varAUses(vuv->getUses(varA, testFunc));
		EXPECT_EQ(varA, varAUses->var) << vuvDesc;
		EXPECT_EQ(testFunc, varAUses->func) << vuvDesc;
		// - direct
		StmtSet refVarADirUses;
		refVarADirUses.insert(varPDef);
		EXPECT_EQ(refVarADirUses, varAUses->dirUses) << vuvDesc;
		// - indirect
		StmtSet refVarAIndirUses;
		refVarAIndirUses.insert(returnP);
		EXPECT_EQ(refVarAIndirUses, varAUses->indirUses) << vuvDesc;
	}
}

TEST_F(VarUsesVisitorTests,
GlobalVariableIsIndirectlyUsedMay) {
	// Set-up the module.
	//
	// a
	//
	// def test():
	//    p = &a
	//    return *p
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p", PointerType::create(
		IntType::create(32))));
	ShPtr<ReturnStmt> returnP(ReturnStmt::create(DerefOpExpr::create(varP)));
	ShPtr<VarDefStmt> varPDef(VarDefStmt::create(varP,
		AddressOpExpr::create(varA), returnP));
	testFunc->setBody(varPDef);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
	// Set-up more specific default actions.
	VarSet refPMayPointTo;
	refPMayPointTo.insert(varA);
	ON_CALL(*aliasAnalysisMock, mayPointTo(varP))
		.WillByDefault(ReturnRef(refPMayPointTo));

	FOR_EVERY_VAR_USES_VISITOR_VARIANT {
		// isUsed()
		EXPECT_TRUE(vuv->isUsed(varA, testFunc, false)) << vuvDesc;
		EXPECT_TRUE(vuv->isUsed(varA, testFunc, true)) << vuvDesc;

		// getUses()
		ShPtr<VarUses> varAUses(vuv->getUses(varA, testFunc));
		EXPECT_EQ(varA, varAUses->var) << vuvDesc;
		EXPECT_EQ(testFunc, varAUses->func) << vuvDesc;
		// - direct
		StmtSet refVarADirUses;
		refVarADirUses.insert(varPDef);
		EXPECT_EQ(refVarADirUses, varAUses->dirUses) << vuvDesc;
		// - indirect
		StmtSet refVarAIndirUses;
		refVarAIndirUses.insert(returnP);
		EXPECT_EQ(refVarAIndirUses, varAUses->indirUses) << vuvDesc;
	}
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
