/**
* @file tests/llvmir2hll/analysis/value_analysis_tests.cpp
* @brief Tests for the @c value_analysis module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "llvmir2hll/analysis/alias_analysis/alias_analysis_mock.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/types.h"

/**
* @brief Instantiates AliasAnalysisMock, AliasAnalysis, and ValueAnalysis using
*        the given module.
*
* This macro does the following:
*  (1) Instantiates AliasAnalysisMock and AliasAnalysis (variables @c
*      aliasAnalysisMock and @c aliasAnalysis).
*  (2) Sets-up default actions for aliasAalysisMock.
*  (3) Instantiates a ValueAnalysis (variable @c va).
*
* @param useCache If @c true, caching in ValueAnalysis will be used.
*
* Example of usage:
* @code
* TEST(TestExample, Test1) {
*   // Set-up a module.
*   INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);
*   // Set-up custom default actions or expectations for aliasAnalysisMock.
*   // Run tests utilizing ValueAnalysis.
* }
* @endcode
*/
#define INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(useCache) \
	/* (1) */ \
	NiceMock<AliasAnalysisMock> *aliasAnalysisMock = \
		new NiceMock<AliasAnalysisMock>(); \
	ShPtr<AliasAnalysis> aliasAnalysis(aliasAnalysisMock); \
	/* (2) */ \
	const VarSet EMPTY_VAR_SET; \
	ON_CALL(*aliasAnalysisMock, mayPointTo(_)) \
		.WillByDefault(ReturnRef(EMPTY_VAR_SET)); \
	ON_CALL(*aliasAnalysisMock, pointsTo(_)) \
		.WillByDefault(Return(ShPtr<Variable>())); \
	ON_CALL(*aliasAnalysisMock, mayBePointed(_)) \
		.WillByDefault(Return(false)); \
	ON_CALL(*aliasAnalysisMock, isInitialized()) \
		.WillByDefault(Return(true)); \
	/* (4) */ \
	ShPtr<ValueAnalysis> va(ValueAnalysis::create(aliasAnalysis, useCache))

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c value_analysis module.
*/
class ValueAnalysisTests: public TestsWithModule {};

TEST_F(ValueAnalysisTests,
ReturnStmtWithNoReturnValueNoCache) {
	// Set-up the module.
	//
	// def test():
	//    return
	//
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	testFunc->setBody(returnStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	ShPtr<ValueData> data(va->getValueData(returnStmt));
	// Directly read/written variables.
	//  - variables: get*()
	EXPECT_EQ(VarSet(), data->getDirReadVars());
	EXPECT_EQ(VarSet(), data->getDirWrittenVars());
	EXPECT_EQ(VarSet(), data->getDirAccessedVars());
	//  - variables: counts
	EXPECT_EQ(0, data->getNumOfDirReadVars());
	EXPECT_EQ(0, data->getNumOfDirWrittenVars());
	EXPECT_EQ(0, data->getNumOfDirAccessedVars());
	ShPtr<Variable> dummyVar(Variable::create("dummy", IntType::create(32)));
	EXPECT_EQ(0, data->getDirNumOfUses(dummyVar));
	EXPECT_FALSE(data->isDirRead(dummyVar));
	EXPECT_FALSE(data->isDirWritten(dummyVar));
	EXPECT_FALSE(data->isDirAccessed(dummyVar));
	//  - variables: iterators
	EXPECT_EQ(data->dir_read_end(), data->dir_read_begin());
	EXPECT_EQ(data->dir_written_end(), data->dir_written_begin());
	EXPECT_EQ(data->dir_all_end(), data->dir_all_begin());
	//  - calls
	EXPECT_EQ(CallVector(), data->getCalls());
	EXPECT_FALSE(data->hasCalls());
	EXPECT_EQ(data->call_end(), data->call_begin());
	//  - address operators
	EXPECT_FALSE(data->hasAddressOps());
	EXPECT_FALSE(data->hasAddressTaken(dummyVar));
	//  - dereferences
	EXPECT_FALSE(data->hasDerefs());
	//  - array accesses
	EXPECT_FALSE(data->hasArrayAccesses());
}

TEST_F(ValueAnalysisTests,
VarDefStmtWithNoInitializerNoCache) {
	// Set-up the module.
	//
	// def test():
	//    a
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<VarDefStmt> varDefStmt(VarDefStmt::create(varA));
	testFunc->setBody(varDefStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	ShPtr<ValueData> data(va->getValueData(varDefStmt));
	// Directly read/written variables.
	//  - variables: get*()
	VarSet refDirReadVars;
	EXPECT_EQ(refDirReadVars, data->getDirReadVars());
	VarSet refDirWrittenVars;
	refDirWrittenVars.insert(varA);
	EXPECT_EQ(refDirWrittenVars, data->getDirWrittenVars());
	VarSet refDirAllVars;
	refDirAllVars.insert(varA);
	EXPECT_EQ(refDirAllVars, data->getDirAccessedVars());
	//  - variables: counts
	EXPECT_EQ(0, data->getNumOfDirReadVars());
	EXPECT_EQ(1, data->getNumOfDirWrittenVars());
	EXPECT_EQ(1, data->getNumOfDirAccessedVars());
	EXPECT_EQ(1, data->getDirNumOfUses(varA));
	EXPECT_FALSE(data->isDirRead(varA));
	EXPECT_TRUE(data->isDirWritten(varA));
	EXPECT_TRUE(data->isDirAccessed(varA));
	ShPtr<Variable> dummyVar(Variable::create("dummy", IntType::create(32)));
	EXPECT_EQ(0, data->getDirNumOfUses(dummyVar));
	EXPECT_FALSE(data->isDirRead(dummyVar));
	EXPECT_FALSE(data->isDirWritten(dummyVar));
	EXPECT_FALSE(data->isDirAccessed(dummyVar));
	//  - variables: iterators
	EXPECT_EQ(refDirReadVars,
		VarSet(data->dir_read_begin(), data->dir_read_end()));
	EXPECT_EQ(refDirWrittenVars,
		VarSet(data->dir_written_begin(), data->dir_written_end()));
	EXPECT_EQ(refDirAllVars,
		VarSet(data->dir_all_begin(), data->dir_all_end()));
	//  - calls
	EXPECT_EQ(CallVector(), data->getCalls());
	EXPECT_FALSE(data->hasCalls());
	EXPECT_EQ(data->call_end(), data->call_begin());
	//  - address operators
	EXPECT_FALSE(data->hasAddressOps());
	EXPECT_FALSE(data->hasAddressTaken(dummyVar));
	//  - dereferences
	EXPECT_FALSE(data->hasDerefs());
	//  - array accesses
	EXPECT_FALSE(data->hasArrayAccesses());
}

TEST_F(ValueAnalysisTests,
VarDefStmtWithConstIntInitializerNoCache) {
	// Set-up the module.
	//
	// def test():
	//    a = 1
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<VarDefStmt> varDefStmt(VarDefStmt::create(
		varA, ConstInt::create(1, 32)));
	testFunc->setBody(varDefStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	ShPtr<ValueData> data(va->getValueData(varDefStmt));
	// Directly read/written variables.
	//  - variables: get*()
	VarSet refDirReadVars;
	EXPECT_EQ(refDirReadVars, data->getDirReadVars());
	VarSet refDirWrittenVars;
	refDirWrittenVars.insert(varA);
	EXPECT_EQ(refDirWrittenVars, data->getDirWrittenVars());
	VarSet refDirAllVars;
	refDirAllVars.insert(varA);
	EXPECT_EQ(refDirAllVars, data->getDirAccessedVars());
	//  - variables: counts
	EXPECT_EQ(0, data->getNumOfDirReadVars());
	EXPECT_EQ(1, data->getNumOfDirWrittenVars());
	EXPECT_EQ(1, data->getNumOfDirAccessedVars());
	EXPECT_EQ(1, data->getDirNumOfUses(varA));
	EXPECT_FALSE(data->isDirRead(varA));
	EXPECT_TRUE(data->isDirWritten(varA));
	EXPECT_TRUE(data->isDirAccessed(varA));
	ShPtr<Variable> dummyVar(Variable::create("dummy", IntType::create(32)));
	EXPECT_EQ(0, data->getDirNumOfUses(dummyVar));
	EXPECT_FALSE(data->isDirRead(dummyVar));
	EXPECT_FALSE(data->isDirWritten(dummyVar));
	EXPECT_FALSE(data->isDirAccessed(dummyVar));
	//  - variables: iterators
	EXPECT_EQ(refDirReadVars,
		VarSet(data->dir_read_begin(), data->dir_read_end()));
	EXPECT_EQ(refDirWrittenVars,
		VarSet(data->dir_written_begin(), data->dir_written_end()));
	EXPECT_EQ(refDirAllVars,
		VarSet(data->dir_all_begin(), data->dir_all_end()));
	//  - calls
	EXPECT_EQ(CallVector(), data->getCalls());
	EXPECT_FALSE(data->hasCalls());
	EXPECT_EQ(data->call_end(), data->call_begin());
	//  - address operators
	EXPECT_FALSE(data->hasAddressOps());
	EXPECT_FALSE(data->hasAddressTaken(dummyVar));
	//  - dereferences
	EXPECT_FALSE(data->hasDerefs());
	//  - array accesses
	EXPECT_FALSE(data->hasArrayAccesses());
}

TEST_F(ValueAnalysisTests,
VarDefStmtInitializedWithGlobalVariableNoCache) {
	// Set-up the module.
	//
	// g
	//
	// def test():
	//    a = g
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<VarDefStmt> varDefStmt(VarDefStmt::create(varA, varG));
	testFunc->setBody(varDefStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	ShPtr<ValueData> data(va->getValueData(varDefStmt));
	// Directly read/written variables.
	//  - variables: get*()
	VarSet refDirReadVars;
	refDirReadVars.insert(varG);
	EXPECT_EQ(refDirReadVars, data->getDirReadVars());
	VarSet refDirWrittenVars;
	refDirWrittenVars.insert(varA);
	EXPECT_EQ(refDirWrittenVars, data->getDirWrittenVars());
	VarSet refDirAllVars;
	refDirAllVars.insert(varA);
	refDirAllVars.insert(varG);
	EXPECT_EQ(refDirAllVars, data->getDirAccessedVars());
	//  - variables: counts
	EXPECT_EQ(1, data->getNumOfDirReadVars());
	EXPECT_EQ(1, data->getNumOfDirWrittenVars());
	EXPECT_EQ(2, data->getNumOfDirAccessedVars());
	EXPECT_EQ(1, data->getDirNumOfUses(varA));
	EXPECT_EQ(1, data->getDirNumOfUses(varG));
	EXPECT_FALSE(data->isDirRead(varA));
	EXPECT_TRUE(data->isDirWritten(varA));
	EXPECT_TRUE(data->isDirAccessed(varA));
	EXPECT_TRUE(data->isDirRead(varG));
	EXPECT_FALSE(data->isDirWritten(varG));
	EXPECT_TRUE(data->isDirAccessed(varG));
	ShPtr<Variable> dummyVar(Variable::create("dummy", IntType::create(32)));
	EXPECT_EQ(0, data->getDirNumOfUses(dummyVar));
	EXPECT_FALSE(data->isDirRead(dummyVar));
	EXPECT_FALSE(data->isDirWritten(dummyVar));
	EXPECT_FALSE(data->isDirAccessed(dummyVar));
	//  - variables: iterators
	EXPECT_EQ(refDirReadVars,
		VarSet(data->dir_read_begin(), data->dir_read_end()));
	EXPECT_EQ(refDirWrittenVars,
		VarSet(data->dir_written_begin(), data->dir_written_end()));
	EXPECT_EQ(refDirAllVars,
		VarSet(data->dir_all_begin(), data->dir_all_end()));
	//  - calls
	EXPECT_EQ(CallVector(), data->getCalls());
	EXPECT_FALSE(data->hasCalls());
	EXPECT_EQ(data->call_end(), data->call_begin());
	//  - address operators
	EXPECT_FALSE(data->hasAddressOps());
	EXPECT_FALSE(data->hasAddressTaken(dummyVar));
	//  - dereferences
	EXPECT_FALSE(data->hasDerefs());
	//  - array accesses
	EXPECT_FALSE(data->hasArrayAccesses());
}

TEST_F(ValueAnalysisTests,
ReturnStmtReturningAddressOfVariableNoCache) {
	// Set-up the module.
	//
	// g
	//
	// def test():
	//    return &g
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(
		AddressOpExpr::create(varG)));
	testFunc->setBody(returnStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	ShPtr<ValueData> data(va->getValueData(returnStmt));
	// Directly read/written variables.
	//  - variables: get*()
	VarSet refDirReadVars;
	refDirReadVars.insert(varG);
	EXPECT_EQ(refDirReadVars, data->getDirReadVars());
	VarSet refDirWrittenVars;
	EXPECT_EQ(refDirWrittenVars, data->getDirWrittenVars());
	VarSet refDirAllVars;
	refDirAllVars.insert(varG);
	EXPECT_EQ(refDirAllVars, data->getDirAccessedVars());
	//  - variables: counts
	EXPECT_EQ(1, data->getNumOfDirReadVars());
	EXPECT_EQ(0, data->getNumOfDirWrittenVars());
	EXPECT_EQ(1, data->getNumOfDirAccessedVars());
	EXPECT_EQ(1, data->getDirNumOfUses(varG));
	EXPECT_TRUE(data->isDirRead(varG));
	EXPECT_FALSE(data->isDirWritten(varG));
	EXPECT_TRUE(data->isDirAccessed(varG));
	ShPtr<Variable> dummyVar(Variable::create("dummy", IntType::create(32)));
	EXPECT_EQ(0, data->getDirNumOfUses(dummyVar));
	EXPECT_FALSE(data->isDirRead(dummyVar));
	EXPECT_FALSE(data->isDirWritten(dummyVar));
	EXPECT_FALSE(data->isDirAccessed(dummyVar));
	//  - variables: iterators
	EXPECT_EQ(refDirReadVars,
		VarSet(data->dir_read_begin(), data->dir_read_end()));
	EXPECT_EQ(refDirWrittenVars,
		VarSet(data->dir_written_begin(), data->dir_written_end()));
	EXPECT_EQ(refDirAllVars,
		VarSet(data->dir_all_begin(), data->dir_all_end()));
	//  - calls
	EXPECT_EQ(CallVector(), data->getCalls());
	EXPECT_FALSE(data->hasCalls());
	EXPECT_EQ(data->call_end(), data->call_begin());
	//  - address operators
	EXPECT_TRUE(data->hasAddressOps());
	EXPECT_TRUE(data->hasAddressTaken(varG));
	EXPECT_FALSE(data->hasAddressTaken(dummyVar));
	//  - dereferences
	EXPECT_FALSE(data->hasDerefs());
	//  - array accesses
	EXPECT_FALSE(data->hasArrayAccesses());
}

TEST_F(ValueAnalysisTests,
ReturnStmtReturningDerefOfVariableNoCache) {
	// Set-up the module.
	//
	// g
	//
	// def test():
	//    return *g
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(
		DerefOpExpr::create(varG)));
	testFunc->setBody(returnStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	ShPtr<ValueData> data(va->getValueData(returnStmt));
	// Directly read/written variables.
	//  - variables: get*()
	VarSet refDirReadVars;
	refDirReadVars.insert(varG);
	EXPECT_EQ(refDirReadVars, data->getDirReadVars());
	VarSet refDirWrittenVars;
	EXPECT_EQ(refDirWrittenVars, data->getDirWrittenVars());
	VarSet refDirAllVars;
	refDirAllVars.insert(varG);
	EXPECT_EQ(refDirAllVars, data->getDirAccessedVars());
	//  - variables: counts
	EXPECT_EQ(1, data->getNumOfDirReadVars());
	EXPECT_EQ(0, data->getNumOfDirWrittenVars());
	EXPECT_EQ(1, data->getNumOfDirAccessedVars());
	EXPECT_EQ(1, data->getDirNumOfUses(varG));
	EXPECT_TRUE(data->isDirRead(varG));
	EXPECT_FALSE(data->isDirWritten(varG));
	EXPECT_TRUE(data->isDirAccessed(varG));
	ShPtr<Variable> dummyVar(Variable::create("dummy", IntType::create(32)));
	EXPECT_EQ(0, data->getDirNumOfUses(dummyVar));
	EXPECT_FALSE(data->isDirRead(dummyVar));
	EXPECT_FALSE(data->isDirWritten(dummyVar));
	EXPECT_FALSE(data->isDirAccessed(dummyVar));
	//  - variables: iterators
	EXPECT_EQ(refDirReadVars,
		VarSet(data->dir_read_begin(), data->dir_read_end()));
	EXPECT_EQ(refDirWrittenVars,
		VarSet(data->dir_written_begin(), data->dir_written_end()));
	EXPECT_EQ(refDirAllVars,
		VarSet(data->dir_all_begin(), data->dir_all_end()));
	//  - calls
	EXPECT_EQ(CallVector(), data->getCalls());
	EXPECT_FALSE(data->hasCalls());
	EXPECT_EQ(data->call_end(), data->call_begin());
	//  - address operators
	EXPECT_FALSE(data->hasAddressOps());
	EXPECT_FALSE(data->hasAddressTaken(varG));
	EXPECT_FALSE(data->hasAddressTaken(dummyVar));
	//  - dereferences
	EXPECT_TRUE(data->hasDerefs());
	//  - array accesses
	EXPECT_FALSE(data->hasArrayAccesses());
}

TEST_F(ValueAnalysisTests,
FunctionCallNoCache) {
	// Set-up the module.
	//
	// def test():
	//    test()
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<CallExpr> callExpr(CallExpr::create(testFunc->getAsVar()));
	ShPtr<CallStmt> callStmt(CallStmt::create(callExpr));
	testFunc->setBody(callStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	ShPtr<ValueData> data(va->getValueData(callStmt));
	// Directly read/written variables.
	//  - variables: get*()
	VarSet refDirReadVars;
	refDirReadVars.insert(testFunc->getAsVar());
	EXPECT_EQ(refDirReadVars, data->getDirReadVars());
	VarSet refDirWrittenVars;
	EXPECT_EQ(refDirWrittenVars, data->getDirWrittenVars());
	VarSet refDirAllVars;
	refDirAllVars.insert(testFunc->getAsVar());
	EXPECT_EQ(refDirAllVars, data->getDirAccessedVars());
	//  - variables: counts
	EXPECT_EQ(1, data->getNumOfDirReadVars());
	EXPECT_EQ(0, data->getNumOfDirWrittenVars());
	EXPECT_EQ(1, data->getNumOfDirAccessedVars());
	EXPECT_TRUE(data->isDirRead(testFunc->getAsVar()));
	EXPECT_FALSE(data->isDirWritten(testFunc->getAsVar()));
	EXPECT_TRUE(data->isDirAccessed(testFunc->getAsVar()));
	ShPtr<Variable> dummyVar(Variable::create("dummy", IntType::create(32)));
	EXPECT_EQ(0, data->getDirNumOfUses(dummyVar));
	EXPECT_FALSE(data->isDirRead(dummyVar));
	EXPECT_FALSE(data->isDirWritten(dummyVar));
	EXPECT_FALSE(data->isDirAccessed(dummyVar));
	//  - variables: iterators
	EXPECT_EQ(refDirReadVars,
		VarSet(data->dir_read_begin(), data->dir_read_end()));
	EXPECT_EQ(refDirWrittenVars,
		VarSet(data->dir_written_begin(), data->dir_written_end()));
	EXPECT_EQ(refDirAllVars,
		VarSet(data->dir_all_begin(), data->dir_all_end()));
	//  - calls
	CallVector refCallList;
	refCallList.push_back(callExpr);
	EXPECT_EQ(refCallList, data->getCalls());
	EXPECT_TRUE(data->hasCalls());
	EXPECT_EQ(refCallList, CallVector(data->call_begin(), data->call_end()));
	//  - address operators
	EXPECT_FALSE(data->hasAddressOps());
	EXPECT_FALSE(data->hasAddressTaken(dummyVar));
	//  - dereferences
	EXPECT_FALSE(data->hasDerefs());
	//  - array accesses
	EXPECT_FALSE(data->hasArrayAccesses());
}

TEST_F(ValueAnalysisTests,
ArrayAccessNoCache) {
	// Set-up the module.
	//
	// a
	//
	// def test():
	//    a[0] = 1;
	//
	ShPtr<Variable> varA(Variable::create("a", ArrayType::create(
		IntType::create(16), ArrayType::Dimensions())));
	module->addGlobalVar(varA);
	ShPtr<AssignStmt> assignA01(AssignStmt::create(
		ArrayIndexOpExpr::create(varA, ConstInt::create(0, 16)),
		ConstInt::create(1, 16)));
	testFunc->setBody(assignA01);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	ShPtr<ValueData> data(va->getValueData(assignA01));
	// Directly read/written variables.
	//  - variables: get*()
	VarSet refDirReadVars;
	refDirReadVars.insert(varA);
	EXPECT_EQ(refDirReadVars, data->getDirReadVars());
	VarSet refDirWrittenVars;
	EXPECT_EQ(refDirWrittenVars, data->getDirWrittenVars());
	VarSet refDirAllVars;
	refDirAllVars.insert(varA);
	EXPECT_EQ(refDirAllVars, data->getDirAccessedVars());
	//  - variables: counts
	EXPECT_EQ(1, data->getNumOfDirReadVars());
	EXPECT_EQ(0, data->getNumOfDirWrittenVars());
	EXPECT_EQ(1, data->getNumOfDirAccessedVars());
	EXPECT_EQ(1, data->getDirNumOfUses(varA));
	EXPECT_TRUE(data->isDirRead(varA));
	EXPECT_FALSE(data->isDirWritten(varA));
	EXPECT_TRUE(data->isDirAccessed(varA));
	ShPtr<Variable> dummyVar(Variable::create("dummy", IntType::create(32)));
	EXPECT_EQ(0, data->getDirNumOfUses(dummyVar));
	EXPECT_FALSE(data->isDirRead(dummyVar));
	EXPECT_FALSE(data->isDirWritten(dummyVar));
	EXPECT_FALSE(data->isDirAccessed(dummyVar));
	//  - variables: iterators
	EXPECT_EQ(refDirReadVars,
		VarSet(data->dir_read_begin(), data->dir_read_end()));
	EXPECT_EQ(refDirWrittenVars,
		VarSet(data->dir_written_begin(), data->dir_written_end()));
	EXPECT_EQ(refDirAllVars,
		VarSet(data->dir_all_begin(), data->dir_all_end()));
	//  - calls
	EXPECT_EQ(CallVector(), data->getCalls());
	EXPECT_FALSE(data->hasCalls());
	EXPECT_EQ(data->call_end(), data->call_begin());
	//  - address operators
	EXPECT_FALSE(data->hasAddressOps());
	EXPECT_FALSE(data->hasAddressTaken(dummyVar));
	//  - dereferences
	EXPECT_FALSE(data->hasDerefs());
	//  - array accesses
	EXPECT_TRUE(data->hasArrayAccesses());
}

TEST_F(ValueAnalysisTests,
StructAccessNoCache) {
	// Set-up the module.
	//
	// a
	//
	// def test():
	//    a[0] = 1;
	//
	ShPtr<Variable> varA(Variable::create("a", StructType::create(
		StructType::ElementTypes())));
	module->addGlobalVar(varA);
	ShPtr<AssignStmt> assignA01(AssignStmt::create(
		StructIndexOpExpr::create(varA, ConstInt::create(0, 16)),
		ConstInt::create(1, 16)));
	testFunc->setBody(assignA01);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	ShPtr<ValueData> data(va->getValueData(assignA01));
	// Directly read/written variables.
	//  - variables: get*()
	VarSet refDirReadVars;
	refDirReadVars.insert(varA);
	EXPECT_EQ(refDirReadVars, data->getDirReadVars());
	VarSet refDirWrittenVars;
	EXPECT_EQ(refDirWrittenVars, data->getDirWrittenVars());
	VarSet refDirAllVars;
	refDirAllVars.insert(varA);
	EXPECT_EQ(refDirAllVars, data->getDirAccessedVars());
	//  - variables: counts
	EXPECT_EQ(1, data->getNumOfDirReadVars());
	EXPECT_EQ(0, data->getNumOfDirWrittenVars());
	EXPECT_EQ(1, data->getNumOfDirAccessedVars());
	EXPECT_EQ(1, data->getDirNumOfUses(varA));
	EXPECT_TRUE(data->isDirRead(varA));
	EXPECT_FALSE(data->isDirWritten(varA));
	EXPECT_TRUE(data->isDirAccessed(varA));
	ShPtr<Variable> dummyVar(Variable::create("dummy", IntType::create(32)));
	EXPECT_EQ(0, data->getDirNumOfUses(dummyVar));
	EXPECT_FALSE(data->isDirRead(dummyVar));
	EXPECT_FALSE(data->isDirWritten(dummyVar));
	EXPECT_FALSE(data->isDirAccessed(dummyVar));
	//  - variables: iterators
	EXPECT_EQ(refDirReadVars,
		VarSet(data->dir_read_begin(), data->dir_read_end()));
	EXPECT_EQ(refDirWrittenVars,
		VarSet(data->dir_written_begin(), data->dir_written_end()));
	EXPECT_EQ(refDirAllVars,
		VarSet(data->dir_all_begin(), data->dir_all_end()));
	//  - calls
	EXPECT_EQ(CallVector(), data->getCalls());
	EXPECT_FALSE(data->hasCalls());
	EXPECT_EQ(data->call_end(), data->call_begin());
	//  - address operators
	EXPECT_FALSE(data->hasAddressOps());
	EXPECT_FALSE(data->hasAddressTaken(dummyVar));
	//  - dereferences
	EXPECT_FALSE(data->hasDerefs());
	//  - array accesses
	EXPECT_FALSE(data->hasArrayAccesses());
	//  - struct accesses
	EXPECT_TRUE(data->hasStructAccesses());
}

TEST_F(ValueAnalysisTests,
Caching) {
	// Set-up the module.
	//
	// def test():
	//    a = 1
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<VarDefStmt> varDefStmt(VarDefStmt::create(
		varA, ConstInt::create(1, 32)));
	testFunc->setBody(varDefStmt);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(true);

	ShPtr<ValueData> data(va->getValueData(varDefStmt));
	// Directly read/written variables.
	//  - variables: get*()
	VarSet refDirReadVars;
	EXPECT_EQ(refDirReadVars, data->getDirReadVars());
	VarSet refDirWrittenVars;
	refDirWrittenVars.insert(varA);
	EXPECT_EQ(refDirWrittenVars, data->getDirWrittenVars());
	VarSet refDirAllVars;
	refDirAllVars.insert(varA);
	EXPECT_EQ(refDirAllVars, data->getDirAccessedVars());

	// Change the module.
	//
	// def test():
	//    b = 1
	//
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	varDefStmt->setVar(varB);

	ShPtr<ValueData> dataAfterChange(va->getValueData(varDefStmt));
	VarSet refDirWrittenVarsAfterChange;
	refDirWrittenVarsAfterChange.insert(varA);
	EXPECT_EQ(refDirWrittenVarsAfterChange, dataAfterChange->getDirWrittenVars()) <<
		"before clearing the cache, there should still be `a`";

	va->clearCache();

	ShPtr<ValueData> dataAfterCacheClear(va->getValueData(varDefStmt));
	VarSet refDirWrittenVarsAfterCacheClear;
	refDirWrittenVarsAfterCacheClear.insert(varB);
	EXPECT_EQ(refDirWrittenVarsAfterCacheClear,
		dataAfterCacheClear->getDirWrittenVars()) <<
		"after clearing the cache, there should be `b`";
}

TEST_F(ValueAnalysisTests,
AfterStatementChangeAndCacheUpdateCorrectResultsAreReturned) {
	// Set-up the module.
	//
	// a
	// b
	//
	// void test() {
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	module->addGlobalVar(varB);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	testFunc->setBody(returnA);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(true);

	VarSet readVarsInReturnA(va->getValueData(returnA)->getDirReadVars());
	EXPECT_EQ(1, readVarsInReturnA.size());
	EXPECT_EQ(varA, *readVarsInReturnA.begin());

	// Now, change `return a` to `return b`, remove the original statement from
	// va's cache, and check that `b` is the only read variable in the new
	// version of `returnA`.
	returnA->replace(varA, varB);
	va->removeFromCache(returnA);
	VarSet newReadVarsInReturnA(va->getValueData(returnA)->getDirReadVars());
	EXPECT_EQ(1, newReadVarsInReturnA.size());
	EXPECT_EQ(varB, *newReadVarsInReturnA.begin());
}

TEST_F(ValueAnalysisTests,
MayBeReadNoCaching) {
	// Set-up the module.
	//
	// a
	//
	// void test() {
	//     int *p = &a;
	//     return *p;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<ReturnStmt> returnP(ReturnStmt::create(DerefOpExpr::create(varP)));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(
		varP, AddressOpExpr::create(varA), returnP));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	// Set-up default actions.
	VarSet refPMayPointTo;
	refPMayPointTo.insert(varA);
	ON_CALL(*aliasAnalysisMock, mayPointTo(varP))
		.WillByDefault(ReturnRef(refPMayPointTo));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));

	ShPtr<ValueData> data(va->getValueData(returnP));
	// Indirectly read variables.
	VarSet refMayBeReadVars;
	refMayBeReadVars.insert(varA);
	EXPECT_EQ(refMayBeReadVars, data->getMayBeReadVars());
	EXPECT_EQ(refMayBeReadVars,
		VarSet(data->may_be_read_begin(), data->may_be_read_end()));
	EXPECT_TRUE(data->mayBeIndirRead(varA));
	// Indirectly written variables.
	VarSet refMayBeWrittenVars;
	EXPECT_EQ(refMayBeWrittenVars, data->getMayBeWrittenVars());
	EXPECT_EQ(refMayBeWrittenVars,
		VarSet(data->may_be_written_begin(), data->may_be_written_end()));
	EXPECT_FALSE(data->mayBeIndirWritten(varA));
	// Indirectly accessed variables.
	VarSet refMayBeAccessedVars;
	refMayBeAccessedVars.insert(varA);
	EXPECT_EQ(refMayBeAccessedVars, data->getMayBeAccessedVars());
	EXPECT_EQ(refMayBeAccessedVars,
		VarSet(data->may_be_accessed_begin(), data->may_be_accessed_end()));
	EXPECT_TRUE(data->mayBeIndirAccessed(varA));
}

TEST_F(ValueAnalysisTests,
MayBeWrittenNoCaching) {
	// Set-up the module.
	//
	// a
	//
	// void test() {
	//     int *p = &a;
	//     *p = 1;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<AssignStmt> assignP1(AssignStmt::create(
		DerefOpExpr::create(varP), ConstInt::create(1, 32)));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(
		varP, AddressOpExpr::create(varA), assignP1));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	// Set-up default actions.
	VarSet refPMayPointTo;
	refPMayPointTo.insert(varA);
	ON_CALL(*aliasAnalysisMock, mayPointTo(varP))
		.WillByDefault(ReturnRef(refPMayPointTo));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));

	ShPtr<ValueData> data(va->getValueData(assignP1));
	// Indirectly read variables.
	VarSet refMayBeReadVars;
	EXPECT_EQ(refMayBeReadVars, data->getMayBeReadVars());
	EXPECT_EQ(refMayBeReadVars,
		VarSet(data->may_be_read_begin(), data->may_be_read_end()));
	EXPECT_FALSE(data->mayBeIndirRead(varA));
	// Indirectly written variables.
	VarSet refMayBeWrittenVars;
	refMayBeWrittenVars.insert(varA);
	EXPECT_EQ(refMayBeWrittenVars, data->getMayBeWrittenVars());
	EXPECT_EQ(refMayBeWrittenVars,
		VarSet(data->may_be_written_begin(), data->may_be_written_end()));
	EXPECT_TRUE(data->mayBeIndirWritten(varA));
	// Indirectly accessed variables.
	VarSet refMayBeAccessedVars;
	refMayBeAccessedVars.insert(varA);
	EXPECT_EQ(refMayBeAccessedVars, data->getMayBeAccessedVars());
	EXPECT_EQ(refMayBeAccessedVars,
		VarSet(data->may_be_accessed_begin(), data->may_be_accessed_end()));
	EXPECT_TRUE(data->mayBeIndirAccessed(varA));
}

TEST_F(ValueAnalysisTests,
MustBeReadNoCaching) {
	// Set-up the module.
	//
	// a
	//
	// void test() {
	//     int *p = &a;
	//     return *p;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<ReturnStmt> returnP(ReturnStmt::create(DerefOpExpr::create(varP)));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(
		varP, AddressOpExpr::create(varA), returnP));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	// Set-up default actions.
	ON_CALL(*aliasAnalysisMock, pointsTo(varP))
		.WillByDefault(Return(varA));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));

	ShPtr<ValueData> data(va->getValueData(returnP));
	// Indirectly read variables.
	VarSet refMustBeReadVars;
	refMustBeReadVars.insert(varA);
	EXPECT_EQ(refMustBeReadVars, data->getMustBeReadVars());
	EXPECT_EQ(refMustBeReadVars,
		VarSet(data->must_be_read_begin(), data->must_be_read_end()));
	// Indirectly written variables.
	VarSet refMustBeWrittenVars;
	EXPECT_EQ(refMustBeWrittenVars, data->getMustBeWrittenVars());
	EXPECT_EQ(refMustBeWrittenVars,
		VarSet(data->must_be_written_begin(), data->must_be_written_end()));
	// Indirectly accessed variables.
	VarSet refMustBeAccessedVars;
	refMustBeAccessedVars.insert(varA);
	EXPECT_EQ(refMustBeAccessedVars, data->getMustBeAccessedVars());
	EXPECT_EQ(refMustBeAccessedVars,
		VarSet(data->must_be_accessed_begin(), data->must_be_accessed_end()));
}

TEST_F(ValueAnalysisTests,
MustBeWrittenNoCaching) {
	// Set-up the module.
	//
	// a
	//
	// void test() {
	//     int *p = &a;
	//     *p = 1;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<AssignStmt> assignP1(AssignStmt::create(
		DerefOpExpr::create(varP), ConstInt::create(1, 32)));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(
		varP, AddressOpExpr::create(varA), assignP1));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	// Set-up default actions.
	ON_CALL(*aliasAnalysisMock, pointsTo(varP))
		.WillByDefault(Return(varA));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));

	ShPtr<ValueData> data(va->getValueData(assignP1));
	// Indirectly read variables.
	VarSet refMustBeReadVars;
	EXPECT_EQ(refMustBeReadVars, data->getMustBeReadVars());
	EXPECT_EQ(refMustBeReadVars,
		VarSet(data->must_be_read_begin(), data->must_be_read_end()));
	// Indirectly written variables.
	VarSet refMustBeWrittenVars;
	refMustBeWrittenVars.insert(varA);
	EXPECT_EQ(refMustBeWrittenVars, data->getMustBeWrittenVars());
	EXPECT_EQ(refMustBeWrittenVars,
		VarSet(data->must_be_written_begin(), data->must_be_written_end()));
	// Indirectly accessed variables.
	VarSet refMustBeAccessedVars;
	refMustBeAccessedVars.insert(varA);
	EXPECT_EQ(refMustBeAccessedVars, data->getMustBeAccessedVars());
	EXPECT_EQ(refMustBeAccessedVars,
		VarSet(data->must_be_accessed_begin(), data->must_be_accessed_end()));
}

TEST_F(ValueAnalysisTests,
MustBeReadNestedDereferencesNoCaching) {
	// Set-up the module.
	//
	// a
	//
	// void test() {
	//     int *p = &a;
	//     int *pp = &p;
	//     return **pp;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<Variable> varPP(Variable::create("pp",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varPP);
	ShPtr<ReturnStmt> returnPP(ReturnStmt::create(
		DerefOpExpr::create(DerefOpExpr::create(varPP))));
	ShPtr<VarDefStmt> varDefPP(VarDefStmt::create(
		varPP, AddressOpExpr::create(varP), returnPP));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(
		varP, AddressOpExpr::create(varA), varDefPP));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	// Set-up default actions.
	ON_CALL(*aliasAnalysisMock, pointsTo(varP))
		.WillByDefault(Return(varA));
	ON_CALL(*aliasAnalysisMock, pointsTo(varPP))
		.WillByDefault(Return(varP));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varP))
		.WillByDefault(Return(true));

	ShPtr<ValueData> data(va->getValueData(returnPP));
	// Indirectly read variables.
	VarSet refMustBeReadVars;
	refMustBeReadVars.insert(varA);
	refMustBeReadVars.insert(varP);
	EXPECT_EQ(refMustBeReadVars, data->getMustBeReadVars());
	EXPECT_EQ(refMustBeReadVars,
		VarSet(data->must_be_read_begin(), data->must_be_read_end()));
	// Indirectly written variables.
	VarSet refMustBeWrittenVars;
	EXPECT_EQ(refMustBeWrittenVars, data->getMustBeWrittenVars());
	EXPECT_EQ(refMustBeWrittenVars,
		VarSet(data->must_be_written_begin(), data->must_be_written_end()));
	// Indirectly accessed variables.
	VarSet refMustBeAccessedVars;
	refMustBeAccessedVars.insert(varA);
	refMustBeAccessedVars.insert(varP);
	EXPECT_EQ(refMustBeAccessedVars, data->getMustBeAccessedVars());
	EXPECT_EQ(refMustBeAccessedVars,
		VarSet(data->must_be_accessed_begin(), data->must_be_accessed_end()));
}

TEST_F(ValueAnalysisTests,
MayBeReadNestedDereferencesNoCaching) {
	// Set-up the module.
	//
	// a
	//
	// void test() {
	//     int *p = &a;
	//     int *pp = &p;
	//     return **pp;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<Variable> varPP(Variable::create("pp",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varPP);
	ShPtr<ReturnStmt> returnPP(ReturnStmt::create(
		DerefOpExpr::create(DerefOpExpr::create(varPP))));
	ShPtr<VarDefStmt> varDefPP(VarDefStmt::create(
		varPP, AddressOpExpr::create(varP), returnPP));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(
		varP, AddressOpExpr::create(varA), varDefPP));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	// Set-up default actions.
	VarSet refPMayPointTo;
	refPMayPointTo.insert(varA);
	ON_CALL(*aliasAnalysisMock, mayPointTo(varP))
		.WillByDefault(ReturnRef(refPMayPointTo));
	VarSet refPPMayPointTo;
	refPPMayPointTo.insert(varP);
	ON_CALL(*aliasAnalysisMock, mayPointTo(varPP))
		.WillByDefault(ReturnRef(refPPMayPointTo));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varP))
		.WillByDefault(Return(true));

	ShPtr<ValueData> data(va->getValueData(returnPP));
	// Indirectly read variables.
	VarSet refMayBeReadVars;
	refMayBeReadVars.insert(varA);
	refMayBeReadVars.insert(varP);
	EXPECT_EQ(refMayBeReadVars, data->getMayBeReadVars());
	EXPECT_EQ(refMayBeReadVars,
		VarSet(data->may_be_read_begin(), data->may_be_read_end()));
	EXPECT_TRUE(data->mayBeIndirRead(varA));
	EXPECT_TRUE(data->mayBeIndirRead(varP));
	// Indirectly written variables.
	VarSet refMayBeWrittenVars;
	EXPECT_EQ(refMayBeWrittenVars, data->getMayBeWrittenVars());
	EXPECT_EQ(refMayBeWrittenVars,
		VarSet(data->may_be_written_begin(), data->may_be_written_end()));
	EXPECT_FALSE(data->mayBeIndirWritten(varA));
	EXPECT_FALSE(data->mayBeIndirWritten(varP));
	// Indirectly accessed variables.
	VarSet refMayBeAccessedVars;
	refMayBeAccessedVars.insert(varA);
	refMayBeAccessedVars.insert(varP);
	EXPECT_EQ(refMayBeAccessedVars, data->getMayBeAccessedVars());
	EXPECT_EQ(refMayBeAccessedVars,
		VarSet(data->may_be_accessed_begin(), data->may_be_accessed_end()));
	EXPECT_TRUE(data->mayBeIndirAccessed(varA));
	EXPECT_TRUE(data->mayBeIndirAccessed(varP));
}

TEST_F(ValueAnalysisTests,
MustBeWrittenNestedDereferencesNoCaching) {
	// Set-up the module.
	//
	// a
	//
	// void test() {
	//     int *p = &a;
	//     int *pp = &p;
	//     **pp = 1;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<Variable> varPP(Variable::create("pp",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varPP);
	ShPtr<AssignStmt> assignPP1(AssignStmt::create(
		DerefOpExpr::create(DerefOpExpr::create(varPP)), ConstInt::create(1, 32)));
	ShPtr<VarDefStmt> varDefPP(VarDefStmt::create(
		varPP, AddressOpExpr::create(varP), assignPP1));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(
		varP, AddressOpExpr::create(varA), varDefPP));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	// Set-up default actions.
	ON_CALL(*aliasAnalysisMock, pointsTo(varP))
		.WillByDefault(Return(varA));
	ON_CALL(*aliasAnalysisMock, pointsTo(varPP))
		.WillByDefault(Return(varP));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varP))
		.WillByDefault(Return(true));

	ShPtr<ValueData> data(va->getValueData(assignPP1));
	// Indirectly read variables.
	VarSet refMustBeReadVars;
	refMustBeReadVars.insert(varP);
	EXPECT_EQ(refMustBeReadVars, data->getMustBeReadVars());
	EXPECT_EQ(refMustBeReadVars,
		VarSet(data->must_be_read_begin(), data->must_be_read_end()));
	// Indirectly written variables.
	VarSet refMustBeWrittenVars;
	refMustBeWrittenVars.insert(varA);
	EXPECT_EQ(refMustBeWrittenVars, data->getMustBeWrittenVars());
	EXPECT_EQ(refMustBeWrittenVars,
		VarSet(data->must_be_written_begin(), data->must_be_written_end()));
	// Indirectly accessed variables.
	VarSet refMustBeAccessedVars;
	refMustBeAccessedVars.insert(varA);
	refMustBeAccessedVars.insert(varP);
	EXPECT_EQ(refMustBeAccessedVars, data->getMustBeAccessedVars());
	EXPECT_EQ(refMustBeAccessedVars,
		VarSet(data->must_be_accessed_begin(), data->must_be_accessed_end()));
}

TEST_F(ValueAnalysisTests,
MayBeWrittenNestedDereferencesNoCaching) {
	// Set-up the module.
	//
	// a
	//
	// void test() {
	//     int *p = &a;
	//     int *pp = &p;
	//     **pp = 1;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<Variable> varPP(Variable::create("pp",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varPP);
	ShPtr<AssignStmt> assignPP1(AssignStmt::create(
		DerefOpExpr::create(DerefOpExpr::create(varPP)), ConstInt::create(1, 32)));
	ShPtr<VarDefStmt> varDefPP(VarDefStmt::create(
		varPP, AddressOpExpr::create(varP), assignPP1));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(
		varP, AddressOpExpr::create(varA), varDefPP));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	// Set-up default actions.
	VarSet refPMayPointTo;
	refPMayPointTo.insert(varA);
	ON_CALL(*aliasAnalysisMock, mayPointTo(varP))
		.WillByDefault(ReturnRef(refPMayPointTo));
	VarSet refPPMayPointTo;
	refPPMayPointTo.insert(varP);
	ON_CALL(*aliasAnalysisMock, mayPointTo(varPP))
		.WillByDefault(ReturnRef(refPPMayPointTo));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));
	ON_CALL(*aliasAnalysisMock, mayBePointed(varP))
		.WillByDefault(Return(true));

	ShPtr<ValueData> data(va->getValueData(assignPP1));
	// Indirectly read variables.
	VarSet refMayBeReadVars;
	refMayBeReadVars.insert(varP);
	EXPECT_EQ(refMayBeReadVars, data->getMayBeReadVars());
	EXPECT_EQ(refMayBeReadVars,
		VarSet(data->may_be_read_begin(), data->may_be_read_end()));
	EXPECT_FALSE(data->mayBeIndirRead(varA));
	EXPECT_TRUE(data->mayBeIndirRead(varP));
	// Indirectly written variables.
	VarSet refMayBeWrittenVars;
	refMayBeWrittenVars.insert(varA);
	EXPECT_EQ(refMayBeWrittenVars, data->getMayBeWrittenVars());
	EXPECT_EQ(refMayBeWrittenVars,
		VarSet(data->may_be_written_begin(), data->may_be_written_end()));
	EXPECT_TRUE(data->mayBeIndirWritten(varA));
	EXPECT_FALSE(data->mayBeIndirWritten(varP));
	// Indirectly accessed variables.
	VarSet refMayBeAccessedVars;
	refMayBeAccessedVars.insert(varA);
	refMayBeAccessedVars.insert(varP);
	EXPECT_EQ(refMayBeAccessedVars, data->getMayBeAccessedVars());
	EXPECT_EQ(refMayBeAccessedVars,
		VarSet(data->may_be_accessed_begin(), data->may_be_accessed_end()));
	EXPECT_TRUE(data->mayBeIndirAccessed(varA));
	EXPECT_TRUE(data->mayBeIndirAccessed(varP));
}

TEST_F(ValueAnalysisTests,
DelegationOfMethodsToAliasAnalysis) {
	// Set-up the module.
	//
	// a
	//
	// void test() {
	//     int *p = &a;
	//     return *p;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varP(Variable::create("p",
		PointerType::create(IntType::create(32))));
	testFunc->addLocalVar(varP);
	ShPtr<ReturnStmt> returnP(ReturnStmt::create(DerefOpExpr::create(varP)));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(
		varP, AddressOpExpr::create(varA), returnP));
	testFunc->setBody(varDefP);

	INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(false);

	// mayBePointed
	ON_CALL(*aliasAnalysisMock, mayBePointed(varA))
		.WillByDefault(Return(true));
	EXPECT_EQ(aliasAnalysis->mayBePointed(varA), va->mayBePointed(varA));
	EXPECT_EQ(aliasAnalysis->mayBePointed(varP), va->mayBePointed(varP));

	// mayPointTo
	const VarSet refPMayPointTo{varA};
	ON_CALL(*aliasAnalysisMock, mayPointTo(varA))
		.WillByDefault(ReturnRef(refPMayPointTo));
	EXPECT_EQ(aliasAnalysis->mayPointTo(varA), va->mayPointTo(varA));
	EXPECT_EQ(aliasAnalysis->mayPointTo(varP), va->mayPointTo(varP));

	// pointsTo
	ON_CALL(*aliasAnalysisMock, pointsTo(varP))
		.WillByDefault(Return(varA));
	EXPECT_EQ(aliasAnalysis->pointsTo(varA), va->pointsTo(varA));
	EXPECT_EQ(aliasAnalysis->pointsTo(varP), va->pointsTo(varP));

	// initAliasAnalysis
	EXPECT_CALL(*aliasAnalysisMock, init(module))
		.Times(1);
	va->initAliasAnalysis(module);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
