/**
* @file tests/llvmir2hll/support/global_vars_sorter_tests.cpp
* @brief Tests for the @c global_vars_sorter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <set>

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/global_vars_sorter.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c global_vars_sorter module.
*/
class GlobalVarsSorterTests: public TestsWithModule {};

TEST_F(GlobalVarsSorterTests,
NoGlobalVarsReturnsEmptyVector) {
	GlobalVarDefVector globalVars;
	GlobalVarDefVector refSortedGlobalVars(globalVars);

	EXPECT_EQ(refSortedGlobalVars,
		GlobalVarsSorter::sortByInterdependencies(globalVars));
}

TEST_F(GlobalVarsSorterTests,
SingleGlobalVarReturnsSingletonVector) {
	GlobalVarDefVector globalVars;

	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Expression> varAInit;
	globalVars.push_back(GlobalVarDef::create(varA, varAInit));

	GlobalVarDefVector refSortedGlobalVars(globalVars);

	EXPECT_EQ(refSortedGlobalVars,
		GlobalVarsSorter::sortByInterdependencies(globalVars));
}

TEST_F(GlobalVarsSorterTests,
WhenThereAreNoInterdependenciesTheVariablesAreSortedByOriginalName) {
	//
	// int a;
	// int b;
	// int c;
	//

	GlobalVarDefVector globalVars;

	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	// Change the name so that we can test that the variables are sorted by
	// their original name.
	varA->setName("z");
	ShPtr<Expression> varAInit;
	ShPtr<GlobalVarDef> varADef(GlobalVarDef::create(varA, varAInit));
	globalVars.push_back(varADef);

	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	// Change the name so that we can test that the variables are sorted by
	// their original name.
	varB->setName("y");
	ShPtr<Expression> varBInit;
	ShPtr<GlobalVarDef> varBDef(GlobalVarDef::create(varB, varBInit));
	globalVars.push_back(varBDef);

	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	// Change the name so that we can test that the variables are sorted by
	// their original name.
	varC->setName("x");
	ShPtr<Expression> varCInit;
	ShPtr<GlobalVarDef> varCDef(GlobalVarDef::create(varC, varCInit));
	globalVars.push_back(varCDef);

	GlobalVarDefVector refSortedGlobalVars;
	refSortedGlobalVars.push_back(varADef);
	refSortedGlobalVars.push_back(varBDef);
	refSortedGlobalVars.push_back(varCDef);

	EXPECT_EQ(refSortedGlobalVars,
		GlobalVarsSorter::sortByInterdependencies(globalVars));
}

TEST_F(GlobalVarsSorterTests,
TwoGlobalVarsWithInterdependenciesTharAreAlreadyOrderedUntouched) {
	//
	// int a;
	// int b = a;
	//

	GlobalVarDefVector globalVars;

	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Expression> varAInit;
	ShPtr<GlobalVarDef> varADef(GlobalVarDef::create(varA, varAInit));
	globalVars.push_back(varADef);

	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Expression> varBInit(varA);
	ShPtr<GlobalVarDef> varBDef(GlobalVarDef::create(varB, varBInit));
	globalVars.push_back(varBDef);

	GlobalVarDefVector refSortedGlobalVars(globalVars);

	EXPECT_EQ(refSortedGlobalVars,
		GlobalVarsSorter::sortByInterdependencies(globalVars));
}

TEST_F(GlobalVarsSorterTests,
TwoGlobalVarsWithInterdependenciesInReverseOrderGetsCorrectlyOrdered) {
	//
	// int b = a;
	// int a;
	//

	GlobalVarDefVector globalVars;

	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Expression> varBInit(varA);
	ShPtr<GlobalVarDef> varBDef(GlobalVarDef::create(varB, varBInit));
	globalVars.push_back(varBDef);

	ShPtr<Expression> varAInit;
	ShPtr<GlobalVarDef> varADef(GlobalVarDef::create(varA, varAInit));
	globalVars.push_back(varADef);

	GlobalVarDefVector refSortedGlobalVars;
	refSortedGlobalVars.push_back(varADef);
	refSortedGlobalVars.push_back(varBDef);

	EXPECT_EQ(refSortedGlobalVars,
		GlobalVarsSorter::sortByInterdependencies(globalVars));
}

TEST_F(GlobalVarsSorterTests,
ThreeGlobalVarsWithInterdependenciesGetsCorrectlyOrdered) {
	//
	// int b = a;
	// int a;
	// int c = b;
	//

	GlobalVarDefVector globalVars;

	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	ShPtr<Expression> varBInit(varA);
	ShPtr<GlobalVarDef> varBDef(GlobalVarDef::create(varB, varBInit));
	globalVars.push_back(varBDef);

	ShPtr<Expression> varAInit;
	ShPtr<GlobalVarDef> varADef(GlobalVarDef::create(varA, varAInit));
	globalVars.push_back(varADef);

	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	ShPtr<Expression> varCInit(varB);
	ShPtr<GlobalVarDef> varCDef(GlobalVarDef::create(varC, varCInit));
	globalVars.push_back(varCDef);

	GlobalVarDefVector refSortedGlobalVars;
	refSortedGlobalVars.push_back(varADef);
	refSortedGlobalVars.push_back(varBDef);
	refSortedGlobalVars.push_back(varCDef);

	EXPECT_EQ(refSortedGlobalVars,
		GlobalVarsSorter::sortByInterdependencies(globalVars));
}

TEST_F(GlobalVarsSorterTests,
SortingWorksCorrectlyEvenIfVariableIsNested) {
	//
	// int *b = &a;
	// int a;
	//

	GlobalVarDefVector globalVars;

	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<Variable> varB(Variable::create("b", PointerType::create(
		IntType::create(32))));
	ShPtr<Expression> varBInit(AddressOpExpr::create(varA));
	ShPtr<GlobalVarDef> varBDef(GlobalVarDef::create(varB, varBInit));
	globalVars.push_back(varBDef);

	ShPtr<Expression> varAInit;
	ShPtr<GlobalVarDef> varADef(GlobalVarDef::create(varA, varAInit));
	globalVars.push_back(varADef);

	GlobalVarDefVector refSortedGlobalVars;
	refSortedGlobalVars.push_back(varADef);
	refSortedGlobalVars.push_back(varBDef);

	EXPECT_EQ(refSortedGlobalVars,
		GlobalVarsSorter::sortByInterdependencies(globalVars));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
