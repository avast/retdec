/**
* @file tests/llvmir2hll/ir/const_symbol_tests.cpp
* @brief Tests for the @c const_symbol module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c const_symbol module.
*/
class ConstSymbolTests: public Test {};

//
// create(), getName(), and getValue()
//

TEST_F(ConstSymbolTests,
CreateGetNameGetValueWorksCorrectly) {
	// 1
	std::string sym1Name("LOCK_SH");
	ShPtr<ConstInt> sym1Value(ConstInt::create(1, 32));
	ShPtr<ConstSymbol> sym1(ConstSymbol::create(sym1Name, sym1Value));

	EXPECT_EQ(sym1Name, sym1->getName());
	EXPECT_EQ(sym1Value, sym1->getValue());

	// 2
	std::string sym2Name("LOCK_EX");
	ShPtr<ConstInt> sym2Value(ConstInt::create(2, 32));
	ShPtr<ConstSymbol> sym2(ConstSymbol::create(sym2Name, sym2Value));

	EXPECT_EQ(sym2Name, sym2->getName());
	EXPECT_EQ(sym2Value, sym2->getValue());

	// 3
	std::string sym3Name("LOCK_NB");
	ShPtr<ConstInt> sym3Value(ConstInt::create(4, 32));
	ShPtr<ConstSymbol> sym3(ConstSymbol::create(sym3Name, sym3Value));

	EXPECT_EQ(sym3Name, sym3->getName());
	EXPECT_EQ(sym3Value, sym3->getValue());
}

#if DEATH_TESTS_ENABLED
TEST_F(ConstSymbolTests,
CreateGetNameGetValueCreatePreconditionViolated) {
	ASSERT_DEATH(ConstSymbol::create("LOCK_SH", ShPtr<Constant>()),
		".*create.*Precondition.*failed.*");
}
#endif

//
// clone()
//

TEST_F(ConstSymbolTests,
CloneWorksCorrectly) {
	std::string refSymName("LOCK_SH");
	ShPtr<ConstInt> refSymValue(ConstInt::create(1, 32));
	ShPtr<ConstSymbol> refSym(ConstSymbol::create(refSymName, refSymValue));
	ShPtr<ConstSymbol> cloneSym(cast<ConstSymbol>(refSym->clone()));

	ASSERT_TRUE(cloneSym);
	EXPECT_NE(refSym, cloneSym);
	EXPECT_EQ(refSymName, cloneSym->getName());
	EXPECT_EQ(refSymValue, cloneSym->getValue());
}

//
// isEqualTo()
//

TEST_F(ConstSymbolTests,
IsEqualToWorksCorrectly) {
	std::string refSymName("LOCK_SH");
	ShPtr<ConstInt> refSymValue(ConstInt::create(1, 32));
	ShPtr<ConstSymbol> refSym(ConstSymbol::create(refSymName, refSymValue));
	ShPtr<ConstSymbol> sym(ConstSymbol::create(refSymName, refSymValue));

	EXPECT_TRUE(refSym->isEqualTo(sym));
	EXPECT_TRUE(sym->isEqualTo(refSym));
}

//
// getType()
//

TEST_F(ConstSymbolTests,
GetTypeWorksCorrectly) {
	std::string symName("LOCK_SH");
	ShPtr<ConstInt> symValue(ConstInt::create(1, 32));
	ShPtr<ConstSymbol> sym(ConstSymbol::create(symName, symValue));

	EXPECT_EQ(symValue->getType(), sym->getType());
}

//
// replace()
//

TEST_F(ConstSymbolTests,
ReplaceWorksCorrectly) {
	std::string symName("LOCK_SH");
	ShPtr<ConstInt> symValue(ConstInt::create(1, 32));
	ShPtr<ConstSymbol> sym(ConstSymbol::create(symName, symValue));
	ShPtr<ConstInt> newValue(ConstInt::create(2, 32));
	sym->replace(symValue, newValue);

	EXPECT_EQ(newValue, sym->getValue());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
