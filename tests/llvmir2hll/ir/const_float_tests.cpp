/**
* @file tests/llvmir2hll/ir/const_float_tests.cpp
* @brief Tests for the @c const_float module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_float.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c const_float module.
*/
class ConstFloatTests: public Test {};

//
// create()
//

TEST_F(ConstFloatTests,
CreateGetValueTestZeroValue) {
	llvm::APFloat f(0.0);
	EXPECT_TRUE(f.compare(ConstFloat::create(f)->getValue()) == llvm::APFloat::cmpEqual);
}

TEST_F(ConstFloatTests,
CreateGetValueTestPositiveValue) {
	llvm::APFloat f(134.56);
	EXPECT_TRUE(f.compare(ConstFloat::create(f)->getValue()) == llvm::APFloat::cmpEqual);
}

TEST_F(ConstFloatTests,
CreateGetValueTestNegativeValue) {
	llvm::APFloat f(-100e+9);
	EXPECT_TRUE(f.compare(ConstFloat::create(f)->getValue()) == llvm::APFloat::cmpEqual);
}

//
// getSize()
//

TEST_F(ConstFloatTests,
GetSizeReturnsCorrectSizeOfUnderlyingTypeForFloatConstant) {
	auto f = ConstFloat::create(llvm::APFloat(llvm::APFloat::IEEEsingle, "0.0"));
	EXPECT_EQ(32, f->getSize());
}

TEST_F(ConstFloatTests,
GetSizeReturnsCorrectSizeOfUnderlyingTypeForDoubleConstant) {
	auto f = ConstFloat::create(llvm::APFloat(llvm::APFloat::IEEEdouble, "0.0"));
	EXPECT_EQ(64, f->getSize());
}

TEST_F(ConstFloatTests,
GetSizeReturnsCorrectSizeOfUnderlyingTypeForLongDoubleConstant) {
	auto f = ConstFloat::create(llvm::APFloat(llvm::APFloat::x87DoubleExtended, "0.0"));
	EXPECT_EQ(80, f->getSize());
}

//
// toString()
//

TEST_F(ConstFloatTests,
ToStringCorrectConversionToStringNormalValues) {
	EXPECT_EQ("0.0e+0", ConstFloat::create(llvm::APFloat(0.0))->toString());
	EXPECT_EQ("1.125e+0", ConstFloat::create(llvm::APFloat(1.125))->toString());
	EXPECT_EQ("2.5e-1", ConstFloat::create(llvm::APFloat(0.25))->toString());
	EXPECT_EQ("1.5e+0", ConstFloat::create(llvm::APFloat(1.5))->toString());

	EXPECT_EQ("-1.125e+0", ConstFloat::create(llvm::APFloat(-1.125))->toString());
	EXPECT_EQ("-2.5e-1", ConstFloat::create(llvm::APFloat(-0.25))->toString());
	EXPECT_EQ("-1.5e+0", ConstFloat::create(llvm::APFloat(-1.5))->toString());
}

TEST_F(ConstFloatTests,
ToStringCorrectConversionToStringSpecialValues) {
	// All llvm::APFloat::getX() functions require an instance of fltSemantics,
	// so get a reference one.
	llvm::APFloat refF(0.0);
	const llvm::fltSemantics &refSemantics(refF.getSemantics());

	EXPECT_EQ("+inf", ConstFloat::create(llvm::APFloat::getInf(refSemantics))->toString());
	EXPECT_EQ("-inf", ConstFloat::create(llvm::APFloat::getInf(refSemantics, true))->toString());
	EXPECT_EQ("nan", ConstFloat::create(llvm::APFloat::getNaN(refSemantics))->toString());
}

//
// toMostReadableString()
//

TEST_F(ConstFloatTests,
ToMostReadableStringCorrectMostReadableRepresentationForIntegralNumbers) {
	EXPECT_EQ("0.0", ConstFloat::create(llvm::APFloat(0.0))->toMostReadableString());
	EXPECT_EQ("5.0", ConstFloat::create(llvm::APFloat(5.0))->toMostReadableString());
	EXPECT_EQ("125.0", ConstFloat::create(llvm::APFloat(125.0))->toMostReadableString());

	EXPECT_EQ("0.0", ConstFloat::create(llvm::APFloat(-0.0))->toMostReadableString());

	EXPECT_EQ("-5.0", ConstFloat::create(llvm::APFloat(-5.0))->toMostReadableString());
	EXPECT_EQ("-125.0", ConstFloat::create(llvm::APFloat(-125.0))->toMostReadableString());
}

TEST_F(ConstFloatTests,
ToMostReadableStringCorrectMostReadableRepresentationForNonIntegralNumbers) {
	EXPECT_EQ("1.125", ConstFloat::create(llvm::APFloat(1.125))->toMostReadableString());
	EXPECT_EQ("0.24", ConstFloat::create(llvm::APFloat(0.24))->toMostReadableString());
	EXPECT_EQ("1.5", ConstFloat::create(llvm::APFloat(1.5))->toMostReadableString());
	EXPECT_EQ("7.4", ConstFloat::create(llvm::APFloat(7.4))->toMostReadableString());

	EXPECT_EQ("-1.125", ConstFloat::create(llvm::APFloat(-1.125))->toMostReadableString());
	EXPECT_EQ("-0.24", ConstFloat::create(llvm::APFloat(-0.24))->toMostReadableString());
	EXPECT_EQ("-1.5", ConstFloat::create(llvm::APFloat(-1.5))->toMostReadableString());
	EXPECT_EQ("-7.4", ConstFloat::create(llvm::APFloat(-7.4))->toMostReadableString());
}

TEST_F(ConstFloatTests,
ToMostReadableStringCorrectMostReadableRepresetnationForBiggerNumbers) {
	EXPECT_EQ("4.5e+34", ConstFloat::create(llvm::APFloat(4.5e34))->toMostReadableString());

	EXPECT_EQ("-4.5e+34", ConstFloat::create(llvm::APFloat(-4.5e34))->toMostReadableString());
}

TEST_F(ConstFloatTests,
ToMostReadableStringMostReadableRepresentationForSpecialValues) {
	// All llvm::APFloat::getX() functions require an instance of fltSemantics,
	// so get a reference one.
	llvm::APFloat refF(0.0);
	const llvm::fltSemantics &refSemantics(refF.getSemantics());

	EXPECT_EQ("+inf", ConstFloat::create(llvm::APFloat::getInf(refSemantics))->toMostReadableString());
	EXPECT_EQ("-inf", ConstFloat::create(llvm::APFloat::getInf(refSemantics, true))->toMostReadableString());
	EXPECT_EQ("nan", ConstFloat::create(llvm::APFloat::getNaN(refSemantics))->toMostReadableString());
}

//
// flipSign()
//

TEST_F(ConstFloatTests,
flipSign) {
	ShPtr<ConstFloat> negFloat(ConstFloat::create(llvm::APFloat(-2.0)));
	ShPtr<ConstFloat> posFloat(ConstFloat::create(llvm::APFloat(5.0)));

	// Flip sign.
	negFloat->flipSign();
	posFloat->flipSign();

	EXPECT_EQ("2.0", negFloat->toMostReadableString());
	EXPECT_EQ("-5.0", posFloat->toMostReadableString());
}

//
// isNegative()
//

TEST_F(ConstFloatTests,
IsNegativeZeroValue) {
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(0.0))->isNegative());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(-0.0))->isNegative());
}

TEST_F(ConstFloatTests,
IsNegativePositiveValue) {
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(1.0))->isNegative());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(5.0))->isNegative());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(127.5))->isNegative());
}

TEST_F(ConstFloatTests,
IsNegativeNegativeValue) {
	EXPECT_TRUE(ConstFloat::create(llvm::APFloat(-2.0))->isNegative());
	EXPECT_TRUE(ConstFloat::create(llvm::APFloat(-8.0))->isNegative());
	EXPECT_TRUE(ConstFloat::create(llvm::APFloat(-127.5))->isNegative());
}

//
// isNegativeOne()
//

TEST_F(ConstFloatTests,
IsNegativeOneNegativeOneValue) {
	EXPECT_TRUE(ConstFloat::create(llvm::APFloat(-1.0))->isNegativeOne());
}

TEST_F(ConstFloatTests,
IsNegativeOneNegativeNonOneValue) {
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(-1.2))->isNegativeOne());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(-12.0))->isNegativeOne());
}

TEST_F(ConstFloatTests,
NegativeOnePositiveNonOneValue) {
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(5.0))->isNegativeOne());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(12.0))->isNegativeOne());
}

//
// isPositive()
//

TEST_F(ConstFloatTests,
IsPositiveZeroValue) {
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(0.0))->isPositive());
}

TEST_F(ConstFloatTests,
IsPositivePositiveValue) {
	EXPECT_TRUE(ConstFloat::create(llvm::APFloat(1.0))->isPositive());
	EXPECT_TRUE(ConstFloat::create(llvm::APFloat(2.18))->isPositive());
	EXPECT_TRUE(ConstFloat::create(llvm::APFloat(127.5))->isPositive());
}

TEST_F(ConstFloatTests,
IsPositiveNegativeValue) {
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(-2.0))->isPositive());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(-8.0))->isPositive());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(-127.5))->isPositive());
}

//
// isZero()
//

TEST_F(ConstFloatTests,
IsZeroZeroValue) {
	EXPECT_TRUE(ConstFloat::create(llvm::APFloat(0.0))->isZero());
}

TEST_F(ConstFloatTests,
IsZeroPositiveValue) {
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(1.0))->isZero());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(2.18))->isZero());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(127.5))->isZero());
}

TEST_F(ConstFloatTests,
IsZeroNegativeValue) {
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(-2.0))->isZero());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(-8.0))->isZero());
	EXPECT_FALSE(ConstFloat::create(llvm::APFloat(-127.5))->isZero());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
