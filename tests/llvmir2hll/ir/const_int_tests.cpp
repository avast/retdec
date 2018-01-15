/**
* @file tests/llvmir2hll/ir/const_int_tests.cpp
* @brief Tests for the @c const_int module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/const_int.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c const_int module.
*/
class ConstIntTests: public Test {};

//
// create() and getValue()
//

TEST_F(ConstIntTests,
CreateGetValueZeroValue) {
	llvm::APSInt ref(llvm::APInt(64, 0), true); // true = unsigned

	// Test all three variants of create().
	EXPECT_EQ(ref, ConstInt::create(0, 64, false)->getValue());
	EXPECT_EQ(ref, ConstInt::create(llvm::APInt(64, 0), false)->getValue());
	EXPECT_EQ(ref, ConstInt::create(ConstInt::create(llvm::APInt(64, 0),
		false)->getValue())->getValue());
}

TEST_F(ConstIntTests,
CreateGetValuePositiveValue) {
	llvm::APSInt ref(llvm::APInt(64, 5), true); // true = unsigned

	// Test all three variants of create().
	EXPECT_EQ(ref, ConstInt::create(5, 64, false)->getValue());
	EXPECT_EQ(ref, ConstInt::create(llvm::APInt(64, 5), false)->getValue());
	EXPECT_EQ(ref, ConstInt::create(ConstInt::create(llvm::APInt(64, 5),
		false)->getValue())->getValue());
}

TEST_F(ConstIntTests,
CreateGetValueNegativeValue) {
	llvm::APSInt ref(llvm::APInt(64, -20), false); // false = signed

	// Test all three variants of create().
	EXPECT_EQ(ref, ConstInt::create(-20, 64, true)->getValue());
	EXPECT_EQ(ref, ConstInt::create(llvm::APInt(64, -20, true))->getValue());
	EXPECT_EQ(ref, ConstInt::create(ConstInt::create(llvm::APInt(64, -20, true),
		true)->getValue())->getValue());
}

//
// toString()
//

TEST_F(ConstIntTests,
ToStringCorrectConversionToStringDecimal) {
	EXPECT_EQ("-65536", ConstInt::create(-65536, 32, true)->toString());
	EXPECT_EQ("-100", ConstInt::create(-100, 64, true)->toString());
	EXPECT_EQ("-1", ConstInt::create(-1, 127, true)->toString());
	EXPECT_EQ("0", ConstInt::create(0, 16, false)->toString());
	EXPECT_EQ("1", ConstInt::create(1, 2, false)->toString());
	EXPECT_EQ("127", ConstInt::create(127, 16, false)->toString());
	EXPECT_EQ("16777216", ConstInt::create(16777216, 30)->toString());
}

TEST_F(ConstIntTests,
ToStringCorrectConversionToStringHexaNoPrefix) {
	EXPECT_EQ("-10000", ConstInt::create(-65536, 32, true)->toString(16));
	EXPECT_EQ("-64", ConstInt::create(-100, 64, true)->toString(16));
	EXPECT_EQ("-1", ConstInt::create(-1, 127, true)->toString(16));
	EXPECT_EQ("0", ConstInt::create(0, 16, false)->toString(16));
	EXPECT_EQ("1", ConstInt::create(1, 2, false)->toString(16));
	EXPECT_EQ("7f", ConstInt::create(127, 16, false)->toString(16));
	EXPECT_EQ("1000000", ConstInt::create(16777216, 30, false)->toString(16));
}

TEST_F(ConstIntTests,
ToStringCorrectConversionToStringHexaWithPrefix) {
	EXPECT_EQ("-0x10000", ConstInt::create(-65536, 32, true)->toString(16, "0x"));
	EXPECT_EQ("-0x64", ConstInt::create(-100, 64, true)->toString(16, "0x"));
	EXPECT_EQ("-0x1", ConstInt::create(-1, 127, true)->toString(16, "0x"));
	EXPECT_EQ("0x0", ConstInt::create(0, 16, false)->toString(16, "0x"));
	EXPECT_EQ("0x1", ConstInt::create(1, 2, false)->toString(16, "0x"));
	EXPECT_EQ("0x7f", ConstInt::create(127, 16, false)->toString(16, "0x"));
	EXPECT_EQ("0x1000000", ConstInt::create(16777216, 30, false)->toString(16, "0x"));
}

#if DEATH_TESTS_ENABLED
TEST_F(ConstIntTests,
ToStringViolatedPreconditionInvalidRadix) {
	ShPtr<ConstInt> i(ConstInt::create(1024, 16, false));

	EXPECT_DEATH(i->toString(0), ".*toString.*Precondition.*failed.*");
	EXPECT_DEATH(i->toString(1), ".*toString.*Precondition.*failed.*");
	EXPECT_DEATH(i->toString(3), ".*toString.*Precondition.*failed.*");
	EXPECT_DEATH(i->toString(7), ".*toString.*Precondition.*failed.*");
	EXPECT_DEATH(i->toString(9), ".*toString.*Precondition.*failed.*");
	EXPECT_DEATH(i->toString(11), ".*toString.*Precondition.*failed.*");
	EXPECT_DEATH(i->toString(15), ".*toString.*Precondition.*failed.*");
	EXPECT_DEATH(i->toString(17), ".*toString.*Precondition.*failed.*");
	EXPECT_DEATH(i->toString(35), ".*toString.*Precondition.*failed.*");
	EXPECT_DEATH(i->toString(37), ".*toString.*Precondition.*failed.*");
}
#endif

//
// toHexString()
//

TEST_F(ConstIntTests,
ToHexStringWorksLikeToString) {
	ShPtr<ConstInt> i(ConstInt::create(1024, 32, false));

	EXPECT_EQ(i->toString(16, "0x"), i->toHexString());
	EXPECT_EQ(i->toString(16, ""), i->toHexString(""));
}

//
// flipSign()
//

TEST_F(ConstIntTests,
flipSign) {
	ShPtr<ConstInt> posInt(ConstInt::create(5, 32, true));
	ShPtr<ConstInt> negInt(ConstInt::create(-2, 64, true));

	// Flip sign.
	posInt->flipSign();
	negInt->flipSign();

	EXPECT_EQ("-5", posInt->toString());
	EXPECT_EQ("2", negInt->toString());
}

//
// isMinSigned()
//

TEST_F(ConstIntTests,
IsMinSignedMinSignedValue) {
	EXPECT_TRUE(ConstInt::create(-8, 4, true)->isMinSigned());
	EXPECT_TRUE(ConstInt::create(-64, 7, true)->isMinSigned());
	EXPECT_TRUE(ConstInt::create(-128, 8, true)->isMinSigned());
}

TEST_F(ConstIntTests,
IsMinSignedNonMinPositiveSignedValue) {
	EXPECT_FALSE(ConstInt::create(0, 4, true)->isMinSigned());
}

TEST_F(ConstIntTests,
IsMinSignedNonMinNegativeSignedValue) {
	EXPECT_FALSE(ConstInt::create(-2, 32, true)->isMinSigned());
	EXPECT_FALSE(ConstInt::create(-8, 64, true)->isMinSigned());
	EXPECT_FALSE(ConstInt::create(-127, 65, true)->isMinSigned());
}

//
// isSigned()
//

TEST_F(ConstIntTests,
IsSignedZeroValue) {
	// Test all three variants of create() for signed.
	EXPECT_TRUE(ConstInt::create(0, 64, true)->isSigned());
	EXPECT_TRUE(ConstInt::create(llvm::APInt(64, 0, true))->isSigned());
	EXPECT_TRUE(ConstInt::create(ConstInt::create(llvm::APInt(64, 0, true),
		true)->getValue())->isSigned());
	// Test all three variants of create() for unsigned.
	EXPECT_FALSE(ConstInt::create(0, 64, false)->isSigned());
	EXPECT_FALSE(ConstInt::create(llvm::APInt(64, 0, false), false)->isSigned());
	EXPECT_FALSE(ConstInt::create(ConstInt::create(llvm::APInt(64, 0, false),
		false)->getValue())->isSigned());
}

TEST_F(ConstIntTests,
IsSignedPositiveValue) {
	// Test all three variants of create() for signed.
	EXPECT_TRUE(ConstInt::create(5, 64, true)->isSigned());
	EXPECT_TRUE(ConstInt::create(llvm::APInt(64, 5, true))->isSigned());
	EXPECT_TRUE(ConstInt::create(ConstInt::create(llvm::APInt(64, 5, true),
		true)->getValue())->isSigned());
	// Test all three variants of create() for unsigned.
	EXPECT_FALSE(ConstInt::create(5, 64, false)->isSigned());
	EXPECT_FALSE(ConstInt::create(llvm::APInt(64, 5, false), false)->isSigned());
	EXPECT_FALSE(ConstInt::create(ConstInt::create(llvm::APInt(64, 5, false),
		false)->getValue())->isSigned());
}

TEST_F(ConstIntTests,
IsSignedNegativeValue) {
	// Test all three variants of create() for signed.
	EXPECT_TRUE(ConstInt::create(-20, 64, true)->isSigned());
	EXPECT_TRUE(ConstInt::create(llvm::APInt(64, -20, true))->isSigned());
	EXPECT_TRUE(ConstInt::create(ConstInt::create(llvm::APInt(64, -20, true),
		true)->getValue())->isSigned());
	// Test all three variants of create() for unsigned.
	EXPECT_FALSE(ConstInt::create(-20, 64, false)->isSigned());
	EXPECT_FALSE(ConstInt::create(llvm::APInt(64, -20, false), false)->isSigned());
	EXPECT_FALSE(ConstInt::create(ConstInt::create(llvm::APInt(64, -20, false),
		false)->getValue())->isSigned());
}

//
// isUnsigned()
//

TEST_F(ConstIntTests,
IsUnsignedReturnsTrueWhenConstantIsUnsigned) {
	EXPECT_TRUE(ConstInt::create(0, 32, false)->isUnsigned());
}

TEST_F(ConstIntTests,
IsUnsignedReturnsFalseWhenConstantIsSigned) {
	EXPECT_FALSE(ConstInt::create(0, 32, true)->isUnsigned());
}

//
// getTwoToPositivePower()
//

TEST_F(ConstIntTests,
GetTwoToPositivePowerTwoToZeroIsOne) {
	ShPtr<ConstInt> x(ConstInt::create(0, 64, false));
	EXPECT_EQ(llvm::APInt(64, 1), ConstInt::getTwoToPositivePower(x)->getValue());
}

TEST_F(ConstIntTests,
GetTwoToPositivePowerTwoToOneIsTwo) {
	ShPtr<ConstInt> x(ConstInt::create(1, 64, false));
	EXPECT_EQ(llvm::APInt(64, 2), ConstInt::getTwoToPositivePower(x)->getValue());
}

TEST_F(ConstIntTests,
GetTwoToPositivePowerTwoToTwoIsFour) {
	ShPtr<ConstInt> x(ConstInt::create(2, 64, false));
	EXPECT_EQ(llvm::APInt(64, 4), ConstInt::getTwoToPositivePower(x)->getValue());
}

TEST_F(ConstIntTests,
GetTwoToPositivePowerTwoToThreeIsEight) {
	ShPtr<ConstInt> x(ConstInt::create(3, 64, false));
	EXPECT_EQ(llvm::APInt(64, 8), ConstInt::getTwoToPositivePower(x)->getValue());
}

TEST_F(ConstIntTests,
GetTwoToPositivePowerTwoTo16Is65536) {
	ShPtr<ConstInt> x(ConstInt::create(16, 64, false));
	EXPECT_EQ(llvm::APInt(64, 65536), ConstInt::getTwoToPositivePower(x)->getValue());
}

#if DEATH_TESTS_ENABLED
TEST_F(ConstIntTests,
GetTwoToPositivePowerPreconditionXNonNull) {
	ASSERT_DEATH(ConstInt::getTwoToPositivePower(ShPtr<ConstInt>()),
		".*getTwoToPositivePower.*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(ConstIntTests,
GetTwoToPositivePowerPreconditionXGreaterOrEqualZero) {
	ShPtr<ConstInt> x(ConstInt::create(-1, 64, true));
	ASSERT_DEATH(ConstInt::getTwoToPositivePower(x),
		".*getTwoToPositivePower.*Precondition.*failed.*");
}
#endif

//
// isNegative()
//

TEST_F(ConstIntTests,
IsNegativeNegativeValue) {
	EXPECT_TRUE(ConstInt::create(-2, 64, true)->isNegative());
	EXPECT_TRUE(ConstInt::create(-4, 37, true)->isNegative());
	EXPECT_TRUE(ConstInt::create(-8, 125, true)->isNegative());
}

TEST_F(ConstIntTests,
IsNegativeZeroValue) {
	EXPECT_FALSE(ConstInt::create(0, 32, true)->isNegative());
	EXPECT_FALSE(ConstInt::create(-0, 32, true)->isNegative());
	EXPECT_FALSE(ConstInt::create(0, 32, false)->isNegative());
}

TEST_F(ConstIntTests,
IsNegativePositiveValue) {
	EXPECT_FALSE(ConstInt::create(2, 32, false)->isNegative());
	EXPECT_FALSE(ConstInt::create(8, 64, false)->isNegative());
	EXPECT_FALSE(ConstInt::create(127, 124, false)->isNegative());
}

TEST_F(ConstIntTests,
IsNegativePositiveUnsignedHighValue) {
	EXPECT_FALSE(ConstInt::create(4294967295U, 32, false)->isNegative());
}

//
// isNegativeOne()
//

TEST_F(ConstIntTests,
IsNegativeOneNegativeOneValue) {
	EXPECT_TRUE(ConstInt::create(-1, 32, true)->isNegativeOne());
	EXPECT_TRUE(ConstInt::create(-1, 64, true)->isNegativeOne());
	EXPECT_TRUE(ConstInt::create(-1, 127, true)->isNegativeOne());
}

TEST_F(ConstIntTests,
IsNegativeOneNegativeNonOneValue) {
	EXPECT_FALSE(ConstInt::create(-2, 32, true)->isNegativeOne());
	EXPECT_FALSE(ConstInt::create(-6, 125, true)->isNegativeOne());
}

TEST_F(ConstIntTests,
IsNegativeOnePositiveNonOneValue) {
	EXPECT_FALSE(ConstInt::create(45, 32, true)->isNegativeOne());
	EXPECT_FALSE(ConstInt::create(1, 125, true)->isNegativeOne());
}

//
// isPositive()
//

TEST_F(ConstIntTests,
IsPositivePositiveValue) {
	EXPECT_TRUE(ConstInt::create(4, 64, false)->isPositive());
	EXPECT_TRUE(ConstInt::create(1, 37, false)->isPositive());
	EXPECT_TRUE(ConstInt::create(12521, 125, false)->isPositive());
}

TEST_F(ConstIntTests,
IsPositiveZeroValue) {
	EXPECT_FALSE(ConstInt::create(0, 32, false)->isPositive());
}

TEST_F(ConstIntTests,
IsPositiveNegativeValue) {
	EXPECT_FALSE(ConstInt::create(-2, 32, true)->isPositive());
	EXPECT_FALSE(ConstInt::create(-8, 64, true)->isPositive());
	EXPECT_FALSE(ConstInt::create(-127, 65, true)->isPositive());
}

//
// isZero()
//

TEST_F(ConstIntTests,
IsZeroZeroValue) {
	EXPECT_TRUE(ConstInt::create(0, 32, false)->isZero());
	EXPECT_TRUE(ConstInt::create(0, 64, false)->isZero());
	EXPECT_TRUE(ConstInt::create(0, 127, false)->isZero());
}

TEST_F(ConstIntTests,
IsZeroNegativeValue) {
	EXPECT_FALSE(ConstInt::create(-2, 32, true)->isZero());
	EXPECT_FALSE(ConstInt::create(-6, 125, true)->isZero());
}

TEST_F(ConstIntTests,
IsZeroPositiveValue) {
	EXPECT_FALSE(ConstInt::create(45, 32, false)->isZero());
	EXPECT_FALSE(ConstInt::create(1, 125, false)->isZero());
}

//
// isOne()
//

TEST_F(ConstIntTests,
IsOneTrue) {
	EXPECT_TRUE(ConstInt::create(1, 32, false)->isOne());
	EXPECT_TRUE(ConstInt::create(1, 64, false)->isOne());
	EXPECT_TRUE(ConstInt::create(1, 127, true)->isOne());
}

TEST_F(ConstIntTests,
IsOneFalse) {
	EXPECT_FALSE(ConstInt::create(-6, 125, true)->isOne());
	EXPECT_FALSE(ConstInt::create(-2, 32, true)->isOne());
	EXPECT_FALSE(ConstInt::create(-1, 32, true)->isOne());
	EXPECT_FALSE(ConstInt::create(0, 32, true)->isOne());
	EXPECT_FALSE(ConstInt::create(2, 125, false)->isOne());
	EXPECT_FALSE(ConstInt::create(45, 32, false)->isOne());
}

//
// isMoreReadableInHexa()
//

TEST_F(ConstIntTests,
IsMoreReadableInHexaIsMoreReadableNonNegativeIntegers) {
	// 0xffff
	EXPECT_TRUE(ConstInt::create(65535, 32)->isMoreReadableInHexa());
	// 0x1000
	EXPECT_TRUE(ConstInt::create(4096, 32)->isMoreReadableInHexa());
	// 0x10000
	EXPECT_TRUE(ConstInt::create(65536, 32)->isMoreReadableInHexa());
	// 0x7fffffff
	EXPECT_TRUE(ConstInt::create(2147483647, 32)->isMoreReadableInHexa());
	// 0x111fff
	EXPECT_TRUE(ConstInt::create(1122303, 32)->isMoreReadableInHexa());
	// 0x101010
	EXPECT_TRUE(ConstInt::create(1052688, 32)->isMoreReadableInHexa());
	// 0xf0f0f0f
	EXPECT_TRUE(ConstInt::create(252645135, 32)->isMoreReadableInHexa());
	// 0xaa00aa
	EXPECT_TRUE(ConstInt::create(11141290, 32)->isMoreReadableInHexa());
	// 0xaa0aa
	EXPECT_TRUE(ConstInt::create(696490, 32)->isMoreReadableInHexa());
	// 0xa000a
	EXPECT_TRUE(ConstInt::create(655370, 32)->isMoreReadableInHexa());
}

TEST_F(ConstIntTests,
IsMoreReadableInHexaIsNotMoreReadableNonNegativeIntegers) {
	// 0x0 (too low)
	EXPECT_FALSE(ConstInt::create(0, 8)->isMoreReadableInHexa());
	// 0x1 (too low)
	EXPECT_FALSE(ConstInt::create(1, 32)->isMoreReadableInHexa());
	// 0xf (too low)
	EXPECT_FALSE(ConstInt::create(15, 32)->isMoreReadableInHexa());
	// 0x11 (too low)
	EXPECT_FALSE(ConstInt::create(17, 32)->isMoreReadableInHexa());
	// 0x80 (too low)
	EXPECT_FALSE(ConstInt::create(128, 32)->isMoreReadableInHexa());
	// 0xfff (too low)
	EXPECT_FALSE(ConstInt::create(4095, 32)->isMoreReadableInHexa());
	// 0xff1aa (not more readable)
	EXPECT_FALSE(ConstInt::create(1044906, 32)->isMoreReadableInHexa());
	// 0x1111fff (not of the form 0xYYY...ZZZ)
	EXPECT_FALSE(ConstInt::create(17899519, 32)->isMoreReadableInHexa());
	// 0x101a10 (not of the form 0xYZYZ...)
	EXPECT_FALSE(ConstInt::create(1055248, 32)->isMoreReadableInHexa());
	// 0xf0f0fa (not of the form 0xYZYZ...X)
	EXPECT_FALSE(ConstInt::create(15790330, 32)->isMoreReadableInHexa());
	// 0xaa0b0aa (not of the form 0xYYZ...ZYY)
	EXPECT_FALSE(ConstInt::create(178303146, 32)->isMoreReadableInHexa());
	// 0xaa00aaa (not of the form 0xYYZ...ZYY)
	EXPECT_FALSE(ConstInt::create(178260650, 32)->isMoreReadableInHexa());
	// 0xaaa00a (not of the form 0xYYZ...ZYY)
	EXPECT_FALSE(ConstInt::create(11182090, 32)->isMoreReadableInHexa());
	// 0xaaa00 (not of the form 0xYYZ...ZYY)
	EXPECT_FALSE(ConstInt::create(698880, 32)->isMoreReadableInHexa());
}

TEST_F(ConstIntTests,
IsMoreReadableInHexaIsMoreReadableNegativeIntegers) {
	//0xffff
	EXPECT_TRUE(ConstInt::create(-65535, 32)->isMoreReadableInHexa());
	//0x1000
	EXPECT_TRUE(ConstInt::create(-4096, 32)->isMoreReadableInHexa());
	//0x10000
	EXPECT_TRUE(ConstInt::create(-65536, 32)->isMoreReadableInHexa());
	//0x111fff
	EXPECT_TRUE(ConstInt::create(-1122303, 32)->isMoreReadableInHexa());
	// 0x101010
	EXPECT_TRUE(ConstInt::create(-1052688, 32)->isMoreReadableInHexa());
}

TEST_F(ConstIntTests,
IsMoreReadableInHexaIsNotMoreReadableNegativeIntegers) {
	//0x1 (too low)
	EXPECT_FALSE(ConstInt::create(-1, 32)->isMoreReadableInHexa());
	//0xf (too low)
	EXPECT_FALSE(ConstInt::create(-15, 32)->isMoreReadableInHexa());
	//0x11 (too low)
	EXPECT_FALSE(ConstInt::create(-17, 32)->isMoreReadableInHexa());
	//0x80 (too low)
	EXPECT_FALSE(ConstInt::create(-128, 32)->isMoreReadableInHexa());
	//0xfff (too low)
	EXPECT_FALSE(ConstInt::create(-4095, 32)->isMoreReadableInHexa());
	//0xff1aa (not more readable)
	EXPECT_FALSE(ConstInt::create(-1044906, 32)->isMoreReadableInHexa());
	//0x1111fff (not of the form 0xYYY...ZZZ)
	EXPECT_FALSE(ConstInt::create(-17899519, 32)->isMoreReadableInHexa());
	//0x101a10 (not of the form 0xYZYZ...)
	EXPECT_FALSE(ConstInt::create(-1055248, 32)->isMoreReadableInHexa());
	//0xaa0b0aa (not of the form 0xYYZ...ZYY)
	EXPECT_FALSE(ConstInt::create(-178303146, 32)->isMoreReadableInHexa());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
