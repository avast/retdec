/**
* @file tests/llvmir2hll/config/configs/json_config_tests.cpp
* @brief Tests for the @c json_config module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/config/configs/json_config.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for JSONConfig.
*/
class JSONConfigTests: public Test {};

//
// Loading
//

TEST_F(JSONConfigTests,
ConfigFromStringIsLoadedCorrectly) {
	auto config = JSONConfig::fromString("{}");
	// At the moment, there is no way of validation.
}

TEST_F(JSONConfigTests,
EmptyReturnsEmptyConfig) {
	auto config = JSONConfig::empty();
	// At the moment, there is no way of validation.
}

TEST_F(JSONConfigTests,
ConfigFromStringRaisesJSONParsingErrorWhenJSONIsInvalid) {
	ASSERT_THROW(JSONConfig::fromString("%"), JSONConfigParsingError);
}

//
// isGlobalVarStoringWideString()
//

TEST_F(JSONConfigTests,
IsGlobalVarStoringWideStringReturnsFalseWhenVarDoesNotExist) {
	auto config = JSONConfig::empty();

	ASSERT_FALSE(config->isGlobalVarStoringWideString("g"));
}

TEST_F(JSONConfigTests,
IsGlobalVarStoringWideStringReturnsTrueWhenVarIsGlobalAndStoresWideString) {
	auto config = JSONConfig::fromString(R"({
		"globals": [
			{
				"name": "g",
				"storage": {
					"type": "global",
					"value": "1000"
				},
				"type": {
					"llvmIr": "i32*",
					"isWideString": true
				}
			}
		]
	})");

	ASSERT_TRUE(config->isGlobalVarStoringWideString("g"));
}

//
// getRegisterForGlobalVar()
//

TEST_F(JSONConfigTests,
GetRegisterForGlobalVarReturnsEmptyStringWhenGlobalVarDoesNotExist) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getRegisterForGlobalVar("g"));
}

TEST_F(JSONConfigTests,
GetRegisterForGlobalVarReturnsEmptyStringWhenGlobalVarHasNoRegisterNameAttached) {
	auto config = JSONConfig::fromString(R"({
		"globals": [
			{
				"name": "g",
				"realName": "my_g",
				"storage": {
					"type": "global",
					"value": "1"
				}
			}
		]
	})");

	ASSERT_EQ("", config->getRegisterForGlobalVar("g"));
}

TEST_F(JSONConfigTests,
GetRegisterForGlobalVarReturnsCorrectNameWhenGlobalVarHasRegisterNameAttached) {
	auto config = JSONConfig::fromString(R"({
		"registers": [
			{
				"name": "g",
				"realName": "ebx",
				"storage": {
					"type": "register",
					"value": "ebx"
				}
			}
		]
	})");

	ASSERT_EQ("ebx", config->getRegisterForGlobalVar("g"));
}

//
// getDetectedCryptoPatternForGlobalVar()
//

TEST_F(JSONConfigTests,
GetDetectedCryptoPatternForGlobalVarReturnsEmptyStringWhenGlobalVarDoesNotExist) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getDetectedCryptoPatternForGlobalVar("g"));
}

TEST_F(JSONConfigTests,
GetDetectedCryptoPatternForGlobalVarReturnsEmptyStringWhenGlobalVarHasNoCryptoPatternAttached) {
	auto config = JSONConfig::fromString(R"({
		"globals": [
			{
				"name": "g",
				"realName": "my_g",
				"storage": {
					"type": "global",
					"value": "1"
				}
			}
		]
	})");

	ASSERT_EQ("", config->getDetectedCryptoPatternForGlobalVar("g"));
}

TEST_F(JSONConfigTests,
GetDetectedCryptoPatternForGlobalVarReturnsCorrectValueWhenGlobalVarHasCryptoPatternAttached) {
	auto config = JSONConfig::fromString(R"({
		"globals": [
			{
				"cryptoDescription": "CRC32",
				"name": "g",
				"realName": "my_g",
				"storage": {
					"type": "global",
					"value": "1"
				}
			}
		]
	})");

	ASSERT_EQ("CRC32", config->getDetectedCryptoPatternForGlobalVar("g"));
}

//
// comesFromGlobalVar()
//

TEST_F(JSONConfigTests,
ComesFromGlobalVarReturnsEmptyStringWhenFuncDoesNotExist) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->comesFromGlobalVar("my_func", "g"));
}

TEST_F(JSONConfigTests,
ComesFromGlobalVarReturnsEmptyStringWhenVarInFuncDoesNotExist) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func"
			}
		]
	})");

	ASSERT_EQ("", config->comesFromGlobalVar("my_func", "g"));
}

TEST_F(JSONConfigTests,
ComesFromGlobalVarReturnsEmptyStringWhenVarDoesNotComeFromRegister) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"locals": [
					{
						"name": "g",
						"realName": "my_g"
					}
				]
			}
		]
	})");

	ASSERT_EQ("", config->comesFromGlobalVar("my_func", "g"));
}

TEST_F(JSONConfigTests,
ComesFromGlobalVarReturnsCorrectValueWhenVarComesFromRegister) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"locals": [
					{
						"name": "g",
						"realName": "my_g",
						"storage": {
							"type": "register",
							"value": "reg1"
						}
					}
				]
			}
		]
	})");

	ASSERT_EQ("reg1", config->comesFromGlobalVar("my_func", "g"));
}

TEST_F(JSONConfigTests,
ComesFromGlobalVarReturnsRealRegisterNameWhenVarComesFromKnownRegister) {
	auto config = JSONConfig::fromString(R"({
		"registers": [
			{
				"name": "reg1",
				"realName": "ebx",
				"storage": {
					"type": "register",
					"value": "ebx"
				}
			}
		],
		"functions": [
			{
				"name": "my_func",
				"locals": [
					{
						"name": "g",
						"realName": "my_g",
						"storage": {
							"type": "register",
							"value": "reg1"
						}
					}
				]
			}
		]
	})");

	ASSERT_EQ("ebx", config->comesFromGlobalVar("my_func", "g"));
}

//
// getRealNameForFunc()
//

TEST_F(JSONConfigTests,
GetRealNameForFuncReturnsEmptyStringWhenThereIsNoSuchFunc) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getRealNameForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetRealNameForFuncReturnsEmptyStringWhenThereIsNoRealName) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func"
			}
		]
	})");

	ASSERT_EQ("", config->getRealNameForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetRealNameForFuncReturnsCorrectValueWhenItHasRealName) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"realName": "myFunc"
			}
		]
	})");

	ASSERT_EQ("myFunc", config->getRealNameForFunc("my_func"));
}

//
// getAddressRangeForFunc()
//

TEST_F(JSONConfigTests,
GetAddressRangeForFuncReturnsNoAddressRangeWhenFuncDoesNotExist) {
	auto config = JSONConfig::empty();

	ASSERT_EQ(NO_ADDRESS_RANGE, config->getAddressRangeForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetAddressRangeForFuncReturnsNoAddressRangeWhenFuncDoesNotHaveCompleteAddressRange) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"startAddr": "0"
			}
		]
	})");

	ASSERT_EQ(NO_ADDRESS_RANGE, config->getAddressRangeForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetAddressRangeForFuncReturnsCorrectRangeWhenFuncHasCompleteAddressRange) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"startAddr": "0",
				"endAddr": "20"
			}
		]
	})");

	ASSERT_EQ(AddressRange(0, 20), config->getAddressRangeForFunc("my_func"));
}

//
// getLineRangeForFunc()
//

TEST_F(JSONConfigTests,
GetLineRangeForFuncReturnsNoLineRangeWhenFuncDoesNotExist) {
	auto config = JSONConfig::empty();

	ASSERT_EQ(NO_LINE_RANGE, config->getLineRangeForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetLineRangeForFuncReturnsNoLineRangeWhenFuncDoesNotHaveCompleteLineRange) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"startLine": "1"
			}
		]
	})");

	ASSERT_EQ(NO_LINE_RANGE, config->getLineRangeForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetLineRangeForFuncReturnsCorrectRangeWhenFuncHasCompleteLineRange) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"startLine": "1",
				"endLine": "10"
			}
		]
	})");

	ASSERT_EQ(LineRange(1, 10), config->getLineRangeForFunc("my_func"));
}

//
// isUserDefinedFunc()
//

TEST_F(JSONConfigTests,
IsUserDefinedFuncReturnsFalseWhenThereIsNoInfoForFunc) {
	auto config = JSONConfig::empty();

	ASSERT_FALSE(config->isUserDefinedFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsUserDefinedFuncReturnsFalseWhenFuncIsDynamicallyLinked) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "dynamicallyLinked"
			}
		]
	})");

	ASSERT_FALSE(config->isUserDefinedFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsUserDefinedFuncReturnsTrueWhenFuncIsUserDefined) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "userDefined"
			}
		]
	})");

	ASSERT_TRUE(config->isUserDefinedFunc("my_func"));
}

//
// isStaticallyLinkedFunc()
//

TEST_F(JSONConfigTests,
IsStaticallyLinkedFuncReturnsFalseWhenThereIsNoInfoForFunc) {
	auto config = JSONConfig::empty();

	ASSERT_FALSE(config->isStaticallyLinkedFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsStaticallyLinkedFuncReturnsFalseWhenFuncIsDynamicallyLinked) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "dynamicallyLinked"
			}
		]
	})");

	ASSERT_FALSE(config->isStaticallyLinkedFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsStaticallyLinkedFuncReturnsTrueWhenFuncIsStaticallyLinked) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "staticallyLinked"
			}
		]
	})");

	ASSERT_TRUE(config->isStaticallyLinkedFunc("my_func"));
}

//
// isDynamicallyLinkedFunc()
//

TEST_F(JSONConfigTests,
IsDynamicallyLinkedFuncReturnsFalseWhenThereIsNoInfoForFunc) {
	auto config = JSONConfig::empty();

	ASSERT_FALSE(config->isDynamicallyLinkedFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsDynamicallyLinkedFuncReturnsFalseWhenFuncIsStaticallyLinked) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "staticallyLinked"
			}
		]
	})");

	ASSERT_FALSE(config->isDynamicallyLinkedFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsDynamicallyLinkedFuncReturnsTrueWhenFuncIsDynamicallyLinked) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "dynamicallyLinked"
			}
		]
	})");

	ASSERT_TRUE(config->isDynamicallyLinkedFunc("my_func"));
}

//
// isSyscallFunc()
//

TEST_F(JSONConfigTests,
IsSyscallFuncReturnsFalseWhenThereIsNoInfoForFunc) {
	auto config = JSONConfig::empty();

	ASSERT_FALSE(config->isSyscallFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsSyscallFuncReturnsFalseWhenFuncIsStaticallyLinked) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "staticallyLinked"
			}
		]
	})");

	ASSERT_FALSE(config->isSyscallFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsSyscallFuncReturnsTrueWhenFuncIsSyscall) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "syscall"
			}
		]
	})");

	ASSERT_TRUE(config->isSyscallFunc("my_func"));
}

//
// isInstructionIdiomFunc()
//

TEST_F(JSONConfigTests,
IsInstructionIdiomFuncReturnsFalseWhenThereIsNoInfoForFunc) {
	auto config = JSONConfig::empty();

	ASSERT_FALSE(config->isInstructionIdiomFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsInstructionIdiomFuncReturnsFalseWhenFuncIsStaticallyLinked) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "staticallyLinked"
			}
		]
	})");

	ASSERT_FALSE(config->isInstructionIdiomFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsInstructionIdiomFuncReturnsTrueWhenFuncIsIdiom) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "idiom"
			}
		]
	})");

	ASSERT_TRUE(config->isInstructionIdiomFunc("my_func"));
}

//
// isExportedFunc()
//

TEST_F(JSONConfigTests,
IsExportedFuncReturnsFalseWhenThereIsNoInfoForFunc) {
	auto config = JSONConfig::empty();

	ASSERT_FALSE(config->isExportedFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsExportedFuncReturnsFalseWhenFuncHasNoInfoWheterItIsExported) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func"
			}
		]
	})");

	ASSERT_FALSE(config->isExportedFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsExportedFuncReturnsFalseWhenFuncIsNotExported) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"isExported": false
			}
		]
	})");

	ASSERT_FALSE(config->isExportedFunc("my_func"));
}

TEST_F(JSONConfigTests,
IsExportedFuncReturnsTrueWhenFuncIsExported) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"isExported": true
			}
		]
	})");

	ASSERT_TRUE(config->isExportedFunc("my_func"));
}

//
// markFuncAsStaticallyLinked()
//

TEST_F(JSONConfigTests,
MarkFuncAsStaticallyLinkedDoesNothingWhenFuncDoesNotExist) {
	auto config = JSONConfig::empty();
	config->markFuncAsStaticallyLinked("my_func");
}

TEST_F(JSONConfigTests,
MarkFuncAsStaticallyLinkedSetsFuncAsStaticallyLinked) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"fncType": "dynamicallyLinked"
			}
		]
	})");

	config->markFuncAsStaticallyLinked("my_func");

	ASSERT_TRUE(config->isStaticallyLinkedFunc("my_func"));
}

//
// getDeclarationStringForFunc()
//

TEST_F(JSONConfigTests,
GetDeclarationStringForFuncReturnsEmptyStringWhenThereIsNoSuchFunc) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getDeclarationStringForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetDeclarationStringForFuncReturnsEmptyStringWhenThereIsNoDeclarationString) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func"
			}
		]
	})");

	ASSERT_EQ("", config->getDeclarationStringForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetDeclarationStringForFuncReturnsCorrectValueWhenItHasDeclarationString) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"declarationStr": "int my_func();"
			}
		]
	})");

	ASSERT_EQ("int my_func();", config->getDeclarationStringForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetDeclarationStringForFuncRemovesBeginningAndTrailingWhitespace) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"declarationStr": "  int my_func();  "
			}
		]
	})");

	ASSERT_EQ("int my_func();", config->getDeclarationStringForFunc("my_func"));
}

//
// getCommentForFunc()
//

TEST_F(JSONConfigTests,
GetCommentForFuncReturnsEmptyStringWhenThereIsNoSuchFunc) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getCommentForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetCommentForFuncReturnsEmptyStringWhenThereIsNoComment) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func"
			}
		]
	})");

	ASSERT_EQ("", config->getCommentForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetCommentForFuncReturnsCorrectValueWhenItHasComment) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"comment": "my comment"
			}
		]
	})");

	ASSERT_EQ("my comment", config->getCommentForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetCommentForFuncRemovesBeginningAndTrailingWhitespace) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"comment": "  my comment \n "
			}
		]
	})");

	ASSERT_EQ("my comment", config->getCommentForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetCommentForFuncPreservesWhitespaceInsideComment) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"comment": "my\nmultiline\ncomment"
			}
		]
	})");

	ASSERT_EQ("my\nmultiline\ncomment", config->getCommentForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetCommentForFuncUnifiesLineEndsInsideCommentFromCRLFToLF) {
	// CRLF (\r\n) is used on Windows).
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"comment": "my\r\nmultiline\r\ncomment"
			}
		]
	})");

	ASSERT_EQ("my\nmultiline\ncomment", config->getCommentForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetCommentForFuncUnifiesLineEndsInsideCommentFromCRToLF) {
	// CR (\r) is used on MacOS).
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"comment": "my\rmultiline\rcomment"
			}
		]
	})");

	ASSERT_EQ("my\nmultiline\ncomment", config->getCommentForFunc("my_func"));
}

//
// getDetectedCryptoPatternsForFunc()
//

TEST_F(JSONConfigTests,
GetDetectedCryptoPatternsForFuncReturnsEmptySetWhenThereIsNoSuchFunc) {
	auto config = JSONConfig::empty();

	ASSERT_EQ(StringSet(), config->getDetectedCryptoPatternsForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetDetectedCryptoPatternsForFuncReturnsEmptySetWhenThereIsNoDetectedCryptoPattern) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func"
			}
		]
	})");

	ASSERT_EQ(StringSet(), config->getDetectedCryptoPatternsForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetDetectedCryptoPatternsForFuncReturnsCorrectValueWhenThereAreDetectedCryptoPatterns) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"usedCryptoConstants": ["CRC32"]
			}
		]
	})");

	ASSERT_EQ(StringSet({"CRC32"}), config->getDetectedCryptoPatternsForFunc("my_func"));
}

//
// getWrappedFunc()
//

TEST_F(JSONConfigTests,
GetWrappedFuncReturnsEmptyStringWhenThereIsNoSuchFunc) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getWrappedFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetWrappedFuncReturnsEmptyStringWhenFuncIsNotWrapper) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func"
			}
		]
	})");

	ASSERT_EQ("", config->getWrappedFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetWrappedFuncReturnsCorrectValueWhenItIsWrapper) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"wrappedFunctionName": "another_func"
			}
		]
	})");

	ASSERT_EQ("another_func", config->getWrappedFunc("my_func"));
}

//
// getDemangledNameOfFunc()
//

TEST_F(JSONConfigTests,
GetDemangledNameOfFuncReturnsEmptyStringWhenThereIsNoSuchFunc) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getDemangledNameOfFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetDemangledNameOfFuncReturnsEmptyStringWhenFuncDoesNotHaveDemangledName) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func"
			}
		]
	})");

	ASSERT_EQ("", config->getDemangledNameOfFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetDemangledNameOfFuncReturnsCorrectValueWhenFuncHasDemangledName) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"demangledName": "demangled_my_func"
			}
		]
	})");

	ASSERT_EQ("demangled_my_func", config->getDemangledNameOfFunc("my_func"));
}

//
// getFuncsFixedWithLLVMIRFixer()
//

TEST_F(JSONConfigTests,
GetFuncsFixedWithLLVMIRFixerReturnsEmptySetWhenThereAreNoFuncs) {
	auto config = JSONConfig::empty();

	ASSERT_EQ(StringSet(), config->getFuncsFixedWithLLVMIRFixer());
}

TEST_F(JSONConfigTests,
GetFuncsFixedWithLLVMIRFixerReturnsCorrectValueWhenThereAreFixedFuncs) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func1",
				"wasFixed": false
			},
			{
				"name": "my_func2",
				"wasFixed": true
			}
		]
	})");

	ASSERT_EQ(
		StringSet({"my_func2"}),
		config->getFuncsFixedWithLLVMIRFixer()
	);
}

//
// getClassNames()
//

TEST_F(JSONConfigTests,
GetClassNamesReturnsEmptySetWhenNoClassesWereFound) {
	auto config = JSONConfig::empty();

	ASSERT_EQ(StringSet(), config->getClassNames());
}

TEST_F(JSONConfigTests,
GetClassNamesReturnsCorrectNamesWhenClassesWereFound) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A"
			},
			{
				"name": "B"
			}
		]
	})");

	ASSERT_EQ(StringSet({"A", "B"}), config->getClassNames());
}

//
// getClassForFunc()
//

TEST_F(JSONConfigTests,
GetClassForFuncReturnsEmptyStringWhenFuncDoesNotBelongToAnyClass) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getClassForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetClassForFuncReturnsCorrectClassWhenFuncIsConstructor) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"constructors": ["my_func"]
			}
		]
	})");

	ASSERT_EQ("A", config->getClassForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetClassForFuncReturnsCorrectClassWhenFuncIsDestructor) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"destructors": ["my_func"]
			}
		]
	})");

	ASSERT_EQ("A", config->getClassForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetClassForFuncReturnsCorrectClassWhenFuncIsMemberFunc) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"methods": ["my_func"]
			}
		]
	})");

	ASSERT_EQ("A", config->getClassForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetClassForFuncReturnsCorrectClassWhenFuncIsVirtualMemberFunc) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"virtualMethods": ["my_func"]
			}
		]
	})");

	ASSERT_EQ("A", config->getClassForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetClassForFuncReturnsNameOfFirstClassWhenFuncBelongsToMultipleClasses) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"methods": ["my_func"]
			},
			{
				"name": "B",
				"methods": ["my_func"]
			}
		]
	})");

	ASSERT_EQ("A", config->getClassForFunc("my_func"));
}

//
// getTypeOfFuncInClass()
//

TEST_F(JSONConfigTests,
GetTypeOfFuncInClassReturnsEmptyStringWhenFuncDoesNotBelongToAnyClass) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getTypeOfFuncInClass("my_func", "A"));
}

TEST_F(JSONConfigTests,
GetTypeOfFuncInClassReturnsEmptyStringWhenFuncDoesNotBelongToGivenClass) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"constructors": ["A"]
			}
		]
	})");

	ASSERT_EQ("", config->getTypeOfFuncInClass("my_func", "A"));
}

TEST_F(JSONConfigTests,
GetTypeOfFuncInClassReturnsEmptyStringWhenFuncBelongsToDifferentClass) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "B",
				"constructors": ["my_func"]
			}
		]
	})");

	ASSERT_EQ("", config->getTypeOfFuncInClass("my_func", "A"));
}

TEST_F(JSONConfigTests,
GetTypeOfFuncInClassReturnsCorrectValueForConstructor) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"constructors": ["my_func"]
			}
		]
	})");

	ASSERT_EQ("constructor", config->getTypeOfFuncInClass("my_func", "A"));
}

TEST_F(JSONConfigTests,
GetTypeOfFuncInClassReturnsCorrectValueForDestructor) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"destructors": ["my_func"]
			}
		]
	})");

	ASSERT_EQ("destructor", config->getTypeOfFuncInClass("my_func", "A"));
}

TEST_F(JSONConfigTests,
GetTypeOfFuncInClassReturnsCorrectValueForMemberFunc) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"methods": ["my_func"]
			}
		]
	})");

	ASSERT_EQ("member function", config->getTypeOfFuncInClass("my_func", "A"));
}

TEST_F(JSONConfigTests,
GetTypeOfFuncInClassReturnsCorrectValueForVirtualMemberFunc) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"virtualMethods": ["my_func"]
			}
		]
	})");

	ASSERT_EQ(
		"virtual member function",
		config->getTypeOfFuncInClass("my_func", "A")
	);
}

//
// getBaseClassNames()
//

TEST_F(JSONConfigTests,
GetBaseClassNamesReturnsEmptyVectorWhenThereIsNoSuchClass) {
	auto config = JSONConfig::empty();

	ASSERT_EQ(StringVector(), config->getBaseClassNames("C"));
}

TEST_F(JSONConfigTests,
GetBaseClassNamesReturnsCorrectVectorWhenClassExists) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "C",
				"superClasses": ["B", "A"]
			}
		]
	})");

	// The order of the classes is important (it has to be preserved).
	ASSERT_EQ(StringVector({"B", "A"}), config->getBaseClassNames("C"));
}

//
// getDemangledNameOfClass()
//

TEST_F(JSONConfigTests,
GetDemangledNameOfClassReturnsEmptyStringWhenThereIsNoSuchClass) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getDemangledNameOfClass("A"));
}

TEST_F(JSONConfigTests,
GetDemangledNameOfClassReturnsEmptyStringWhenClassDoesNotHaveDemangedName) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A"
			}
		]
	})");

	ASSERT_EQ("", config->getDemangledNameOfClass("A"));
}

TEST_F(JSONConfigTests,
GetDemangledNameOfClassReturnsCorrectNameWhenClassHasDemangledName) {
	auto config = JSONConfig::fromString(R"({
		"classes": [
			{
				"name": "A",
				"demangledName": "DemangledA"
			}
		]
	})");

	ASSERT_EQ("DemangledA", config->getDemangledNameOfClass("A"));
}

//
// getDebugModuleNameForFunc()
//

TEST_F(JSONConfigTests,
GetDebugModuleNameForFuncReturnsEmptyStringWhenFuncDoesNotExist) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getDebugModuleNameForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetDebugModuleNameForFuncReturnsEmptyStringWhenDebugInfoIsNotAvailable) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func"
			}
		]
	})");

	ASSERT_EQ("", config->getDebugModuleNameForFunc("my_func"));
}

TEST_F(JSONConfigTests,
GetDebugModuleNameForFuncReturnsCorrectValueWhenDebugInfoIsAvailable) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"srcFileName": "module.c"
			}
		]
	})");

	ASSERT_EQ("module.c", config->getDebugModuleNameForFunc("my_func"));
}

//
// isDebugInfoAvailable()
//

TEST_F(JSONConfigTests,
IsDebugInfoAvailableReturnsFalseOnEmptyModule) {
	auto config = JSONConfig::empty();

	ASSERT_FALSE(config->isDebugInfoAvailable());
}

TEST_F(JSONConfigTests,
IsDebugInfoAvailableReturnsTrueWhenGlobalVariableHasNameAssignedFromDebugInfo) {
	auto config = JSONConfig::fromString(R"({
		"globals": [
			{
				"name": "h",
				"isFromDebug": true,
				"storage": {
					"type": "global",
					"value": "0"
				}
			}
		]
	})");

	ASSERT_TRUE(config->isDebugInfoAvailable());
}

TEST_F(JSONConfigTests,
IsDebugInfoAvailableReturnsTrueWhenLocalVariableHasNameAssignedFromDebugInfo) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"locals": [
					{
						"isFromDebug": false,
						"name": "v_408004",
						"realName": "v"
					}
				]
			}
		]
	})");

	ASSERT_TRUE(config->isDebugInfoAvailable());
}

TEST_F(JSONConfigTests,
IsDebugInfoAvailableReturnsTrueWhenLineNumbersAreAvailable) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"startLine": "1",
				"endLine": "10"
			}
		]
	})");

	ASSERT_TRUE(config->isDebugInfoAvailable());
}

TEST_F(JSONConfigTests,
IsDebugInfoAvailableReturnsTrueWhenParameterHasNameAssignedFromDebugInfo) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"parameters": [
					{
						"isFromDebug": false,
						"name": "a_408004",
						"realName": "a"
					}
				]
			}
		]
	})");

	ASSERT_TRUE(config->isDebugInfoAvailable());
}

TEST_F(JSONConfigTests,
IsDebugInfoAvailableReturnsTrueWhenFuncIsFromDebug) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"isFromDebug": true,
				"name": "my_func"
			}
		]
	})");

	ASSERT_TRUE(config->isDebugInfoAvailable());
}

TEST_F(JSONConfigTests,
IsDebugInfoAvailableReturnsTrueWhenFuncHasDebugModuleNameAvailable) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"srcFileName": "module1.c"
			}
		]
	})");

	ASSERT_TRUE(config->isDebugInfoAvailable());
}

//
// getDebugModuleNames()
//

TEST_F(JSONConfigTests,
GetDebugModuleNameReturnsEmptySetWhenThereAreNoFuncs) {
	auto config = JSONConfig::empty();

	ASSERT_EQ(StringSet(), config->getDebugModuleNames());
}

TEST_F(JSONConfigTests,
GetDebugModuleNamesReturnsCorrectSetWhenDebugInfoIsAvailable) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func1",
				"srcFileName": "module1.c"
			},
			{
				"name": "my_func2",
				"srcFileName": "module2.c"
			}
		]
	})");

	ASSERT_EQ(
		StringSet({"module1.c", "module2.c"}),
		config->getDebugModuleNames()
	);
}

//
// getDebugNameForGlobalVar()
//

TEST_F(JSONConfigTests,
GetDebugNameForGlobalVarReturnsEmptyStringWhenThereAreNoGlobalVars) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getDebugNameForGlobalVar("g_408004"));
}

TEST_F(JSONConfigTests,
GetDebugNameForGlobalVarReturnsEmptyStringWhenGlobalVariableDoesNotExist) {
	auto config = JSONConfig::fromString(R"({
		"globals": [
			{
				"isFromDebug": true,
				"name": "h_01",
				"realName": "h",
				"storage": {
					"type": "global",
					"value": "1"
				}
			}
		]
	})");

	ASSERT_EQ("", config->getDebugNameForGlobalVar("g_408004"));
}

TEST_F(JSONConfigTests,
GetDebugNameForGlobalVarReturnsEmptyStringWhenGlobalVariableIsNotFromDebugInfo) {
	auto config = JSONConfig::fromString(R"({
		"globals": [
			{
				"isFromDebug": false,
				"name": "g_408004",
				"realName": "g",
				"storage": {
					"type": "global",
					"value": "4227076"
				}
			}
		]
	})");

	ASSERT_EQ("", config->getDebugNameForGlobalVar("g_408004"));
}

TEST_F(JSONConfigTests,
GetDebugNameForGlobalVarReturnsCorrectValueWhenGlobalVarHasAssignedDebugName) {
	auto config = JSONConfig::fromString(R"({
		"globals": [
			{
				"isFromDebug": true,
				"name": "g_408004",
				"realName": "g",
				"storage": {
					"type": "global",
					"value": "4227076"
				}
			}
		]
	})");

	ASSERT_EQ("g", config->getDebugNameForGlobalVar("g_408004"));
}

//
// getDebugNameForLocalVar()
//

TEST_F(JSONConfigTests,
GetDebugNameForLocalVarReturnsEmptyStringWhenFuncDoesNotExist) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getDebugNameForLocalVar("my_func", "v_408004"));
}

TEST_F(JSONConfigTests,
GetDebugNameForLocalVarReturnsEmptyStringWhenLocalVariableDoesNotExist) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func"
			}
		]
	})");

	ASSERT_EQ("", config->getDebugNameForLocalVar("my_func", "v_408004"));
}

TEST_F(JSONConfigTests,
GetDebugNameForLocalVarReturnsEmptyStringWhenLocalVariableIsNotFromDebugInfo) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"locals": [
					{
						"isFromDebug": false,
						"name": "v_408004",
						"realName": "v"
					}
				]
			}
		]
		})");

	ASSERT_EQ("", config->getDebugNameForLocalVar("my_func", "v_408004"));
}

TEST_F(JSONConfigTests,
GetDebugNameForLocalVarReturnsCorrectValueWhenLocalVarHasAssignedDebugName) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"locals": [
					{
						"isFromDebug": true,
						"name": "v_408004",
						"realName": "v"
					}
				]
			}
		]
	})");

	ASSERT_EQ("v", config->getDebugNameForLocalVar("my_func", "v_408004"));
}

TEST_F(JSONConfigTests,
GetDebugNameForLocalVarReturnsCorrectValueWhenLocalVarIsParameterWithAssignedDebugName) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "my_func",
				"parameters": [
					{
						"isFromDebug": true,
						"name": "a_408004",
						"realName": "a"
					}
				]
			}
		]
	})");

	ASSERT_EQ("a", config->getDebugNameForLocalVar("my_func", "a_408004"));
}

//
// getPrefixesOfFuncsToBeRemoved()
//

TEST_F(JSONConfigTests,
GetPrefixesOfFuncsToBeRemovedReturnsEmptySetWhenThereAreNoPrefixes) {
	auto config = JSONConfig::empty();

	ASSERT_EQ(StringSet(), config->getPrefixesOfFuncsToBeRemoved());
}

TEST_F(JSONConfigTests,
GetPrefixesOfFuncsToBeRemovedReturnsCorrectValueWhenThereArePrefixes) {
	auto config = JSONConfig::fromString(R"({
		"decompParams": {
			"frontendFunctions": [
				"prefix1",
				"prefix2"
			]
		}
	})");

	ASSERT_EQ(
		StringSet({"prefix1", "prefix2"}),
		config->getPrefixesOfFuncsToBeRemoved()
	);
}

//
// getFrontendRelease()
//

TEST_F(JSONConfigTests,
GetFrontendReleaseReturnsEmptyStringWhenThereIsNoRelease) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getFrontendRelease());
}

TEST_F(JSONConfigTests,
GetFrontendReleaseReturnsCorrectStringWhenReleaseIsSet) {
	auto config = JSONConfig::fromString(R"({
		"frontendVersion": "v1.0"
	})");

	ASSERT_EQ("v1.0", config->getFrontendRelease());
}

//
// getNumberOfFuncsDetectedInFrontend()
//

TEST_F(JSONConfigTests,
GetNumberOfFuncsDetectedInFrontendReturnsZeroWhenThereAreNoDetectedFuncs) {
	auto config = JSONConfig::empty();

	ASSERT_EQ(0, config->getNumberOfFuncsDetectedInFrontend());
}

TEST_F(JSONConfigTests,
GetNumberOfFuncsDetectedInFrontendReturnsCorrectValueWhenThereAreDetectedFuncs) {
	auto config = JSONConfig::fromString(R"({
		"functions": [
			{
				"name": "func1"
			},
			{
				"name": "func2"
			}
		]
	})");

	ASSERT_EQ(2, config->getNumberOfFuncsDetectedInFrontend());
}

//
// getDetectedCompilerOrPacker()
//

TEST_F(JSONConfigTests,
GetDetectedCompilerOrPackerReturnsEmptyStringWhenThereIsNoCompilerOrPacker) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getDetectedCompilerOrPacker());
}

TEST_F(JSONConfigTests,
GetDetectedCompilerOrPackerReturnsCorrectValueWhenCompilerWithVersionIsDetected) {
	// The additional attributes (like "heuristics") is here only because the
	// config is unable to parse a non-complete tool info.
	auto config = JSONConfig::fromString(R"({
		"tools": [
			{
				"name": "gcc",
				"version": "4.7.3",

				"heuristics": false,
				"identicalSignificantNibbles": 169,
				"percentage": 100,
				"totalSignificantNibbles": 169
			}
		]
	})");

	ASSERT_EQ("gcc (4.7.3)", config->getDetectedCompilerOrPacker());
}

TEST_F(JSONConfigTests,
GetDetectedCompilerOrPackerReturnsCorrectValueWhenCompilerWithoutVersionIsDetected) {
	// The additional attributes (like "heuristics") is here only because the
	// config is unable to parse a non-complete tool info.
	auto config = JSONConfig::fromString(R"({
		"tools": [
			{
				"name": "gcc",
				"version": "",

				"heuristics": false,
				"identicalSignificantNibbles": 169,
				"percentage": 100,
				"totalSignificantNibbles": 169
			}
		]
	})");

	ASSERT_EQ("gcc", config->getDetectedCompilerOrPacker());
}

//
// getDetectedLanguage()
//

TEST_F(JSONConfigTests,
GetDetectedLanguageReturnsEmptyStringWhenThereIsNoLanguage) {
	auto config = JSONConfig::empty();

	ASSERT_EQ("", config->getDetectedLanguage());
}

TEST_F(JSONConfigTests,
GetDetectedLanguageReturnsCorrectValueWhenOneLanguageIsDetected) {
	auto config = JSONConfig::fromString(R"({
		"languages": [
			{
				"name": "C"
			}
		]
	})");

	ASSERT_EQ("C", config->getDetectedLanguage());
}

TEST_F(JSONConfigTests,
GetDetectedLanguageReturnsCorrectValueWhenTwoLanguagesAreDetected) {
	auto config = JSONConfig::fromString(R"({
		"languages": [
			{
				"name": "C++"
			},
			{
				"name": "C"
			}
		]
	})");

	ASSERT_EQ("C, C++", config->getDetectedLanguage());
}

TEST_F(JSONConfigTests,
GetDetectedLanguageReturnsCorrectValueWhenBytecodeLanguageIsDetected) {
	auto config = JSONConfig::fromString(R"({
		"languages": [
			{
				"name": "C#",
				"bytecode": true
			}
		]
	})");

	ASSERT_EQ("C# (bytecode)", config->getDetectedLanguage());
}

TEST_F(JSONConfigTests,
GetDetectedLanguageReturnsCorrectValueWhenNumberOfModulesIsSet) {
	auto config = JSONConfig::fromString(R"({
		"languages": [
			{
				"name": "C",
				"moduleCount": 3
			}
		]
	})");

	ASSERT_EQ("C (3 modules)", config->getDetectedLanguage());
}

TEST_F(JSONConfigTests,
GetDetectedLanguageDoesNotIncludeTrailingSWhenOnlyOneModuleIsDetected) {
	auto config = JSONConfig::fromString(R"({
		"languages": [
			{
				"name": "C",
				"moduleCount": 1
			}
		]
	})");

	ASSERT_EQ("C (1 module)", config->getDetectedLanguage());
}

//
// getSelectedButNotFoundFuncs()
//

TEST_F(JSONConfigTests,
GetSelectedButNotFoundFuncsReturnsEmptySetWhenThereIsNoSuchFunc) {
	auto config = JSONConfig::empty();

	ASSERT_EQ(StringSet(), config->getSelectedButNotFoundFuncs());
}

TEST_F(JSONConfigTests,
GetSelectedButNotFoundFuncsReturnsCorrectValueWhenSuchFuncsExist) {
	auto config = JSONConfig::fromString(R"({
		"decompParams": {
			"selectedNotFoundFncs": [
				"func1",
				"func2"
			]
		}
	})");

	ASSERT_EQ(
		StringSet({"func1", "func2"}),
		config->getSelectedButNotFoundFuncs()
	);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
