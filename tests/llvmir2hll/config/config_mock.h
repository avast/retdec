/**
* @file tests/llvmir2hll/config/config_mock.h
* @brief A mock for Config.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_CONFIG_TESTS_CONFIG_MOCK_H
#define BACKEND_BIR_CONFIG_TESTS_CONFIG_MOCK_H

#include <gmock/gmock.h>

#include "retdec/llvmir2hll/config/config.h"

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief A mock for Config.
*/
class ConfigMock: public Config {
public:
	MOCK_METHOD1(saveTo, void (const std::string &));
	MOCK_METHOD0(dump, void ());
	MOCK_CONST_METHOD1(isGlobalVarStoringWideString, bool (const std::string &));
	MOCK_CONST_METHOD2(comesFromGlobalVar, std::string (const std::string &, const std::string &));
	MOCK_CONST_METHOD1(getRegisterForGlobalVar, std::string (const std::string &));
	MOCK_CONST_METHOD1(getDetectedCryptoPatternForGlobalVar, std::string (const std::string &));
	MOCK_CONST_METHOD1(getAddressRangeForFunc, AddressRange (const std::string &));
	MOCK_CONST_METHOD1(getLineRangeForFunc, LineRange (const std::string &));
	MOCK_CONST_METHOD1(isUserDefinedFunc, bool (const std::string &));
	MOCK_CONST_METHOD1(isStaticallyLinkedFunc, bool (const std::string &));
	MOCK_CONST_METHOD1(isDynamicallyLinkedFunc, bool (const std::string &));
	MOCK_CONST_METHOD1(isSyscallFunc, bool (const std::string &));
	MOCK_CONST_METHOD1(isInstructionIdiomFunc, bool (const std::string &));
	MOCK_CONST_METHOD1(isExportedFunc, bool (const std::string &));
	MOCK_METHOD1(markFuncAsStaticallyLinked, void (const std::string &));
	MOCK_CONST_METHOD1(getRealNameForFunc, std::string (const std::string &func));
	MOCK_CONST_METHOD1(getDeclarationStringForFunc, std::string (const std::string &));
	MOCK_CONST_METHOD1(getCommentForFunc, std::string (const std::string &));
	MOCK_CONST_METHOD1(getDetectedCryptoPatternsForFunc, StringSet (const std::string &));
	MOCK_CONST_METHOD1(getWrappedFunc, std::string (const std::string &));
	MOCK_CONST_METHOD1(getDemangledNameOfFunc, std::string (const std::string &));
	MOCK_CONST_METHOD0(getFuncsFixedWithLLVMIRFixer, StringSet ());
	MOCK_CONST_METHOD0(getClassNames, StringSet ());
	MOCK_CONST_METHOD1(getClassForFunc, std::string (const std::string &));
	MOCK_CONST_METHOD2(getTypeOfFuncInClass, std::string (const std::string &, const std::string &));
	MOCK_CONST_METHOD1(getBaseClassNames, StringVector (const std::string &));
	MOCK_CONST_METHOD1(getDemangledNameOfClass, std::string (const std::string &));
	MOCK_CONST_METHOD1(getDebugModuleNameForFunc, std::string (const std::string &));
	MOCK_CONST_METHOD0(isDebugInfoAvailable, bool ());
	MOCK_CONST_METHOD0(getDebugModuleNames, StringSet ());
	MOCK_CONST_METHOD1(getDebugNameForGlobalVar, std::string (const std::string &));
	MOCK_CONST_METHOD2(getDebugNameForLocalVar, std::string (const std::string &,
		const std::string &));
	MOCK_CONST_METHOD0(getPrefixesOfFuncsToBeRemoved, StringSet ());
	MOCK_CONST_METHOD0(getFrontendRelease, std::string ());
	MOCK_CONST_METHOD0(getNumberOfFuncsDetectedInFrontend, std::size_t ());
	MOCK_CONST_METHOD0(getDetectedCompilerOrPacker, std::string ());
	MOCK_CONST_METHOD0(getDetectedLanguage, std::string ());
	MOCK_CONST_METHOD0(getSelectedButNotFoundFuncs, StringSet ());
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

/**
* @brief Instantiates ConfigMock with the given name.
*
* More specifically, this macro instantiates two classes:
*  (1) @c configNameMock, which is of type
*      @code
*      ::testing::NiceMock<ConfigMock> *
*      @endcode
*  (2) @c configName, which is of type
*      @code
*      ShPtr<Config>
*      @endcode
*      and delegates to the mock from (1).
*/
#define INSTANTIATE_CONFIG_MOCK(configName) \
	::testing::NiceMock<ConfigMock> *configName##Mock = \
		new ::testing::NiceMock<ConfigMock>(); \
	ShPtr<Config> configName(configName##Mock);

#endif
