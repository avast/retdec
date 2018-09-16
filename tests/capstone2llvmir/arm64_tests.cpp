/**
 * @file tests/capstone2llvmir/arm64_tests.cpp
 * @brief Capstone2LlvmIrTranslatorArm64 unit tests.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/InstIterator.h>

#include "capstone2llvmir/capstone2llvmir_tests.h"
#include "retdec/capstone2llvmir/arm64/arm64.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace capstone2llvmir {
namespace tests {

class Capstone2LlvmIrTranslatorArm64Tests :
		public Capstone2LlvmIrTranslatorTests,
		public ::testing::WithParamInterface<cs_mode>
{
	protected:
		virtual void initKeystoneEngine() override
		{
			ks_mode mode = KS_MODE_ARM;
			switch(GetParam())
			{
				// Basic modes.
				case CS_MODE_ARM: mode = KS_MODE_LITTLE_ENDIAN; break;
				// Extra modes.
				case CS_MODE_MCLASS: mode = KS_MODE_LITTLE_ENDIAN; break; // Missing in Keystone.
				case CS_MODE_V8: mode = KS_MODE_V8; break;
				// Unhandled modes.
				default: throw std::runtime_error("ERROR: unknown mode.\n");
			}
			if (ks_open(KS_ARCH_ARM64, mode, &_assembler) != KS_ERR_OK)
			{
				throw std::runtime_error("ERROR: failed on ks_open().\n");
			}
		}

		virtual void initCapstone2LlvmIrTranslator() override
		{
			switch(GetParam())
			{
				case CS_MODE_ARM:
					_translator = Capstone2LlvmIrTranslator::createArm64(&_module);
					break;
				default:
					throw std::runtime_error("ERROR: unknown mode.\n");
			}
		}

};

struct PrintCapstoneModeToString_Arm64
{
	template <class ParamType>
	std::string operator()(const TestParamInfo<ParamType>& info) const
	{
		switch (info.param)
		{
			case CS_MODE_ARM: return "CS_MODE_ARM";
			case CS_MODE_MCLASS: return "CS_MODE_MCLASS";
			case CS_MODE_V8: return "CS_MODE_V8";
			default: return "UNHANDLED CS_MODE";
		}
	}
};

INSTANTIATE_TEST_CASE_P(
		InstantiateArm64WithAllModes,
		Capstone2LlvmIrTranslatorArm64Tests,
		::testing::Values(CS_MODE_ARM),
		 PrintCapstoneModeToString_Arm64());

//
// ARM64_INS_ADD
//

TEST_P(Capstone2LlvmIrTranslatorArm64Tests, ARM64_INS_ADD_r_r_i)
{

	setRegisters({
		{ARM64_REG_X1, 0x1230},
	});

	emulate("add x0, x1, #3");

	EXPECT_JUST_REGISTERS_LOADED({ARM64_REG_X1});
	EXPECT_JUST_REGISTERS_STORED({{ARM64_REG_X0, 0x1233},});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM64_INS_MOV
//

TEST_P(Capstone2LlvmIrTranslatorArm64Tests, ARM64_INS_MOV_r_r)
{
	setRegisters({
		{ARM64_REG_X1, 0xcafebabecafebabe},
	});

	emulate("mov x0, x1");

	EXPECT_JUST_REGISTERS_LOADED({ARM64_REG_X1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM64_REG_X0, 0xcafebabecafebabe},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArm64Tests, ARM64_INS_MOVZ_r_i)
{
	setRegisters({
		{ARM64_REG_X0, 0xcafebabecafebabe},
	});

	emulate("mov x0, #0xa");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{ARM64_REG_X0, 0xa},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArm64Tests, ARM64_INS_MVN_r_r)
{
	setRegisters({
		{ARM64_REG_X1, 0x0123456789abcdef},
	});

	emulate("mvn x0, x1");

	EXPECT_JUST_REGISTERS_LOADED({ARM64_REG_X1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM64_REG_X0, 0xfedcba9876543210},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

} // namespace tests
} // namespace capstone2llvmir
} // namespace retdec
