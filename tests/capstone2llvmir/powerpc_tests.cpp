/**
 * @file tests/capstone2llvmir/powerpc_tests.cpp
 * @brief Capstone2LlvmIrTranslatorPowerpc unit tests.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/InstIterator.h>

#include "capstone2llvmir/capstone2llvmir_tests.h"
#include "retdec/capstone2llvmir/powerpc/powerpc.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace capstone2llvmir {
namespace tests {

class Capstone2LlvmIrTranslatorPowerpcTests :
		public Capstone2LlvmIrTranslatorTests,
		public ::testing::WithParamInterface<cs_mode>
{
	protected:
		virtual void initKeystoneEngine() override
		{
			ks_mode mode = KS_MODE_PPC32;
			switch(GetParam())
			{
				case CS_MODE_32: mode = KS_MODE_PPC32; break;
				case CS_MODE_64: mode = KS_MODE_PPC64; break;
				case CS_MODE_QPX: mode = KS_MODE_QPX; break;
				default: throw std::runtime_error("ERROR: unknown mode.\n");
			}
			if (ks_open(KS_ARCH_PPC, mode | KS_MODE_BIG_ENDIAN, &_assembler) != KS_ERR_OK)
			{
				throw std::runtime_error("ERROR: failed on ks_open().\n");
			}
		}

		virtual void initCapstone2LlvmIrTranslator() override
		{
			switch(GetParam())
			{
				case CS_MODE_32:
					_translator = Capstone2LlvmIrTranslator::createPpc32(
							&_module,
							CS_MODE_BIG_ENDIAN);
					break;
				case CS_MODE_64:
					_translator = Capstone2LlvmIrTranslator::createPpc64(
							&_module,
							CS_MODE_BIG_ENDIAN);
					break;
				case CS_MODE_QPX:
					_translator = Capstone2LlvmIrTranslator::createPpcQpx(
							&_module,
							CS_MODE_BIG_ENDIAN);
					break;
				default:
					throw std::runtime_error("ERROR: unknown mode.\n");
			}
		}

		// These can/should be used at the beginning of each test case to
		// determine which modes should the case be run for.
		// They are macros because we want them to cause return in the current
		// function (test case).
		//
		protected:
#define ALL_MODES
#define ONLY_MODE_32 if (GetParam() != CS_MODE_32) return;
#define ONLY_MODE_64 if (GetParam() != CS_MODE_64) return;
#define ONLY_MODE_QPX if (GetParam() != CS_MODE_QPX) return;
#define SKIP_MODE_32 if (GetParam() == CS_MODE_32) return;
#define SKIP_MODE_64 if (GetParam() == CS_MODE_64) return;
#define SKIP_MODE_QPX if (GetParam() == CS_MODE_QPX) return;
};

struct PrintCapstoneModeToString_Powerpc
{
	template <class ParamType>
	std::string operator()(const TestParamInfo<ParamType>& info) const
	{
		switch (info.param)
		{
			case CS_MODE_16: return "CS_MODE_16";
			case CS_MODE_32: return "CS_MODE_32";
			case CS_MODE_64: return "CS_MODE_64";
			case CS_MODE_QPX: return "CS_MODE_QPX";
			default: return "UNHANDLED CS_MODE";
		}
	}
};

// By default, all the test cases are run with all the modes.
// If some test case is not meant for all modes, use some of the ONLY_MODE_*,
// SKIP_MODE_* macros.
//
INSTANTIATE_TEST_CASE_P(
		InstantiatePowerpcWithAllModes,
		Capstone2LlvmIrTranslatorPowerpcTests,
		::testing::Values(CS_MODE_32, CS_MODE_64),
		 PrintCapstoneModeToString_Powerpc());

//
// PPC_INS_ADD
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADD)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x1111},
		{PPC_REG_R1, 0x2222},
	});

	emulate("add 0, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x3333},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADD_dot_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x0},
		{PPC_REG_R1, 0x0},
	});

	emulate("add. 0, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x0},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, true},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADD_dot_negative)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R0, 0xffff0000},
		{PPC_REG_R1, 0x00001234},
	});

	emulate("add. 0, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, ANY},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADD_dot_postitive)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x1111},
		{PPC_REG_R1, 0x2222},
	});

	emulate("add. 0, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x3333},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ADDI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDI)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1111},
	});

	emulate("addi 0, 1, 0x2222");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x3333},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LA
// 1. and 2. operands are reversed, but it probbaly does not matter.
// la 0, 0x4, 1 (reg, imm, reg) == addi 0, 1, 0x4 (reg, reg, imm)
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LA)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1111},
	});

	emulate("la 0, 0x2222, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x3333},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ADDIS
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDIS)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1111},
	});

	emulate("addis 0, 1, 0x2222");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x22221111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ADDIC
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDIC_32_true)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
	});

	emulate("addic 0, 1, 0xff");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfe}, // 0xffffffff + 0xff = 0x01 | 00 00 00 fe
		{PPC_REG_CARRY, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDIC_64_true)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0xffffffffffffffff},
	});

	emulate("addic 0, 1, 0xff");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfe}, // 0xffffffffffffffff + 0xff = 0x01 | 00 00 00 00 00 00 00 fe
		{PPC_REG_CARRY, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDIC_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1200},
	});

	emulate("addic 0, 1, 0x34");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234},
		{PPC_REG_CARRY, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDIC_dot_32_true)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
	});

	emulate("addic. 0, 1, 0xff");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfe}, // 0xffffffff + 0xff = 0x01 | 00 00 00 fe
		{PPC_REG_CARRY, true},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ADDC
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDC_32_true)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0xff},
	});

	emulate("addc 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfe}, // 0xffffffff + 0xff = 0x01 | 00 00 00 fe
		{PPC_REG_CARRY, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDC_64_true)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0xffffffffffffffff},
		{PPC_REG_R2, 0xff},
	});

	emulate("addc 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfe}, // 0xffffffffffffffff + 0xff = 0x01 | 00 00 00 00 00 00 00 fe
		{PPC_REG_CARRY, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDC_dot_32_true)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0xff},
	});

	emulate("addc. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfe}, // 0xffffffff + 0xff = 0x01 | 00 00 00 fe
		{PPC_REG_CARRY, true},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ADDE
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDE_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_R2, 0x5670},
		{PPC_REG_CARRY, true},
	});

	emulate("adde 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12345671},
		{PPC_REG_CARRY, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDE_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_R2, 0x5670},
		{PPC_REG_CARRY, false},
	});

	emulate("adde 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12345670},
		{PPC_REG_CARRY, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDE_dot_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_R2, 0x5670},
		{PPC_REG_CARRY, true},
	});

	emulate("adde. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12345671},
		{PPC_REG_CARRY, false},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ADDZE
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDZE_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_CARRY, true},
	});

	emulate("addze 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12340001},
		{PPC_REG_CARRY, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDZE_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_CARRY, false},
	});

	emulate("addze 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12340000},
		{PPC_REG_CARRY, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDZE_dot_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_CARRY, true},
	});

	emulate("addze. 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12340001},
		{PPC_REG_CARRY, false},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ADDME
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDME_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_CARRY, true},
	});

	emulate("addme 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12340000},
		{PPC_REG_CARRY, true}, // TODO: I'm not sure about this, check it somehow.
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDME_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340001},
		{PPC_REG_CARRY, false},
	});

	emulate("addme 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12340000},
		{PPC_REG_CARRY, true}, // TODO: I'm not sure about this, check it somehow.
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ADDME_dot_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_CARRY, true},
	});

	emulate("addme. 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12340000},
		{PPC_REG_CARRY, true}, // TODO: I'm not sure about this, check it somehow.
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_AND
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_AND)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0x10203040},
	});

	emulate("and 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x10203040},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_AND_dot)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0x10203040},
	});

	emulate("and. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x10203040},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ANDI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ANDI_dot)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
	});

	emulate("andi. 0, 1, 0xf0f0");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xf0f0},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ANDC
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ANDC)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("andc 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xf0f0f0f0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ANDC_dot)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("andc. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xf0f0f0f0},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ANDIS
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ANDIS_dot)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
	});

	emulate("andis. 0, 1, 0xffff");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffff0000},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_OR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_OR)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("or 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1f3f0f0f},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_OR_dot)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("or. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1f3f0f0f},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ORI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ORI)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
	});

	emulate("ori 0, 1, 0xf0f0");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234f0f0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ORC
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ORC)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0xf0f0f0f0},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("andc 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xf0f0f0f0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ORC_dot)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0xf0f0f0f0},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("orc. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xf0f0f0f0},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ORIS
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ORIS)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x10203456},
	});

	emulate("oris 0, 1, 0xffff");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffff3456},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_XOR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_XOR)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("xor 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xf0f0f0f0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_XOR_dot)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("xor. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xf0f0f0f0},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_XORI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_XORI)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1234ffff},
	});

	emulate("xori 0, 1, 0xf0f0");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12340f0f},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_XORIS
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_XORIS)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x10203456},
	});

	emulate("xoris 0, 1, 0xffff");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xefdf3456},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_NOR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NOR_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("nor 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xe0c0f0f0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NOR_64)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("nor 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffffffe0c0f0f0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NOR_dot_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12340000},
		{PPC_REG_R2, 0x0f0f0f0f},
	});

	emulate("nor. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xe0c0f0f0},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_NOT
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NOT)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
	});

	emulate("not 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xEDCBA987},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_NOP
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NOP)
{
	ALL_MODES;

	emulate("nop");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_NEG
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NEG_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
	});

	emulate("neg 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xedcba988},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NEG_dot_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
	});

	emulate("neg. 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xedcba988},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NEG_64)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x0123456789abcdef},
	});

	emulate("neg 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfedcba9876543211},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NEG_dot_64)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x0123456789abcdef},
	});

	emulate("neg. 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfedcba9876543211},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_NAND
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NAND_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0x10203040},
	});

	emulate("nand 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xefdfcfbf},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NAND_64)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0x10203040},
	});

	emulate("nand 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffffffefdfcfbf},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_NAND_dot)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0xffffffff},
		{PPC_REG_R2, 0x10203040},
	});

	emulate("nand. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xefdfcfbf},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_SUBF
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBF)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_R2, 0x1111},
	});

	emulate("subf 0, 2, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBF_dot)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_R2, 0x2222},
	});

	emulate("subf. 0, 2, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x0},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, true},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_SUBFC
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFC_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_R2, 0x1111},
	});

	emulate("subfc 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffeeef},
		{PPC_REG_CARRY, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFC_dot_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_R2, 0x1111},
	});

	emulate("subfc. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffeeef},
		{PPC_REG_CARRY, false},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_SUBFIC
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFIC_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
	});

	emulate("subfic 0, 1, 0x1111");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffeeef},
		{PPC_REG_CARRY, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_SUBFE
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFE_32_carry_true)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_R2, 0x1111},
		{PPC_REG_CARRY, true},
	});

	emulate("subfe 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffeeef},
		{PPC_REG_CARRY, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFE_32_carry_false)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_R2, 0x1111},
		{PPC_REG_CARRY, false},
	});

	emulate("subfe 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffeeee},
		{PPC_REG_CARRY, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFE_dot_32_carry_true)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_R2, 0x1111},
		{PPC_REG_CARRY, true},
	});

	emulate("subfe. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffeeef},
		{PPC_REG_CARRY, false},
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_SUBFME
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFME_32_carry_true)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_CARRY, true},
	});

	emulate("subfme 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffdddd},
		{PPC_REG_CARRY, true}, // ???
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFME_32_carry_false)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_CARRY, false},
	});

	emulate("subfme 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffdddc},
		{PPC_REG_CARRY, true}, // ???
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFME_32_dot_carry_true)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_CARRY, true},
	});

	emulate("subfme. 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffdddd},
		{PPC_REG_CARRY, true}, // ???
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_SUBFZE
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFZE_32_carry_true)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_CARRY, true},
	});

	emulate("subfze 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffddde},
		{PPC_REG_CARRY, false}, // ???
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFZE_32_carry_false)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_CARRY, false},
	});

	emulate("subfze 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffdddd},
		{PPC_REG_CARRY, false}, // ???
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SUBFZE_dot_32_carry_true)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_CARRY, true},
	});

	emulate("subfze. 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_CARRY});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffddde},
		{PPC_REG_CARRY, false}, // ???
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_MULLI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MULLI)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x2222},
	});

	emulate("mulli 0, 1, 0x123");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x26cca6},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_MULLW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MULLW)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_R2, 0x123},
	});

	emulate("mullw 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x26cca6},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MULLW_dot)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x2222},
		{PPC_REG_R2, 0x123},
	});

	emulate("mullw. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x26cca6},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_MULHW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MULHW)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x11111111},
		{PPC_REG_R2, 0x22222222},
	});

	emulate("mulhw 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x02468acf}, // 0x02 46 8a cf | 0e ca 86 42
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MULHW_dot)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x11111111},
		{PPC_REG_R2, 0x22222222},
	});

	emulate("mulhw. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x02468acf}, // 0x02 46 8a cf | 0e ca 86 42
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_MULHWU
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MULHWU)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x11111111},
		{PPC_REG_R2, 0x22222222},
	});

	emulate("mulhwu 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x02468acf}, // 0x02 46 8a cf | 0e ca 86 42
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MULHWU_dot)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x11111111},
		{PPC_REG_R2, 0x22222222},
	});

	emulate("mulhwu. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x02468acf}, // 0x02 46 8a cf | 0e ca 86 42
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_DIVW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_DIVW)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
		{PPC_REG_R2, 0xabcd},
	});

	emulate("divw 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1b20},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_DIVW_dot)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
		{PPC_REG_R2, 0xabcd},
	});

	emulate("divw. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1b20},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_DIVWU
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_DIVWU)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
		{PPC_REG_R2, 0xabcd},
	});

	emulate("divwu 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1b20},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_DIVWU_dot)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
		{PPC_REG_R2, 0xabcd},
	});

	emulate("divwu. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1b20},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_EQV
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EQV)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
		{PPC_REG_R2, 0x87654321},
	});

	emulate("eqv 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x6aaeeaa6},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EQV_dot)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
		{PPC_REG_R2, 0x87654321},
	});

	emulate("eqv. 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x6aaeeaa6},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CNTLZW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CNTLZW_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0xffffffffffffffff},
	});

	emulate("cntlzw 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CNTLZW_dot_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0xffffffffffffffff},
	});

	emulate("cntlzw. 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x0},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, true},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CNTLZW_non_zero_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x0000ffff},
	});

	emulate("cntlzw 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 16},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_EXTSB
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EXTSB_zero_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12345678}, // last byte = 01111000
	});

	emulate("extsb 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x78},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EXTSB_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x123456f8}, // last byte = 11111000
	});

	emulate("extsb 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfffffff8},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EXTSB_zero_dot_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12345678}, // last byte = 01111000
	});

	emulate("extsb. 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x78},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_EXTSH
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EXTSH_zero_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12347856}, // last word = 01111000 ...
	});

	emulate("extsh 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x7856},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EXTSH_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x1234f856}, // last word = 11111000 ...
	});

	emulate("extsh 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfffff856},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EXTSH_zero_dot_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12347856}, // last word = 01111000 ...
	});

	emulate("extsh. 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x7856},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_EXTSW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EXTSW_zero_32)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x1234567878123456}, // last dword = 01111000 ...
	});

	emulate("extsw 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x78123456},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EXTSW_32)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x12345678f8123456}, // last dword = 11111000 ...
	});

	emulate("extsw 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xfffffffff8123456},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_EXTSW_zero_dot_32)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x1234567878123456}, // last dword = 01111000 ...
	});

	emulate("extsw. 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x78123456},
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_RLWINM
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_RLWINM)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1234},
	});

	emulate("rlwinm 0, 1, 0x4, 0x2, 0x5");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_rlwinm"), {0x1234, 0x4, 0x2, 0x5}},
	});
}

//
// PPC_INS_RLWIMI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_RLWIMI)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1234},
	});

	emulate("rlwimi 0, 1, 0x4, 0x2, 0x5");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_rlwimi"), {0x1234, 0x4, 0x2, 0x5}},
	});
}

//
// PPC_INS_RLWNM
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_RLWNM)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1234},
		{PPC_REG_R2, 0x4},
	});

	emulate("rlwnm 0, 1, 2, 0x2, 0x5");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_rlwnm"), {0x1234, 0x4, 0x2, 0x5}},
	});
}

//
// PPC_INS_SLW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SLW)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
		{PPC_REG_R2, 0x12345690}, // last byte = 10|010000 = 144 -> (6 bits) 16
	});

	emulate("slw 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x56780000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_SRW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SRW)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
		{PPC_REG_R2, 0x12345690}, // last byte = 10|010000 = 144 -> (6 bits) 16
	});

	emulate("srw 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x00001234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_SRAW
//

// TODO
//TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SRAW)
//{
//	ALL_MODES;
//
//	setRegisters({
//		{PPC_REG_R1, 0x1234},
//		{PPC_REG_R2, 0x5678},
//	});
//
//	emulate("sraw 0, 1, 2");
//
//	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
//	EXPECT_JUST_REGISTERS_STORED({
//		{PPC_REG_R0, ANY},
//		{PPC_REG_CARRY, ANY},
//	});
//	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_module.getFunction("__asm_sraw"), {0x1234, 0x5678}},
//	});
//}

//
// PPC_INS_SRAWI
//

// TODO
//TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SRAWI)
//{
//	ALL_MODES;
//
//	setRegisters({
//		{PPC_REG_R1, 0x1234},
//	});
//
//	emulate("srawi 0, 1, 0xf");
//
//	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
//	EXPECT_JUST_REGISTERS_STORED({
//		{PPC_REG_R0, ANY},
//		{PPC_REG_CARRY, ANY},
//	});
//	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_module.getFunction("__asm_srawi"), {0x1234, 0xf}},
//	});
//}

//
// PPC_INS_MR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MR)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R11, 0x1234},
	});

	emulate("mr 0, 11");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R11});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_MTCRF
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MTCRF)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1234},
	});

	emulate("mtcrf 0xf0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR0_LT, ANY},
		{PPC_REG_CR0_GT, ANY},
		{PPC_REG_CR0_EQ, ANY},
		{PPC_REG_CR0_SO, ANY},
		{PPC_REG_CR1, ANY},
		{PPC_REG_CR2, ANY},
		{PPC_REG_CR3, ANY},
		{PPC_REG_CR4, ANY},
		{PPC_REG_CR5, ANY},
		{PPC_REG_CR6, ANY},
		{PPC_REG_CR7, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_mtcrf"), {0xf0, 0x1234}},
	});
}

//
// PPC_INS_MTCTR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MTCTR)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R11, 0x1234},
	});

	emulate("mtctr 11");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R11});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_MTLR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MTLR)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R11, 0x1234},
	});

	emulate("mtlr 11");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R11});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CRAND
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CRAND)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x12},
		{PPC_REG_R2, 0x34},
		{PPC_REG_R3, 0x56},
	});

	emulate("crand 1, 2, 3");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2, PPC_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR0_LT, ANY},
		{PPC_REG_CR0_GT, ANY},
		{PPC_REG_CR0_EQ, ANY},
		{PPC_REG_CR0_SO, ANY},
		{PPC_REG_CR1, ANY},
		{PPC_REG_CR2, ANY},
		{PPC_REG_CR3, ANY},
		{PPC_REG_CR4, ANY},
		{PPC_REG_CR5, ANY},
		{PPC_REG_CR6, ANY},
		{PPC_REG_CR7, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_crand"), {0x12, 0x34, 0x56}},
	});
}

//
// PPC_INS_LBZ
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LBZ)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0x12_b},
	});

	emulate("lbz 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LBZ_zext)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0xff_b},
	});

	emulate("lbz 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xff},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LHZ
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHZ)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0x1234_w},
	});

	emulate("lhz 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LWZ
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LWZ)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0x12345678_dw},
	});

	emulate("lwz 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LBZU
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LBZU)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0x12_b},
	});

	emulate("lbzu 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LBZU_zext)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0xff_b},
	});

	emulate("lbzu 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xff},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LHZU
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHZU)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0x1234_w},
	});

	emulate("lhzu 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LWZU
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LWZU)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0x12345678_dw},
	});

	emulate("lwzu 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LBZX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LBZX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0x12_b},
	});

	emulate("lbzx 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LBZX_zext)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0xff_b},
	});

	emulate("lbzx 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xff},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LHZX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHZX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0x1234_w},
	});

	emulate("lhzx 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LWZX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LWZX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0x12345678_dw},
	});

	emulate("lwzx 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LBZUX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LBZUX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0x12_b},
	});

	emulate("lbzux 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LBZUX_zext)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0xff_b},
	});

	emulate("lbzux 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xff},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LHZUX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHZUX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0x1234_w},
	});

	emulate("lhzux 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LWZUX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LWZUX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0x12345678_dw},
	});

	emulate("lwzux 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LHA
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHA)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0x1234_w},
	});

	emulate("lha 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHA_sext_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0xff34_w},
	});

	emulate("lha 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffff34},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHA_sext_64)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0xff34_w},
	});

	emulate("lha 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffffffffffff34},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LHAU
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHAU)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0x1234_w},
	});

	emulate("lhau 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHAU_sext_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0xff34_w},
	});

	emulate("lhau 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffff34},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHAU_sext_64)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x1000},
	});
	setMemory({
		{0x1120, 0xff34_w},
	});

	emulate("lhau 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffffffffffff34},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LHAX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHAX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0x1234_w},
	});

	emulate("lhax 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHAX_sext_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0xff34_w},
	});

	emulate("lhax 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffff34},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHAX_sext_64)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0xff34_w},
	});

	emulate("lhax 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffffffffffff34},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LHAUX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHAUX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0x1234_w},
	});

	emulate("lhaux 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x1234},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHAUX_sext_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0xff34_w},
	});

	emulate("lhaux 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffff34},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHAUX_sext_64)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});
	setMemory({
		{0x1120, 0xff34_w},
	});

	emulate("lhaux 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0xffffffffffffff34},
		{PPC_REG_R1, 0x1120},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1120});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LHBRX
//

// TODO: Not working, maybe because of little vs big endian?
//
//TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LHBRX)
//{
//	ALL_MODES;
//
//	setRegisters({
//		{PPC_REG_R1, 0x1000},
//		{PPC_REG_R2, 0x120},
//	});
//	setMemory({
//		{0x1120, 0x12ff_w},
//	});
//
//	emulate("lhbrx 0, 1, 2");
//
//	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
//	EXPECT_JUST_REGISTERS_STORED({
//		{PPC_REG_R0, 0xff12},
//	});
//	EXPECT_JUST_MEMORY_LOADED({0x1120});
//	EXPECT_NO_MEMORY_STORED();
//	EXPECT_NO_VALUE_CALLED();
//}

//
// PPC_INS_LI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LI)
{
	ALL_MODES;

	emulate("li 11, 0x1234");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R11, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LIS
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LIS)
{
	ALL_MODES;

	emulate("lis 11, 0x1234");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R11, 0x12340000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_LWBRX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_LWBRX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});

	emulate("lwbrx 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_lwbrx"), {0x1000, 0x120}},
	});
}

//
// PPC_INS_MTSPR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MTSPR)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R1, 0x1234},
	});

	emulate("mtspr 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_mtspr"), {0, 0x1234}},
	});
}

//
// PPC_INS_MFSPR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MFSPR)
{
	ALL_MODES;

	emulate("mfspr 0, 0");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_mfspr"), {0}},
	});
}

//
// PPC_INS_MFCR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MFCR)
{
	ALL_MODES;

	emulate("mfcr 0");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_mfcr"), {}},
	});
}

//
// PPC_INS_MFCTR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MFCTR)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x1234},
	});

	emulate("mfctr 11");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R11, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_MFLR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MFLR)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x1234},
	});

	emulate("mflr 11");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R11, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_MCRF
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MCRF_same)
{
	ALL_MODES;

	emulate("mcrf 0, 0");

	EXPECT_NO_REGISTERS_LOADED_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MCRF_read_cr0)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, true},
		{PPC_REG_CR0_SO, false},
	});

	emulate("mcrf 4, 0");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT, PPC_REG_CR0_GT, PPC_REG_CR0_EQ, PPC_REG_CR0_SO});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR4, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_mcrf_cr0_read"), {true, false, true, false}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MCRF_write_cr0)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4, 0xa},
	});

	emulate("mcrf 0, 4");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR0_LT, ANY},
		{PPC_REG_CR0_GT, ANY},
		{PPC_REG_CR0_EQ, ANY},
		{PPC_REG_CR0_SO, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_mcrf_cr0_write"), {0xa}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_MCRF_other)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4, 0xa},
	});

	emulate("mcrf 2, 4");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_mcrf"), {0xa}},
	});
}

//
// PPC_INS_STHBRX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STHBRX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12},
		{PPC_REG_R4, 0x34},
		{PPC_REG_R5, 0x56},
	});

	emulate("sthbrx 0, 4, 5");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R4, PPC_REG_R5});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_sthbrx"), {0x12, 0x34, 0x56}},
	});
}

//
// PPC_INS_STWBRX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STWBRX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12},
		{PPC_REG_R4, 0x34},
		{PPC_REG_R5, 0x56},
	});

	emulate("stwbrx 0, 4, 5");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R4, PPC_REG_R5});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_stwbrx"), {0x12, 0x34, 0x56}},
	});
}

//
// PPC_INS_STB
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STB)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
	});

	emulate("stb 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x78_b}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STH
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STH)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
	});

	emulate("sth 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x5678_w}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STW)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
	});

	emulate("stw 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x12345678_w}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STBU
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STBU)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
	});

	emulate("stbu 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R1, 0x1120}
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x78_b}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STHU
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STHU)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
	});

	emulate("sthu 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R1, 0x1120}
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x5678_w}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STWU
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STWU)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
	});

	emulate("stwu 0, 0x120, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R1, 0x1120}
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x12345678_w}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STBX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STBX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});

	emulate("stbx 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1, PPC_REG_R2});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x78_b}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STHX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STHX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});

	emulate("sthx 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1, PPC_REG_R2});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x5678_w}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STWX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STWX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});

	emulate("stwx 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1, PPC_REG_R2});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x12345678_w}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STBUX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STBUX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});

	emulate("stbux 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R1, 0x1120}
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x78_b}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STHUX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STHUX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});

	emulate("sthux 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R1, 0x1120}
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x5678_w}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_STWUX
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_STWUX)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x12345678},
		{PPC_REG_R1, 0x1000},
		{PPC_REG_R2, 0x120},
	});

	emulate("stwux 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R1, 0x1120}
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1120, 0x12345678_w}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CMPD
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPD_lt)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x1111},
		{PPC_REG_R1, 0x2222},
	});

	emulate("cmpd 0, 1"); // cr0 is default

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPD_gt)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x3333},
		{PPC_REG_R1, 0x2222},
	});

	emulate("cmpd cr0, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPD_eq)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x2222},
		{PPC_REG_R1, 0x2222},
	});

	emulate("cmpd cr0, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, true},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPD_lt_sign_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R0, 0xffff0000},
		{PPC_REG_R1, 0x0},
	});

	emulate("cmpd cr0, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPD_lt_sign_64)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R0, 0xffff000000000000},
		{PPC_REG_R1, 0x0},
	});

	emulate("cmpd cr0, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPD_lt_cr7)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x1111},
		{PPC_REG_R1, 0x2222},
	});

	emulate("cmpd cr7, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR7_LT, true},
		{PPC_REG_CR7_GT, false},
		{PPC_REG_CR7_EQ, false},
		{PPC_REG_CR7_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CMPDI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPDI_lt_cr7)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x1111},
	});

	emulate("cmpdi cr7, 0, 0x2222");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR7_LT, true},
		{PPC_REG_CR7_GT, false},
		{PPC_REG_CR7_EQ, false},
		{PPC_REG_CR7_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CMPW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPW_lt_cr7)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x1111},
		{PPC_REG_R1, 0x2222},
	});

	emulate("cmpw cr7, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR7_LT, true},
		{PPC_REG_CR7_GT, false},
		{PPC_REG_CR7_EQ, false},
		{PPC_REG_CR7_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPW_lt_cr7_64_trunc)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R0, 0xffffffff11111111},
		{PPC_REG_R1, 0x22222222},
	});

	emulate("cmpw cr7, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR7_LT, true},
		{PPC_REG_CR7_GT, false},
		{PPC_REG_CR7_EQ, false},
		{PPC_REG_CR7_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CMPWI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPWI_lt_cr7)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_R0, 0x1111},
	});

	emulate("cmpwi cr7, 0, 0x2222");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR7_LT, true},
		{PPC_REG_CR7_GT, false},
		{PPC_REG_CR7_EQ, false},
		{PPC_REG_CR7_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CMPLD
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPLD_gt_unsign_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R0, 0xffff0000},
		{PPC_REG_R1, 0x0},
	});

	emulate("cmpld cr5, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR5_LT, false},
		{PPC_REG_CR5_GT, true},
		{PPC_REG_CR5_EQ, false},
		{PPC_REG_CR5_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CMPLDI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPLDI_gt_unsign_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R0, 0xffff0000},
	});

	emulate("cmpldi cr5, 0, 0x0");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR5_LT, false},
		{PPC_REG_CR5_GT, true},
		{PPC_REG_CR5_EQ, false},
		{PPC_REG_CR5_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CMPLW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPLW_gt_unsign_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R0, 0xffff0000},
		{PPC_REG_R1, 0x0},
	});

	emulate("cmplw cr5, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR5_LT, false},
		{PPC_REG_CR5_GT, true},
		{PPC_REG_CR5_EQ, false},
		{PPC_REG_CR5_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPLW_eq_unsign_64)
{
	ONLY_MODE_64;

	setRegisters({
		{PPC_REG_R0, 0xffff000000000000},
		{PPC_REG_R1, 0x0},
	});

	emulate("cmplw cr5, 0, 1");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0, PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR5_LT, false},
		{PPC_REG_CR5_GT, false},
		{PPC_REG_CR5_EQ, true},
		{PPC_REG_CR5_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CMPLWI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CMPLWI_gt_unsign_32)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R0, 0xffff0000},
	});

	emulate("cmplwi cr5, 0, 0x0");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR5_LT, false},
		{PPC_REG_CR5_GT, true},
		{PPC_REG_CR5_EQ, false},
		{PPC_REG_CR5_SO, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CRSET
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CRSET_cr0)
{
	ALL_MODES;

	emulate("crset eq");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR0_EQ, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CRSET_cr5)
{
	ALL_MODES;

	emulate("crset 4*cr5+eq");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR5_EQ, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CRCLR
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CRCLR_cr0)
{
	ALL_MODES;

	emulate("crclr eq");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR0_EQ, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CRCLR_cr5)
{
	ALL_MODES;

	emulate("crclr 4*cr5+eq");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR5_EQ, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CRNOT
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CRNOT)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR5_SO, true},
	});

	emulate("crnot 4*cr2+eq, 4*cr5+so");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR5_SO});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR2_EQ, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CRNOT
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CRMOVE)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR5_SO, true},
	});

	emulate("crmove 4*cr2+eq, 4*cr5+so");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR5_SO});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CR2_EQ, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_SLWI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SLWI)
{
	SKIP_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
	});

	emulate("slwi 0, 1, 0x8");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x34567800},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_SRWI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_SRWI)
{
	SKIP_MODE_64;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
	});

	emulate("srwi 0, 1, 0x8");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x00123456},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_CLRLWI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CLRLWI)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
	});

	emulate("clrlwi 0, 1, 16");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x00005678},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CLRLWI_zero)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
	});

	emulate("clrlwi 0, 1, 0");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x12345678},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_CLRLWI_31)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x12345678},
	});

	emulate("clrlwi 0, 1, 31");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ROTLW
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ROTLW)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x00240000}, // 00100100 0...
		{PPC_REG_R2, 0x8},
	});

	emulate("rotlw 0, 1, 2");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1, PPC_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x24000000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// PPC_INS_ROTLWI
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_ROTLWI)
{
	ONLY_MODE_32;

	setRegisters({
		{PPC_REG_R1, 0x00240000}, // 00100100 0...
	});

	emulate("rotlwi 0, 1, 0x8");

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_R0, 0x24000000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
//==============================================================================
// PPC_INS_B
//==============================================================================
//

// PPC_BC_INVALID, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_uncond)
{
	ALL_MODES;

	emulate("b 0x4bc", 0x10000510);

	EXPECT_NO_REGISTERS_LOADED_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_blt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, true},
	});

	emulate("blt 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_blt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, false},
	});

	emulate("blt 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_LE, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_ble_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CR0_EQ, false},
	});

	emulate("ble 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT, PPC_REG_CR0_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LE, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_ble_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CR0_EQ, false},
	});

	emulate("ble 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT, PPC_REG_CR0_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_EQ, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_beq_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_EQ, true},
	});

	emulate("beq 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_EQ, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_beq_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_EQ, false},
	});

	emulate("beq 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_NE, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bne_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_EQ, false},
	});

	emulate("bne 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_NE, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bne_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_EQ, true},
	});

	emulate("bne 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_GT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bgt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_GT, true},
	});

	emulate("bgt 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_GT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_GT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bgt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_GT, false},
	});

	emulate("bgt 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_GT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_GE, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bge_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_GT, true},
		{PPC_REG_CR0_EQ, false},
	});

	emulate("bge 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_GT, PPC_REG_CR0_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_GE, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bge_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_GT, false},
		{PPC_REG_CR0_EQ, false},
	});

	emulate("bge 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_GT, PPC_REG_CR0_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_SO (PPC_BC_UN is not used here), op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bun_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_SO, true},
	});

	emulate("bun 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_SO});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_SO (PPC_BC_UN is not used here), op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bun_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_SO, false},
	});

	emulate("bun 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_SO});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_SO, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bso_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_SO, true},
	});

	emulate("bso 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_SO});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_SO, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bso_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_SO, false},
	});

	emulate("bso 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_SO});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_NS, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bns_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_SO, false},
	});

	emulate("bns 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_SO});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_NS, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bns_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_SO, true},
	});

	emulate("bns 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_SO});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_NS (PPC_BC_NU is not used here), op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bnu_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_SO, false},
	});

	emulate("bnu 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_SO});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_NS (PPC_BC_NU is not used here), op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_bnu_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_SO, true},
	});

	emulate("bnu 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_SO});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_blt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
	});

	emulate("blt cr4, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_B_blt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
	});

	emulate("blt cr4, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BA
//==============================================================================
//

// PPC_BC_INVALID, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BA_uncond)
{
	ALL_MODES;

	emulate("ba 0x4bc", 0x10000510);

	EXPECT_NO_REGISTERS_LOADED_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x4bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BA_blt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, true},
	});

	emulate("blta 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BA_blt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, false},
	});

	emulate("blta 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BA_blt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
	});

	emulate("blta cr4, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BA_blt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
	});

	emulate("blta cr4, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BL
//==============================================================================
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BL_uncond)
{
	ALL_MODES;

	emulate("bl 0x4bc", 0x10000510);

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BL_blt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, true},
	});

	emulate("bltl 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BL_blt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, false},
	});

	emulate("bltl 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BL_blt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
	});

	emulate("bltl cr4, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BL_blt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
	});

	emulate("bltl cr4, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BLA
//==============================================================================
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLA_uncond)
{
	ALL_MODES;

	emulate("bla 0x4bc", 0x10000510);

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x4bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLA_blt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, true},
	});

	emulate("bltla 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLA_blt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, false},
	});

	emulate("bltla 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLA_blt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
	});

	emulate("bltla cr4, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLA_blt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
	});

	emulate("bltla cr4, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BLR
//==============================================================================
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLR_uncond)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("blr", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLR_lt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR0_LT, true},
	});

	emulate("bltlr", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR0_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLR_lt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR0_LT, false},
	});

	emulate("bltlr", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR0_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
// TODO: We cannot check this, because it is in always false branch.
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//		{_translator->getReturnFunction(), {0x100004bc}},
//	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLR_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR4_LT, true},
	});

	emulate("bltlr cr4", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLR_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR4_LT, false},
	});

	emulate("bltlr cr4", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BCTR
//==============================================================================
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BCTR_uncond)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
	});

	emulate("bctr", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BCTR_lt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR0_LT, true},
	});

	emulate("bltctr", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR0_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BCTR_lt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR0_LT, false},
	});

	emulate("bltctr", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR0_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BCTR_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR4_LT, true},
	});

	emulate("bltctr cr4", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BCTR_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR4_LT, false},
	});

	emulate("bltctr cr4", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BLRL
//==============================================================================
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLRL_uncond)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("blrl", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLRL_lt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR0_LT, true},
	});

	emulate("bltlrl", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLRL_lt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR0_LT, false},
	});

	emulate("bltlrl", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLRL_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR4_LT, true},
	});

	emulate("bltlrl cr4", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BLRL_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR4_LT, false},
	});

	emulate("bltlrl cr4", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BCTRL
//==============================================================================
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BCTRL_uncond)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
	});

	emulate("bctrl", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BCTRL_lt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR0_LT, true},
	});

	emulate("bltctrl", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BCTRL_lt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR0_LT, false},
	});

	emulate("bltctrl", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BCTRL_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR4_LT, true},
	});

	emulate("bltctrl cr4", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BCTRL_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR4_LT, false},
	});

	emulate("bltctrl cr4", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BT
//==============================================================================
//

// PPC_BC_LT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BT_lt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, true},
	});

	emulate("bt lt, 0x4bc", 0x10000510); // gets translated to b

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BT_lt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, false},
	});

	emulate("bt lt, 0x4bc", 0x10000510); // gets translated to b

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BT_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
	});

	emulate("bt 4*cr4+lt, 0x4bc", 0x10000510); // gets translated to b

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BT_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
	});

	emulate("bt 4*cr4+lt, 0x4bc", 0x10000510); // gets translated to b

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BTA
//==============================================================================
//

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTA_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
	});

	emulate("bta 4*cr4+lt, 0x4bc", 0x10000510); // gets translated to ba

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTA_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
	});

	emulate("bta 4*cr4+lt, 0x4bc", 0x10000510); // gets translated to ba

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BTLR
//==============================================================================
//

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTLR_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR4_LT, true},
	});

	emulate("btlr 4*cr4+lt", 0x10000510); // gets translated to blr

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTLR_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR4_LT, false},
	});

	emulate("btlr 4*cr4+lt", 0x10000510); // gets translated to blr

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BTCTR
//==============================================================================
//

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTCTR_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR4_LT, true},
	});

	emulate("btctr 4*cr4+lt", 0x10000510); // gets translated to bctr

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTCTR_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR4_LT, false},
	});

	emulate("btctr 4*cr4+lt", 0x10000510); // gets translated to bctr

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BTL
//==============================================================================
//

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTL_blt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
	});

	emulate("btl 4*cr4+lt, 0x4bc", 0x10000510); // gets translated to bl

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTL_blt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
	});

	emulate("btl 4*cr4+lt, 0x4bc", 0x10000510); // gets translated to bl

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BTLA
//==============================================================================
//

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTLA_blt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
	});

	emulate("btla 4*cr4+lt, 0x4bc", 0x10000510); // gets translated to bla

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTLA_blt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
	});

	emulate("btla 4*cr4+lt, 0x4bc", 0x10000510); // gets translated to bla

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BTLA
//==============================================================================
//

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTLRL_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR4_LT, true},
	});

	emulate("btlrl 4*cr4+lt", 0x10000510); // gets translated to blrl

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTLRL_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CR4_LT, false},
	});

	emulate("btlrl 4*cr4+lt", 0x10000510); // gets translated to blrl

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_LR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BTCTRL
//==============================================================================
//

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTCTRL_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR4_LT, true},
	});

	emulate("btctrl 4*cr4+lt", 0x10000510); // gets translated to bctrl

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_LT, op0 = PPC_OP_REG = cr4
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BTCTRL_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 0x100004bc},
		{PPC_REG_CR4_LT, false},
	});

	emulate("btctrl 4*cr4+lt", 0x10000510); // gets translated to bctrl

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BF
//==============================================================================
//

// PPC_BC_GE, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BF_lt_cr0_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_GT, false},
	});

	emulate("bf lt, 0x4bc", 0x10000510); // gets translated to b ge

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_GT, PPC_REG_CR0_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_GE, op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BF_lt_cr0_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_EQ, false},
		{PPC_REG_CR0_GT, true},
	});

	emulate("bf lt, 0x4bc", 0x10000510); // gets translated to b ge

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR0_GT, PPC_REG_CR0_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// PPC_BC_GE, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BF_lt_cr4_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_EQ, false},
		{PPC_REG_CR4_GT, false},
	});

	emulate("bf 4*cr4+lt, 0x4bc", 0x10000510); // gets translated to b ge

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_GT, PPC_REG_CR4_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// PPC_BC_GE, op0 = PPC_OP_REG = cr4, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_Bf_lt_cr4_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_EQ, true},
		{PPC_REG_CR4_GT, false},
	});

	emulate("bf 4*cr4+lt, 0x4bc", 0x10000510); // gets translated to b ge

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CR4_GT, PPC_REG_CR4_EQ});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZ
//==============================================================================
//

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZ_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 10},
	});

	emulate("bdnz 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZ_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 1},
	});

	emulate("bdnz 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZA
//==============================================================================
//

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZA_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 10},
	});

	emulate("bdnza 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZA_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 1},
	});

	emulate("bdnza 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZLR
//==============================================================================
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZLR_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzlr", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZLR_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzlr", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BDNZL
//==============================================================================
//

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZL_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzl 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZL_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzl 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZLA
//==============================================================================
//

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZLA_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzla 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZLA_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzla 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZLRL
//==============================================================================
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZLRL_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzlrl", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZLRL_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzlrl", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BDNZ
//==============================================================================
//

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZ_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 10},
	});

	emulate("bdz 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZ_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 1},
	});

	emulate("bdz 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZA
//==============================================================================
//

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZA_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 10},
	});

	emulate("bdza 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZA_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 1},
	});

	emulate("bdza 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZLR
//==============================================================================
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZLR_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzlr", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZLR_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzlr", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZL
//==============================================================================
//

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZL_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 10},
	});

	emulate("bdzl 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZL_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 1},
	});

	emulate("bdzl 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZLA
//==============================================================================
//

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZLA_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 10},
	});

	emulate("bdzla 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZLA_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CTR, 1},
	});

	emulate("bdzla 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZLRL
//==============================================================================
//

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZLRL_nonzero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzlrl", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZLRL_zero)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_LR, 0x100004bc},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzlrl", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZT
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZT_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzt 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZT_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzt 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZT_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzt 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZT_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzt 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZT_nonzero_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzt lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZT_nonzero_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzt lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZT_zero_true)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzt lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZT_zero_false)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR0_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzt lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR0_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZTA
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTA_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzta 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTA_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzta 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTA_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzta 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTA_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzta 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZTLR
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLR_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnztlr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLR_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnztlr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLR_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnztlr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLR_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnztlr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BDNZTL
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTL_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnztl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTL_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnztl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTL_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnztl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTL_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnztl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZTLA
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLA_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnztla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLA_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnztla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLA_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnztla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLA_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnztla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZTLRL
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLRL_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnztlrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLRL_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnztlrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLRL_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnztlrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZTLRL_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnztlrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BDNZF
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZF_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzf 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZF_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzf 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZF_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzf 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZF_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzf 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZFA
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFA_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzfa 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFA_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzfa 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFA_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzfa 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFA_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzfa 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZFLR
//==============================================================================
//

// TODO: PPC_INS_BDNZFLR - missing, it gets translated to PPC_INS_BCLR,
// but then we dont know that CRT should be decremented -- only hint is that
// insn is reading and writing it, but we are not using this info at the moment.

//// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
//TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLR_nonzero_true_cr4)
//{
//	ALL_MODES;
//
//	setRegisters({
//		{PPC_REG_CR4_LT, true},
//		{PPC_REG_CTR, 10},
//		{PPC_REG_LR, 0x100004bc},
//	});
//
//	emulate("bdnzflr 4*cr4+lt", 0x10000510);
//
//	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
//	EXPECT_JUST_REGISTERS_STORED({
//		{PPC_REG_CTR, 9},
//	});
//	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
//}
//
//// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
//TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLR_nonzero_false_cr4)
//{
//	ALL_MODES;
//
//	setRegisters({
//		{PPC_REG_CR4_LT, false},
//		{PPC_REG_CTR, 10},
//		{PPC_REG_LR, 0x100004bc},
//	});
//
//	emulate("bdnzflr 4*cr4+lt", 0x10000510);
//
//	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
//	EXPECT_JUST_REGISTERS_STORED({
//		{PPC_REG_CTR, 9},
//	});
//	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
//	});
//}
//
//// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
//TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLR_zero_true_cr4)
//{
//	ALL_MODES;
//
//	setRegisters({
//		{PPC_REG_CR4_LT, true},
//		{PPC_REG_CTR, 1},
//		{PPC_REG_LR, 0x100004bc},
//	});
//
//	emulate("bdnzflr 4*cr4+lt", 0x10000510);
//
//	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
//	EXPECT_JUST_REGISTERS_STORED({
//		{PPC_REG_CTR, 0},
//	});
//	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
//}
//
//// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
//TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLR_zero_false_cr4)
//{
//	ALL_MODES;
//
//	setRegisters({
//		{PPC_REG_CR4_LT, false},
//		{PPC_REG_CTR, 1},
//		{PPC_REG_LR, 0x100004bc},
//	});
//
//	emulate("bdnzflr 4*cr4+lt", 0x10000510);
//
//	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
//	EXPECT_JUST_REGISTERS_STORED({
//		{PPC_REG_CTR, 0},
//	});
//	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
//}

//
//==============================================================================
// PPC_INS_BDNZFL
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFL_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzfl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFL_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzfl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFL_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzfl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFL_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzfl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZFLA
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLA_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzfla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLA_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdnzfla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLA_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzfla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLA_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdnzfla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDNZFLRL
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLRL_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnzflrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLRL_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnzflrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLRL_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnzflrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDNZFLRL_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdnzflrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BDZT
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZT_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzt 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZT_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzt 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZT_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzt 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZT_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzt 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZTA
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTA_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzta 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTA_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzta 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTA_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzta 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTA_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzta 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZTLR
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLR_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdztlr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLR_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdztlr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLR_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdztlr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLR_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdztlr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BDZTL
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTL_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdztl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTL_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdztl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTL_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdztl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTL_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdztl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZTLA
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLA_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdztla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLA_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdztla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLA_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdztla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLA_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdztla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZTLRL
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLRL_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdztlrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLRL_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdztlrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLRL_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdztlrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZTLRL_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdztlrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

//
//==============================================================================
// PPC_INS_BDZF
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZF_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzf 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZF_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzf 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZF_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzf 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZF_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzf 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZFA
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFA_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzfa 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFA_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzfa 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFA_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzfa 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFA_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzfa 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZFLR
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLR_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdzflr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLR_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdzflr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLR_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdzflr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLR_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdzflr 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZFL
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFL_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzfl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFL_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzfl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFL_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzfl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFL_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzfl 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x100004bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZFLA
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLA_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzfla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLA_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
	});

	emulate("bdzfla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLA_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzfla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x4bc}},
	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLA_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
	});

	emulate("bdzfla 4*cr4+lt, 0x4bc", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x4bc}},
	});
}

//
//==============================================================================
// PPC_INS_BDZFLRL
//==============================================================================
//

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLRL_nonzero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdzflrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLRL_nonzero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 10},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdzflrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 9},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLRL_zero_true_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, true},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdzflrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
//	EXPECT_JUST_VALUES_CALLED({
//		{_translator->getCondBranchFunction(), {false, 0x100004bc}},
//	});
}

// op0 = ppc_op_crx, op1 = PPC_OP_IMM = target
TEST_P(Capstone2LlvmIrTranslatorPowerpcTests, PPC_INS_BDZFLRL_zero_false_cr4)
{
	ALL_MODES;

	setRegisters({
		{PPC_REG_CR4_LT, false},
		{PPC_REG_CTR, 1},
		{PPC_REG_LR, 0x100004bc},
	});

	emulate("bdzflrl 4*cr4+lt", 0x10000510);

	EXPECT_JUST_REGISTERS_LOADED({PPC_REG_CTR, PPC_REG_CR4_LT, PPC_REG_LR});
	EXPECT_JUST_REGISTERS_STORED({
		{PPC_REG_CTR, 0},
		{PPC_REG_LR, 0x10000514},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getReturnFunction(), {0x100004bc}},
	});
}

} // namespace tests
} // namespace capstone2llvmir
} // namespace retdec
