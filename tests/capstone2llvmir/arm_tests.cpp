/**
 * @file tests/capstone2llvmir/arm_tests.cpp
 * @brief Capstone2LlvmIrTranslatorArm unit tests.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/InstIterator.h>

#include "capstone2llvmir/capstone2llvmir_tests.h"
#include "retdec/capstone2llvmir/arm/arm.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace capstone2llvmir {
namespace tests {

class Capstone2LlvmIrTranslatorArmTests :
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
				case CS_MODE_ARM: mode = KS_MODE_ARM; break;
				case CS_MODE_THUMB: mode = KS_MODE_THUMB; break;
				// Extra modes.
				case CS_MODE_MCLASS: mode = KS_MODE_ARM; break; // Missing in Keystone.
				case CS_MODE_V8: mode = KS_MODE_V8; break;
				// Unhandled modes.
				default: throw std::runtime_error("ERROR: unknown mode.\n");
			}
			if (ks_open(KS_ARCH_ARM, mode, &_assembler) != KS_ERR_OK)
			{
				throw std::runtime_error("ERROR: failed on ks_open().\n");
			}
		}

		virtual void initCapstone2LlvmIrTranslator() override
		{
			switch(GetParam())
			{
				case CS_MODE_ARM:
					_translator = Capstone2LlvmIrTranslator::createArm(&_module);
					break;
				case CS_MODE_THUMB:
					_translator = Capstone2LlvmIrTranslator::createThumb(&_module);
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
#define ONLY_MODE_ARM if (GetParam() != CS_MODE_ARM) return;
#define ONLY_MODE_THUMB if (GetParam() != CS_MODE_THUMB) return;
#define SKIP_MODE_ARM if (GetParam() == CS_MODE_ARM) return;
#define SKIP_MODE_THUMB if (GetParam() == CS_MODE_THUMB) return;
};

struct PrintCapstoneModeToString_Arm
{
	template <class ParamType>
	std::string operator()(const TestParamInfo<ParamType>& info) const
	{
		switch (info.param)
		{
			case CS_MODE_ARM: return "CS_MODE_ARM";
			case CS_MODE_THUMB: return "CS_MODE_THUMB";
			case CS_MODE_MCLASS: return "CS_MODE_MCLASS";
			case CS_MODE_V8: return "CS_MODE_V8";
			default: return "UNHANDLED CS_MODE";
		}
	}
};

// By default, all the test cases are run with all the modes.
// If some test case is not meant for all modes, use some of the ONLY_MODE_*,
// SKIP_MODE_* macros.
//
INSTANTIATE_TEST_CASE_P(
		InstantiateArmWithAllModes,
		Capstone2LlvmIrTranslatorArmTests,
		::testing::Values(CS_MODE_ARM, CS_MODE_THUMB),
		 PrintCapstoneModeToString_Arm());

//
// ARM_INS_ADD
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1230},
	});

	emulate("add r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_i)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1230},
	});

	emulate("add r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R1, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_R2, 0x4},
	});

	emulate("add r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x1230},
		{ARM_REG_R1, 0x4},
	});

	emulate("add r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_s_zero_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x0},
		{ARM_REG_R2, 0x0},
	});

	emulate("adds r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x0},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, true},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_s_negative_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xffff0000},
		{ARM_REG_R2, 0x1234},
	});

	emulate("adds r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xffff1234},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_s_carry_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xffffffff},
		{ARM_REG_R2, 0x1},
	});

	emulate("adds r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x0},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, true},
		{ARM_REG_CPSR_C, true},
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_s_overflow_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x0fffffff},
		{ARM_REG_R2, 0x74080891},
	});

	emulate("adds r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x84080890},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_V, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_eq_true)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_Z, true},
	});

	emulate("addeq r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_Z});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_eq_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_Z, false},
	});

	emulate("addeq r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_Z});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_ne_true)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_Z, false},
	});

	emulate("addne r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_Z});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_ne_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_Z, true},
	});

	emulate("addne r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_Z});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_hs_true)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_C, true},
	});

	emulate("addhs r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_hs_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_C, false},
	});

	emulate("addhs r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_C});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_lo_true)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_C, false},
	});

	emulate("addlo r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_lo_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_C, true},
	});

	emulate("addlo r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_C});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_mi_true)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, true},
	});

	emulate("addmi r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_N});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_mi_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, false},
	});

	emulate("addmi r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_N});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_pl_true)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, false},
	});

	emulate("addpl r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_N});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_pl_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, true},
	});

	emulate("addpl r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_N});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_vs_true)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_V, true},
	});

	emulate("addvs r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_V});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_vs_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_V, false},
	});

	emulate("addvs r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_V});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_vc_true)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_V, false},
	});

	emulate("addvc r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_V});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_vc_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_V, true},
	});

	emulate("addvc r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_V});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_hi_true_1)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_C, true},
		{ARM_REG_CPSR_Z, false},
	});

	emulate("addhi r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C, ARM_REG_CPSR_Z});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_hi_false_1)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_C, true},
		{ARM_REG_CPSR_Z, true},
	});

	emulate("addhi r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_C, ARM_REG_CPSR_Z});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_hi_false_2)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_Z, false},
	});

	emulate("addhi r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_C, ARM_REG_CPSR_Z});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_ls_true_1)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_Z, false},
	});

	emulate("addls r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C, ARM_REG_CPSR_Z});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_ls_true_2)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_Z, true},
	});

	emulate("addls r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C, ARM_REG_CPSR_Z});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_ls_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_C, true},
		{ARM_REG_CPSR_Z, false},
	});

	emulate("addls r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_C, ARM_REG_CPSR_Z});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_ge_true_1)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_V, true},
	});

	emulate("addge r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_ge_true_2)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_V, false},
	});

	emulate("addge r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_ge_false_1)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_V, false},
	});

	emulate("addge r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_ge_false_2)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_V, true},
	});

	emulate("addge r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_lt_true_1)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_V, false},
	});

	emulate("addlt r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_lt_true_2)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_V, true},
	});

	emulate("addlt r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_lt_false_1)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_V, true},
	});

	emulate("addlt r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_lt_false_2)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_V, false},
	});

	emulate("addlt r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_gt_true_1)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_V, true},
	});

	emulate("addgt r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_Z, ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_gt_true_2)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_V, false},
	});

	emulate("addgt r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_Z, ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_gt_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_Z, true},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_V, true},
	});

	emulate("addgt r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_Z, ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_le_true_1)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_Z, true},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_V, true},
	});

	emulate("addle r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_Z, ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_le_true_2)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_V, false},
	});

	emulate("addle r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_Z, ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_r_r_i_le_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_V, false},
	});

	emulate("addle r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_Z, ARM_REG_CPSR_N, ARM_REG_CPSR_V});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_Seq_r_r_i_eq_true)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x0},
		{ARM_REG_R2, 0x0},
		{ARM_REG_CPSR_Z, true},
	});

	emulate("addseq r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_CPSR_Z});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x0},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, true},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_Seq_r_r_i_eq_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x0},
		{ARM_REG_R2, 0x0},
		{ARM_REG_CPSR_Z, false},
	});

	emulate("addseq r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_CPSR_Z});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_lsl)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x08000001}, // shifted out to CF | 1 << 5 = 0x20 = 32
	});

	emulate("add r0, r1, r2, LSL#5");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1020},
		{ARM_REG_CPSR_C, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_lsl_reg)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x1}, // 1 << 5 = 0x20 = 32
		{ARM_REG_R3, 0x5},
	});

	emulate("add r0, r1, r2, LSL r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1020},
		{ARM_REG_CPSR_C, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_lsr)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x410}, // 0x410 >> 5 = 0x20 | shifted out to CF
	});

	emulate("add r0, r1, r2, LSR#5");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1020},
		{ARM_REG_CPSR_C, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_lsr_reg)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x400}, // 0x400 >> 5 = 0x20
		{ARM_REG_R3, 0x5},
	});

	emulate("add r0, r1, r2, LSR r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1020},
		{ARM_REG_CPSR_C, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_asr)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x410}, // 0x410 >> 5 = 0x20 | shifted out to CF
	});

	emulate("add r0, r1, r2, ASR#5");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1020},
		{ARM_REG_CPSR_C, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_asr_reg)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x80000400}, // 0x80000400 >> 5 = 0xfc000020
		{ARM_REG_R3, 0x5},
	});

	emulate("add r0, r1, r2, ASR r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xfc001020},
		{ARM_REG_CPSR_C, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_ror)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x410}, // 0x410 ror 5 = 0x80 00 00 20 | shifted out to CF
	});

	emulate("add r0, r1, r2, ROR#5");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x80001020},
		{ARM_REG_CPSR_C, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_ror_reg)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x400}, // 0x400 ror 5 = 0x20
		{ARM_REG_R3, 0x5},
	});

	emulate("add r0, r1, r2, ASR r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1020},
		{ARM_REG_CPSR_C, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

// TODO: Keystone/Capstone does not like this asm.
//
//TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_rrx)
//{
//	ALL_MODES;
//
//	setRegisters({
//		{ARM_REG_CPSR_C, true},
//		{ARM_REG_R1, 0x1000},
//		{ARM_REG_R2, 0x410}, // (0x410 | 0x1) ror 5 = 0x08 00 00 20 | shifted out to CF
//	});
//
//	emulate("add r0, r1, r2, RRX#5");
//
//	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_CPSR_C});
//	EXPECT_JUST_REGISTERS_STORED({
//		{ARM_REG_R0, 0x8001020},
//		{ARM_REG_CPSR_C, true},
//	});
//	EXPECT_NO_MEMORY_LOADED_STORED();
//	EXPECT_NO_VALUE_CALLED();
//}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_arm_r_pc_i)
{
	SKIP_MODE_THUMB;

	emulate("add r0, pc, #4", 0x1000);

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x100c}, // 0x4 + 0x1000 + 0x8
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_thumb_r_pc)
{
	ONLY_MODE_THUMB;

	setRegisters({
		{ARM_REG_R0, 0x4},
	});

	emulate("add r0, pc", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1008}, // 0x4 + 0x1000 + 0x4
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADD_arm_pc_result)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x4},
	});

	emulate("add pc, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x1004}},
	});
}

//
// ARM_INS_CMN
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_CMN_zero_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x0},
		{ARM_REG_R2, 0x0},
	});

	emulate("cmn r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, true},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_CMN_negative_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xffff0000},
		{ARM_REG_R2, 0x1234},
	});

	emulate("cmn r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_CMN_carry_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xffffffff},
		{ARM_REG_R2, 0x1},
	});

	emulate("cmn r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, true},
		{ARM_REG_CPSR_C, true},
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_CMN_overflow_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x0fffffff},
		{ARM_REG_R2, 0x74080891},
	});

	emulate("cmn r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_V, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_SUB
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_SUB_r_r_i)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
	});

	emulate("sub r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1230},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_SUB_s_zero_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x1234},
	});

	emulate("subs r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x0},
		{ARM_REG_CPSR_N, false}, // TODO: check flags with some emulator
		{ARM_REG_CPSR_Z, true},
		{ARM_REG_CPSR_C, true},
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_CMP
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_CMP_zero_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x1234},
	});

	emulate("cmp r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, true},
		{ARM_REG_CPSR_C, true},
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_AND
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_AND_r_r_i)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12345678},
	});

	emulate("and r0, r1, #0x78");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x78},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_AND_s_zero_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12345678},
		{ARM_REG_R2, 0x0},
	});

	emulate("ands r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x0},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_BIC
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_BIC_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12345678},
		{ARM_REG_R2, 0xff00ff00}, // -> 0x00ff00ff
	});

	emulate("bic r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x00340078},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_BIC_s_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12345678},
		{ARM_REG_R2, 0xffffffff}, // -> 0x0
	});

	emulate("bics r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x0},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_ORR
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ORR_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12005678},
		{ARM_REG_R2, 0x00340078},
	});

	emulate("orr r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ORR_s_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xff000000},
		{ARM_REG_R2, 0x12345678},
	});

	emulate("orrs r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xff345678},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_EOR
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_EOR_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12005678},
		{ARM_REG_R2, 0x00340078},
	});

	emulate("eor r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345600},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_EOR_s_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xff00ff00},
		{ARM_REG_R2, 0x12345678},
	});

	emulate("eors r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xed34a978},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_MOV
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MOV_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12345678},
	});

	emulate("mov r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MOV_s_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xff000000},
	});

	emulate("movs r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xff000000},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_MOVT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MOVT)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R0, 0x12345678},
	});

	emulate("movt r0, #0xabcd");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xabcd5678},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_MOVW
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MOVW)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R0, 0x12345678},
	});

	emulate("movw r0, #0xabcd");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234abcd},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_MVN
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MVN_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xf0f0f0f0},
	});

	emulate("mvn r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x0f0f0f0f},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MVN_s_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x0000ffff},
	});

	emulate("mvns r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xffff0000},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_NOP
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_NOP)
{
	ALL_MODES;

	emulate("nop");

	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_ADC
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADC_r_r_i_false)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_CPSR_C, false},
		{ARM_REG_R1, 0x1230},
	});

	emulate("adc r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
		// TODO: These probably should not be set for "adc" without "s".
		// Probbaly a Capstone bug.
		{ARM_REG_CPSR_N, ANY},
		{ARM_REG_CPSR_Z, ANY},
		{ARM_REG_CPSR_C, ANY},
		{ARM_REG_CPSR_V, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADC_r_r_i_true)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_CPSR_C, true},
		{ARM_REG_R1, 0x1230},
	});

	emulate("adc r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1235},
		// TODO: These probably should not be set for "adc" without "s".
		// Probbaly a Capstone bug.
		{ARM_REG_CPSR_N, ANY},
		{ARM_REG_CPSR_Z, ANY},
		{ARM_REG_CPSR_C, ANY},
		{ARM_REG_CPSR_V, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ADC_s_r_r_i_false)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_CPSR_C, false},
		{ARM_REG_R1, 0x1230},
	});

	emulate("adcs r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_C, false},
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_SBC
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_SBC_r_r_i_false)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_CPSR_C, false},
		{ARM_REG_R1, 0x1235},
	});

	emulate("sbc r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1230},
		// TODO: These probably should not be set for "sbc" without "s".
		// Probbaly a Capstone bug.
		{ARM_REG_CPSR_N, ANY},
		{ARM_REG_CPSR_Z, ANY},
		{ARM_REG_CPSR_C, ANY},
		{ARM_REG_CPSR_V, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_SBC_r_r_i_true)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_CPSR_C, true},
		{ARM_REG_R1, 0x1235},
	});

	emulate("sbc r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1231},
		// TODO: These probably should not be set for "sbc" without "s".
		// Probbaly a Capstone bug.
		{ARM_REG_CPSR_N, ANY},
		{ARM_REG_CPSR_Z, ANY},
		{ARM_REG_CPSR_C, ANY},
		{ARM_REG_CPSR_V, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_SBC_s_r_r_i_false)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_CPSR_C, false},
		{ARM_REG_R1, 0x1235},
	});

	emulate("sbcs r0, r1, #4");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1230},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_C, false}, // TODO: check, somehow (emul) is it ok?
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_RSC
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_RSC_r_r_r_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_CPSR_C, false},
		{ARM_REG_R1, 0x1235},
		{ARM_REG_R2, 0x4},
	});

	emulate("rsc r0, r2, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1230},
		// TODO: These probably should not be set for "rsc" without "s".
		// Probbaly a Capstone bug.
		{ARM_REG_CPSR_N, ANY},
		{ARM_REG_CPSR_Z, ANY},
		{ARM_REG_CPSR_C, ANY},
		{ARM_REG_CPSR_V, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_RSC_r_r_r_true)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_CPSR_C, true},
		{ARM_REG_R1, 0x1235},
		{ARM_REG_R2, 0x4},
	});

	emulate("rsc r0, r2, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1231},
		// TODO: These probably should not be set for "rsc" without "s".
		// Probbaly a Capstone bug.
		{ARM_REG_CPSR_N, ANY},
		{ARM_REG_CPSR_Z, ANY},
		{ARM_REG_CPSR_C, ANY},
		{ARM_REG_CPSR_V, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_RSC_s_r_r_r_false)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_CPSR_C, false},
		{ARM_REG_R1, 0x1235},
		{ARM_REG_R2, 0x4},
	});

	emulate("rscs r0, r2, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_CPSR_C});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1230},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_C, false}, // TODO: check, somehow (emul) is it ok?
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_RSB
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_RSB_r_r_i)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x4},
	});

	emulate("rsb r0, r1, #0x8");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x4},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_RSB_s_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x1234},
	});

	emulate("rsbs r0, r2, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
		{ARM_REG_CPSR_C, false}, // TODO: Chek with some emulator.
		{ARM_REG_CPSR_V, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_MUL
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MUL_r_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x1234},
	});

	emulate("mul r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1234000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MUL_s_r_r)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x0},
	});

	emulate("muls r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R1, ANY},
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDR
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0x12345678_dw},
	});

	emulate("ldr r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_plus_imm)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1008, 0x12345678_dw},
	});

	emulate("ldr r0, [r1, #8]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1008});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_minus_imm)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1010},
	});
	setMemory({
		{0x1008, 0x12345678_dw},
	});

	emulate("ldr r0, [r1, #-8]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1008});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_plus_reg)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x8},
	});
	setMemory({
		{0x1008, 0x12345678_dw},
	});

	emulate("ldr r0, [r1, r2]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1008});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_minus_reg)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1010},
		{ARM_REG_R2, -0x8},
	});
	setMemory({
		{0x1008, 0x12345678_dw},
	});

	emulate("ldr r0, [r1, r2]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1008});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_plus_imm_preindexed_writeback)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1008, 0x12345678_dw},
	});

	emulate("ldr r0, [r1, #8]!");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1008},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1008});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_minus_imm_preindexed_writeback)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1010},
	});
	setMemory({
		{0x1008, 0x12345678_dw},
	});

	emulate("ldr r0, [r1, #-8]!");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1008},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1008});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_plus_reg_preindexed_writeback)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x8},
	});
	setMemory({
		{0x1008, 0x12345678_dw},
	});

	emulate("ldr r0, [r1, r2]!");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1008},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1008});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_minus_reg_preindexed_writeback)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1010},
		{ARM_REG_R2, -0x8},
	});
	setMemory({
		{0x1008, 0x12345678_dw},
	});

	emulate("ldr r0, [r1, r2]!");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1008},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1008});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_plus_imm_postindexed_writeback)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0x12345678_dw},
	});

	emulate("ldr r0, [r1], #8");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1008},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_minus_imm_postindexed_writeback)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0x12345678_dw},
	});

	emulate("ldr r0, [r1], #-8");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0xff8},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_plus_reg_postindexed_writeback)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x8},
	});
	setMemory({
		{0x1000, 0x12345678_dw},
	});

	emulate("ldr r0, [r1], r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1008},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_minus_reg_postindexed_writeback_1)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, -0x8},
	});
	setMemory({
		{0x1000, 0x12345678_dw},
	});

	emulate("ldr r0, [r1], r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0xff8},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDR_minus_reg_postindexed_writeback_2)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x8},
	});
	setMemory({
		{0x1000, 0x12345678_dw},
	});

	emulate("ldr r0, [r1], -r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0xff8},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDRT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDRT)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0x12345678_dw},
	});

	emulate("ldrt r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDREX
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDREX)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0x12345678_dw},
	});

	emulate("ldrex r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDRB
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDRB)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0xf1_b},
	});

	emulate("ldrb r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xf1},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDRBT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDRBT)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0xf1_b},
	});

	emulate("ldrbt r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xf1},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDREXB
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDREXB)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0xf1_b},
	});

	emulate("ldrexb r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xf1},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDRSB
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDRSB)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0xf1_b},
	});

	emulate("ldrsb r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xfffffff1},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDRSBT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDRSBT)
{
	ONLY_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0xf1_b},
	});

	emulate("ldrsbt r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xfffffff1},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDRH
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDRH)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0xf123_w},
	});

	emulate("ldrh r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xf123},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDRHT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDRHT)
{
	ONLY_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0xf123_w},
	});

	emulate("ldrht r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xf123},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDREXH
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDREXH)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0xf123_w},
	});

	emulate("ldrexh r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xf123},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDRSH
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDRSH)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0xf123_w},
	});

	emulate("ldrsh r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xfffff123},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDRSHT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDRSHT)
{
	ONLY_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
	});
	setMemory({
		{0x1000, 0xf123_w},
	});

	emulate("ldrsht r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xfffff123},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDRD
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDRD)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R2, 0x1000},
	});
	setMemory({
		{0x1000, 0x1234567890abcdef_qw},
	});

	emulate("ldrd r0, r1, [r2]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x90abcdef},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDREXD
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDREXD)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R2, 0x1000},
	});
	setMemory({
		{0x1000, 0x1234567890abcdef_qw},
	});

	emulate("ldrexd r0, r1, [r2]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x90abcdef},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_STR
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STR)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1000},
	});

	emulate("str r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x12345678_dw}
	});
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STR_dst_shift)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R4, 0x12345678},
		{ARM_REG_R0, 0x1000},
		{ARM_REG_R6, 0x2}, // 2 << 2 = 8
	});

	emulate("str r4, [r0, r6, lsl #2]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R4, ARM_REG_R6});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_C, false},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1008, 0x12345678_dw}
	});
	EXPECT_NO_VALUE_CALLED();
}

// TODO: Same extensive testing as for LDR.

//
// ARM_INS_STRT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STRT)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1000},
	});

	emulate("strt r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x12345678_dw}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_STRB
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STRB)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1000},
	});

	emulate("strb r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x78_b}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_STRBT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STRBT)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1000},
	});

	emulate("strbt r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x78_b}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_STRH
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STRH)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1000},
	});

	emulate("strh r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x5678_w}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_STRHT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STRHT)
{
	ONLY_MODE_THUMB;

	setRegisters({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x1000},
	});

	emulate("strht r0, [r1]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x5678_w}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_STRD
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STRD)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x12345678},
		{ARM_REG_R1, 0x90abcdef},
		{ARM_REG_R2, 0x1000},
	});

	emulate("strd r0, r1, [r2]");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1, ARM_REG_R2});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
//		{0x1000, 0x1234567890abcdef_qw}
		{0x1000, 0x12345678_dw}
	});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_TEQ
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_TQE_r_r_eq)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_R2, 0x1230},
	});

	emulate("teq r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, false}, // XOR of original sign bits
		{ARM_REG_CPSR_Z, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_TQE_r_r_neg_1)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1230},
		{ARM_REG_R2, -0x1230},
	});

	emulate("teq r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, true}, // XOR of original sign bits
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_TQE_r_r_neg_2)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, -0x5678},
		{ARM_REG_R2, -0x1234},
	});

	emulate("teq r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, false}, // XOR of original sign bits
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_TQE_r_r_neg_3)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, -0x5678},
		{ARM_REG_R2, 0x1234},
	});

	emulate("teq r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, true}, // XOR of original sign bits
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_TST
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_TST_eq)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xffff0000},
		{ARM_REG_R2, 0x0000ffff},
	});

	emulate("tst r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_TST_neg)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xffff0000},
		{ARM_REG_R2, 0xf000ffff},
	});

	emulate("tst r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_REV
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_REV)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12345678},
	});

	emulate("rev r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x78563412},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_REV16
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_REV16)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12345678},
	});

	emulate("rev16 r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_rev16.i32"), {0x12345678}},
	});
}

//
// ARM_INS_REVSH
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_REVSH)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12345678},
	});

	emulate("revsh r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_revsh.i32"), {0x12345678}},
	});
}

//
// ARM_INS_RBIT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_RBIT)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x12345678},
	});

	emulate("rbit r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_rbit.i32"), {0x12345678}},
	});
}

//
// ARM_INS_CLZ
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_CLZ_zeroes)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x0000ffff},
	});

	emulate("clz r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 16},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_CLZ_ones)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0xf0000000},
	});

	emulate("clz r0, r1");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_UQADD8
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UQADD8)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
	});

	emulate("uqadd8 r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_uqadd8.i32.i32"), {0x1234, 0x5678}},
	});
}

//
// ARM_INS_UQADD16
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UQADD16)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
	});

	emulate("uqadd16 r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_uqadd16.i32.i32"), {0x1234, 0x5678}},
	});
}

//
// ARM_INS_UQSUB8
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UQSUB8)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
	});

	emulate("uqsub8 r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_uqsub8.i32.i32"), {0x1234, 0x5678}},
	});
}

//
// ARM_INS_UQADD16
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UQSUB16)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
	});

	emulate("uqsub16 r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_uqsub16.i32.i32"), {0x1234, 0x5678}},
	});
}

//
// ARM_INS_UQASX
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UQASX)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
	});

	emulate("uqasx r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_uqasx.i32.i32"), {0x1234, 0x5678}},
	});
}

//
// ARM_INS_UQSAX
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UQSAX)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
	});

	emulate("uqsax r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_uqsax.i32.i32"), {0x1234, 0x5678}},
	});
}

//
// ARM_INS_SEL
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_SEL)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
	});

	emulate("sel r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_sel.i32.i32"), {0x1234, 0x5678}},
	});
}

//
// ARM_INS_USAD8
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_USAD8)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
	});

	emulate("usad8 r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_usad8.i32.i32"), {0x1234, 0x5678}},
	});
}

//
// ARM_INS_USADA8
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_USADA8)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
		{ARM_REG_R3, 0x9abc},
	});

	emulate("usada8 r0, r1, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_usada8"), {0x1234, 0x5678, 0x9abc}},
	});
}

//
// ARM_INS_USAT
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_USAT)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R2, 0x5678},
	});

	emulate("usat r0, #8, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_usat.i32.i32"), {0x8, 0x5678}},
	});
}

//
// ARM_INS_USAT16
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_USAT16)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R2, 0x5678},
	});

	emulate("usat16 r0, #8, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_usat16.i32.i32"), {0x8, 0x5678}},
	});
}

//
// ARM_INS_UHADD8
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UHADD8)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
	});

	emulate("uhadd8 r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_uhadd8.i32.i32"), {0x1234, 0x5678}},
	});
}

//
// ARM_INS_B
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_B)
{
	ALL_MODES;

	emulate("b #0x110d8", 0x1107C);

	EXPECT_NO_REGISTERS_LOADED_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x110d8}},
	});
}

//
// ARM_INS_BX
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_BX)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x110d8},
	});

	emulate("bx r1", 0x1107C);

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x110d8}},
	});
}

//
// ARM_INS_BL
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_BL)
{
	ALL_MODES;

	emulate("bl #0x110d8", 0x1107C);

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_LR, 0x11080},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x110d8}},
	});
}

//
// ARM_INS_BLX
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_BLX_arm)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x110d8},
	});

	emulate("blx r1", 0x1107C);

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_LR, 0x11080},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x110d8}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_BLX_thumb)
{
	ONLY_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x110d8},
	});

	emulate("blx r1", 0x1107C);

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_LR, 0x1107e},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x110d8}},
	});
}

//
// ARM_INS_LSL
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LSL_imm)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x00001234},
	});

	emulate("lsl r0, r1, #16");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12340000},
		{ARM_REG_CPSR_C, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LSL_reg)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R1, 0x00001234},
		{ARM_REG_R2, 0x10},
	});

	emulate("lsl r0, r1, r2");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x12340000},
		{ARM_REG_CPSR_C, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LSR
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LSR_imm)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R2, 0x410}, // 0x410 >> 5 = 0x20 | shifted out to CF
	});

	emulate("lsr r0, r2, #5");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x20},
		{ARM_REG_CPSR_C, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LSR_reg)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x400}, // 0x400 >> 5 = 0x20
		{ARM_REG_R3, 0x5},
	});

	emulate("lsr r0, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x20},
		{ARM_REG_CPSR_C, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_ASR
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ASR_imm)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R2, 0x410}, // 0x410 >> 5 = 0x20 | shifted out to CF
	});

	emulate("asr r0, r2, #5");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x20},
		{ARM_REG_CPSR_C, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ASR_reg)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R2, 0x80000400}, // 0x80000400 >> 5 = 0xfc000020
		{ARM_REG_R3, 0x5},
	});

	emulate("asr r0, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xfc000020},
		{ARM_REG_CPSR_C, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_ROR
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ROR_imm)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R2, 0x410}, // 0x410 ror 5 = 0x80 00 00 20 | shifted out to CF
	});

	emulate("ror r0, r2, #5");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x80000020},
		{ARM_REG_CPSR_C, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_ROR_reg)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R2, 0x400}, // 0x400 ror 5 = 0x20
		{ARM_REG_R3, 0x5},
	});

	emulate("ror r0, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x20},
		{ARM_REG_CPSR_C, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDM
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDM)
{
	ALL_MODES;

	setMemory({
		{0x1000, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1008, 0x6_dw},
	});

	setRegisters({
		{ARM_REG_R0, 0x1000},
	});

	emulate("ldm r0, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x1000, 0x1004, 0x1008});
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDM_wb)
{
	ALL_MODES;

	setMemory({
		{0x1000, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1008, 0x6_dw},
	});

	setRegisters({
		{ARM_REG_R0, 0x1000},
	});

	emulate("ldm r0!, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x100c},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x1000, 0x1004, 0x1008});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_POP
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_POP)
{
	ALL_MODES;

	setMemory({
		{0x1000, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1008, 0x6_dw},
	});

	setRegisters({
		{ARM_REG_SP, 0x1000},
	});

	emulate("pop {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_SP});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_SP, 0x100c},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x1000, 0x1004, 0x1008});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDMIB - ARM only
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDMIB)
{
	SKIP_MODE_THUMB;

	setMemory({
		{0x1004, 0x2_dw},
		{0x1008, 0x4_dw},
		{0x100c, 0x6_dw},
	});

	setRegisters({
		{ARM_REG_R0, 0x1000},
	});

	emulate("ldmib r0, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x1004, 0x1008, 0x100c});
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDMIB_wb)
{
	SKIP_MODE_THUMB;

	setMemory({
		{0x1004, 0x2_dw},
		{0x1008, 0x4_dw},
		{0x100c, 0x6_dw},
	});

	setRegisters({
		{ARM_REG_R0, 0x1000},
	});

	emulate("ldmib r0!, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x100c},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x1004, 0x1008, 0x100c});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDMDA - ARM only
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDMDA)
{
	SKIP_MODE_THUMB;

	setMemory({
		{0x1004, 0x2_dw},
		{0x1008, 0x4_dw},
		{0x100c, 0x6_dw},
	});

	setRegisters({
		{ARM_REG_R0, 0x100c},
	});

	emulate("ldmda r0, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R2, 0x6},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x2},
	});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x100c, 0x1008, 0x1004});
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDMDA_wb)
{
	SKIP_MODE_THUMB;

	setMemory({
		{0x1004, 0x2_dw},
		{0x1008, 0x4_dw},
		{0x100c, 0x6_dw},
	});

	setRegisters({
		{ARM_REG_R0, 0x100c},
	});

	emulate("ldmda r0!, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1000},
		{ARM_REG_R2, 0x6},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x2},
	});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x100c, 0x1008, 0x1004});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_LDMDB
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDMDB)
{
	ALL_MODES;

	setMemory({
		{0x1000, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1008, 0x6_dw},
	});

	setRegisters({
		{ARM_REG_R0, 0x100c},
	});

	emulate("ldmdb r0, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R2, 0x6},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x2},
	});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x1008, 0x1004, 0x1000});
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_LDMDB_wb)
{
	ALL_MODES;

	setMemory({
		{0x1000, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1008, 0x6_dw},
	});

	setRegisters({
		{ARM_REG_R0, 0x100c},
	});

	emulate("ldmdb r0!, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1000},
		{ARM_REG_R2, 0x6},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x2},
	});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x1008, 0x1004, 0x1000});
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_STM
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STM)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x1000},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});

	emulate("stm r0, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R2, ARM_REG_R4, ARM_REG_R6});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1008, 0x6_dw},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STM_wb)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x1000},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});

	emulate("stm r0!, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R2, ARM_REG_R4, ARM_REG_R6});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x100c},
	});
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1008, 0x6_dw},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_STMIB
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STMIB)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R0, 0xffc},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});

	emulate("stmib r0, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R2, ARM_REG_R4, ARM_REG_R6});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1008, 0x6_dw},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STMIB_wb)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R0, 0xffc},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});

	emulate("stmib r0!, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R2, ARM_REG_R4, ARM_REG_R6});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1008},
	});
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1008, 0x6_dw},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_STMDA
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STMDA)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R0, 0x1008},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});

	emulate("stmda r0, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R2, ARM_REG_R4, ARM_REG_R6});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1008, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1000, 0x6_dw},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STMDA_wb)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R0, 0x1008},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});

	emulate("stmda r0!, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R2, ARM_REG_R4, ARM_REG_R6});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0xffc},
	});
	EXPECT_JUST_MEMORY_STORED({
		{0x1008, 0x2_dw},
		{0x1004, 0x4_dw},
		{0x1000, 0x6_dw},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_STMDB
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STMDB)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x100c},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});

	emulate("stmdb r0, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R2, ARM_REG_R4, ARM_REG_R6});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1008, 0x6_dw},
		{0x1004, 0x4_dw},
		{0x1000, 0x2_dw},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_STMDB_wb)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x100c},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});

	emulate("stmdb r0!, {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R2, ARM_REG_R4, ARM_REG_R6});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1000},
	});
	EXPECT_JUST_MEMORY_STORED({
		{0x1008, 0x6_dw},
		{0x1004, 0x4_dw},
		{0x1000, 0x2_dw},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_PUSH
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_PUSH)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_SP, 0x100c},
		{ARM_REG_R2, 0x2},
		{ARM_REG_R4, 0x4},
		{ARM_REG_R6, 0x6},
	});

	emulate("push {r2, r4, r6}");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_SP, ARM_REG_R2, ARM_REG_R4, ARM_REG_R6});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_SP, 0x1000},
	});
	EXPECT_JUST_MEMORY_STORED({
		{0x1008, 0x6_dw},
		{0x1004, 0x4_dw},
		{0x1000, 0x2_dw},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_UMULL
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UMULL)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R2, 0x12345678},
		{ARM_REG_R3, 0x90abcdef},
	});

	emulate("umull r0, r1, r2, r3"); // -> 0a 49 a8 3e | 2a 42 d2 08

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x2a42d208}, // lo
		{ARM_REG_R1, 0x0a49a83e}, // hi
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UMULL_s)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R2, 0x12345678},
		{ARM_REG_R3, 0x90abcdef},
	});

	emulate("umulls r0, r1, r2, r3"); // -> 0a 49 a8 3e | 2a 42 d2 08

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x2a42d208}, // lo
		{ARM_REG_R1, 0x0a49a83e}, // hi
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_SMULL
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_SMULL)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R2, 0x12345678},
		{ARM_REG_R3, 0x90abcdef},
	});

	emulate("smull r0, r1, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x2a42d208}, // lo
		{ARM_REG_R1, 0xF81551C6}, // hi
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_SMULL_s)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R2, 0x12345678},
		{ARM_REG_R3, 0x90abcdef},
	});

	emulate("smulls r0, r1, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x2a42d208}, // lo
		{ARM_REG_R1, 0xF81551C6}, // hi
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_UMLAL
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UMLAL)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x1000},
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x12345678},
		{ARM_REG_R3, 0x90abcdef},
	});

	emulate("umlal r0, r1, r2, r3"); // -> 0a 49 b8 3e | 2a 42 e2 08

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x2a42e208}, // lo
		{ARM_REG_R1, 0x0a49b83e}, // hi
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UMLAL_s)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R0, 0x1000},
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x12345678},
		{ARM_REG_R3, 0x90abcdef},
	});

	emulate("umlals r0, r1, r2, r3"); // -> 0a 49 b8 3e | 2a 42 e2 08

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x2a42e208}, // lo
		{ARM_REG_R1, 0x0a49b83e}, // hi
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}
//
// ARM_INS_SMLAL
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_SMLAL)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x1000},
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x12345678},
		{ARM_REG_R3, 0x90abcdef},
	});

	emulate("smlal r0, r1, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x2a42e208}, // lo
		{ARM_REG_R1, 0xF81561C6}, // hi
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_SMLAL_s)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R0, 0x1000},
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x12345678},
		{ARM_REG_R3, 0x90abcdef},
	});

	emulate("smlals r0, r1, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x2a42e208}, // lo
		{ARM_REG_R1, 0xF81561C6}, // hi
		{ARM_REG_CPSR_N, true},
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_UMAAL
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_UMAAL)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x4321},
		{ARM_REG_R1, 0x1234},
		{ARM_REG_R2, 0x5678},
		{ARM_REG_R3, 0x9abc},
	});

	emulate("umaal r0, r1, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
		{ARM_REG_R1, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_umaal"), {0x4321, 0x1234, 0x5678, 0x9abc}},
	});
}

//
// ARM_INS_MLS
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MLS)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x5},
		{ARM_REG_R3, 0x20000},
	});

	emulate("mls r0, r1, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x1b000}, // 0x20000 - 0x1000 * 0x5 = 0x1b000
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_MLA
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MLA)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x5},
		{ARM_REG_R3, 0x20000},
	});

	emulate("mla r0, r1, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x25000}, // 0x20000 + 0x1000 * 0x5 = 0x25000
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_MLA_s)
{
	SKIP_MODE_THUMB;

	setRegisters({
		{ARM_REG_R1, 0x1000},
		{ARM_REG_R2, 0x5},
		{ARM_REG_R3, 0x20000},
	});

	emulate("mlas r0, r1, r2, r3");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R1, ARM_REG_R2, ARM_REG_R3});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, 0x25000}, // 0x20000 + 0x1000 * 0x5 = 0x25000
		{ARM_REG_CPSR_N, false},
		{ARM_REG_CPSR_Z, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// ARM_INS_BFC
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_BFC)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x1234},
	});

	emulate("bfc r0, #0x5, #0x10");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_bfc"), {0x1234, 0x5, 0x10}},
	});
}

//
// ARM_INS_BFI
//

TEST_P(Capstone2LlvmIrTranslatorArmTests, ARM_INS_BFI)
{
	ALL_MODES;

	setRegisters({
		{ARM_REG_R0, 0x1234},
		{ARM_REG_R1, 0x5678},
	});

	emulate("bfi r0, r1, #0x5, #0x10");

	EXPECT_JUST_REGISTERS_LOADED({ARM_REG_R0, ARM_REG_R1});
	EXPECT_JUST_REGISTERS_STORED({
		{ARM_REG_R0, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_bfi"), {0x1234, 0x5678, 0x5, 0x10}},
	});
}

} // namespace tests
} // namespace capstone2llvmir
} // namespace retdec
