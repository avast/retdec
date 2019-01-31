/**
 * @file tests/capstone2llvmir/x86_tests.cpp
 * @brief Capstone2LlvmIrTranslatorX86 unit tests.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cmath>

#include <llvm/IR/InstIterator.h>

#include "capstone2llvmir/capstone2llvmir_tests.h"
#include "retdec/capstone2llvmir/x86/x86.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace capstone2llvmir {
namespace tests {

class Capstone2LlvmIrTranslatorX86Tests :
		public Capstone2LlvmIrTranslatorTests,
		public ::testing::WithParamInterface<cs_mode>
{
	protected:
		virtual void initKeystoneEngine() override
		{
			ks_mode mode = KS_MODE_32;
			switch(GetParam())
			{
				case CS_MODE_16: mode = KS_MODE_16; break;
				case CS_MODE_32: mode = KS_MODE_32; break;
				case CS_MODE_64: mode = KS_MODE_64; break;
				default: throw std::runtime_error("ERROR: unknown mode.\n");
			}
			if (ks_open(KS_ARCH_X86, mode, &_assembler) != KS_ERR_OK)
			{
				throw std::runtime_error("ERROR: failed on ks_open().\n");
			}
		}

		virtual void initCapstone2LlvmIrTranslator() override
		{
			switch(GetParam())
			{
				case CS_MODE_16:
					_translator = Capstone2LlvmIrTranslator::createX86_16(&_module);
					break;
				case CS_MODE_32:
					_translator = Capstone2LlvmIrTranslator::createX86_32(&_module);
					break;
				case CS_MODE_64:
					_translator = Capstone2LlvmIrTranslator::createX86_64(&_module);
					break;
				default:
					throw std::runtime_error("ERROR: unknown mode.\n");
			}
		}

	protected:
		virtual llvm::Function* modifyTranslationForEmulation(llvm::Function* f) override
		{
			Capstone2LlvmIrTranslatorX86* x86Trans = getX86Translator();

			auto* top = getRegister(X87_REG_TOP);
			assert(top);
			int topVal = _emulator->getGlobalVariableValue(top).IntVal.getZExtValue();

			std::map<Value*, int> vals;

			for (llvm::inst_iterator I = llvm::inst_begin(f),
					E = llvm::inst_end(f); I != E; ++I)
			{
				llvm::Instruction* i = &*I;

				auto* l = dyn_cast<LoadInst>(i);
				auto* sub = dyn_cast<SubOperator>(i);
				auto* add = dyn_cast<AddOperator>(i);
				auto* call = dyn_cast<CallInst>(i);

				if (l && l->getPointerOperand() == top)
				{
					vals[l] = topVal;
				}
				else if (sub
						&& vals.find(sub->getOperand(0)) != vals.end()
						&& isa<ConstantInt>(sub->getOperand(1)))
				{
					uint64_t v = cast<ConstantInt>(sub->getOperand(1))->getZExtValue();
					auto fIt = vals.find(sub->getOperand(0));
					assert(fIt != vals.end());
					vals[sub] = fIt->second - v;
				}
				else if (add
						&& vals.find(add->getOperand(0)) != vals.end()
						&& isa<ConstantInt>(add->getOperand(1)))
				{
					uint64_t v = cast<ConstantInt>(add->getOperand(1))->getZExtValue();
					auto fIt = vals.find(add->getOperand(0));
					assert(fIt != vals.end());
					vals[add] = fIt->second + v;
				}
				else if (call
						&& (x86Trans->getX87DataStoreFunction() == call->getCalledFunction()
						||  x86Trans->getX87TagStoreFunction() == call->getCalledFunction()))
				{
					int idx = 0;
					if (auto* ci = dyn_cast<ConstantInt>(call->getArgOperand(0)))
					{
						idx = ci->getZExtValue();
					}
					else
					{
						auto fIt = vals.find(call->getArgOperand(0));
						assert(fIt != vals.end());
						idx = fIt->second;
					}
					assert(0 <= idx && idx <= 7);
					auto* val = call->getArgOperand(1);
					GlobalVariable* reg = nullptr;
					if (x86Trans->getX87DataStoreFunction() == call->getCalledFunction())
					{
						reg = x86Trans->getRegister(X86_REG_ST0 + idx);
					}
					else if (x86Trans->getX87TagStoreFunction() == call->getCalledFunction())
					{
						reg = x86Trans->getRegister(X87_REG_TAG0 + idx);
					}
					assert(reg);

					new StoreInst(val, reg, i);
					E = llvm::inst_end(f);
				}
				else if (call
						&& (x86Trans->getX87DataLoadFunction() == call->getCalledFunction()
						||  x86Trans->getX87TagLoadFunction() == call->getCalledFunction()))
				{
					int idx = 0;
					if (auto* ci = dyn_cast<ConstantInt>(call->getArgOperand(0)))
					{
						idx = ci->getZExtValue();
					}
					else
					{
						auto fIt = vals.find(call->getArgOperand(0));
						assert(fIt != vals.end());
						idx = fIt->second;
					}
					assert(0 <= idx && idx <= 7);
					GlobalVariable* reg = nullptr;
					if (x86Trans->getX87DataLoadFunction() == call->getCalledFunction())
					{
						reg = x86Trans->getRegister(X86_REG_ST0 + idx);
					}
					else if (x86Trans->getX87TagLoadFunction() == call->getCalledFunction())
					{
						reg = x86Trans->getRegister(X87_REG_TAG0 + idx);
					}
					assert(reg);

					auto* l = new LoadInst(reg, "", i);
					call->replaceAllUsesWith(l);
					E = llvm::inst_end(f);
				}
			}

			return f;
		}

	// These can/should be used at the beginning of each test case to
	// determine which modes should the case be run for.
	// They are macros because we want them to cause return in the current
	// function (test case).
	//
	protected:
#define ALL_MODES
#define ONLY_MODE_16 if (GetParam() != CS_MODE_16) return;
#define ONLY_MODE_32 if (GetParam() != CS_MODE_32) return;
#define ONLY_MODE_64 if (GetParam() != CS_MODE_64) return;
#define SKIP_MODE_16 if (GetParam() == CS_MODE_16) return;
#define SKIP_MODE_32 if (GetParam() == CS_MODE_32) return;
#define SKIP_MODE_64 if (GetParam() == CS_MODE_64) return;

	protected:
		Capstone2LlvmIrTranslatorX86* getX86Translator()
		{
			return dynamic_cast<Capstone2LlvmIrTranslatorX86*>(_translator.get());
		}

	// Some of these (or their parts) might be moved to abstract parent class.
	//
	protected:
		uint32_t getParentRegister(uint32_t reg)
		{
			return getX86Translator()->getParentRegister(reg);
		}

		virtual llvm::GlobalVariable* getRegister(uint32_t reg) override
		{
			return _translator->getRegister(getParentRegister(reg));
		}

		virtual uint64_t getRegisterValueUnsigned(uint32_t reg) override
		{
			auto preg = getParentRegister(reg);
			auto* gv = getRegister(preg);
			auto val = _emulator->getGlobalVariableValue(gv).IntVal.getZExtValue();

			if (reg == preg)
			{
				return val;
			}

			if (reg == X86_REG_AH
					|| reg == X86_REG_CH
					|| reg == X86_REG_DH
					|| reg == X86_REG_BH)
			{
				val = val >> 8;
			}

			switch (_translator->getRegisterBitSize(reg))
			{
				case 1: return static_cast<bool>(val);
				case 8: return static_cast<uint8_t>(val);
				case 16: return static_cast<uint16_t>(val);
				case 32: return static_cast<uint32_t>(val);
				case 64: return static_cast<uint64_t>(val);
				default: throw std::runtime_error("Unknown reg bit size.");
			}
		}

		virtual void setRegisterValueUnsigned(uint32_t reg, uint64_t val) override
		{
			auto preg = getParentRegister(reg);
			auto* gv = getRegister(preg);
			auto* t = cast<llvm::IntegerType>(gv->getValueType());

			GenericValue v = _emulator->getGlobalVariableValue(gv);

			if (reg == preg)
			{
				bool isSigned = false;
				v.IntVal = APInt(t->getBitWidth(), val, isSigned);
				_emulator->setGlobalVariableValue(gv, v);
				return;
			}

			uint64_t old = v.IntVal.getZExtValue();

			if (reg == X86_REG_AH
					|| reg == X86_REG_CH
					|| reg == X86_REG_DH
					|| reg == X86_REG_BH)
			{
				val = val << 8;
				val = val & 0x000000000000ff00;
				old = old & 0xffffffffffff00ff;
			}
			else
			{
				switch (_translator->getRegisterBitSize(reg))
				{
					case 8:
						val = val & 0x00000000000000ff;
						old = old & 0xffffffffffffff00;
						break;
					case 16:
						val = val & 0x000000000000ffff;
						old = old & 0xffffffffffff0000;
						break;
					case 32:
						val = val & 0x00000000ffffffff;
						old = old & 0xffffffff00000000;
						break;
					case 64:
						val = val & 0xffffffffffffffff;
						old = old & 0x0000000000000000;
						break;
					default:
						throw std::runtime_error("Unknown reg bit size.");
				}
			}

			val = old | val;
			bool isSigned = false;
			v.IntVal = APInt(t->getBitWidth(), val, isSigned);
			_emulator->setGlobalVariableValue(gv, v);
			return;
		}
};

struct PrintCapstoneModeToString_x86
{
	template <class ParamType>
	std::string operator()(const TestParamInfo<ParamType>& info) const
	{
		switch (info.param)
		{
			case CS_MODE_16: return "CS_MODE_16";
			case CS_MODE_32: return "CS_MODE_32";
			case CS_MODE_64: return "CS_MODE_64";
			default: return "UNHANDLED CS_MODE";
		}
	}
};

// By default, all the test cases are run with all the modes.
// If some test case is not meant for all modes, use some of the ONLY_MODE_*,
// SKIP_MODE_* macros.
//
INSTANTIATE_TEST_CASE_P(
		InstantiateX86WithAllModes,
		Capstone2LlvmIrTranslatorX86Tests,
		::testing::Values(CS_MODE_16, CS_MODE_32, CS_MODE_64),
		PrintCapstoneModeToString_x86());

//
// X86_INS_AAA
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAA_decimal_carry)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xa},
		{X86_REG_AH, 0x4},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});

	emulate("aaa");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AH, X86_REG_AF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x5},
		{X86_REG_AL, 0x0},
		{X86_REG_AF, true},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAA_decimal_carry_af)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0x0},
		{X86_REG_AH, 0x4},
		{X86_REG_AF, true},
		{X86_REG_CF, false},
	});

	emulate("aaa");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AH, X86_REG_AF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x5},
		{X86_REG_AL, 0x6},
		{X86_REG_AF, true},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAA_no_decimal_carry)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0x2},
		{X86_REG_AH, 0x4},
		{X86_REG_AF, false},
		{X86_REG_CF, true},
	});

	emulate("aaa");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AH, X86_REG_AF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x4ULL},
		{X86_REG_AL, 0x2ULL},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_AAS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAS_decimal_carry)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xa},
		{X86_REG_AH, 0x4},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});

	emulate("aas");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AH, X86_REG_AF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x3ULL},
		{X86_REG_AL, 0x4ULL},
		{X86_REG_AF, true},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAS_decimal_carry_af)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0x0},
		{X86_REG_AH, 0x4},
		{X86_REG_AF, true},
		{X86_REG_CF, false},
	});

	emulate("aas");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AH, X86_REG_AF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x3},
		{X86_REG_AL, 0xa}, // (0x0 - 0x6) & 0xf = 0xa
		{X86_REG_AF, true},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAS_no_decimal_carry)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0x2},
		{X86_REG_AH, 0x4},
		{X86_REG_AF, false},
		{X86_REG_CF, true},
	});

	emulate("aas");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AH, X86_REG_AF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x4ULL},
		{X86_REG_AL, 0x2ULL},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_DAA
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DAA_decimal_carry)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xa},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});

	emulate("daa");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AF, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x10ULL},
		{X86_REG_AF, true},
		{X86_REG_CF, false},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DAA_decimal_carry_cf)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xa},
		{X86_REG_AF, false},
		{X86_REG_CF, true},
	});

	emulate("daa");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AF, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x70ULL},
		{X86_REG_AF, true},
		{X86_REG_CF, true},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DAA_decimal_carry_af_cf)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xf0},
		{X86_REG_AF, true},
		{X86_REG_CF, true},
	});

	emulate("daa");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AF, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x56ULL}, // 0xf0 + 0x6 + 0x60 = 0x156 (overflow) = 0x56
		{X86_REG_AF, true},
		{X86_REG_CF, true},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DAA_no_decimal_carry)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xf0},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});

	emulate("daa");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AF, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x50ULL}, // 0xf0 + 0x60 = 0x150 (overflow) = 0x50
		{X86_REG_AF, false},
		{X86_REG_CF, true},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_DAS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DAS_decimal_carry)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xa},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});

	emulate("das");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AF, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x4ULL}, // 0xa - 0x6 - 0x60 = 0xa4 (negative -92)
		{X86_REG_AF, true},
		{X86_REG_CF, false},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DAS_decimal_carry_cf)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xa},
		{X86_REG_AF, false},
		{X86_REG_CF, true},
	});

	emulate("das");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AF, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0xa4ULL}, // 0xa - 0x6 - 0x60 = 0xa4 (negative -92)
		{X86_REG_AF, true},
		{X86_REG_CF, true},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DAS_decimal_carry_af_cf)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xf0},
		{X86_REG_AF, true},
		{X86_REG_CF, true},
	});

	emulate("das");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AF, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x8aULL}, // 0xf0 - 0x6 - 0x60 = 0x8a
		{X86_REG_AF, true},
		{X86_REG_CF, true},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DAS_no_decimal_carry)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xf0},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});

	emulate("das");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_AF, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x90ULL}, // 0xf0 - 0x60 = 0x90
		{X86_REG_AF, false},
		{X86_REG_CF, true},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_AAD
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAD_default_val)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0x80},
		{X86_REG_AH, 0x10},
	});

	emulate("aad");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x0ULL}, // 0x0
		{X86_REG_AL, 0x20ULL}, // 0x80 + (0x10 * 0xa) = 0x120 (overflow) = 0x20
		{X86_REG_SF, false},
		{X86_REG_ZF, false},
		{X86_REG_PF, false},
	}); // according to Ollydbg, CF, OF are also set
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAD_imm_val)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0x80},
		{X86_REG_AH, 0x10},
	});

	emulate("aad 0x2");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x0ULL}, // 0x0
		{X86_REG_AL, 0xa0ULL}, // 0x80 + (0x10 * 0x2) = 0xa0
		{X86_REG_SF, true},
		{X86_REG_ZF, false},
		{X86_REG_PF, true},
	}); // according to Ollydbg, CF, OF are also set
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAD_default_val_overflow)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0x80},
		{X86_REG_AH, 0x10},
	});

	emulate("aad");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x0ULL}, // 0x0
		{X86_REG_AL, 0x20ULL}, // 0x80 + (0x10 * 0xa) = 0x120 (overflow) = 0x20
		{X86_REG_SF, false},
		{X86_REG_ZF, false},
		{X86_REG_PF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_AAM
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAM_flags_false)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0x80},
		{X86_REG_AH, 0x12}, // this should be overwritten
	});

	emulate("aam");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0xcULL}, // 0x80 / 0xa
		{X86_REG_AL, 0x8ULL}, // 0x80 % 0xa
		{X86_REG_SF, false},
		{X86_REG_ZF, false},
		{X86_REG_PF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAM_pf)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0x81},
		{X86_REG_AH, 0x12}, // this should be overwritten
	});

	emulate("aam");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0xcULL}, // 0x81 / 0xa
		{X86_REG_AL, 0x9ULL}, // 0x81 % 0xa
		{X86_REG_SF, false},
		{X86_REG_ZF, false},
		{X86_REG_PF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAM_zf_pf)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0x82},
		{X86_REG_AH, 0x12}, // this should be overwritten
	});

	emulate("aam");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0xdULL}, // 0x82 / 0xa
		{X86_REG_AL, 0x0ULL}, // 0x82 % 0xa
		{X86_REG_SF, false},
		{X86_REG_ZF, true},
		{X86_REG_PF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AAM_imm)
{
	SKIP_MODE_64; // undef op

	setRegisters({
		{X86_REG_AL, 0xf5},
		{X86_REG_AH, 0x12}, // this should be overwritten
	});

	emulate("aam 0x23");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x7ULL}, // 0xf5 / 0x23
		{X86_REG_AL, 0x0ULL}, // 0xf5 % 0x23
		{X86_REG_SF, false},
		{X86_REG_ZF, true},
		{X86_REG_PF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_ADC
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ADC_reg16_imm16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0x1200},
		{X86_REG_CF, 0x1},
	});

	emulate("adc cx, 0x34");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x1235ULL},
		{X86_REG_PF, true},
		{X86_REG_SF, false},
		{X86_REG_ZF, false},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ADC_reg32_imm32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_ECX, 0xffffff00},
		{X86_REG_CF, 0x1},
	});

	emulate("adc ecx, 0xff");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ECX, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0x0ULL},
		{X86_REG_PF, true},
		{X86_REG_SF, false},
		{X86_REG_ZF, true},
		{X86_REG_OF, false},
		{X86_REG_AF, true},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ADC_reg64_imm64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RCX, 0xffffffffffff0000},
		{X86_REG_CF, 0x0},
	});

	emulate("adc rcx, 0xffff");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ECX, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RCX, 0xffffffffffffffffULL},
		{X86_REG_PF, true},
		{X86_REG_SF, true},
		{X86_REG_ZF, false},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_ADCX
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ADCX_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_ECX, 0xffffff00},
		{X86_REG_EAX, 0xff},
		{X86_REG_CF, 0x1},
	});

	emulate("adcx ecx, eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ECX, X86_REG_EAX, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0x0ULL},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_ADOX
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ADOX_reg32_ref32)
{
	SKIP_MODE_16

	setRegisters({
		{X86_REG_ECX, 0xffffff00},
		{X86_REG_EAX, 0xff},
		{X86_REG_OF, 0x1},
	});

	emulate("adox ecx, eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ECX, X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0x0ULL},
		{X86_REG_OF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_ADD
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ADD_reg8_imm8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DL, 0xf0},
	});

	emulate("add dl, 0x12");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_DL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DL, 0x2ULL},
		{X86_REG_PF, false},
		{X86_REG_SF, false},
		{X86_REG_ZF, false},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ADD_reg16_mem16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 0xff00},
	});
	setMemory({
		{0x1234, 0xff_w},
	});

	emulate("add dx, [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_DX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DX, 0xffffULL},
		{X86_REG_PF, true},
		{X86_REG_SF, true},
		{X86_REG_ZF, false},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ADD_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x12340000},
		{X86_REG_ECX, 0x00005678},
	});

	emulate("add eax, ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x12345678},
		{X86_REG_PF, true},
		{X86_REG_SF, false},
		{X86_REG_ZF, false},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ADD_reg64_imm32)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RDX, 0x100},
	});

	emulate("add rdx, -0x200");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RDX, -0x100}, // 0xffffffffffffff00
		{X86_REG_PF, true},
		{X86_REG_SF, true},
		{X86_REG_ZF, false},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_XADD
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_XADD_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x12340000},
		{X86_REG_ECX, 0x00005678},
	});

	emulate("xadd eax, ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x12345678},
		{X86_REG_ECX, 0x12340000},
		{X86_REG_PF, true},
		{X86_REG_SF, false},
		{X86_REG_ZF, false},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_AND
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AND_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x12345678},
		{X86_REG_ECX, 0x10305070},
	});

	emulate("and eax, ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x10305070},
		{X86_REG_PF, false},
		{X86_REG_SF, false},
		{X86_REG_ZF, false},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_AND_reg32_reg32_zf)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x12345678},
		{X86_REG_ECX, 0x00000000},
	});

	emulate("and eax, ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x0},
		{X86_REG_PF, true},
		{X86_REG_SF, false},
		{X86_REG_ZF, true},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_TEST
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_TEST_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x12345678},
		{X86_REG_ECX, 0x10305070},
	});

	emulate("test eax, ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_PF, false},
		{X86_REG_SF, false},
		{X86_REG_ZF, false},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_TEST_reg32_reg32_zf)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x12345678},
		{X86_REG_ECX, 0x00000000},
	});

	emulate("test eax, ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_PF, true},
		{X86_REG_SF, false},
		{X86_REG_ZF, true},
		{X86_REG_OF, false},
		{X86_REG_AF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_BSF
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BSF_reg16_reg16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 1<<5 | 1<<10},
	});

	emulate("bsf ax, dx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_DX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 5}, // least significant set bit
		{X86_REG_ZF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BSF_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EDX, 1<<20 | 1<<25},
	});

	emulate("bsf eax, edx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 20}, // least significant set bit
		{X86_REG_ZF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BSF_reg32_reg32_src_zero)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 1234}, // will not be changed
		{X86_REG_EDX, 0},
	});

	emulate("bsf eax, edx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 1234},
		{X86_REG_ZF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BSF_reg64_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RDX, 1ULL<<40 | 1ULL<<50},
	});

	emulate("bsf rax, rdx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_RDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 40}, // least significant set bit
		{X86_REG_ZF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_BSR
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BSR_reg16_reg16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 1<<5 | 1<<10},
	});

	emulate("bsr ax, dx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_DX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 10}, // most significant set bit
		{X86_REG_ZF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BSR_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EDX, 1<<20 | 1<<25},
	});

	emulate("bsr eax, edx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 25}, // most significant set bit
		{X86_REG_ZF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BSR_reg32_reg32_src_zero)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 1234}, // will not be changed
		{X86_REG_EDX, 0},
	});

	emulate("bsr eax, edx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 1234},
		{X86_REG_ZF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BSR_reg64_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RDX, 1ULL<<40 | 1ULL<<50},
	});

	emulate("bsr rax, rdx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_RDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 50}, // most significant set bit
		{X86_REG_ZF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_BSWAP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BSWAP_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EDX, 0x12345678},
	});

	emulate("bswap edx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EDX, 0x78563412},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BSWAP_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RDX, 0x0123456789abcdef},
	});

	emulate("bswap rdx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RDX, 0xefcdab8967452301},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_BT
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BT_r32_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_EDX, 0xf0f0f0f0},
	});

	emulate("bt edx, 0x2");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BT_r64_true)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_RDX, 0xf0f0f0f0},
	});

	emulate("bt rdx, 0x46"); // 0x46 & 0x1f = 0x6

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_BTC
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BTC_r32_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_EDX, 0x000000f0},
	});

	emulate("btc edx, 0x2");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_EDX, 0x000000f4},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BTC_r64_true)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_RDX, 0x000000f0},
	});

	emulate("btc rdx, 0x46"); // 0x46 & 0x1f = 0x6

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RDX, 0x000000b0},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_BTR
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BTR_r32_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_EDX, 0x000000f0},
	});

	emulate("btr edx, 0x2");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_EDX, 0x000000f0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BTR_r64_true)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_RDX, 0x000000f0},
	});

	emulate("btr rdx, 0x46"); // 0x46 & 0x1f = 0x6

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RDX, 0x000000b0},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_BTS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BTS_r32_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_EDX, 0x000000f0},
	});

	emulate("bts edx, 0x2");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_EDX, 0x000000f4},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_BTS_r64_true)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_RDX, 0x000000f0},
	});

	emulate("bts rdx, 0x46"); // 0x46 & 0x1f = 0x6

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RDX, 0x000000f0},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CBW
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CBW_sign)
{
	SKIP_MODE_16; // For some reason, 16 bit mode does not like this.

	setRegisters({
		{X86_REG_AX, 0x12f0},
	});

	emulate("cbw");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0xfff0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CBW_no_sign)
{
	SKIP_MODE_16; // For some reason, 16 bit mode does not like this.

	setRegisters({
		{X86_REG_AX, 0x120f},
	});

	emulate("cbw");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x000f},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CWDE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CWDE_sign)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x1234f000},
	});

	emulate("cwde");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0xfffff000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CWDE_no_sign)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x12340fff},
	});

	emulate("cwde");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x00000fff},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CDQE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CDQE_sign)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x12345678f0000000},
	});

	emulate("cdqe");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0xfffffffff0000000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CDQE_no_sign)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x123456780000000f},
	});

	emulate("cdqe");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x000000000000000f},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CWD
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CWD_sign)
{
	SKIP_MODE_16; // For some reason, 16 bit mode does not like this.

	setRegisters({
		{X86_REG_AX, 0xf000},
		{X86_REG_DX, 0x1234},
	});

	emulate("cwd");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DX, 0xffff},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CWD_no_sign)
{
	SKIP_MODE_16; // For some reason, 16 bit mode does not like this.

	setRegisters({
		{X86_REG_AX, 0x000f},
		{X86_REG_DX, 0x1234},
	});

	emulate("cwd");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DX, 0x0000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CDQ
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CDQ_sign)
{
	SKIP_MODE_16; // For some reason, 16 bit mode does not like this.

	setRegisters({
		{X86_REG_EAX, 0xf0000000},
		{X86_REG_EDX, 0x12345678},
	});

	emulate("cdq");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EDX, 0xffffffff},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CDQ_no_sign)
{
	SKIP_MODE_16; // For some reason, 16 bit mode does not like this.

	setRegisters({
		{X86_REG_EAX, 0x0000000f},
		{X86_REG_EDX, 0x12345678},
	});

	emulate("cdq");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DX, 0x00000000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CQO
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CQO_sign)
{
	ONLY_MODE_64; // For some reason, 16 bit mode does not like this.

	setRegisters({
		{X86_REG_RAX, 0xf000000000000000},
		{X86_REG_RDX, 0x0123456789abcdef},
	});

	emulate("cqo");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RDX, 0xffffffffffffffff},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CQO_no_sign)
{
	ONLY_MODE_64; // For some reason, 16 bit mode does not like this.

	setRegisters({
		{X86_REG_RAX, 0x000000000000000f},
		{X86_REG_RDX, 0x0123456789abcdef},
	});

	emulate("cqo");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RDX, 0x0000000000000000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CLC
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CLC_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
	});

	emulate("clc");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CLC_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
	});

	emulate("clc");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CLD
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CLD_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DF, true},
	});

	emulate("cld");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CLD_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DF, false},
	});

	emulate("cld");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMC
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMC_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
	});

	emulate("cmc");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMC_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
	});

	emulate("cmc");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMPXCHG
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMPXCHG_r8_eq)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AL, 0x12},
		{X86_REG_CL, 0x12},
		{X86_REG_DL, 0x34},
		{X86_REG_ZF, false},
	});

	emulate("cmpxchg cl, dl");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_CL, X86_REG_DL, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x12},
		{X86_REG_CL, 0x34},
		{X86_REG_ZF, true},
		{X86_REG_CF, ANY},
		{X86_REG_PF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_OF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMPXCHG_r8_ne)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AL, 0x12},
		{X86_REG_CL, 0x34},
		{X86_REG_DL, 0x56},
		{X86_REG_ZF, true},
	});

	emulate("cmpxchg cl, dl");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_CL, X86_REG_DL, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x34},
		{X86_REG_CL, 0x34},
		{X86_REG_ZF, false},
		{X86_REG_CF, ANY},
		{X86_REG_PF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_OF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMPXCHG_r16_eq)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1234},
		{X86_REG_CX, 0x1234},
		{X86_REG_DX, 0x5678},
		{X86_REG_ZF, false},
	});

	emulate("cmpxchg cx, dx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_DX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1234},
		{X86_REG_CX, 0x5678},
		{X86_REG_ZF, true},
		{X86_REG_CF, ANY},
		{X86_REG_PF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_OF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMPXCHG_r16_ne)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1234},
		{X86_REG_CX, 0x5678},
		{X86_REG_DX, 0x90ab},
		{X86_REG_ZF, true},
	});

	emulate("cmpxchg cx, dx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_DX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x5678},
		{X86_REG_CX, 0x5678},
		{X86_REG_ZF, false},
		{X86_REG_CF, ANY},
		{X86_REG_PF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_OF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMPXCHG_r32_eq)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x1234},
		{X86_REG_ECX, 0x1234},
		{X86_REG_EDX, 0x5678},
		{X86_REG_ZF, false},
	});

	emulate("cmpxchg ecx, edx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX, X86_REG_EDX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x1234},
		{X86_REG_ECX, 0x5678},
		{X86_REG_ZF, true},
		{X86_REG_CF, ANY},
		{X86_REG_PF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_OF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMPXCHG_r32_ne)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x1234},
		{X86_REG_ECX, 0x5678},
		{X86_REG_EDX, 0x90ab},
		{X86_REG_ZF, true},
	});

	emulate("cmpxchg ecx, edx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX, X86_REG_EDX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x5678},
		{X86_REG_ECX, 0x5678},
		{X86_REG_ZF, false},
		{X86_REG_CF, ANY},
		{X86_REG_PF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_OF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMPXCHG_r64_eq)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x1234},
		{X86_REG_RCX, 0x1234},
		{X86_REG_RDX, 0x5678},
		{X86_REG_ZF, false},
	});

	emulate("cmpxchg rcx, rdx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x1234},
		{X86_REG_RCX, 0x5678},
		{X86_REG_ZF, true},
		{X86_REG_CF, ANY},
		{X86_REG_PF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_OF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMPXCHG_r64_ne)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x1234},
		{X86_REG_RCX, 0x5678},
		{X86_REG_RDX, 0x90ab},
		{X86_REG_ZF, true},
	});

	emulate("cmpxchg rcx, rdx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x5678},
		{X86_REG_RCX, 0x5678},
		{X86_REG_ZF, false},
		{X86_REG_CF, ANY},
		{X86_REG_PF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_OF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMPXCHG8B
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMPXCHG8B_eq)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EDX, 0x01234567},
		{X86_REG_EAX, 0x89abcdef},
		{X86_REG_ECX, 0x11111111},
		{X86_REG_EBX, 0x22222222},
		{X86_REG_ZF, false},

	});
	setMemory({
		{0x1000, 0x0123456789abcdef_qw},
	});

	emulate("cmpxchg8b [0x1000]");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX, X86_REG_EAX, X86_REG_ECX, X86_REG_EBX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ZF, true},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_JUST_MEMORY_STORED({
		{0x1000, 0x1111111122222222_qw}
	});
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMPXCHG8B_ne)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EDX, 0x11111111},
		{X86_REG_EAX, 0x22222222},
		{X86_REG_ECX, 0x11111111},
		{X86_REG_EBX, 0x22222222},
		{X86_REG_ZF, true},

	});
	setMemory({
		{0x1000, 0x0123456789abcdef_qw},
	});

	emulate("cmpxchg8b [0x1000]");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX, X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EDX, 0x01234567},
		{X86_REG_EAX, 0x89abcdef},
		{X86_REG_ZF, false},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMPXCHG16B
//

// TODO: this is the same thing as X86_INS_CMPXCHG8B but on 128 bit integers.
// Right now, StoredValue can not work with such a big numbers. Add this test
// when it is refactored to use llvm::APInt.

//
// X86_INS_DEC
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DEC_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x0},
	});

	emulate("dec ax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0xffff},
		{X86_REG_ZF, false},
		{X86_REG_PF, true},
		{X86_REG_AF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DEC_r32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x1234},
	});

	emulate("dec eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x1233},
		{X86_REG_ZF, false},
		{X86_REG_PF, true},
		{X86_REG_AF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DEC_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x1},
	});

	emulate("dec rax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x0},
		{X86_REG_ZF, true},
		{X86_REG_PF, true},
		{X86_REG_AF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_INC
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_INC_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0xffff},
	});

	emulate("inc ax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x0},
		{X86_REG_ZF, true},
		{X86_REG_PF, true},
		{X86_REG_AF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_INC_r32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x1234},
	});

	emulate("inc eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x1235},
		{X86_REG_ZF, false},
		{X86_REG_PF, true},
		{X86_REG_AF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_INC_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x0},
	});

	emulate("inc rax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x1},
		{X86_REG_ZF, false},
		{X86_REG_PF, false},
		{X86_REG_AF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_DIV
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DIV_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CL, 0x0f},
		{X86_REG_AX, 0x123},
	});

	emulate("div cl");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CL, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x6}, // remainder
		{X86_REG_AL, 0x13}, // quotient
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DIV_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0x1234},
		{X86_REG_DX, 0x12},
		{X86_REG_AX, 0x345},
	});

	emulate("div cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_DX, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DX, 0x5e1}, // remainder
		{X86_REG_AX, 0xfd}, // quotient
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DIV_r32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_ECX, 0x1234},
		{X86_REG_EDX, 0x12},
		{X86_REG_EAX, 0x345},
	});

	emulate("div ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ECX, X86_REG_EDX, X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EDX, 0xb1d}, // remainder
		{X86_REG_EAX, 0xfd24b2}, // quotient
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_DIV_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RCX, 0x1234},
		{X86_REG_RDX, 0x12},
		{X86_REG_RAX, 0x345},
	});

	emulate("div rcx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RCX, X86_REG_RDX, X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RDX, 0x7d}, // remainder
		{X86_REG_RAX, 0xfd24b26e4f8bfa}, // quotient
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_IDIV
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_IDIV_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CL, 0x0f},
		{X86_REG_AX, 0x123},
	});

	emulate("idiv cl");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CL, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0x6}, // remainder
		{X86_REG_AL, 0x13}, // quotient
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_IDIV_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0x1234},
		{X86_REG_DX, 0x12},
		{X86_REG_AX, 0x345},
	});

	emulate("idiv cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_DX, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DX, 0x5e1}, // remainder
		{X86_REG_AX, 0xfd}, // quotient
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_IDIV_r32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_ECX, 0x1234},
		{X86_REG_EDX, 0x12},
		{X86_REG_EAX, 0x345},
	});

	emulate("idiv ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ECX, X86_REG_EDX, X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EDX, 0xb1d}, // remainder
		{X86_REG_EAX, 0xfd24b2}, // quotient
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_IDIV_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RCX, 0x1234},
		{X86_REG_RDX, 0x12},
		{X86_REG_RAX, 0x345},
	});

	emulate("idiv rcx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RCX, X86_REG_RDX, X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RDX, 0x7d}, // remainder
		{X86_REG_RAX, 0xfd24b26e4f8bfa}, // quotient
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_JMP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JMP_absolute)
{
	ALL_MODES;

	emulate("jmp 0x1234");

	EXPECT_NO_REGISTERS_LOADED_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JMP_reg16)
{
	SKIP_MODE_64;

	setRegisters({
		{X86_REG_AX, 0x5678},
	});

	emulate("jmp ax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x5678}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JMP_reg32)
{
	ONLY_MODE_32;

	setRegisters({
		{X86_REG_EAX, 0x12345678},
	});

	emulate("jmp eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x12345678}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JMP_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x12345678},
	});

	emulate("jmp rax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x12345678}},
	});
}

//
// X86_INS_LJMP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LJMP_absolute)
{
	SKIP_MODE_64;

	emulate("ljmp  0x1234:0x5678");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CS, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getBranchFunction(), {0x5678}},
	});
}

//
// X86_INS_CALL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CALL_absolute_16)
{
	ONLY_MODE_16;

	setRegisters({
		{X86_REG_SP, 0x100},
	});

	emulate("call 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_SP, 0xfe}, // 0x100 - 0x2
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xfe, 0x1006_w} // 0x100 - 0x2, 0x1000 (addr) + 0x6 (size) = next addr
	});
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CALL_absolute_32)
{
	ONLY_MODE_32;

	setRegisters({
		{X86_REG_ESP, 0x100},
	});

	emulate("call 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ESP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ESP, 0xfc}, // 0x100 - 0x4
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xfc, 0x1005_dw} // 0x100 - 0x4, 0x1000 (addr) + 0x5 (size) = next addr
	});
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CALL_absolute_64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RSP, 0x100},
	});

	emulate("call 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RSP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RSP, 0xf8}, // 0x100 - 0x8
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xf8, 0x1005_qw} // 0x100 - 0x8, 0x1000 (addr) + 0x5 (size) = next addr
	});
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CALL_reg16)
{
	ONLY_MODE_16;

	setRegisters({
		{X86_REG_SP, 0x100},
		{X86_REG_CX, 0x1234},
	});

	emulate("call cx", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SP, X86_REG_CX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_SP, 0xfe}, // 0x100 - 0x2
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xfe, 0x1002_w} // 0x100 - 0x2, 0x1000 (addr) + 0x2 (size) = next addr
	});
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CALL_reg32)
{
	ONLY_MODE_32;

	setRegisters({
		{X86_REG_ESP, 0x100},
		{X86_REG_ECX, 0x1234},
	});

	emulate("call ecx", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ESP, X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ESP, 0xfc}, // 0x100 - 0x4
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xfc, 0x1002_dw} // 0x100 - 0x4, 0x1000 (addr) + 0x2 (size) = next addr
	});
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CALL_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RSP, 0x100},
		{X86_REG_RCX, 0x1234},
	});

	emulate("call rcx", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RSP, X86_REG_RCX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RSP, 0xf8}, // 0x100 - 0x8
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xf8, 0x1002_qw} // 0x100 - 0x8, 0x1000 (addr) + 0x2 (size) = next addr
	});
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCallFunction(), {0x1234}},
	});
}

//
// X86_INS_LAHF
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LAHF)
{
	SKIP_MODE_64;

	setRegisters({
		{X86_REG_AH, 0x12}, // will be overwritten
		{X86_REG_SF, true},
		{X86_REG_ZF, true},
		{X86_REG_AF, true},
		{X86_REG_PF, true},
		{X86_REG_CF, true},
	});

	emulate("lahf");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_ZF, X86_REG_AF, X86_REG_PF, X86_REG_CF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AH, 0xd7}, // 11010111
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_LEA
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LEA_32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x1234},
		{X86_REG_EDX, 0xa},
	});

	emulate("lea ecx, [eax + edx * 8 + 64]");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0x12c4}, // 0x1234 + 0xa * 8 + 64
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LEA_64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x1234},
		{X86_REG_RDX, 0xa},
	});

	emulate("lea rcx, [rax + rdx * 8 + 64]");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_RDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RCX, 0x12c4}, // 0x1234 + 0xa * 8 + 64
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_LEAVE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LEAVE_16)
{
	ONLY_MODE_16;

	setRegisters({
		{X86_REG_SP, 0x1234},
		{X86_REG_BP, 0x5678},
	});
	setMemory({
		{0x5678, 0xffff_w},
	});

	emulate("leave");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_BP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_SP, 0x567a}, // 0x5678 + 2
		{X86_REG_BP, 0xffff},
	});
	EXPECT_MEMORY_LOADED({0x5678});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LEAVE_32)
{
	ONLY_MODE_32;

	setRegisters({
		{X86_REG_ESP, 0x1234},
		{X86_REG_EBP, 0x5678},
	});
	setMemory({
		{0x5678, 0xffffffff_dw},
	});

	emulate("leave");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EBP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ESP, 0x567c}, // 0x5678 + 4
		{X86_REG_EBP, 0xffffffff},
	});
	EXPECT_MEMORY_LOADED({0x5678});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LEAVE_64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RSP, 0x1234},
		{X86_REG_RBP, 0x5678},
	});
	setMemory({
		{0x5678, 0xffffffffffffffff_qw},
	});

	emulate("leave");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RBP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RSP, 0x5680}, // 0x5678 + 8
		{X86_REG_RBP, 0xffffffffffffffff},
	});
	EXPECT_MEMORY_LOADED({0x5678});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_LDS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LDS_16)
{
	ONLY_MODE_16;

	setMemory({
		{0x1000, 0x1234_w},
		{0x1002, 0x90ab_w},
	});

	emulate("lds ax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DS, 0x90ab},
		{X86_REG_AX, 0x1234},
	});
	EXPECT_MEMORY_LOADED({0x1000, 0x1002});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LDS_32)
{
	ONLY_MODE_32;

	setMemory({
		{0x1000, 0x12345678_dw},
		{0x1004, 0x90ab_w},
	});

	emulate("lds eax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DS, 0x90ab},
		{X86_REG_EAX, 0x12345678},
	});
	EXPECT_MEMORY_LOADED({0x1000, 0x1004});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_LES
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LES_16)
{
	ONLY_MODE_16;

	setMemory({
		{0x1000, 0x1234_w},
		{0x1002, 0x90ab_w},
	});

	emulate("les ax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ES, 0x90ab},
		{X86_REG_AX, 0x1234},
	});
	EXPECT_MEMORY_LOADED({0x1000, 0x1002});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LES_32)
{
	ONLY_MODE_32;

	setMemory({
		{0x1000, 0x12345678_dw},
		{0x1004, 0x90ab_w},
	});

	emulate("les eax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ES, 0x90ab},
		{X86_REG_EAX, 0x12345678},
	});
	EXPECT_MEMORY_LOADED({0x1000, 0x1004});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_LFS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LFS_16)
{
	ONLY_MODE_16;

	setMemory({
		{0x1000, 0x1234_w},
		{0x1002, 0x90ab_w},
	});

	emulate("lfs ax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_FS, 0x90ab},
		{X86_REG_AX, 0x1234},
	});
	EXPECT_MEMORY_LOADED({0x1000, 0x1002});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LFS_32)
{
	ONLY_MODE_32;

	setMemory({
		{0x1000, 0x12345678_dw},
		{0x1004, 0x90ab_w},
	});

	emulate("lfs eax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_FS, 0x90ab},
		{X86_REG_EAX, 0x12345678},
	});
	EXPECT_MEMORY_LOADED({0x1000, 0x1004});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_LGS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LGS_16)
{
	ONLY_MODE_16;

	setMemory({
		{0x1000, 0x1234_w},
		{0x1002, 0x90ab_w},
	});

	emulate("lgs ax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_GS, 0x90ab},
		{X86_REG_AX, 0x1234},
	});
	EXPECT_MEMORY_LOADED({0x1000, 0x1002});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LGS_32)
{
	ONLY_MODE_32;

	setMemory({
		{0x1000, 0x12345678_dw},
		{0x1004, 0x90ab_w},
	});

	emulate("lgs eax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_GS, 0x90ab},
		{X86_REG_EAX, 0x12345678},
	});
	EXPECT_MEMORY_LOADED({0x1000, 0x1004});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_LSS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LSS_16)
{
	ONLY_MODE_16;

	setMemory({
		{0x1000, 0x1234_w},
		{0x1002, 0x90ab_w},
	});

	emulate("lss ax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_SS, 0x90ab},
		{X86_REG_AX, 0x1234},
	});
	EXPECT_MEMORY_LOADED({0x1000, 0x1002});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LSS_32)
{
	ONLY_MODE_32;

	setMemory({
		{0x1000, 0x12345678_dw},
		{0x1004, 0x90ab_w},
	});

	emulate("lss eax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_SS, 0x90ab},
		{X86_REG_EAX, 0x12345678},
	});
	EXPECT_MEMORY_LOADED({0x1000, 0x1004});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_MOV
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_reg8_reg8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AL, 0x12},
	});

	emulate("mov cl, al");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_CX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CL, 0x12},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_reg8_mem8)
{
	ALL_MODES;

	setMemory({
		{0x1000, 0x12_b},
	});

	emulate("mov cl, [0x1000]");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CL, 0x12},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_reg16_imm16)
{
	ALL_MODES;

	emulate("mov cx, 0x1234");

	if (GetParam() != CS_MODE_16)
	{
		EXPECT_JUST_REGISTERS_LOADED({X86_REG_ECX});
	}
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x12345678},
	});

	emulate("mov ecx, eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0x12345678},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_mem32_reg32)
{
	ONLY_MODE_32;

	setRegisters({
		{X86_REG_EAX, 0x12345678},
	});

	emulate("mov [0x1234], eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 0x12345678_dw}
	});
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_reg64_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x0123456789abcdef},
	});

	emulate("mov rcx, rax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RCX, 0x0123456789abcdef},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_from_ds_addr_space_1)
{
	SKIP_MODE_16;

	setMemory({
		{0x1000, 0x12345678_dw},
	});

	// should be the same as "mov eax, ds:0x1000"
	emulate("mov eax, [0x1000]");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_from_ds_addr_space_2)
{
	SKIP_MODE_16;

	setMemory({
		{0x1000, 0x12345678_dw},
	});

	// should be the same as "mov eax, [0x1000]"
	emulate("mov eax, ds:0x1000");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1000});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_from_gs_addr_space)
{
	SKIP_MODE_16;

	emulate("mov eax, gs:0x1000");

	bool loadInsnOk = false;
	for (llvm::inst_iterator I = llvm::inst_begin(_function),
			E = llvm::inst_end(_function); I != E; ++I)
	{
		if (llvm::LoadInst* l = llvm::dyn_cast<llvm::LoadInst>(&*I))
		{
			llvm::ConstantExpr* ce = llvm::dyn_cast<llvm::ConstantExpr>(l->getPointerOperand());
			llvm::ConstantInt* ci = ce ? llvm::dyn_cast<llvm::ConstantInt>(ce->getOperand(0)) : nullptr;

			loadInsnOk = ce
					&& ci
					&& ce->getOpcode() == llvm::Instruction::IntToPtr
					&& ce->getType()->getPointerAddressSpace()
						== static_cast<unsigned>(x86_addr_space::GS);
			if (loadInsnOk)
			{
				break;
			}
		}
	}

	EXPECT_TRUE(loadInsnOk);
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_from_fs_addr_space)
{
	SKIP_MODE_16;

	emulate("mov eax, fs:0x1000");

	bool loadInsnOk = false;
	for (llvm::inst_iterator I = llvm::inst_begin(_function),
			E = llvm::inst_end(_function); I != E; ++I)
	{
		if (llvm::LoadInst* l = llvm::dyn_cast<llvm::LoadInst>(&*I))
		{
			llvm::ConstantExpr* ce = llvm::dyn_cast<llvm::ConstantExpr>(l->getPointerOperand());
			llvm::ConstantInt* ci = ce ? llvm::dyn_cast<llvm::ConstantInt>(ce->getOperand(0)) : nullptr;

			loadInsnOk = ce
					&& ci
					&& ce->getOpcode() == llvm::Instruction::IntToPtr
					&& ce->getType()->getPointerAddressSpace()
						== static_cast<unsigned>(x86_addr_space::FS);
			if (loadInsnOk)
			{
				break;
			}
		}
	}

	EXPECT_TRUE(loadInsnOk);
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_from_ss_addr_space)
{
	SKIP_MODE_16;

	emulate("mov eax, ss:0x1000");

	bool loadInsnOk = false;
	for (llvm::inst_iterator I = llvm::inst_begin(_function),
			E = llvm::inst_end(_function); I != E; ++I)
	{
		if (llvm::LoadInst* l = llvm::dyn_cast<llvm::LoadInst>(&*I))
		{
			llvm::ConstantExpr* ce = llvm::dyn_cast<llvm::ConstantExpr>(l->getPointerOperand());
			llvm::ConstantInt* ci = ce ? llvm::dyn_cast<llvm::ConstantInt>(ce->getOperand(0)) : nullptr;

			loadInsnOk = ce
					&& ci
					&& ce->getOpcode() == llvm::Instruction::IntToPtr
					&& ce->getType()->getPointerAddressSpace()
						== static_cast<unsigned>(x86_addr_space::SS);
			if (loadInsnOk)
			{
				break;
			}
		}
	}

	EXPECT_TRUE(loadInsnOk);
}

//
// X86_INS_MOVABS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOV_reg64_imm64)
{
	ONLY_MODE_64;

	emulate("movabs rcx, 0x0123456789abcdef");

	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RCX, 0x0123456789abcdef},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_MOVSX
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOVSX_sign)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_AX, 0xff00},
	});

	emulate("movsx ecx, ax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0xffffff00},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOVSX_unsign)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_AX, 0x00ff},
	});

	emulate("movsx ecx, ax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0x000000ff},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_MOVSXD
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOVSXD_sign)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_EAX, 0xff000000},
	});

	emulate("movsxd rcx, eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RCX, 0xffffffffff000000},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOVSXD_unsign)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_EAX, 0x000000ff},
	});

	emulate("movsxd rcx, eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RCX, 0x00000000000000ff},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_MOVZX
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MOVZX)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_AX, 0xff00},
	});

	emulate("movzx ecx, ax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0x0000ff00},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_MUL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MUL_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CL, 0x0f},
		{X86_REG_AL, 0xa0},
	});

	emulate("mul cl");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CL, X86_REG_AL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x0960},
		{X86_REG_OF, true},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MUL_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 0x0f},
		{X86_REG_AX, 0xa0},
	});

	emulate("mul dx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_DX, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x0960},
		{X86_REG_DX, 0x0000},
		{X86_REG_OF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MUL_r32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EDX, 0x0f},
		{X86_REG_EAX, 0xa0},
	});

	emulate("mul edx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX, X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x0960},
		{X86_REG_EDX, 0x0000},
		{X86_REG_OF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_MUL_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RDX, 0x0f},
		{X86_REG_RAX, 0xa0},
	});

	emulate("mul rdx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RDX, X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x0960},
		{X86_REG_RDX, 0x0000},
		{X86_REG_OF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_IMUL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_IMUL_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CL, 0x0f},
		{X86_REG_AL, 0xa0},
	});

	emulate("imul cl");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CL, X86_REG_AL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0xfa60},
		{X86_REG_OF, true},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_IMUL_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 0x0f},
		{X86_REG_AX, 0xa0},
	});

	emulate("imul dx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_DX, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x0960},
		{X86_REG_DX, 0x0000},
		{X86_REG_OF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_IMUL_r32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EDX, 0x0f},
		{X86_REG_EAX, 0xa0},
	});

	emulate("imul edx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX, X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x0960},
		{X86_REG_EDX, 0x0000},
		{X86_REG_OF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_IMUL_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RDX, 0x0f},
		{X86_REG_RAX, 0xa0},
	});

	emulate("imul rdx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RDX, X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x0960},
		{X86_REG_RDX, 0x0000},
		{X86_REG_OF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_IMUL_r32_binary)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EDX, 0x0f000000},
		{X86_REG_EAX, 0xa0000000},
	});

	emulate("imul eax, edx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX, X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x0},
		{X86_REG_OF, true},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_IMUL_r32_ternary)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EDX, 0x00001234},
	});

	emulate("imul eax, edx, 0xf0");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EDX, X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x1110c0},
		{X86_REG_OF, false},
		{X86_REG_CF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_NEG
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_NEG_reg8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CL, 0x4d}, // 01001101
		{X86_REG_CF, false},
	});

	emulate("neg cl");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CL, 0xb3}, // 10110011
		{X86_REG_CF, true},
		{X86_REG_OF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_NEG_reg16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0x0},
		{X86_REG_CF, true},
	});

	emulate("neg cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x0}, // yes, this is really 0x0, not oxffff
		{X86_REG_CF, false},
		{X86_REG_OF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_NEG_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_ECX, 0x4d}, // 01001101
		{X86_REG_CF, false},
	});

	emulate("neg ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0xffffffb3}, // 10110011
		{X86_REG_CF, true},
		{X86_REG_OF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_NEG_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RCX, 0x4d}, // 01001101
		{X86_REG_CF, false},
	});

	emulate("neg rcx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RCX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RCX, 0xffffffffffffffb3}, // 10110011
		{X86_REG_CF, true},
		{X86_REG_OF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_NOP, X86_INS_UD2, X86_INS_UD2B, X86_INS_FNOP, X86_INS_HLT
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_NOP)
{
	ALL_MODES;

	emulate("nop");

	EXPECT_NO_REGISTERS_LOADED_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_UD2)
{
	ALL_MODES;

	emulate("ud2");

	EXPECT_NO_REGISTERS_LOADED_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_UD2B)
{
	ALL_MODES;

	emulate("ud2b");

	EXPECT_NO_REGISTERS_LOADED_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FNOP)
{
	ALL_MODES;

	emulate("fnop");

	EXPECT_NO_REGISTERS_LOADED_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_NOT
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_NOT_reg8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CL, 0xf0},
	});

	emulate("not cl");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CL});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CL, 0x0f},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_NOT_reg16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0xf0f0},
	});

	emulate("not cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x0f0f},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_NOT_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_ECX, 0xf0f0f0f0},
	});

	emulate("not ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0x0f0f0f0f},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_NOT_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RCX, 0xf0f0f0f0f0f0f0f0},
	});

	emulate("not rcx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RCX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RCX, 0x0f0f0f0f0f0f0f0f},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_OR
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_OR_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x12345678},
		{X86_REG_ECX, 0x10305070},
	});

	emulate("or eax, ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x12345678},
		{X86_REG_PF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_OF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_CF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_OR_reg64_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x0123456700000000},
		{X86_REG_RCX, 0x0000000089abcdef},
	});

	emulate("or rax, rcx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_RCX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x0123456789abcdef},
		{X86_REG_PF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_OF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_CF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_POP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_POP_reg16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SP, 0xfe},
	});
	setMemory({
		{0xfe, 0x1234_w}
	});

	emulate("pop ax");

	if (GetParam() == CS_MODE_16)
	{
		EXPECT_JUST_REGISTERS_LOADED({X86_REG_SP});
	}
	else
	{
		EXPECT_JUST_REGISTERS_LOADED({X86_REG_SP, X86_REG_AX});
	}
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_SP, 0x100}, // 0xfe + 0x2
		{X86_REG_AX, 0x1234},
	});
	EXPECT_JUST_MEMORY_LOADED({0xfe});
	EXPECT_NO_MEMORY_STORED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_POP_reg32)
{
	ONLY_MODE_32;

	setRegisters({
		{X86_REG_ESP, 0xfc},
	});
	setMemory({
		{0xfc, 0x12345678_dw}
	});

	emulate("pop eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ESP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ESP, 0x100}, // 0xfc + 0x4
		{X86_REG_EAX, 0x12345678},
	});
	EXPECT_JUST_MEMORY_LOADED({0xfc});
	EXPECT_NO_MEMORY_STORED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_POP_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RSP, 0xf8},
	});
	setMemory({
		{0xf8, 0x0123456789abcdef_qw}
	});

	emulate("pop rax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RSP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RSP, 0x100}, // 0xf8 + 0x8
		{X86_REG_RAX, 0x0123456789abcdef},
	});
	EXPECT_JUST_MEMORY_LOADED({0xf8});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_POPAW (POPA)
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_POPAW)
{
	ONLY_MODE_16;

	setRegisters({
		{X86_REG_SP, 0x100},
	});
	setMemory({
		{0x100, 0x0001_w},
		{0x102, 0x0002_w},
		{0x104, 0x0003_w},
		// skip next 2 bytes
		{0x108, 0x0004_w},
		{0x10a, 0x0005_w},
		{0x10c, 0x0006_w},
		{0x10e, 0x0007_w},
	});

	emulate("popaw");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_SP, 0x110}, // 0x100 + 7 * 2 + 2 (2 more bytes are skipped)
		{X86_REG_DI, 0x0001},
		{X86_REG_SI, 0x0002},
		{X86_REG_BP, 0x0003},
		{X86_REG_BX, 0x0004},
		{X86_REG_DX, 0x0005},
		{X86_REG_CX, 0x0006},
		{X86_REG_AX, 0x0007},
	});
	EXPECT_JUST_MEMORY_LOADED({
		0x100, 0x102, 0x104, 0x108, 0x10a, 0x10c, 0x10e
	});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_POPAL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_POPAL)
{
	ONLY_MODE_32;

	setRegisters({
		{X86_REG_SP, 0x100},
	});
	setMemory({
		{0x100, 0x0001_dw},
		{0x104, 0x0002_dw},
		{0x108, 0x0003_dw},
		// skip next 4 bytes
		{0x110, 0x0004_dw},
		{0x114, 0x0005_dw},
		{0x118, 0x0006_dw},
		{0x11c, 0x0007_dw},
	});

	emulate("popal");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ESP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ESP, 0x120}, // 0x100 + 7 * 4 + 4 (4 more bytes are skipped)
		{X86_REG_EDI, 0x0001},
		{X86_REG_ESI, 0x0002},
		{X86_REG_EBP, 0x0003},
		{X86_REG_EBX, 0x0004},
		{X86_REG_EDX, 0x0005},
		{X86_REG_ECX, 0x0006},
		{X86_REG_EAX, 0x0007},
	});
	EXPECT_JUST_MEMORY_LOADED({
		0x100, 0x104, 0x108, 0x110, 0x114, 0x118, 0x11c
	});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_PUSH
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_PUSH_reg16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SP, 0x100},
		{X86_REG_AX, 0x1234},
	});

	emulate("push ax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SP, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_SP, 0xfe}, // 0x100 - 0x2
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xfe, 0x1234_w} // 0x100 - 0x2
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_PUSH_reg32)
{
	ONLY_MODE_32;

	setRegisters({
		{X86_REG_ESP, 0x100},
		{X86_REG_EAX, 0x12345678},
	});

	emulate("push eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ESP, X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ESP, 0xfc}, // 0x100 - 0x4
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xfc, 0x12345678_dw} // 0x100 - 0x4
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_PUSH_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RSP, 0x100},
		{X86_REG_RAX, 0x0123456789abcdef},
	});

	emulate("push rax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RSP, X86_REG_RAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RSP, 0xf8}, // 0x100 - 0x8
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xf8, 0x0123456789abcdef_qw} // 0x100 - 0x8
	});
}

//
// X86_INS_PUSHAW
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_PUSHAW)
{
	ONLY_MODE_16;

	setRegisters({
		{X86_REG_SP, 0x100},
		{X86_REG_DI, 0x0001},
		{X86_REG_SI, 0x0002},
		{X86_REG_BP, 0x0003},
		{X86_REG_BX, 0x0004},
		{X86_REG_DX, 0x0005},
		{X86_REG_CX, 0x0006},
		{X86_REG_AX, 0x0007},
	});

	emulate("pushaw");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SP, X86_REG_DI, X86_REG_SI, X86_REG_BP, X86_REG_BX, X86_REG_DX, X86_REG_CX, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_SP, 0xf0}, // 0x100 - (7 * 2 + 2 (2 more bytes are skipped))

	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xfe, 0x0007_w},
		{0xfc, 0x0006_w},
		{0xfa, 0x0005_w},
		{0xf8, 0x0004_w},
		{0xf6, ANY},
		{0xf4, 0x0003_w},
		{0xf2, 0x0002_w},
		{0xf0, 0x0001_w},
	});
}

//
// X86_INS_PUSHAL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_PUSHAL)
{
	ONLY_MODE_32;

	setRegisters({
		{X86_REG_ESP, 0x100},
		{X86_REG_EDI, 0x0001},
		{X86_REG_ESI, 0x0002},
		{X86_REG_EBP, 0x0003},
		{X86_REG_EBX, 0x0004},
		{X86_REG_EDX, 0x0005},
		{X86_REG_ECX, 0x0006},
		{X86_REG_EAX, 0x0007},
	});

	emulate("pushal");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ESP, X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX, X86_REG_EDX, X86_REG_ECX, X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ESP, 0xe0}, // 0x100 - (7 * 4 + 4 (4 more bytes are skipped))

	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0xfc, 0x0007_w},
		{0xf8, 0x0006_w},
		{0xf4, 0x0005_w},
		{0xf0, 0x0004_w},
		{0xec, ANY},
		{0xe8, 0x0003_w},
		{0xe4, 0x0002_w},
		{0xe0, 0x0001_w},
	});
}

//
// X86_INS_SAHF
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAHF)
{
	SKIP_MODE_64;

	setRegisters({
		{X86_REG_AH, 0xff},
	});

	emulate("sahf");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AH});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_SF, true},
		{X86_REG_ZF, true},
		{X86_REG_AF, true},
		{X86_REG_PF, true},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SALC
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SALC_cf)
{
	SKIP_MODE_64;

	setRegisters({
		{X86_REG_AL, 0x12},
		{X86_REG_CF, true},
	});

	emulate("salc");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0xff},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SALC_no_cf)
{
	SKIP_MODE_64;

	setRegisters({
		{X86_REG_AL, 0x12},
		{X86_REG_CF, false},
	});

	emulate("salc");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x00},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_STC
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_STC)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
	});

	emulate("stc");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_STD
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_STD)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DF, false},
	});

	emulate("std");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_DF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SHL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHL_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AL, 0x24}, // 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("shl al, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x20}, // 00000001 | 00100000 = 0x120 = 0x20
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHL_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x2400}, // 00100100 0...
		{X86_REG_OF, true} // should not be affected
	});

	emulate("shl ax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2000}, // 00000001 | 00100000 = 0x120 = 0x20
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHL_r32_cf_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x24000000}, // 00100100 0...
		{X86_REG_OF, false} // should not be affected
	});

	emulate("shl eax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x20000000}, // 00000001 | 00100000 = 0x120 = 0x20
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHL_r32_cf_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x24000000}, // 00100100 0...
		{X86_REG_OF, false} // should not be affected
	});

	emulate("shl eax, 0x4");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x40000000}, // 00000010 | 01000000 = 0x140 = 0x40
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHL_r32_of_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0xc0000000}, // 11000000 0...
		{X86_REG_OF, true}
	});

	emulate("shl eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x80000000}, // 00000010 | 01000000 = 0x140 = 0x40
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHL_r32_of_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0xa0000000}, // 10100000 0...
		{X86_REG_OF, false}
	});

	emulate("shl eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x40000000}, // 00000010 | 01000000 = 0x140 = 0x40
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHL_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x2400000000000000}, // 00100100 0...
		{X86_REG_OF, true} // should not be affected
	});

	emulate("shl rax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x2000000000000000}, // 00000001 | 00100000 = 0x120 = 0x20
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SAL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAL_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AL, 0x24}, // 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("sal al, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x20}, // 00000001 | 00100000 = 0x120 = 0x20
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAL_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x2400}, // 00100100 0...
		{X86_REG_OF, true} // should not be affected
	});

	emulate("sal ax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2000}, // 00000001 | 00100000 = 0x120 = 0x20
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAL_r32_cf_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x24000000}, // 00100100 0...
		{X86_REG_OF, false} // should not be affected
	});

	emulate("sal eax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x20000000}, // 00000001 | 00100000 = 0x120 = 0x20
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAL_r32_cf_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x24000000}, // 00100100 0...
		{X86_REG_OF, false} // should not be affected
	});

	emulate("sal eax, 0x4");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x40000000}, // 00000010 | 01000000 = 0x140 = 0x40
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAL_r32_of_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0xc0000000}, // 11000000 0...
		{X86_REG_OF, true}
	});

	emulate("sal eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x80000000}, // 00000010 | 01000000 = 0x140 = 0x40
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAL_r32_of_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0xa0000000}, // 10100000 0...
		{X86_REG_OF, false}
	});

	emulate("sal eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x40000000}, // 00000010 | 01000000 = 0x140 = 0x40
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAL_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x2400000000000000}, // 00100100 0...
		{X86_REG_OF, true} // should not be affected
	});

	emulate("sal rax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x2000000000000000}, // 00000001 | 00100000 = 0x120 = 0x20
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SHR
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHR_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AL, 0x24}, // 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("shr al, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x4}, // 00000100 = 0x4
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHR_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x8024}, // 10000000 00100100
		{X86_REG_OF, true} // should not be affected
	});

	emulate("shr ax, 0x8");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x80}, // 10000000 = 0x80
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHR_r32_cf_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x00000024}, // 0... 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("shr eax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x4}, // 00000100 = 0x4
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHR_r32_cf_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x00000024}, // 0... 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("shr eax, 24");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x0}, // 0x0
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHR_r32_of_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x7e000000}, // 01111110 0...
		{X86_REG_OF, true}
	});

	emulate("shr eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x3f000000}, // 00111111 0... = 0x3f 0...
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHR_r32_of_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0xf0000000}, // 11110000 0...
		{X86_REG_OF, false}
	});

	emulate("shr eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x78000000}, // 01111000 0... = 0x78 0...
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SHR_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x0000000000000024}, // 0... 00100100
		{X86_REG_OF, true} // should not be affected
	});

	emulate("shr rax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x4}, // 00000100 = 0x4
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SAR
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAR_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AL, 0x24}, // 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("sar al, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x4}, // 00000100 = 0x4
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAR_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x8024}, // 10000000 00100100
		{X86_REG_OF, true} // should not be affected
	});

	emulate("sar ax, 0x8");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0xff80}, // 11111111 10000000 = 0xff 0x80
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAR_r32_cf_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x80000024}, // 10... 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("sar eax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0xf0000004}, // 11110000 0... 00000100
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAR_r32_cf_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x00000024}, // 0... 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("sar eax, 24");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x0}, // 0x0
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAR_r32_of_false_1)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x7e000000}, // 01111110 0...
		{X86_REG_OF, true}
	});

	emulate("sar eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x3f000000}, // 00111111 0... = 0x3f 0...
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAR_r32_of_false_2)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0xf0000000}, // 11110000 0...
		{X86_REG_OF, true}
	});

	emulate("sar eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0xf8000000}, // 11111000 0... = 0xf8 0...
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, false},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SAR_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x0000000000000024}, // 0... 00100100
		{X86_REG_OF, true} // should not be affected
	});

	emulate("sar rax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x4}, // 00000100 = 0x4
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true},
		{X86_REG_ZF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_PF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_ROL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROL_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AL, 0x24}, // 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("rol al, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x21}, // 00100 001
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROL_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x2400}, // 00100100 0...
		{X86_REG_OF, true} // should not be affected
	});

	emulate("rol ax, 0x5");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x8004}, // 10000000 00000100
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROL_r32_mask)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x00240000}, // 00100100 0...
		{X86_REG_OF, false} // should not be affected
	});

	emulate("rol eax, 0x48"); // 0x48 and 0x1f = 0x8

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x24000000},
		{X86_REG_CF, false},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROL_r32_of_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0xc0000000}, // 11000000 0...
		{X86_REG_OF, true}
	});

	emulate("rol eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x80000001},
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false}, // CF xor MSB
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROL_r32_of_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0xa0000000}, // 10100000 0...
		{X86_REG_OF, false}
	});

	emulate("rol eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x40000001},
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true}, // CF xor MSB
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROL_r64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x2400000000000000}, // 00100100 0...
		{X86_REG_OF, true} // should not be affected
	});

	emulate("rol rax, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x2000000000000001},
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_ROR
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROR_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AL, 0x24}, // 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("ror al, 0x3");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x84}, // 100 00100
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROR_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x8024}, // 10000000 00100100
		{X86_REG_OF, true} // should not be affected
	});

	emulate("ror ax, 0x5");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2401}, // 00100 10000000 001
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROR_r32_mask)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x00000024}, // 0... 00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("ror eax, 0x48"); // 0x48 and 0x1f = 0x8

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x24000000}, // 00100100 0..
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROR_r32_of_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0xfe000001}, // 11111110 0...1
		{X86_REG_OF, true}
	});

	emulate("ror eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0xff000000}, // 11111111 0..
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, false}, // xor 2 MSBs
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROR_r32_of_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0xfe000000}, // 11111110 0...
		{X86_REG_OF, false}
	});

	emulate("ror eax");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x7f000000}, // 01111111 0..
		{X86_REG_CF, false}, // last shifted
		{X86_REG_OF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_ROR_r64_mask)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x00000000000000ff},
		{X86_REG_OF, true} // should not be affected
	});

	emulate("ror rax, 0x88"); // 0x88 & 0x3f = 0x8

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0xff00000000000000},
		{X86_REG_CF, true}, // last shifted
		{X86_REG_OF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_RCR
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCR_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true}, // 1
		{X86_REG_AL, 0x24}, //  00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("rcr al, 0x3"); // 1 00100100 -> 100 1 00100

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_AL, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, true},
		{X86_REG_AL, 0x24},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCR_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},   // 1
		{X86_REG_AX, 0x8024}, //  10000000 00100100
		{X86_REG_OF, true} // should not be affected
	});

	emulate("rcr ax, 0x5"); // 1 10000000 00100100 -> 00100 1 10000000 001

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_AX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_AX, 0x4c01},
		{X86_REG_OF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCR_r32_mask)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_CF, false},       // 0
		{X86_REG_EAX, 0x00000024}, //  0... 00100100
		{X86_REG_OF, false} // should not be affected
	});

	// 0x48 and 0x1f = 0x8
	// 0 0... 00100100 -> 00100100 0 0..
	emulate("rcr eax, 0x48");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_EAX, 0x48000000},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCR_r32_of_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_CF, false},       // 0
		{X86_REG_EAX, 0xfe000000}, //  11111110 0...
		{X86_REG_OF, false}
	});

	emulate("rcr eax"); // 0 11111110 0... -> 0 0 11111110 0...

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_EAX, 0x7f000000},
		{X86_REG_OF, true}, // xor 2 MSBs of result (not CF, checked by olly)
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCR_r32_of_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_CF, true},        // 1
		{X86_REG_EAX, 0xfe000000}, //  11111110 0...
		{X86_REG_OF, true}
	});

	emulate("rcr eax"); // 1 11111110 0... -> 0 1 11111110 0...

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_EAX, 0xff000000},
		{X86_REG_OF, false}, // xor 2 MSBs of result (not CF, checked by olly)
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCR_r64_mask)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_CF, true},                // 1
		{X86_REG_RAX, 0x00000000000000ff}, //  0... 11111111
		{X86_REG_OF, true} // should not be affected
	});

	emulate("rcr rax, 0x88"); // 1 0... 11111111 -> 11111111 1 0...

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_RAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, true},
		{X86_REG_RAX, 0xff00000000000000},
		{X86_REG_OF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_RCL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCL_r8)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true}, // 1
		{X86_REG_AL, 0x24}, //  00100100
		{X86_REG_OF, false} // should not be affected
	});

	emulate("rcl al, 0x3"); // 1 00|100100 -> 100100 1 00

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_AL, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, true},
		{X86_REG_AL, 0x24},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCL_r16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},   // 1
		{X86_REG_AX, 0x8024}, //  10000000 00100100
		{X86_REG_OF, true} // should not be affected
	});

	emulate("rcl ax, 0x5"); // 1 1000|0000 00100100

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_AX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_AX, 0x498},
		{X86_REG_OF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCL_r32_mask)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_CF, false},       // 0
		{X86_REG_EAX, 0x00000024}, //  0... 00100100
		{X86_REG_OF, false} // should not be affected
	});

	// 0x48 and 0x1f = 0x8
	// 0 0000000|0 0... 00100100
	emulate("rcl eax, 0x48");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_EAX, 0x2400},
		{X86_REG_OF, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCL_r32_of_false)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_CF, false},       // 0
		{X86_REG_EAX, 0xfe000000}, //  11111110 0...
		{X86_REG_OF, true}
	});

	emulate("rcl eax"); // 0| 11111110 0...

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, true},
		{X86_REG_EAX, 0xfc000000},
		{X86_REG_OF, false}, // CF xor MSB
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCL_r32_of_true)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_CF, false},        // 0
		{X86_REG_EAX, 0x7e000000}, //  01111110 0...
		{X86_REG_OF, false}
	});

	emulate("rcl eax"); // 0 |01111110 0...

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_EAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_EAX, 0xfc000000},
		{X86_REG_OF, true}, // CF xor MSB
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RCL_r64_mask)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_CF, true},                // 1
		{X86_REG_RAX, 0x00000000000000ff}, //  0... 11111111
		{X86_REG_OF, true} // should not be affected
	});

	emulate("rcl rax, 0x88"); // 1 0000000|0 0... 11111111

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_RAX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CF, false},
		{X86_REG_RAX, 0x000000000000ff80},
		{X86_REG_OF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_XCHG
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_XCHG_reg16_reg16)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1234},
		{X86_REG_CX, 0x5678},
	});

	emulate("xchg ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x5678},
		{X86_REG_CX, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_XCHG_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x1234},
		{X86_REG_ECX, 0x5678},
	});

	emulate("xchg eax, ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x5678},
		{X86_REG_ECX, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_XCHG_reg32_mem32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_ECX, 0x5678},
	});
	setMemory({
		{0x1234, 0xffff_dw},
	});

	emulate("xchg ecx, [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ECX, 0xffff},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 0x5678_dw}
	});
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_XCHG_reg64_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x1234},
		{X86_REG_RCX, 0x5678},
	});

	emulate("xchg rax, rcx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_RCX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x5678},
		{X86_REG_RCX, 0x1234},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_XLATB
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_XLATB_16)
{
	ONLY_MODE_16;

	setRegisters({
		{X86_REG_AL, 0x0034},
		{X86_REG_BX, 0x1200},
	});
	setMemory({
		{0x1234, 0x11_b},
	});

	emulate("xlatb");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_BX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x11},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_XLATB_32)
{
	ONLY_MODE_32;

	setRegisters({
		{X86_REG_AL, 0x0034},
		{X86_REG_EBX, 0x1200},
	});
	setMemory({
		{0x1234, 0x11_b},
	});

	emulate("xlatb");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_EBX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x11},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_XLATB_64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_AL, 0x0034},
		{X86_REG_RBX, 0x1200},
	});
	setMemory({
		{0x1234, 0x11_b},
	});

	emulate("xlatb");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AL, X86_REG_RBX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, 0x11},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_XOR
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_XOR_reg32_reg32)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x12345678},
		{X86_REG_ECX, 0x10305070},
	});

	emulate("xor eax, ecx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX, X86_REG_ECX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, 0x02040608},
		{X86_REG_PF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_OF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_CF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_XOR_reg64_reg64)
{
	ONLY_MODE_64;

	setRegisters({
		{X86_REG_RAX, 0x0123456700000000},
		{X86_REG_RCX, 0x0000000089abcdef},
	});

	emulate("xor rax, rcx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_RAX, X86_REG_RCX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_RAX, 0x0123456789abcdef},
		{X86_REG_PF, ANY},
		{X86_REG_SF, ANY},
		{X86_REG_ZF, ANY},
		{X86_REG_OF, ANY},
		{X86_REG_AF, ANY},
		{X86_REG_CF, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_LOOP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOP_r16_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0xa},
	});

	emulate("loop 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1012}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOP_r16_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0x1},
	});

	emulate("loop 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1012}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOP_r16_jump_underflow)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0x0},
	});

	emulate("loop 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0xffff},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1012}},
	});
}

//
// X86_INS_LOOPE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOPE_r16_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0xa},
		{X86_REG_ZF, true},
	});

	emulate("loope 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1012}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOPE_r16_no_jump_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0xa},
		{X86_REG_ZF, false},
	});

	emulate("loope 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1012}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOPE_r16_no_jump_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0x1},
		{X86_REG_ZF, true},
	});

	emulate("loope 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1012}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOPE_r16_no_jump_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0x1},
		{X86_REG_ZF, false},
	});

	emulate("loope 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1012}},
	});
}

//
// X86_INS_LOOPNE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOPNE_r16_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0xa},
		{X86_REG_ZF, false},
	});

	emulate("loopne 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1012}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOPNE_r16_no_jump_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0xa},
		{X86_REG_ZF, true},
	});

	emulate("loopne 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x9},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1012}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOPNE_r16_no_jump_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0x1},
		{X86_REG_ZF, false},
	});

	emulate("loopne 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1012}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_LOOPNE_r16_no_jump_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CX, 0x1},
		{X86_REG_ZF, true},
	});

	emulate("loopne 0x1012", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_CX, 0x0},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1012}},
	});
}

//
// X86_INS_JAE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JAE_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
	});

	emulate("jae 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JAE_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
	});

	emulate("jae 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JA
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JA_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_ZF, false},
	});

	emulate("ja 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JA_no_jump_cf)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_ZF, false},
	});

	emulate("ja 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JA_no_jump_zf)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_ZF, true},
	});

	emulate("ja 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JA_no_jump_cf_zf)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_ZF, true},
	});

	emulate("ja 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JBE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JBE_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_ZF, false},
	});

	emulate("jbe 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JBE_jump_cf)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_ZF, false},
	});

	emulate("jbe 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JBE_jump_zf)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_ZF, true},
	});

	emulate("jbe 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JBE_jump_cf_zf)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_ZF, true},
	});

	emulate("jbe 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

//
// X86_INS_JB
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JB_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
	});

	emulate("jb 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JB_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
	});

	emulate("jb 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JE_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
	});

	emulate("je 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JE_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
	});

	emulate("je 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JGE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JGE_jump_eq_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("jge 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JGE_jump_ef_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("jge 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JGE_no_jump_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("jge 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JGE_no_jump_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("jge 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JG
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JG_jump_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("jg 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JG_jump_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("jg 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JG_no_jump_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("jg 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JG_no_jump_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("jg 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JG_no_jump_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("jg 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JG_no_jump_4)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("jg 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JG_no_jump_5)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("jg 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JG_no_jump_6)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("jg 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JLE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JLE_jump_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("jle 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JLE_jump_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("jle 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JLE_jump_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("jle 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JLE_jump_4)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("jle 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JLE_jump_5)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("jle 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JLE_jump_6)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("jle 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JLE_no_jump_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("jle 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JLE_no_jump_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("jle 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JL_jump_ne_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("jl 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JL_jump_ne_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("jl 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JL_no_jump_eq_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("jl 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JL_no_jump_eq_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("jl 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JNE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JNE_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
	});

	emulate("jne 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JNE_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
	});

	emulate("jne 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JNO
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JNO_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_OF, false},
	});

	emulate("jno 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JNO_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_OF, true},
	});

	emulate("jno 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JNP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JNP_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_PF, false},
	});

	emulate("jnp 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_PF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JNP_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_PF, true},
	});

	emulate("jnp 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_PF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JNS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JNS_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
	});

	emulate("jns 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JNS_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
	});

	emulate("jns 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JO
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JO_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_OF, true},
	});

	emulate("jo 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JO_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_OF, false},
	});

	emulate("jo 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_OF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JP_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_PF, true},
	});

	emulate("jp 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_PF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JP_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_PF, false},
	});

	emulate("jp 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_PF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_JS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JS_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
	});

	emulate("js 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {true, 0x1234}},
	});
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_JS_no_jump)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
	});

	emulate("js 0x1234", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_translator->getCondBranchFunction(), {false, 0x1234}},
	});
}

//
// X86_INS_SETAE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETAE_set_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
	});

	emulate("setae al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETAE_set_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
	});

	emulate("setae al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETA
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETA_set_true_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_ZF, false},
	});

	emulate("seta al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETA_set_false_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_ZF, false},
	});

	emulate("seta al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETA_set_false_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_ZF, true},
	});

	emulate("seta al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETA_set_false_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_ZF, true},
	});

	emulate("seta al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETBE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETBE_set_false_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_ZF, false},
	});

	emulate("setbe al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETBE_set_true_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_ZF, false},
	});

	emulate("setbe al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETBE_set_true_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
		{X86_REG_ZF, true},
	});

	emulate("setbe al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETBE_set_true_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
		{X86_REG_ZF, true},
	});

	emulate("setbe al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETB
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETB_set_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, true},
	});

	emulate("setb al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETB_set_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_CF, false},
	});

	emulate("setb al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_CF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETE_set_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
	});

	emulate("sete al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETE_set_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
	});

	emulate("sete al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETGE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETGE_set_true_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("setge al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETGE_set_true_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("setge al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETGE_set_false_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("setge al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETGE_set_false_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("setge al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETG
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETG_set_true_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("setg al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETG_set_true_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("setg al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETG_set_false_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("setg al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETG_set_false_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("setg al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETG_set_false_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("setg al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETG_set_false_4)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("setg al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETG_set_false_5)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("setg al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETG_set_false_6)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("setg al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETLE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETLE_set_true_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("setle al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETLE_set_true_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("setle al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETLE_set_true_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("setle al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETLE_set_true_4)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("setle al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETLE_set_true_5)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("setle al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETLE_set_true_6)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("setle al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETLE_set_false_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("setle al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETLE_set_false_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("setle al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETL_set_true_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("setl al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETL_set_true_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("setl al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETL_set_false_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("setl al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETL_set_false_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("setl al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETNE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETNE_set_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, false},
	});

	emulate("setne al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETNE_set_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_ZF, true},
	});

	emulate("setne al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_ZF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETNO
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETNO_set_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_OF, false},
	});

	emulate("setno al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETNO_set_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_OF, true},
	});

	emulate("setno al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETNP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETNP_set_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_PF, false},
	});

	emulate("setnp al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_PF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETNP_set_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_PF, true},
	});

	emulate("setnp al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_PF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETNS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETNS_set_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
	});

	emulate("setns al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETNS_set_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
	});

	emulate("setns al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETO
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETO_set_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_OF, true},
	});

	emulate("seto al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETO_set_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_OF, false},
	});

	emulate("seto al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_OF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETP_set_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_PF, true},
	});

	emulate("setp al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_PF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETP_set_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_PF, false},
	});

	emulate("setp al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_PF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_SETS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETS_set_true)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, true},
	});

	emulate("sets al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_SETS_set_false)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_SF, false},
	});

	emulate("sets al", 0x1000);

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_SF, X86_REG_AX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AL, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVAE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVAE_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, false},
	});

	emulate("cmovae ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVAE_no_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, true},
	});

	emulate("cmovae ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVA
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVA_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, false},
		{X86_REG_ZF, false},
	});

	emulate("cmova ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVA_no_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, true},
		{X86_REG_ZF, false},
	});

	emulate("cmova ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVA_no_move_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, false},
		{X86_REG_ZF, true},
	});

	emulate("cmova ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVA_no_move_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, true},
		{X86_REG_ZF, true},
	});

	emulate("cmova ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVBE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVBE_no_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, false},
		{X86_REG_ZF, false},
	});

	emulate("cmovbe ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVBE_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, true},
		{X86_REG_ZF, false},
	});

	emulate("cmovbe ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVBE_move_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, false},
		{X86_REG_ZF, true},
	});

	emulate("cmovbe ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVBE_move_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, true},
		{X86_REG_ZF, true},
	});

	emulate("cmovbe ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVB
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVB_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, true},
	});

	emulate("cmovb ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVB_no_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_CF, false},
	});

	emulate("cmovb ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_CF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVE_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, true},
	});

	emulate("cmove ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVE_no_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, false},
	});

	emulate("cmove ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVGE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVGE_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("cmovge ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVGE_move_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("cmovge ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVGE_no_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("cmovge ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVGE_no_move_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("cmovge ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVG
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVG_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("cmovg ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVG_move_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("cmovg ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVG_no_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("cmovg ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVG_no_move_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("cmovg ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVG_no_move_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("cmovg ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVG_no_move_4)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("cmovg ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVG_no_move_5)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("cmovg ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVG_no_move_6)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("cmovg ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVLE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVLE_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("cmovle ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVLE_move_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("cmovle ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVLE_move_3)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, true},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("cmovle ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVLE_move_4)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, true},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("cmovle ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVLE_move_5)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("cmovle ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVLE_move_6)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("cmovle ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVLE_no_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, false},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("cmovle ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVLE_no_move_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, false},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("cmovle ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVL
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVL_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, true},
		{X86_REG_OF, false},
	});

	emulate("cmovl ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVL_move_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, false},
		{X86_REG_OF, true},
	});

	emulate("cmovl ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVL_no_move_1)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, true},
		{X86_REG_OF, true},
	});

	emulate("cmovl ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVL_no_move_2)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, false},
		{X86_REG_OF, false},
	});

	emulate("cmovl ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVNE
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVNE_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, false},
	});

	emulate("cmovne ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVNE_no_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_ZF, true},
	});

	emulate("cmovne ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_ZF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVNO
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVNO_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_OF, false},
	});

	emulate("cmovno ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVNO_no_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_OF, true},
	});

	emulate("cmovno ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVNP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVNP_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_PF, false},
	});

	emulate("cmovnp ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_PF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVNP_no_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_PF, true},
	});

	emulate("cmovnp ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_PF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVNS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVNS_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, false},
	});

	emulate("cmovns ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVNS_no_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, true},
	});

	emulate("cmovns ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVO
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVO_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_OF, true},
	});

	emulate("cmovo ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVO_no_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_OF, false},
	});

	emulate("cmovo ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_OF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVP_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_PF, true},
	});

	emulate("cmovp ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_PF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVP_no_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_PF, false},
	});

	emulate("cmovp ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_PF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_CMOVS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVS_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, true},
	});

	emulate("cmovs ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x2222},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CMOVS_no_move)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_AX, 0x1111},
		{X86_REG_CX, 0x2222},
		{X86_REG_SF, false},
	});

	emulate("cmovs ax, cx");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_AX, X86_REG_CX, X86_REG_SF});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_AX, 0x1111},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_NO_VALUE_CALLED();
}

//
// X86_INS_FLD
//

// D9 /0	FLD m32fp	Push m32fp onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FLD_m32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
	});

	setMemory({
		{0x1234, 3.14_f32},
	});

	emulate("fld dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST4, 3.14},
		{X87_REG_TAG4, ANY},
		{X87_REG_TOP, 0x4},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DD /0	FLD m64fp	Push m64fp onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FLD_m64)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
	});

	setMemory({
		{0x1234, 3.14_f64},
	});

	emulate("fld qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST4, 3.14},
		{X87_REG_TAG4, ANY},
		{X87_REG_TOP, 0x4},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// D9 C0+i	FLD ST(i)	Push ST(i) onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FLD_stX)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x4},
		{X86_REG_ST6, 3.14}, // st(2)
	});

	emulate("fld st(2)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST6});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST3, 3.14},
		{X87_REG_TAG3, ANY},
		{X87_REG_TOP, 0x3},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FILD
//

// DF /0	FILD m16int	Push m16int onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FILD_m16)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
	});

	setMemory({
		{0x1234, 123_w},
	});

	emulate("fild word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST4, 123.0},
		{X87_REG_TAG4, ANY},
		{X87_REG_TOP, 0x4},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DB /0	FILD m32int	Push m32int onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FILD_m32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
	});

	setMemory({
		{0x1234, 123_dw},
	});

	emulate("fild dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST4, 123.0},
		{X87_REG_TAG4, ANY},
		{X87_REG_TOP, 0x4},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DF /5	FILD m64int	Push m64int onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FILD_m64)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
	});

	setMemory({
		{0x1234, 123_qw},
	});

	emulate("fild qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST4, 123.0},
		{X87_REG_TAG4, ANY},
		{X87_REG_TOP, 0x4},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_FST
//

// D9 /2	FST m32fp	Copy ST(0) to m32fp.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FST_m32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14}, // st(0)
	});

	emulate("fst dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 3.14_f32},
	});
}

// DD /2	FST m64fp	Copy ST(0) to m64fp.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FST_m64)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14}, // st(0)
	});

	emulate("fst qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 3.14_f64},
	});
}

// DD D0+i	FST ST(i)	Copy ST(0) to ST(i).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FST_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14}, // st(0)
	});

	emulate("fst st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST4, 3.14},
		{X87_REG_TAG4, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FSTP
//

// D9 /3	FSTP m32fp	Copy ST(0) to m32fp and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSTP_m32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14}, // st(0)
	});

	emulate("fstp dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x2},
		{X87_REG_TAG1, ANY},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 3.14_f32},
	});
}

// DD /3	FSTP m64fp	Copy ST(0) to m64fp and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSTP_m64)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14}, // st(0)
	});

	emulate("fstp qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x2},
		{X87_REG_TAG1, ANY},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 3.14_f64},
	});
}

// DD D8+i	FSTP ST(i)	Copy ST(0) to ST(i) and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSTP_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14}, // st(0)
	});

	emulate("fstp st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x2},
		{X87_REG_TAG1, ANY},
		{X86_REG_ST4, 3.14},
		{X87_REG_TAG4, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FIST
//

// DF /2	FIST m16int	Store ST(0) in m16int.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FIST_16)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14},
	});

	emulate("fist word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 3_w},
	});
}

// DB /2	FIST m32int	Store ST(0) in m32int.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FIST_32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14},
	});

	emulate("fist dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 3_dw},
	});
}

//
// X86_INS_FISTP
//

// DF /3	FISTP m16int	Store ST(0) in m16int and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FISTP_16)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14},
	});

	emulate("fistp word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x2},
		{X87_REG_TAG1, ANY},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 3_w},
	});
}

// DB /3	FISTP m32int	Store ST(0) in m32int and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FISTP_32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14},
	});

	emulate("fistp dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x2},
		{X87_REG_TAG1, ANY},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 3_dw},
	});
}

// DF /7	FISTP m64int	Store ST(0) in m64int and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FISTP_64)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 3.14},
	});

	emulate("fistp qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x2},
		{X87_REG_TAG1, ANY},
	});
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x1234, 3_qw},
	});
}

//
// X86_INS_FMUL
//

// D8 /1	FMUL m32fp	Multiply ST(0) by m32fp and store result in ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FMUL_d8)
{
	ALL_MODES;

	setMemory({
		{0x1234, 3.14_f32},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
	});

	emulate("fmul dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14 * 3.14},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DC /1	FMUL m64fp	Multiply ST(0) by m64fp and store result in ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FMUL_dc)
{
	ALL_MODES;

	setMemory({
		{0x1234, 3.14_f64},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
	});

	emulate("fmul qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14 * 3.14},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// D8 C8+i	FMUL ST(0), ST(i)	Multiply ST(0) by ST(i) and store result in ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FMUL_d8_c8)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("fmul st(0), st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14 * 3.14},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DC C8+i	FMUL ST(i), ST(0)	Multiply ST(i) by ST(0) and store result in ST(i)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FMUL_dc_c8)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("fmul st(3), st(0)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 * 3.14},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FMUL_mem_complex)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_ECX, 0x100},
		{X86_REG_EDX, 0x4},
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14},
	});
	setMemory({
		{0x1354, 3.14}
	});

	emulate("fmul qword ptr [0x1234 + ecx + edx * 8");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5, X86_REG_ECX, X86_REG_EDX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 * 3.14},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1354});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_FMULP
//

// DE C8+i	FMULP ST(i), ST(0)	Multiply ST(i) by ST(0), store result in ST(i), and pop the register stack
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FMULP_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("fmulp st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST5, 3.14 * 3.14},
		{X87_REG_TAG5, ANY},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DE C9	FMULP	Multiply ST(1) by ST(0), store result in ST(1), and pop the register stack
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FMULP)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST3, 3.14}, // st(1)
	});

	emulate("fmulp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST3, 3.14 * 3.14},
		{X87_REG_TAG3, ANY},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FIMUL
//

// DA /1	FIMUL m32int	Multiply ST(0) by m32int and store result in ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FIMUL_m32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 3_dw},
	});

	emulate("fimul dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 * 3.0},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DE /1	FIMUL m16int	Multiply ST(0) by m16int and store result in ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FIMUL_m16)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 3_w},
	});

	emulate("fimul word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 * 3.0},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_FADD
//

// D8 /0	FADD m32fp	Add m32fp to ST(0) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FADD_d8)
{
	ALL_MODES;

	setMemory({
		{0x1234, 3.14_f32},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
	});

	emulate("fadd dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14 + 3.14},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DC /0	FADD m64fp	Add m64fp to ST(0) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FADD_dc)
{
	ALL_MODES;

	setMemory({
		{0x1234, 3.14_f64},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
	});

	emulate("fadd qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14 + 3.14},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// D8 C0+i	FADD ST(0), ST(i)	Add ST(0) to ST(i) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FADD_d8_c0)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("fadd st(0), st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14 + 3.14},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DC C0+i	FADD ST(i), ST(0)	Add ST(i) to ST(0) and store result in ST(i).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FADD_dc_c0)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("fadd st(3), st(0)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 + 3.14},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FADDP
//

// DE C0+i	FADDP ST(i), ST(0)	Add ST(0) to ST(i), store result in ST(i), and pop the register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FADDP_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("faddp st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST5, 3.14 + 3.14},
		{X87_REG_TAG5, ANY},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DE C1	FADDP	Add ST(0) to ST(1), store result in ST(1), and pop the register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FADDP)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST3, 3.14}, // st(1)
	});

	emulate("faddp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST3, 3.14 + 3.14},
		{X87_REG_TAG3, ANY},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FIADD
//

// DA /0	FIADD m32int	Add m32int to ST(0) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FIADD_m32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 3_dw},
	});

	emulate("fiadd dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 + 3.0},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DE /0	FIADD m16int	Add m16int to ST(0) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FIADD_m16)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 3_w},
	});

	emulate("fiadd word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 + 3.0},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_FTST
//

// D9 E4	FTST	Compare ST(0) with 0.0.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FTST_gt)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	emulate("ftst");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, false},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// D9 E4	FTST	Compare ST(0) with 0.0.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FTST_lt)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, -3.14}, // st(0)
	});

	emulate("ftst");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// D9 E4	FTST	Compare ST(0) with 0.0.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FTST_eq)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 0.0}, // st(0)
	});

	emulate("ftst");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, false},
		{X87_REG_C2, false},
		{X87_REG_C3, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FCOM
//

// D8 /2	FCOM m32fp	Compare ST(0) with m32fp.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOM_m32_gt)
{
	ALL_MODES;

	setMemory({
		{0x1234, 2.0_f32},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
	});

	emulate("fcom dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, false},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// D8 /2	FCOM m32fp	Compare ST(0) with m32fp.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOM_m32_lt)
{
	ALL_MODES;

	setMemory({
		{0x1234, 3.0_f32},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 2.0}, // st(0)
	});

	emulate("fcom dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// D8 /2	FCOM m32fp	Compare ST(0) with m32fp.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOM_m32_eq)
{
	ALL_MODES;

	setMemory({
		{0x1234, 2.0_f32},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 2.0}, // st(0)
	});

	emulate("fcom dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, false},
		{X87_REG_C2, false},
		{X87_REG_C3, true},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DC /2	FCOM m64fp	Compare ST(0) with m64fp.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOM_m64_lt)
{
	ALL_MODES;

	setMemory({
		{0x1234, 3.0_f64},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 2.0}, // st(0)
	});

	emulate("fcom qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// D8 D0+i	FCOM ST(i)	Compare ST(0) with ST(i).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOM_stX)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST5, 5.0}, // st(3)
	});

	emulate("fcom st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// D8 D1	FCOM	Compare ST(0) with ST(1).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOM_st1)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST3, 5.0}, // st(1)
	});

	emulate("fcom");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FCOMP
//

// D8 D8+i	FCOMP ST(i)	Compare ST(0) with ST(i) and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOMP_stX)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST3, 5.0}, // st(1)
	});

	emulate("fcomp st(1)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X87_REG_TAG2, ANY},
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FCOMPP
//

// DE D9	FCOMPP	Compare ST(0) with ST(1) and pop register stack twice.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOMPP_stX)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST3, 5.0}, // st(1)
	});

	emulate("fcompp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x4},
		{X87_REG_TAG2, ANY},
		{X87_REG_TAG3, ANY},
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FUCOM
//

// DD E0+i	FUCOM ST(i)	Compare ST(0) with ST(i).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FUCOM_stX)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST5, 5.0}, // st(3)
	});

	emulate("fucom st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DD E1	FUCOM	Compare ST(0) with ST(1).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FUCOM_st1)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST3, 5.0}, // st(1)
	});

	emulate("fucom");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FUCOMP
//

// DD E8+i	FUCOMP ST(i)	Compare ST(0) with ST(i) and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FUCOMP_stX)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST3, 5.0}, // st(1)
	});

	emulate("fucomp st(1)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X87_REG_TAG2, ANY},
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DD E9	FUCOMP	Compare ST(0) with ST(1) and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FUCOMP)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST3, 5.0}, // st(1)
	});

	emulate("fucomp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X87_REG_TAG2, ANY},
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FUCOMPP
//

// DA E9	FUCOMPP	Compare ST(0) with ST(1) and pop register stack twice.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FUCOMPP_stX)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST3, 5.0}, // st(1)
	});

	emulate("fucompp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x4},
		{X87_REG_TAG2, ANY},
		{X87_REG_TAG3, ANY},
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FCOMI
//

// DB F0+i	FCOMI ST, ST(i)	Compare ST(0) with ST(i) and set status flags accordingly.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOMI_lt)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST5, 5.0}, // st(3)
	});

	emulate("fcomi st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ZF, false},
		{X86_REG_PF, false},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FCOMIP
//

// DF F0+i	FCOMIP ST, ST(i)	Compare ST(0) with ST(i), set status flags
// accordingly, and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOMIP_lt)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST5, 5.0}, // st(3)
	});

	emulate("fcomip st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X87_REG_TAG2, ANY},
		{X86_REG_ZF, false},
		{X86_REG_PF, false},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FUCOMI
//

// DB E8+i	FUCOMI ST, ST(i)	Compare ST(0) with ST(i), check for ordered values,
// and set status flags accordingly.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FUCOMI_lt)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST5, 5.0}, // st(3)
	});

	emulate("fucomi st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ZF, false},
		{X86_REG_PF, false},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FUCOMIP
//

// DF E8+i	FUCOMIP ST, ST(i)	Compare ST(0) with ST(i), check for ordered values,
// set status flags accordingly, and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FUCOMIP_lt)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.0}, // st(0)
		{X86_REG_ST5, 5.0}, // st(3)
	});

	emulate("fucomip st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X87_REG_TAG2, ANY},
		{X86_REG_ZF, false},
		{X86_REG_PF, false},
		{X86_REG_CF, true},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FICOM
//

// DE /2	FICOM m16int	Compare ST(0) with m16int.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FICOM_m16_gt)
{
	ALL_MODES;

	setMemory({
		{0x1234, 2_w},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 1.0}, // st(0)
	});

	emulate("ficom word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DA /2	FICOM m32int	Compare ST(0) with m32int.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FICOM_m32_gt)
{
	ALL_MODES;

	setMemory({
		{0x1234, 2_dw},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 1.0}, // st(0)
	});

	emulate("ficom dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_FICOMP
//

// DE /2	FICOM m16int	Compare ST(0) with m16int.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FICOMP_m16_gt)
{
	ALL_MODES;

	setMemory({
		{0x1234, 2_w},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 1.0}, // st(0)
	});

	emulate("ficomp word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X87_REG_TAG2, ANY},
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DA /2	FICOMP m32int	Compare ST(0) with m32int.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FICOMP_m32_gt)
{
	ALL_MODES;

	setMemory({
		{0x1234, 2_dw},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 1.0}, // st(0)
	});

	emulate("ficomp dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X87_REG_TAG2, ANY},
		{X87_REG_C0, true},
		{X87_REG_C2, false},
		{X87_REG_C3, false},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_FDIV
//

// D8 /6	FDIV m32fp	Divide ST(0) by m32fp and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIV_d8)
{
	ALL_MODES;

	setMemory({
		{0x1234, 5.0_f32},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
	});

	emulate("fdiv dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 10.0 / 5.0},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DC /6	FDIV m64fp	Divide ST(0) by m64fp and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIV_dc)
{
	ALL_MODES;

	setMemory({
		{0x1234, 5.0_f64},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
	});

	emulate("fdiv qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 10.0 / 5.0},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// D8 F0+i	FDIV ST(0), ST(i)	Divide ST(0) by ST(i) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIV_st0_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
		{X86_REG_ST5, 5.0}, // st(3)
	});

	emulate("fdiv st(0), st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 10.0 / 5.0},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DC F8+i	FDIV ST(i), ST(0)	Divide ST(i) by ST(0) and store result in ST(i).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIV_st3_st0)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
		{X86_REG_ST5, 5.0}, // st(3)
	});

	emulate("fdiv st(3), st(0)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 5.0 / 10.0},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FDIVP
//

// DE F8+i	FDIVP ST(i), ST(0)	Divide ST(i) by ST(0), store result in ST(i),
// and pop the register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIVP_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.123}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("fdivp st(3), st(0)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST5, 3.14 / 10.123},
		{X87_REG_TAG2, ANY},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DE F9	FDIVP	Divide ST(1) by ST(0), store result in ST(1), and pop the
// register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIVP)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.123}, // st(0)
		{X86_REG_ST3, 3.14}, // st(1)
	});

	emulate("fdivp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST3, 3.14 / 10.123},
		{X87_REG_TAG2, ANY},
		{X87_REG_TAG3, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FIDIV
//

// DE /6	FIDIV m16int	Divide ST(0) by m64int and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FIDIV_m16)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 3_w},
	});

	emulate("fidiv word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 / 3.0},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DA /6	FIDIV m32int	Divide ST(0) by m32int and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FIDIV_m32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 3_dw},
	});

	emulate("fidiv dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 / 3.0},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_FDIVR
//

// D8 /7	FDIVR m32fp	Divide m32fp by ST(0) and store result in ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIVR_d8)
{
	ALL_MODES;

	setMemory({
		{0x1234, 5.0_f32},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
	});

	emulate("fdivr dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 5.0 / 10.0},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DC /7	FDIVR m64fp	Divide m64fp by ST(0) and store result in ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIVR_dc)
{
	ALL_MODES;

	setMemory({
		{0x1234, 5.0_f64},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
	});

	emulate("fdivr qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 5.0 / 10.0},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// D8 F8+i	FDIVR ST(0), ST(i)	Divide ST(i) by ST(0) and store result in ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIVR_st0_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
		{X86_REG_ST5, 5.0}, // st(3)
	});

	emulate("fdivr st(0), st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 5.0 / 10.0},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DC F0+i	FDIVR ST(i), ST(0)	Divide ST(0) by ST(i) and store result in ST(i)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIVR_st3_st0)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
		{X86_REG_ST5, 5.0}, // st(3)
	});

	emulate("fdivr st(3), st(0)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 10.0 / 5.0},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FDIVRP
//

// DE F0+i	FDIVRP ST(i), ST(0)	Divide ST(0) by ST(i), store result in ST(i),
// and pop the register stack
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIVRP_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.123}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("fdivrp st(3), st(0)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST5, 10.123 / 3.14},
		{X87_REG_TAG2, ANY},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DE F1	FDIVRP	Divide ST(0) by ST(1), store result in ST(1), and pop the
// register stack
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDIVRP)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.123}, // st(0)
		{X86_REG_ST3, 3.14}, // st(1)
	});

	emulate("fdivrp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST3, 10.123 / 3.14},
		{X87_REG_TAG2, ANY},
		{X87_REG_TAG3, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FIDIVR
//

// DE /7	FIDIVR m16int	Divide m16int by ST(0) and store result in ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FIDIVR_m16)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 10_w},
	});

	emulate("fidivr word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 10.0 / 3.14},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DA /7	FIDIVR m32int	Divide m32int by ST(0) and store result in ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FIDIVR_m32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 10_dw},
	});

	emulate("fidivr dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 10.0 / 3.14},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_FSUB
//

// D8 /4	FSUB m32fp	Subtract m32fp from ST(0) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUB_d8)
{
	ALL_MODES;

	setMemory({
		{0x1234, 3.14_f32},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
	});

	emulate("fsub dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 10.0 - 3.14},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DC /4	FSUB m64fp	Subtract m64fp from ST(0) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUB_dc)
{
	ALL_MODES;

	setMemory({
		{0x1234, 3.14_f64},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
	});

	emulate("fsub qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 10.0 - 3.14},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// D8 E0+i	FSUB ST(0), ST(i)	Subtract ST(i) from ST(0) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUB_d8_e0)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("fsub st(0), st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 10.0 - 3.14},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DC E8+i	FSUB ST(i), ST(0)	Subtract ST(0) from ST(i) and store result in ST(i).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUB_dc_e8)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST5, 10.0}, // st(3)
	});

	emulate("fsub st(3), st(0)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 10.0 - 3.14},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FSUBP
//

// DE E8+i	FSUBP ST(i), ST(0)	Subtract ST(0) from ST(i), store result in ST(i),
// and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUBP_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST5, 10.0}, // st(3)
	});

	emulate("fsubp st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST5, 10.0 - 3.14},
		{X87_REG_TAG5, ANY},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DE E9	FSUBP	Subtract ST(0) from ST(1), store result in ST(1),
// and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUBP)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST3, 10.0}, // st(1)
	});

	emulate("fsubp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST3, 10.0 - 3.14},
		{X87_REG_TAG3, ANY},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FISUB
//

// DA /4	FISUB m32int	Subtract m32int from ST(0) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FISUB_m32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 3_dw},
	});

	emulate("fisub dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 - 3.0},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DE /4	FISUB m16int	Subtract m16int from ST(0) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FISUB_m16)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 3_w},
	});

	emulate("fisub word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.14 - 3.0},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_FSUBR
//

// D8 /5	FSUBR m32fp	Subtract ST(0) from m32fp and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUBR_d8)
{
	ALL_MODES;

	setMemory({
		{0x1234, 3.14_f32},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
	});

	emulate("fsubr dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14 - 10.0},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DC /5	FSUBR m64fp	Subtract ST(0) from m64fp and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUBR_dc)
{
	ALL_MODES;

	setMemory({
		{0x1234, 3.14_f64},
	});

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
	});

	emulate("fsubr qword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14 - 10.0},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// D8 E8+i	FSUBR ST(0), ST(i)	Subtract ST(0) from ST(i) and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUBR_d8_e0)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("fsubr st(0), st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14 - 10.0},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DC E0+i	FSUBR ST(i), ST(0)	Subtract ST(i) from ST(0) and store result in ST(i).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUBR_dc_e8)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0}, // st(0)
		{X86_REG_ST5, 3.14}, // st(3)
	});

	emulate("fsubr st(3), st(0)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 10.0 - 3.14},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FSUBRP
//

// DE E0+i	FSUBRP ST(i), ST(0)	Subtract ST(i) from ST(0), store result in ST(i),
// and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUBRP_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST5, 10.0}, // st(3)
	});

	emulate("fsubrp st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST5, 3.14 - 10.0},
		{X87_REG_TAG5, ANY},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// DE E1	FSUBRP	Subtract ST(1) from ST(0), store result in ST(1),
// and pop register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSUBRP)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 3.14}, // st(0)
		{X86_REG_ST3, 10.0}, // st(1)
	});

	emulate("fsubrp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST3, 3.14 - 10.0},
		{X87_REG_TAG3, ANY},
		{X87_REG_TAG2, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FISUBR
//

// DA /5	FISUBR m32int	Subtract ST(0) from m32int and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FISUBR_m32)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 3_dw},
	});

	emulate("fisubr dword ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.0 - 3.14},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

// DE /5	FISUBR m16int	Subtract ST(0) from m16int and store result in ST(0).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FISUBR_m16)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x5},
		{X86_REG_ST5, 3.14}, // st(0)
	});

	setMemory({
		{0x1234, 3_w},
	});

	emulate("fisubr word ptr [0x1234]");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST5, 3.0 - 3.14},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
}

//
// X86_INS_FABS
// llvm.fabs.*() can not be lowered, so we need to check call.
//

// D9 E1	FABS	Replace ST with its absolute value.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FABS)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 10.0},
	});

	emulate("fabs");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST1, ANY},
		{X87_REG_TAG1, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_VALUES_CALLED({
		{_module.getFunction("llvm.fabs.f80"), {10.0}},
	});
}

//
// X86_INS_FCHS
//

// D9 E0	FCHS	Complements sign of ST(0)
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCHS)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 10.0},
	});

	emulate("fchs");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST1, -10.0},
		{X87_REG_TAG1, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FSQRT
// llvm.sqrt.*() is transformed to sqrtl().
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSQRT)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 10.0},
	});

	emulate("fsqrt");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST1, ANY},
		{X87_REG_TAG1, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_VALUES_CALLED({
		{_module.getFunction("sqrtl"), {10.0}},
	});
}

//
// X86_INS_FXCH
//

// D9 C9	FXCH	Exchange the contents of ST(0) and ST(1).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FXCH)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0},
		{X86_REG_ST3, 3.14},
	});

	emulate("fxch");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14},
		{X86_REG_ST3, 10.0},
		{X87_REG_TAG2, ANY},
		{X87_REG_TAG3, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// D9 C8+i	FXCH ST(i)	Exchange the contents of ST(0) and ST(i).
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FXCH_st3)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x2},
		{X86_REG_ST2, 10.0},
		{X86_REG_ST5, 3.14},
	});

	emulate("fxch st(3)");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST2, X86_REG_ST5});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14},
		{X86_REG_ST5, 10.0},
		{X87_REG_TAG2, ANY},
		{X87_REG_TAG5, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FCOS
//

// D9 FF	FCOS	Replace ST(0) with its cosine.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FCOS_compute)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 10.0}, // st(0)
	});

	emulate("fcos");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST1, ANY},
		{X87_REG_TAG1, ANY},
		{X87_REG_C2, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_VALUES_CALLED({
		{_module.getFunction("llvm.fabs.f80"), {10.0}},
		{_module.getFunction("cosl"), {10.0}},
	});
}

//
// X86_INS_FSIN
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSIN_compute)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 10.0},
	});

	emulate("fsin");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST1, ANY},
		{X87_REG_TAG1, ANY},
		{X87_REG_C2, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_VALUES_CALLED({
		{_module.getFunction("llvm.fabs.f80"), {10.0}},
		{_module.getFunction("sinl"), {10.0}},
	});
}

//
// X86_INS_FSINCOS
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FSINCOS_compute)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x1},
		{X86_REG_ST1, 10.0},
	});

	emulate("fsincos");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST1});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST1, ANY},
		{X87_REG_TAG1, ANY},
		{X86_REG_ST0, ANY},
		{X87_REG_TAG0, ANY},
		{X87_REG_TOP, 0x0},
		{X87_REG_C2, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_VALUES_CALLED({
		{_module.getFunction("llvm.fabs.f80"), {10.0}},
		{_module.getFunction("sinl"), {10.0}},
		{_module.getFunction("cosl"), {10.0}},
	});
}

//
// X86_INS_FLD1
//

// D9 E8	FLD1	Push +1.0 onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FLD1)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x3},
	});

	emulate("fld1");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 1.0},
		{X87_REG_TAG2, ANY},
		{X87_REG_TOP, 2},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FLDL2T
//

// D9 E9	FLDL2T	Push log_2(10) onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FLDL2T)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x3},
	});

	emulate("fldl2t");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, static_cast<double>(std::log2(10.0L))},
		{X87_REG_TAG2, ANY},
		{X87_REG_TOP, 2},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FLDL2E
//

// D9 EA	FLDL2E	Push log_2(e) onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FLDL2E)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x3},
	});

	emulate("fldl2e");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, static_cast<double>(std::log2(std::exp(1.0L)))},
		{X87_REG_TAG2, ANY},
		{X87_REG_TOP, 2},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FLDPI
//

// D9 EB	FLDPI	Push pi onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FLDPI)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x3},
	});

	emulate("fldpi");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 3.14159265358979323846},
		{X87_REG_TAG2, ANY},
		{X87_REG_TOP, 2},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FLDLG2
//

// D9 EC	FLDLG2	Push log_10(2) onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FLDLG2)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x3},
	});

	emulate("fldlg2");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, static_cast<double>(std::log10(2.0L))},
		{X87_REG_TAG2, ANY},
		{X87_REG_TOP, 2},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FLDLN2
//

// D9 ED	FLDLN2	Push log_e(2) onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FLDLN2)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x3},
	});

	emulate("fldln2");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, static_cast<double>(std::log(2.0L))},
		{X87_REG_TAG2, ANY},
		{X87_REG_TOP, 2},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FLDZ
//

// D9 EE	FLDZ	Push +0.0 onto the FPU register stack.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FLDZ)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x3},
	});

	emulate("fldz");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST2, 0.0},
		{X87_REG_TAG2, ANY},
		{X87_REG_TOP, 2},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FINCSTP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FINCSTP)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x3},
	});

	emulate("fincstp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x4},
		{X87_REG_C1, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FINCSTP_rotate)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x7},
	});

	emulate("fincstp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x0},
		{X87_REG_C1, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FDECSTP
//

// D9 F6	FDECSTP	Decrement TOP field in FPU status word.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDECSTP)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x3},
	});

	emulate("fdecstp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x2},
		{X87_REG_C1, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

// D9 F6	FDECSTP	Decrement TOP field in FPU status word.
TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FDECSTP_rotate)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x0},
	});

	emulate("fdecstp");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP});
	EXPECT_JUST_REGISTERS_STORED({
		{X87_REG_TOP, 0x7},
		{X87_REG_C1, false},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
}

//
// X86_INS_FRNDINT
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_FRNDINT)
{
	ALL_MODES;

	setRegisters({
		{X87_REG_TOP, 0x3},
		{X86_REG_ST3, 10.123},
	});

	emulate("frndint");

	EXPECT_JUST_REGISTERS_LOADED({X87_REG_TOP, X86_REG_ST3});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_ST3, ANY},
		{X87_REG_TAG3, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_VALUES_CALLED({
		{_module.getFunction("roundl"), {10.123}}, // not llvm.round.f80
	});
}

//
// X86_INS_CPUID
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_CPUID)
{
	SKIP_MODE_16;

	setRegisters({
		{X86_REG_EAX, 0x1234},
	});

	emulate("cpuid");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_EAX});
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, ANY},
		{X86_REG_EBX, ANY},
		{X86_REG_ECX, ANY},
		{X86_REG_EDX, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_cpuid"), {0x1234}},
	});
}

//
// X86_INS_OUTSB
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_OUTSB)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 0x1234},
		{X86_REG_SI, 0x1234},
	});
	setMemory({
		{0x1234, 0x56_b},
	});

	emulate("outsb");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_DX, X86_REG_SI});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_outsb"), {0x1234, 0x56}},
	});
}

//
// X86_INS_OUTSW
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_OUTSW)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 0x1234},
		{X86_REG_SI, 0x1234},
	});
	setMemory({
		{0x1234, 0x5678_w},
	});

	emulate("outsw");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_DX, X86_REG_SI});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_outsw"), {0x1234, 0x5678}},
	});
}

//
// X86_INS_OUTSD
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_OUTSD)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 0x1234},
		{X86_REG_SI, 0x1234},
	});
	setMemory({
		{0x1234, 0x567890ab_dw},
	});

	emulate("outsd");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_DX, X86_REG_SI});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_JUST_MEMORY_LOADED({0x1234});
	EXPECT_NO_MEMORY_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_outsd"), {0x1234, 0x567890ab}},
	});
}

//
// X86_INS_INSB
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_INSB)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 0x1234},
		{X86_REG_DI, 0x5678},
	});

	emulate("insb");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_DX, X86_REG_DI});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x5678, ANY}
	});
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_insb"), {0x1234}},
	});
}

//
// X86_INS_INSW
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_INSW)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 0x1234},
		{X86_REG_DI, 0x5678},
	});

	emulate("insw");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_DX, X86_REG_DI});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x5678, ANY}
	});
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_insw"), {0x1234}},
	});
}

//
// X86_INS_INSD
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_INSD)
{
	ALL_MODES;

	setRegisters({
		{X86_REG_DX, 0x1234},
		{X86_REG_DI, 0x5678},
	});

	emulate("insd");

	EXPECT_JUST_REGISTERS_LOADED({X86_REG_DX, X86_REG_DI});
	EXPECT_NO_REGISTERS_STORED();
	EXPECT_NO_MEMORY_LOADED();
	EXPECT_JUST_MEMORY_STORED({
		{0x5678, ANY}
	});
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_insd"), {0x1234}},
	});
}

//
// X86_INS_RDTSC
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RDTSC)
{
	SKIP_MODE_16;

	emulate("rdtsc");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, ANY},
		{X86_REG_EDX, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_rdtsc"), {}},
	});
}

//
// X86_INS_RDTSCP
//

TEST_P(Capstone2LlvmIrTranslatorX86Tests, X86_INS_RDTSCP)
{
	SKIP_MODE_16;

	emulate("rdtscp");

	EXPECT_NO_REGISTERS_LOADED();
	EXPECT_JUST_REGISTERS_STORED({
		{X86_REG_EAX, ANY},
		{X86_REG_EDX, ANY},
		{X86_REG_ECX, ANY},
	});
	EXPECT_NO_MEMORY_LOADED_STORED();
	EXPECT_JUST_VALUES_CALLED({
		{_module.getFunction("__asm_rdtscp"), {}},
	});
}

//
// TODO:
// X86_INS_STOSB, X86_INS_STOSW, X86_INS_STOSD, X86_INS_STOSQ
// + REP prefix variants
//

//
// TODO:
// X86_INS_MOVSB, X86_INS_MOVSW, X86_INS_MOVSD, X86_INS_MOVSQ
// + REP prefix variants
//

//
// TODO
// X86_INS_SCASB, X86_INS_SCASW, X86_INS_SCASD, X86_INS_SCASQ
// + REP prefix variants
//

//
// TODO
// X86_INS_CMPSB, X86_INS_CMPSW, X86_INS_CMPSD, X86_INS_CMPSQ
// + REP prefix variants
//

} // namespace tests
} // namespace capstone2llvmir
} // namespace retdec
