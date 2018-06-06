/**
 * @file tests/capstone2llvmir/capstone2llvmir_tests.h
 * @brief Capstone2LlvmIr unit testing base class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CAPSTONE2LLVMIR_TESTS_CAPSTONE2LLVMIR_TESTS_H
#define CAPSTONE2LLVMIR_TESTS_CAPSTONE2LLVMIR_TESTS_H

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include <gtest/gtest.h>
#include <keystone/keystone.h>

#include "retdec/capstone2llvmir/capstone2llvmir.h"
#include "retdec/llvmir-emul/llvmir_emul.h"

/**
 * Print any LLVM object which implements @c print(llvm::raw_string_ostream&)
 * method into std::string.
 * @param t LLVM object to print.
 * @return String with printed object.
 *
 * TODO: This is on multiple places in this repo.
 */
template<typename T>
std::string llvmObjToString(const T* t)
{
	std::string str;
	llvm::raw_string_ostream ss(str);
	if (t)
		t->print(ss);
	else
		ss << "nullptr";
	return ss.str();
}

namespace retdec {
namespace capstone2llvmir {
namespace tests {

class StoredValue
{
	public:
		StoredValue() :
			type(eType::NOTHING)
		{

		}

		StoredValue(int v, size_t s = 32) :
			ui(v),
			bitSize(s),
			type(eType::UNSIGNED)
		{

		}

		StoredValue(long v, size_t s = 32) :
			ui(v),
			bitSize(s),
			type(eType::UNSIGNED)
		{

		}

		StoredValue(long long v, size_t s = 32) :
			ui(v),
			bitSize(s),
			type(eType::UNSIGNED)
		{

		}

		StoredValue(unsigned int v, size_t s = 32) :
			ui(v),
			bitSize(s),
			type(eType::UNSIGNED)
		{

		}

		StoredValue(unsigned long v, size_t s = 32) :
			ui(v),
			bitSize(s),
			type(eType::UNSIGNED)
		{

		}

		StoredValue(unsigned long long v, size_t s = 32) :
			ui(v),
			bitSize(s),
			type(eType::UNSIGNED)
		{

		}

		StoredValue(float fv) :
			f(fv),
			type(eType::FLOAT)
		{

		}

		StoredValue(double dv) :
			d(dv),
			type(eType::DOUBLE)
		{

		}

	public:
		uint64_t ui = 0;
		double d = 0.0;
		float f = 0.0;
		size_t bitSize = 64;

		enum class eType
		{
			UNSIGNED,
			FLOAT,
			DOUBLE,
			NOTHING
		} type;
};

const StoredValue ANY;

inline StoredValue operator "" _b(unsigned long long v) // byte = 8
{
	return StoredValue(v, 8);
}

inline StoredValue operator "" _w(unsigned long long v) // word = 16
{
	return StoredValue(v, 16);
}

inline StoredValue operator "" _dw(unsigned long long v) // doubleword = 32
{
	return StoredValue(v, 32);
}

inline StoredValue operator "" _qw(unsigned long long v) // quadword = 64
{
	return StoredValue(v, 64);
}

inline StoredValue operator "" _ow(unsigned long long v) // octaword = 128
{
	// TODO: We can not store 128 bits into unsigned long long.
	// We will probably have to use llvm::APInt in StoredValue.
	// Or maybe use llvm::GenericValue instead of StoredValue.
	assert(false);
	return StoredValue(v, 128);
}

inline StoredValue operator "" _f32(long double v)
{
	return StoredValue(float(v));
}

inline StoredValue operator "" _f64(long double v)
{
	return StoredValue(double(v));
}

inline StoredValue operator "" _f80(long double v)
{
	return StoredValue(double(v));
}

/**
 * 1) LLVM module is initialized in constructor.
 * 2) Translator is initialized with the module in SetUp(). Translator will
 *    set up architecture specific environment (e.g. registers) at
 *    initialization, so module already has this environment then tests
 *    functions start.
 * 3) Emulator is initialized with module in SetUp(), after the translator's
 *    initialization. At its initalization, it sets initializator values for
 *    all global variables, so they already need to be in the module when
 *    emulator is being initialized. After the initialization, but before the
 *    emulation run, it is possible to modify these default values.
 *    One limitation is, that emulator knows only about the globals present
 *    at the time of its initialization, if translation creates new globals,
 *    they will not be initialized with their initializers, and it will not be
 *    possible to modify their values.
 */
class Capstone2LlvmIrTranslatorTests : public ::testing::Test
{
	public:
		Capstone2LlvmIrTranslatorTests() :
			_module("test", _context)
		{

		}

		~Capstone2LlvmIrTranslatorTests()
		{
			if (_assembler)
			{
				ks_close(_assembler);
			}
		}

	// Inherited from @c ::testing::Test.
	//
	protected:
		virtual void SetUp() override
		{
			initKeystoneEngine();
			initCapstone2LlvmIrTranslator(); // Generate environment to module.
			initLlvmEmulator(); // Loads up the environment for emulation.

			_translator->getCallFunction()->setName("__pseudo_call");
			_translator->getReturnFunction()->setName("__pseudo_return");
			_translator->getBranchFunction()->setName("__pseudo_branch");
			_translator->getCondBranchFunction()->setName("__pseudo_cond_branch");
		}

	// Implemented here.
	//
	protected:
		virtual void initLlvmEmulator()
		{
			_emulator = std::make_unique<retdec::llvmir_emul::LlvmIrEmulator>(
					&_module);
		}

		std::vector<uint8_t> assemble(
				const std::string& code,
				uint64_t addr = 0)
		{
			size_t cnt;
			size_t sz;
			unsigned char* out;
			if (ks_asm(
					_assembler,
					code.data(),
					addr, &out,
					&sz,
					&cnt) != KS_ERR_OK)
			{
				std::stringstream ss;
				ss << "ERROR: failed on ks_asm(): "
						<< ks_strerror(ks_errno(_assembler)) << "\n";
				throw std::runtime_error(ss.str());
			}

			std::vector<uint8_t> res;
			res.reserve(sz);
			for (size_t i = 0; i < sz; ++i)
			{
				res.push_back(out[i]);
			}

			ks_free(out);

			return res;
		}

		virtual llvm::Function* translate(
				const std::string& code,
				uint64_t addr = 0)
		{
			auto asmBytes = assemble(code, addr);

			// Each translation gets its own function.
			//
			auto* f = llvm::Function::Create(
					llvm::FunctionType::get(
							llvm::Type::getVoidTy(_context),
							false),
					llvm::GlobalValue::ExternalLinkage,
					"",
					&_module);
			auto* bb = llvm::BasicBlock::Create(_context, "", f);
			llvm::IRBuilder<> irb(bb);
			auto* ret = irb.CreateRetVoid();
			irb.SetInsertPoint(ret);

			_translator->translate(asmBytes.data(), asmBytes.size(), addr, irb);

			return f;
		}

		virtual llvm::Function* modifyTranslationForEmulation(llvm::Function* f)
		{
			return f;
		}

		virtual llvm::Function* emulate(const std::string& code,
				uint64_t addr = 0)
		{
			auto* f = translate(code, addr);
			f = modifyTranslationForEmulation(f);

			_emulator->runFunction(f, {});
			_function = f;
			return f;
		}

		std::string dumpFunction(llvm::Function* f)
		{
			std::stringstream ret;

			// We need to rename nameless bbs, so we know where branches are
			// branching.
			//
			for (llvm::inst_iterator I = llvm::inst_begin(f),
					E = llvm::inst_end(f); I != E; ++I)
			{
				llvm::Instruction* i = &*I;
				if (i->getPrevNode() == nullptr)
				{
					if (!i->getParent()->hasName())
					{
						i->getParent()->setName("bb");
					}
				}
			}

			ret << std::endl << "function: \"" << f->getName().str() << "\""
					<< std::endl;
			for (llvm::inst_iterator I = llvm::inst_begin(f),
					E = llvm::inst_end(f); I != E; ++I)
			{
				llvm::Instruction* i = &*I;

				if (i->getPrevNode() == nullptr)
				{
					ret << "bb: \"" << i->getParent()->getName().str()
							<< "\"" << std::endl;
				}

				std::stringstream ss;
				if (i->getType()->isIntegerTy())
				{
					ss << _emulator->getValueValue(i).IntVal.getZExtValue();
				}
				else if (i->getType()->isFloatTy())
				{
					ss << _emulator->getValueValue(i).FloatVal;
				}
				else if (i->getType()->isFloatingPointTy())
				{
					ss << _emulator->getValueValue(i).DoubleVal;
				}
				else if (auto* s = llvm::dyn_cast<llvm::StoreInst>(i))
				{
					auto* i = s->getValueOperand();
					if (i->getType()->isIntegerTy())
					{
						ss << _emulator->getValueValue(i).IntVal.getZExtValue();
					}
					else if (i->getType()->isFloatTy())
					{
						ss << _emulator->getValueValue(i).FloatVal;
					}
					else if (i->getType()->isFloatingPointTy())
					{
						ss << _emulator->getValueValue(i).DoubleVal;
					}
					else
					{
						ss << "unknown";
					}
				}
				else
				{
					ss << "unknown";
				}

				ret << "\t" << std::setw(10) << ss.str() << " : "
						<< llvmObjToString(i) << std::endl;
			}

			return ret.str();
		}

	// Implemented here, but might be reimplemented in children.
	//
	protected:
		virtual llvm::GlobalVariable* getRegister(uint32_t reg)
		{
			return _translator->getRegister(reg);
		}

		virtual uint64_t getRegisterValueUnsigned(uint32_t reg)
		{
			auto* gv = getRegister(reg);
			assert(gv);
			return _emulator->getGlobalVariableValue(gv).IntVal.getZExtValue();
		}

		virtual double getRegisterValueDouble(uint32_t reg)
		{
			auto* gv = getRegister(reg);
			assert(gv);
			return _emulator->getGlobalVariableValue(gv).DoubleVal;
		}

		virtual float getRegisterValueFloat(uint32_t reg)
		{
			auto* gv = getRegister(reg);
			assert(gv);
			return _emulator->getGlobalVariableValue(gv).FloatVal;
		}

		virtual uint64_t getMemoryValueUnsigned(uint64_t addr, size_t s)
		{
			return _emulator->getMemoryValue(addr).IntVal.getZExtValue();
		}

		virtual double getMemoryValueDouble(uint64_t addr)
		{
			return _emulator->getMemoryValue(addr).DoubleVal;
		}

		virtual float getMemoryValueFloat(uint64_t addr)
		{
			return _emulator->getMemoryValue(addr).FloatVal;
		}

		virtual void setRegisterValueUnsigned(uint32_t reg, uint64_t val)
		{
			auto* gv = getRegister(reg);
			assert(gv);
			auto* t = llvm::cast<llvm::IntegerType>(gv->getValueType());

			llvm::GenericValue v = _emulator->getGlobalVariableValue(gv);
			bool isSigned = false;
			v.IntVal = llvm::APInt(t->getBitWidth(), val, isSigned);
			_emulator->setGlobalVariableValue(gv, v);
		}

		virtual void setRegisterValueDouble(uint32_t reg, double val)
		{
			auto* gv = getRegister(reg);
			assert(gv);

			llvm::GenericValue v;
			v.DoubleVal = val;
			_emulator->setGlobalVariableValue(gv, v);
		}

		virtual void setRegisterValueFloat(uint32_t reg, float val)
		{
			auto* gv = getRegister(reg);
			assert(gv);

			llvm::GenericValue v;
			v.FloatVal = val;
			_emulator->setGlobalVariableValue(gv, v);
		}

		virtual void setMemoryValueUnsigned(uint64_t addr, uint64_t val, size_t s)
		{
			llvm::GenericValue v;
			bool isSigned = false;
			v.IntVal = llvm::APInt(s, val, isSigned);
			_emulator->setMemoryValue(addr, v);
		}

		virtual void setMemoryValueDouble(uint64_t addr, double val)
		{
			llvm::GenericValue v;
			v.DoubleVal = val;
			_emulator->setMemoryValue(addr, v);
		}

		virtual void setMemoryValueFloat(uint64_t addr, float val)
		{
			llvm::GenericValue v;
			v.FloatVal = val;
			_emulator->setMemoryValue(addr, v);
		}

		virtual void setRegisters(
				const std::vector<std::pair<uint32_t, StoredValue>>& regs)
		{
			for (auto& p : regs)
			{
				auto& reg = p.first;
				auto& val = p.second;

				switch (val.type)
				{
					case StoredValue::eType::UNSIGNED:
						setRegisterValueUnsigned(reg, val.ui);
						break;
					case StoredValue::eType::DOUBLE:
						setRegisterValueDouble(reg, val.d);
						break;
					case StoredValue::eType::FLOAT:
						setRegisterValueFloat(reg, val.f);
						break;
					case StoredValue::eType::NOTHING:
						// Do nothing.
						break;
					default:
						throw std::runtime_error("Unknown StoredValue::eType.");
						break;
				}
			}
		}

		virtual void setMemory(
				const std::vector<std::pair<uint64_t, StoredValue>>& mems)
		{
			for (auto& p : mems)
			{
				auto& addr = p.first;
				auto& val = p.second;

				switch (val.type)
				{
					case StoredValue::eType::UNSIGNED:
						setMemoryValueUnsigned(addr, val.ui, val.bitSize);
						break;
					case StoredValue::eType::DOUBLE:
						setMemoryValueDouble(addr, val.d);
						break;
					case StoredValue::eType::FLOAT:
						setMemoryValueFloat(addr, val.f);
						break;
					case StoredValue::eType::NOTHING:
						// Do nothing.
						break;
					default:
						throw std::runtime_error("Unknown StoredValue::eType.");
						break;
				}
			}
		}

	// These are environment testing methods.
	//
	protected:
		std::set<llvm::GlobalVariable*> regsToGlobals(
				const std::vector<uint32_t>& regs)
		{
			std::set<llvm::GlobalVariable*> gvs;
			for (auto r : regs)
			{
				gvs.insert(getRegister(r));
			}
			return gvs;
		}

		void EXPECT_REGISTERS_LOADED(const std::vector<uint32_t>& regs)
		{
			auto gvs = regsToGlobals(regs);
			for (auto& gv : gvs)
			{
				EXPECT_TRUE(_emulator->wasGlobalVariableLoaded(gv))
						<< dumpFunction(_function);
			}
		}
		void EXPECT_JUST_REGISTERS_LOADED(const std::vector<uint32_t>& regs)
		{
			auto gvs = regsToGlobals(regs);
			auto lgvs = _emulator->getLoadedGlobalVariablesSet();
			EXPECT_EQ(lgvs, gvs) << dumpFunction(_function);
		}

		void EXPECT_NO_REGISTERS_LOADED()
		{
			auto lgvs = _emulator->getLoadedGlobalVariables();
			EXPECT_TRUE(lgvs.empty()) << dumpFunction(_function);
		}

		void EXPECT_REGISTERS_STORED(const std::vector<uint32_t>& regs)
		{
			auto gvs = regsToGlobals(regs);
			for (auto& gv : gvs)
			{
				EXPECT_TRUE(_emulator->wasGlobalVariableStored(gv))
						<< dumpFunction(_function);
			}
		}

		void EXPECT_JUST_REGISTERS_STORED(
				const std::vector<std::pair<uint32_t, StoredValue>>& regs)
		{
			auto sgvs = _emulator->getStoredGlobalVariablesSet();
			sgvs.erase(_translator->getAsm2LlvmMapGlobalVariable());
			std::set<llvm::GlobalVariable*> gvs;
			for (auto& p : regs)
			{
				gvs.insert(getRegister(p.first));
			}
			EXPECT_EQ(sgvs, gvs) << dumpFunction(_function);

			for (auto& p : regs)
			{
				auto& reg = p.first;
				auto& val = p.second;

				switch (val.type)
				{

					case StoredValue::eType::UNSIGNED:
						EXPECT_EQ(val.ui, getRegisterValueUnsigned(reg))
								<< "\nregister = " << _translator->getRegisterName(reg)
								<< "\n" << dumpFunction(_function);
						break;
					case StoredValue::eType::DOUBLE:
						EXPECT_DOUBLE_EQ(val.d, getRegisterValueDouble(reg))
								<< "\nregister = " << _translator->getRegisterName(reg)
								<< "\n" << dumpFunction(_function);
						break;
					case StoredValue::eType::FLOAT:
						EXPECT_FLOAT_EQ(val.f, getRegisterValueFloat(reg))
								<< "\nregister = " << _translator->getRegisterName(reg)
								<< "\n" << dumpFunction(_function);
						break;
					case StoredValue::eType::NOTHING:
						// Do not check the value.
						break;
					default:
						throw std::runtime_error("Unknown StoredValue::eType.");
						break;
				}
			}
		}

		void EXPECT_NO_REGISTERS_STORED()
		{
			auto sgvs = _emulator->getStoredGlobalVariablesSet();
			sgvs.erase(_translator->getAsm2LlvmMapGlobalVariable());
			EXPECT_TRUE(sgvs.empty()) << dumpFunction(_function);
		}

		void EXPECT_NO_REGISTERS_LOADED_STORED()
		{
			EXPECT_NO_REGISTERS_LOADED();
			EXPECT_NO_REGISTERS_STORED();
		}

		void EXPECT_MEMORY_LOADED(const std::set<uint64_t>& mems)
		{
			for (auto& m : mems)
			{
				EXPECT_TRUE(_emulator->wasMemoryLoaded(m))
						<< dumpFunction(_function);
			}
		}
		void EXPECT_JUST_MEMORY_LOADED(const std::set<uint64_t>& mems)
		{
			auto lmems = _emulator->getLoadedMemorySet();
			EXPECT_EQ(lmems, mems) << dumpFunction(_function);
		}
		void EXPECT_NO_MEMORY_LOADED()
		{
			auto lmems = _emulator->getLoadedMemory();
			EXPECT_TRUE(lmems.empty()) << dumpFunction(_function);
		}

		void EXPECT_MEMORY_STORED(const std::set<uint64_t>& mems)
		{
			for (auto& m : mems)
			{
				EXPECT_TRUE(_emulator->wasMemoryStored(m))
						<< dumpFunction(_function);
			}
		}

		void EXPECT_JUST_MEMORY_STORED(
				const std::vector<std::pair<uint64_t, StoredValue>>& mems)
		{
			auto smems = _emulator->getStoredMemorySet();
			std::set<uint64_t> memss;
			for (auto& p : mems)
			{
				memss.insert(p.first);
			}
			EXPECT_EQ(smems, memss) << dumpFunction(_function);

			for (auto& p : mems)
			{
				auto& addr = p.first;
				auto& val = p.second;

				switch (val.type)
				{
					case StoredValue::eType::UNSIGNED:
						EXPECT_EQ(val.ui, getMemoryValueUnsigned(addr, val.bitSize))
								<< "\nmemory = " << addr
								<< "\n" << dumpFunction(_function);
						break;
					case StoredValue::eType::DOUBLE:
						EXPECT_DOUBLE_EQ(val.d, getMemoryValueDouble(addr))
								<< "\nmemory = " << addr
								<< "\n" << dumpFunction(_function);
						break;
					case StoredValue::eType::FLOAT:
						EXPECT_FLOAT_EQ(val.f, getMemoryValueFloat(addr))
								<< "\nmemory = " << addr
								<< "\n" << dumpFunction(_function);
						break;
					case StoredValue::eType::NOTHING:
						// Do not check the value.
						break;
					default:
						throw std::runtime_error("Unknown StoredValue::eType.");
						break;
				}
			}
		}

		void EXPECT_NO_MEMORY_STORED()
		{
			auto smems = _emulator->getStoredMemory();
			EXPECT_TRUE(smems.empty()) << dumpFunction(_function);
		}

		void EXPECT_NO_MEMORY_LOADED_STORED()
		{
			EXPECT_NO_MEMORY_LOADED();
			EXPECT_NO_MEMORY_STORED();
		}

		void EXPECT_VALUES_CALLED(
				const std::vector<std::pair<llvm::Value*, std::vector<StoredValue>>>& vals)
		{
			for (auto& p : vals)
			{
				auto* v = p.first;
				auto& args = p.second;
				auto* ce = _emulator->getCallEntry(v);

				EXPECT_EQ(args.size(), ce->calledArguments.size());

				size_t cntr = 0;
				for (auto& sv : args)
				{
					switch (sv.type)
					{

						case StoredValue::eType::UNSIGNED:
							EXPECT_EQ(sv.ui, ce->calledArguments[cntr].IntVal.getZExtValue())
									<< "\narg # = " << cntr
									<< "\n" << dumpFunction(_function);
							break;
						case StoredValue::eType::DOUBLE:
							EXPECT_DOUBLE_EQ(sv.d, ce->calledArguments[cntr].DoubleVal)
									<< "\narg # = " << cntr
									<< "\n" << dumpFunction(_function);
							break;
						case StoredValue::eType::FLOAT:
							EXPECT_FLOAT_EQ(sv.f, ce->calledArguments[cntr].FloatVal)
									<< "\narg # = " << cntr
									<< "\n" << dumpFunction(_function);
							break;
						case StoredValue::eType::NOTHING:
							// Do not check the value.
							break;
						default:
							throw std::runtime_error("Unknown StoredValue::eType.");
							break;
					}
					++cntr;
				}
			}
		}

		// TODO: Good enough for now, not perfect -- problem if there are
		// multiple calls of the same function.
		void EXPECT_JUST_VALUES_CALLED(
				const std::vector<std::pair<llvm::Value*, std::vector<StoredValue>>>& vals)
		{
			auto ecvals = _emulator->getCalledValuesSet();
			std::set<llvm::Value*> cvals;
			for (auto& p : vals)
			{
				cvals.insert(p.first);
			}
			EXPECT_EQ(cvals, ecvals) << dumpFunction(_function);

			for (auto& p : vals)
			{
				auto* v = p.first;
				auto& args = p.second;
				auto* ce = _emulator->getCallEntry(v);

				EXPECT_EQ(args.size(), ce->calledArguments.size());

				size_t cntr = 0;
				for (auto& sv : args)
				{
					switch (sv.type)
					{

						case StoredValue::eType::UNSIGNED:
							EXPECT_EQ(sv.ui, ce->calledArguments[cntr].IntVal.getZExtValue())
									<< "\narg # = " << cntr
									<< "\n" << dumpFunction(_function);
							break;
						case StoredValue::eType::DOUBLE:
							EXPECT_DOUBLE_EQ(sv.d, ce->calledArguments[cntr].DoubleVal)
									<< "\narg # = " << cntr
									<< "\n" << dumpFunction(_function);
							break;
						case StoredValue::eType::FLOAT:
							EXPECT_FLOAT_EQ(sv.f, ce->calledArguments[cntr].FloatVal)
									<< "\narg # = " << cntr
									<< "\n" << dumpFunction(_function);
							break;
						case StoredValue::eType::NOTHING:
							// Do not check the value.
							break;
						default:
							throw std::runtime_error("Unknown StoredValue::eType.");
							break;
					}
					++cntr;
				}
			}
		}
		void EXPECT_NO_VALUE_CALLED()
		{
			auto cvals = _emulator->getCalledValuesSet();
			EXPECT_TRUE(cvals.empty()) << dumpFunction(_function);
		}

	// Implemented in children.
	//
	protected:
		virtual void initKeystoneEngine() = 0;
		virtual void initCapstone2LlvmIrTranslator() = 0;

	// Data members.
	//
	protected:
		llvm::LLVMContext _context;
		llvm::Module _module;
		/// Last emulated function, member mostly for debugging purposes so
		/// we do not need to pass it everywhere.
		llvm::Function* _function = nullptr;

		std::unique_ptr<retdec::llvmir_emul::LlvmIrEmulator> _emulator;
		std::unique_ptr<Capstone2LlvmIrTranslator> _translator;
		ks_engine* _assembler = nullptr;
};

} // namespace tests
} // namespace capstone2llvmir
} // namespace retdec

#endif
