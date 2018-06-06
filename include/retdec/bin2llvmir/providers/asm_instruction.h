/**
 * @file include/retdec/bin2llvmir/providers/asm_instruction.h
 * @brief Mapping of LLVM instructions to underlying ASM instructions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_ASM_INSTRUCTION_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_ASM_INSTRUCTION_H

#include <capstone/capstone.h>
#include "retdec/capstone2llvmir/arm/arm_defs.h"
#include "retdec/capstone2llvmir/mips/mips_defs.h"
#include "retdec/capstone2llvmir/powerpc/powerpc_defs.h"
#include "retdec/capstone2llvmir/x86/x86_defs.h"

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/utils/address.h"
#include "retdec/utils/value.h"

namespace retdec {
namespace bin2llvmir {

class Config;

using Llvm2CapstoneMap = typename std::map<llvm::StoreInst*, cs_insn*>;

class AsmInstruction
{
	public:
		template<
			typename Category,
			typename Type,
			typename Reference = Type&,
			typename Pointer = Type*,
			typename Distance = std::ptrdiff_t>
		class iterator_impl;

		using iterator = iterator_impl<
				std::bidirectional_iterator_tag,
				llvm::Instruction>;
		using const_iterator = iterator_impl<
				std::bidirectional_iterator_tag,
				const llvm::Instruction>;
		using reverse_iterator = std::reverse_iterator<iterator>;
		using const_reverse_iterator = std::reverse_iterator<const_iterator>;

		iterator begin();
		iterator end();
		reverse_iterator rbegin();
		reverse_iterator rend();
		const_iterator begin() const;
		const_iterator end() const;
		const_reverse_iterator rbegin() const;
		const_reverse_iterator rend() const;

	public:
		AsmInstruction();
		AsmInstruction(llvm::Instruction* inst);
		AsmInstruction(llvm::BasicBlock* bb);
		AsmInstruction(llvm::Function* f);
		AsmInstruction(llvm::Module* m, retdec::utils::Address addr);

		bool operator<(const AsmInstruction& o) const;
		bool operator==(const AsmInstruction& o) const;
		bool operator!=(const AsmInstruction& o) const;
		explicit operator bool() const;

		bool isValid() const;
		bool isInvalid() const;
		bool isConditional(Config* conf) const;
		cs_insn* getCapstoneInsn() const;
		bool isThumb() const;

		std::string getDsm() const;
		retdec::utils::Maybe<unsigned> getLatency() const;
		retdec::utils::Address getAddress() const;
		retdec::utils::Address getEndAddress() const;
		std::size_t getByteSize() const;
		std::size_t getBitSize() const;
		bool contains(retdec::utils::Address addr) const;

		AsmInstruction getNext() const;
		AsmInstruction getPrev() const;

		bool instructionsCanBeErased();
		bool eraseInstructions();
		llvm::TerminatorInst* makeTerminal();
		llvm::BasicBlock* makeStart(const std::string& name = "");

		llvm::BasicBlock* getBasicBlock() const;
		llvm::Function* getFunction() const;
		llvm::Module* getModule() const;
		llvm::LLVMContext& getContext() const;
		std::vector<llvm::Instruction*> getInstructions();
		std::vector<llvm::BasicBlock*> getBasicBlocks();

		bool empty();
		llvm::Instruction* front();
		llvm::Instruction* back();
		llvm::StoreInst* getLlvmToAsmInstruction() const;

		llvm::Instruction* insertBack(llvm::Instruction* i);
		llvm::Instruction* insertBackSafe(llvm::Instruction* i);

		bool storesValue(llvm::Value* val) const;

		std::string dump() const;
		friend std::ostream& operator<<(
				std::ostream& out,
				const AsmInstruction &a);

	// Templates.
	//
	public:
		template<typename T>
		bool containsInstruction()
		{
			for (auto& i : *this)
			{
				if (llvm::isa<T>(&i))
				{
					return true;
				}
			}
			return false;
		}

		template<typename T>
		T* getInstructionFirst()
		{
			for (auto& i : *this)
			{
				if (auto* ret = llvm::dyn_cast<T>(&i))
				{
					return ret;
				}
			}
			return nullptr;
		}

	public:
		static Llvm2CapstoneMap& getLlvmToCapstoneInsnMap(
				const llvm::Module* m);
		static llvm::GlobalVariable* getLlvmToAsmGlobalVariable(
				const llvm::Module* m);
		static void setLlvmToAsmGlobalVariable(
				const llvm::Module* m,
				llvm::GlobalVariable* gv);
		static retdec::utils::Address getInstructionAddress(
				llvm::Instruction* inst);
		static retdec::utils::Address getBasicBlockAddress(
				llvm::BasicBlock* bb);
		static retdec::utils::Address getFunctionAddress(
				llvm::Function* f);
		static bool isLlvmToAsmInstruction(const llvm::Value* inst);
		static void clear();

	private:
		const llvm::GlobalVariable* getLlvmToAsmGlobalVariablePrivate(
				llvm::Module* m) const;
		bool isLlvmToAsmInstructionPrivate(llvm::Value* inst) const;

	private:
		using ModuleGlobalPair = std::pair<
				const llvm::Module*,
				llvm::GlobalVariable*>;
		using ModuleInstructionMap = std::pair<
				const llvm::Module*,
				std::map<llvm::StoreInst*, cs_insn*>>;

	private:
		llvm::StoreInst* _llvmToAsmInstr = nullptr;
		static std::vector<ModuleGlobalPair> _module2global;
		static std::vector<ModuleInstructionMap> _module2instMap;

	public:
		template<
			typename Category,
			typename Type,
			typename Reference,
			typename Pointer,
			typename Distance>
		class iterator_impl
		{
			public:
				using difference_type = Distance;
				using value_type = Type;
				using reference = Reference;
				using pointer = Pointer;
				using iterator_category = Category;

			public:
				iterator_impl(llvm::StoreInst* s, bool end = false)
				{
					_first = s;
					_last = s;
					if (s == nullptr)
					{
						return;
					}
					llvm::Instruction* i = s;

					auto* bb = i->getParent();
					while (i && (i == _first
							|| !isLlvmToAsmInstruction(i)))
					{
						if (i != _first)
						{
							_last = i;
							if (_current == nullptr)
							{
								_current = i;
							}
						}

						if (&bb->back() == i)
						{
							if (&bb->getParent()->back() == bb)
							{
								break;
							}
							else
							{
								bb = bb->getNextNode();
								i = &bb->front();
							}
						}
						else
						{
							i = i->getNextNode();
						}
					}

					if (end)
					{
						_current = nullptr;
					}
				}
				iterator_impl() = default;
				iterator_impl(const iterator_impl& itr) = default;
				iterator_impl& operator=(iterator_impl rhs)
				{
					_first = rhs._first;
					_last = rhs._last;
					_current = rhs._current;
					return *this;
				}

				iterator_impl& operator++()
				{
					if (_current == nullptr)
					{
						return *this;
					}

					auto* bb = _current->getParent()->getNextNode();
					_current = _current->getNextNode();
					if (_current == nullptr)
					{
						if (bb)
						{
							_current = &bb->front();
						}
					}
					if (isLlvmToAsmInstruction(_current))
					{
						_current = nullptr;
					}
					return *this;
				}

				iterator_impl operator++(int)
				{
					if (_current == nullptr)
					{
						return *this;
					}

					iterator_impl tmp(*this);
					auto* bb = _current->getParent()->getNextNode();
					_current = _current->getNextNode();
					if (_current == nullptr)
					{
						if (bb)
						{
							_current = &bb->front();
						}
					}
					if (isLlvmToAsmInstruction(_current))
					{
						_current = nullptr;
					}
					return tmp;
				}

				iterator_impl& operator--()
				{
					if (_current == _first)
					{
						return *this;
					}
					if (_current == nullptr)
					{
						_current = _last;
						return *this;
					}

					auto* bb = _current->getParent()->getPrevNode();
					_current = _current->getPrevNode();
					if (_current == nullptr)
					{
						if (bb)
						{
							_current = &bb->back();
						}
					}
					return *this;
				}

				iterator_impl operator--(int)
				{
					if (_current == _first)
					{
						return *this;
					}

					iterator_impl tmp(*this);

					if (_current == nullptr)
					{
						_current = _last;
						return tmp;
					}

					auto* bb = _current->getParent()->getPrevNode();
					_current = _current->getPrevNode();
					if (_current == nullptr)
					{
						if (bb)
						{
							_current = &bb->back();
						}
					}
					return tmp;
				}

				reference operator*()
				{
					assert(_first != _current);
					return *_current;
				}

				pointer operator->()
				{
					assert(_first != _current);
					return &(*_current);
				}

				bool operator==(const iterator_impl& rhs) const
				{
					return (_current == nullptr && rhs._current == nullptr)
							|| (_first == rhs._first
									&& _last == rhs._last
									&& _current == rhs._current);
				}

				bool operator!=(const iterator_impl& rhs) const
				{
					return !(*this == rhs);
				}

			private:
				bool isLlvmToAsmInstruction(const llvm::Instruction* i) const
				{
					auto* s = llvm::dyn_cast_or_null<llvm::StoreInst>(i);
					return s &&
						s->getPointerOperand() == _first->getPointerOperand();
				}

			private:
				llvm::StoreInst* _first = nullptr;
				llvm::Instruction* _last = nullptr;
				llvm::Instruction* _current = nullptr;
		};
};

} // namespace bin2llvmir
} // namespace retdec

#endif
