/**
* @file include/bin2llvmir/optimizations/decoder/decoder.h
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BIN2LLVMIR_OPTIMIZATIONS_DECODER_DECODER_H
#define BIN2LLVMIR_OPTIMIZATIONS_DECODER_DECODER_H

#include <queue>
#include <sstream>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "tl-cpputils/address.h"
#include "bin2llvmir/providers/asm_instruction.h"
#include "bin2llvmir/providers/config.h"
#include "bin2llvmir/providers/debugformat.h"
#include "bin2llvmir/providers/fileimage.h"
#include "bin2llvmir/utils/ir_modifier.h"
#include "capstone2llvmir/capstone2llvmir.h"
#include "capstone2llvmir/x86/x86.h"

namespace bin2llvmir {

class Decoder : public llvm::ModulePass
{
	public:
		static char ID;
		Decoder();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				FileImage* o,
				DebugFormat* d);

	public:
		class JumpTarget
		{
			public:
				/**
				 * Jump target type and its priority. Lower number -> higher
				 * priority.
				 */
				enum class eType
				{
					ENTRY_POINT = 0,
					DELAY_SLOT,
					CONTROL_FLOW,
					SELECTED_RANGE_START,
					CONFIG_FUNCTION,
//					STATICALLY_LINKED_FUNCTION, // TODO: remove from here?
					DEBUG_FUNCTION,
					IMPORT_FUNCTION,
					EXPORT_FUNCTION,
					SYMBOL_FUNCTION_PUBLIC, // better than PRIVATE, and other.
					SYMBOL_FUNCTION,
					STATICALLY_LINKED_FUNCTION,
					DELPHI_FNC_TABLE_FUNCTION,
					CODE_POINTER_FROM_DATA,
					CODE_POINTER_FROM_OTHER,
					SECTION_START,
				};

			public:
				JumpTarget() {} // just so it can be used in std::map.
				JumpTarget(
						Config* conf,
						tl_cpputils::Address a,
						eType t,
						cs_mode m,
						tl_cpputils::Address f = tl_cpputils::Address::getUndef,
						const std::string& n = "")
						:
						address(a),
						from(f),
						type(t),
						mode(m)
				{
					setName(n);

					if (conf->getConfig().architecture.isArmOrThumb())
					{
						if (address % 2)
						{
							mode = CS_MODE_THUMB;
							--address;
						}
					}
				}

				bool operator<(const JumpTarget& o) const
				{
					if (type == o.type)
					{
						return address < o.address;
					}
					else
					{
						return type < o.type;
					}
				}

				bool createFunction() const
				{
					return type == eType::SECTION_START
							|| type == eType::ENTRY_POINT
							|| type == eType::CONFIG_FUNCTION
							|| type == eType::DEBUG_FUNCTION
							|| type == eType::SYMBOL_FUNCTION
							|| type == eType::SYMBOL_FUNCTION_PUBLIC
							|| type == eType::EXPORT_FUNCTION
							|| type == eType::IMPORT_FUNCTION
							|| type == eType::STATICALLY_LINKED_FUNCTION
							|| type == eType::SELECTED_RANGE_START
							|| type == eType::DELPHI_FNC_TABLE_FUNCTION
							;
				}

				bool hasName() const
				{
					return !name.empty();
				}

				std::string getName(Config* config = nullptr) const
				{
					return config && config->isPic32()
							? fixWeirdManglingOfPic32(name)
							: name;
				}

				void setName(const std::string& n) const
				{
					name = n;
				}

				friend std::ostream& operator<<(std::ostream &out, const JumpTarget& jt);

				bool isKnownMode() const
				{
					return !isUnknownMode();
				}
				bool isUnknownMode() const
				{
					return mode == CS_MODE_BIG_ENDIAN;
				}

			private:
				std::string fixWeirdManglingOfPic32(const std::string& n) const
				{
					std::string name = n;
					if (name.empty()) return name;

					if (name.find("_d") == 0)
					{
						name = name.substr(2);
					}
					else if (name[0] == '_')
					{
						name = name.substr(1);
					}

					if (name.empty()) return name;

					if (name.find("_cd") != std::string::npos)
					{
						name = name.substr(0, name.find("_cd"));
					}
					else if (name.find("_eE") != std::string::npos)
					{
						name = name.substr(0, name.find("_eE"));
					}
					else if (name.find("_fF") != std::string::npos)
					{
						name = name.substr(0, name.find("_fF"));
					}
					else if (tl_cpputils::endsWith(name, "_s"))
					{
						name.pop_back();
						name.pop_back();
					}
					return name;
				}

			public:
				tl_cpputils::Address address;
				/// If jump target is code pointer, this is an address where
				/// it was found;
				tl_cpputils::Address from;
				eType type;
				cs_mode mode = CS_MODE_BIG_ENDIAN;

			private:
				mutable std::string name;
		};

		class JumpTargets
		{
			friend std::ostream& operator<<(std::ostream &out, const JumpTargets& jts);
			public:
				void push(const JumpTarget& jt)
				{
					if (jt.address.isDefined())
					{
						_data.insert(jt);
					}
				}

				void push(
						Config* c,
						tl_cpputils::Address a,
						JumpTarget::eType t,
						cs_mode m)
				{
					if (a.isDefined())
					{
						_data.insert(JumpTarget(c, a, t, m));
					}
				}

				void push(
						Config* c,
						tl_cpputils::Address a,
						JumpTarget::eType t,
						cs_mode m,
						tl_cpputils::Address f)
				{
					if (a.isDefined())
					{
						_data.insert(JumpTarget(c, a, t, m, f));
					}
				}

				void push(
						Config* c,
						tl_cpputils::Address a,
						JumpTarget::eType t,
						cs_mode m,
						const std::string name)
				{
					if (a.isDefined())
					{
						_data.insert(JumpTarget(c, a, t, m, tl_cpputils::Address::getUndef, name));
					}
				}

				std::size_t size() const
				{
					return _data.size();
				}

				void clear()
				{
					_data.clear();
				}

				bool empty()
				{
					return _data.empty();
				}

				const JumpTarget& top()
				{
					return *_data.begin();
				}

				void pop()
				{
					_poped.insert(top().address);
					_data.erase(top());
				}

				bool wasAlreadyPoped(JumpTarget& ct) const
				{
					return _poped.count(ct.address);
				}

				auto begin()
				{
					return _data.begin();
				}
				auto end()
				{
					return _data.end();
				}

			public:
				std::set<JumpTarget> _data;
				std::set<tl_cpputils::Address> _poped;
		};

	private:
		bool runCatcher();
		bool run();
		void checkIfSomethingDecoded();

		bool initTranslator();
		void initEnvironment();
		void initEnvironmentAsm2LlvmMapping();
		void initEnvironmentPseudoFunctions();
		void initEnvironmentRegisters();

		void initRangesAndTargets();
		void initAllowedRangesWithSegments();
		void initAllowedRangesWithConfig();
		void initJumpTargets();
		void initJumpTargetsWithStaticCode();
		void removeZeroSequences(tl_cpputils::AddressRangeContainer& rs);

		void doDecoding();
		bool looksLikeValidJumpTarget(tl_cpputils::Address addr);

		void doStaticCodeRecognition();

		tl_cpputils::Address getJumpTarget(llvm::Value* val);

		void findDelphiFunctionTable();

		bool fixMainName();
		std::string getFunctionNameFromLibAndOrd(
				const std::string& libName,
				int ord);
		bool loadOrds(const std::string& libName);
		void removeStaticallyLinkedFunctions();
		void hackDeleteKnownLinkedFunctions();

		void fixMipsDelaySlots();

		bool isArmOrThumb() const;
		cs_mode getUnknownMode() const;
		cs_mode determineMode(AsmInstruction ai, tl_cpputils::Address target) const;

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _image = nullptr;
		DebugFormat* _debug = nullptr;

		std::unique_ptr<capstone2llvmir::Capstone2LlvmIrTranslator> _c2l;

		const std::string _asm2llvmGv = "_asm_program_counter";
		const std::string _asm2llvmMd = "llvmToAsmGlobalVariableName";
		const std::string _callFunction = "__pseudo_call";
		const std::string _returnFunction = "__pseudo_return";
		const std::string _branchFunction = "__pseudo_branch";
		const std::string _condBranchFunction = "__pseudo_cond_branch";

		std::map<tl_cpputils::Address, std::pair<std::string, tl_cpputils::AddressRange>> _staticCode;
		tl_cpputils::AddressRangeContainer _allowedRanges;
		tl_cpputils::AddressRangeContainer _alternativeRanges;
		tl_cpputils::AddressRangeContainer _processedRanges;
		JumpTargets _jumpTargets;

		std::size_t decodingChunk = 0x50;

		std::map<llvm::Function*, std::pair<tl_cpputils::Address, tl_cpputils::Address>> _functions;

		/// <ordinal number, function name>
		using OrdMap = std::map<int, std::string>;
		/// <library name without suffix ".dll", map with ordinals>
		std::map<std::string, OrdMap> _dllOrds;

		cs_mode _currentMode;
};

} // namespace bin2llvmir

#endif
