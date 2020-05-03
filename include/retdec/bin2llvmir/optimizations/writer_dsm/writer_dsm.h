/**
 * @file include/retdec/bin2llvmir/optimizations/writer_dsm/writer_dsm.h
 * @brief Generate the current disassembly.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_WRITER_DSM_WRITER_DSM_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_WRITER_DSM_WRITER_DSM_H

#include <ostream>

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class DsmWriter : public llvm::ModulePass
{
	public:
		static char ID;
		DsmWriter();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				FileImage* objf,
				Abi* abi,
				std::ostream& ret);

	private:
		void run(std::ostream& ret);
		void generateHeader(std::ostream& ret);
		void generateCode(std::ostream& ret);
		void generateCodeSeg(
				const retdec::loader::Segment* seg,
				std::ostream& ret);
		void generateFunction(
				const retdec::common::Function* fnc,
				std::ostream& ret);
		void generateInstruction(AsmInstruction& ai, std::ostream& ret);
		void generateData(std::ostream& ret);
		void generateDataSeg(
				const retdec::loader::Segment* seg,
				std::ostream& ret);
		void generateDataRange(
				retdec::common::Address start,
				retdec::common::Address end,
				std::ostream& ret);
		void generateAlignedAddress(
				retdec::common::Address addr,
				std::ostream& ret);

		void getAsmInstructionHex(AsmInstruction& ai, std::ostream& ret);
		std::string processInstructionDsm(AsmInstruction& ai);
		void generateData(
				std::ostream& ret,
				retdec::common::Address start,
				std::size_t size,
				const std::string& objVal = "");
		std::string escapeString(const std::string& str);
		std::string reduceNegativeNumbers(const std::string& str);
		void findLongestInstruction();
		void findLongestAddress();
		std::string getString(
				const retdec::common::Object* cgv,
				const llvm::ConstantDataArray* cda);

		std::string getFunctionName(llvm::Function* f) const;
		std::string getFunctionName(const retdec::common::Function* f) const;

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _objf = nullptr;
		Abi* _abi = nullptr;

		std::size_t _longestInst = 0;
		std::size_t _longestAddr = 0;
		std::map<retdec::common::Address, const retdec::common::Function*> _addr2fnc;

		const std::size_t DATA_SEGMENT_LINE    = 16;
		const std::string ALIGN = "   ";
		const std::string INSTR_SEPARATOR = "\t"; // maybe "\t"
};

} // namespace bin2llvmir
} // namespace retdec

#endif
