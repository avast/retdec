/**
 * @file include/retdec/bin2llvmir/optimizations/data_references/data_references.h
 * @brief Search for references in input file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DATA_REFERENCES_DATA_REFERENCES_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DATA_REFERENCES_DATA_REFERENCES_H

#include <set>

#include <llvm/IR/Function.h>
#include <llvm/Pass.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/address.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

/**
 * This pass scans an entire binary word by word for words that reference
 * some other location in the binary = it holds an address of that location.
 * If there is some known object at that location (function, global variable,
 * instruction, etc.) it is associated with the reference.
 *
 * TODO: This should not be a pass but analysis that works on demand. If it
 * needs persistent data (e.g. addresses of references) then add it to object
 * file provider or config or something like that.
 */
class DataReferences : public llvm::ModulePass
{
	public:
		static char ID;
		DataReferences();
		virtual void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
		virtual bool runOnModule(llvm::Module &) override;

	private:
		class ReferencedObject
		{
			public:
				ReferencedObject(retdec::utils::Address a);

			public:
				retdec::utils::Address addr;
				const retdec::loader::Segment *seg = nullptr;

				llvm::Function *function = nullptr;
				llvm::GlobalVariable *globalVar = nullptr;
				llvm::Instruction *instruction = nullptr;
		};

	public:
		using Addr2Obj = std::map<retdec::utils::Address, ReferencedObject>;

	public:
		const Addr2Obj& getAddressToObjectMapping() const;
		bool hasReferenceOnAddress(retdec::utils::Address a) const;
		const ReferencedObject* getReferenceFromAddress(
				retdec::utils::Address a) const;

	private:
		void detectReferencesIntoSegments();
		void linkReferencesWithKnownObjects();

	private:
		Config* config = nullptr;
		FileImage* objf = nullptr;
		Addr2Obj addr2obj;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
