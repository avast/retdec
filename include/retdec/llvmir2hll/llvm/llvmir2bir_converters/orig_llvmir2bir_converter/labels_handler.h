/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/labels_handler.h
* @brief Handling of labels during conversion of LLVM IR to BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_ORIG_LLVMIR2BIR_CONVERTER_LABELS_HANDLER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_ORIG_LLVMIR2BIR_CONVERTER_LABELS_HANDLER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class BasicBlock;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class Statement;

/**
* @brief Handler of labels during conversion of LLVM IR to BIR.
*/
class LabelsHandler final: private retdec::utils::NonCopyable {
public:
	LabelsHandler();
	~LabelsHandler();

	std::string getLabel(const llvm::BasicBlock *bb) const;
	void removeLabel(const std::string &label);
	void setGotoTargetLabel(ShPtr<Statement> target,
		const llvm::BasicBlock *targetBB);

private:
	std::string createLabelFor(const llvm::BasicBlock *bb) const;
	std::string ensureLabelIsValid(const std::string &label) const;
	std::string ensureLabelIsUnique(const std::string &label) const;
	bool labelIsUsed(const std::string &label) const;
	std::string generateNewLabel(const std::string &origLabel,
		std::size_t i);
	void markLabelAsUsed(const std::string &label);

private:
	// Note: We could have used a mapping of llvm::Function to a set of used
	// labels, but creating globally unique labels is simpler and sufficient
	// (we use instruction addresses in basic block names, so the labels should
	// be pretty unique across all functions).
	StringSet usedLabels;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
