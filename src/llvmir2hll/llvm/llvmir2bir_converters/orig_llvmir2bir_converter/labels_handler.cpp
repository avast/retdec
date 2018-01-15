/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/labels_handler.cpp
* @brief Implementation of LabelsHandler.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/BasicBlock.h>

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/labels_handler.h"
#include "retdec/llvmir2hll/utils/string.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

LabelsHandler::LabelsHandler() = default;

LabelsHandler::~LabelsHandler() = default;

/**
* @brief Returns the label of the given basic block.
*
* If there is an address in the name of @a bb, it is returned. Otherwise, the
* name of @a bb is returned.
*/
std::string LabelsHandler::getLabel(const llvm::BasicBlock *bb) const {
	return getAddressFromLabel(
		bb->getName(),
		LLVMSupport::getBasicBlockLabelPrefix()
	);
}

/**
* @brief Removes the given label from the set of used labels.
*/
void LabelsHandler::removeLabel(const std::string &label) {
	usedLabels.erase(label);
}

/**
* @brief Sets a proper label of a goto target that is in the given basic block.
*/
void LabelsHandler::setGotoTargetLabel(ShPtr<Statement> target,
		const llvm::BasicBlock *targetBB) {
	auto label = createLabelFor(targetBB);
	target->setLabel(label);
	markLabelAsUsed(label);
}

std::string LabelsHandler::createLabelFor(const llvm::BasicBlock *bb) const {
	auto label = getLabel(bb);
	label = ensureLabelIsValid(label);
	label = ensureLabelIsUnique(label);
	return label;
}

std::string LabelsHandler::ensureLabelIsValid(const std::string &label) const {
	return makeIdentifierValid(label);
}

std::string LabelsHandler::ensureLabelIsUnique(const std::string &label) const {
	auto uniqueLabel = label;
	std::size_t i = 1;
	while (labelIsUsed(uniqueLabel)) {
		++i;
		uniqueLabel = label + "_" + std::to_string(i);
	}
	return uniqueLabel;
}

bool LabelsHandler::labelIsUsed(const std::string &label) const {
	return hasItem(usedLabels, label);
}

void LabelsHandler::markLabelAsUsed(const std::string &label) {
	usedLabels.insert(label);
}

} // namespace llvmir2hll
} // namespace retdec
