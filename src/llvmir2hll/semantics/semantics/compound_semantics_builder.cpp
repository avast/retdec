/**
* @file src/llvmir2hll/semantics/semantics/compound_semantics_builder.cpp
* @brief Implementation of CompoundSemanticsBuilder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/compound_semantics.h"
#include "retdec/llvmir2hll/semantics/semantics/compound_semantics_builder.h"
#include "retdec/llvmir2hll/semantics/semantics_factory.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvm-support/diagnostics.h"

using namespace retdec::llvm_support;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Builds compound semantics from the given list of IDs.
*
* If @a semanticsIds is of the form <tt>("sem1", "sem2", "sem3")</tt>, then the
* resulting compound semantics will be of the form <tt>(sem1, sem2, sem3)</tt>.
* This means that when the functions from the Semantics' interface are called,
* @c sem1 is asked first, then @c sem2 (if @c sem1 doesn't know the answer) and
* so on.
*
* For every ID in @a semanticsIds, the builder calls SemanticsFactory to obtain
* an instance of the requested semantics. If there is no semantics with a given
* ID, a warning message is emitted and the semantics is not added.
*/
ShPtr<CompoundSemantics> CompoundSemanticsBuilder::build(
		const StringVector &semanticsIds) {
	ShPtr<CompoundSemantics> compoundSemantics(CompoundSemantics::create());

	// Try to instantiate and add all semantics from semanticsIds.
	for (const auto &id : semanticsIds) {
		ShPtr<Semantics> semantics(SemanticsFactory::getInstance().createObject(id));
		if (semantics) {
			compoundSemantics->appendSemantics(semantics);
		} else {
			printWarningMessage("There is no registered semantics with ID \"",
				id, "\", skipping.");
		}
	}

	return compoundSemantics;
}

} // namespace llvmir2hll
} // namespace retdec
