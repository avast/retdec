/**
* @file src/llvm-support/diagnostics.cpp
* @brief Implementation of the functions concerning emission of diagnostics
*        messages, like error or warning messages.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iomanip>
#include <sstream>

#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/time.h"

using retdec::utils::getElapsedTime;

namespace retdec {
namespace llvm_support {

namespace {

/**
* @brief Formats the given elapsed time so it can be printed.
*
* The resulting string is a representation of @a elapsedTime with fixed two
* numbers after the decimal point. For example, number @c 1.16397 is formatted
* as @c 1.16.
*/
std::string formatElapsedTime(double elapsedTime) {
	std::stringstream formatted;
	formatted << std::fixed << std::setprecision(2) << elapsedTime;
	return formatted.str();
}

/**
* @brief Prints the given phase to the given stream with the given prefix.
*
* This function is used to implement the print*Phase() functions.
*/
void printPrefixedPhase(const std::string &prefix, const std::string &phaseName,
		llvm::raw_ostream &stream) {
	printColoredLine(stream, llvm::raw_ostream::YELLOW, /* bold */ true, prefix,
		phaseName, " ( ", formatElapsedTime(getElapsedTime()), "s )");

	// Make it appear as soon as possible to keep the user updated.
	stream.flush();
}

} // anonymous namespace

/**
* @brief Prints the given phase to the given stream.
*
* A new line is appended after the emitted text and the stream is flushed.
*/
void printPhase(const std::string &phaseName, llvm::raw_ostream &stream) {
	printPrefixedPhase("Running phase: ", phaseName, stream);
}

/**
* @brief Prints the given sub-phase to the given stream.
*
* A new line is appended after the emitted text and the stream is flushed.
*/
void printSubPhase(const std::string &phaseName, llvm::raw_ostream &stream) {
	printPrefixedPhase(" -> ", phaseName, stream);
}

/**
* @brief Prints the given sub-sub-phase to the given stream.
*
* A new line is appended after the emitted text and the stream is flushed.
*/
void printSubSubPhase(const std::string &phaseName, llvm::raw_ostream &stream) {
	printPrefixedPhase("     -> ", phaseName, stream);
}

/**
* @brief Prints the given sub-sub-sub-phase to the given stream.
*
* A new line is appended after the emitted text and the stream is flushed.
*/
void printSubSubSubPhase(const std::string &phaseName, llvm::raw_ostream &stream) {
	printPrefixedPhase("         -> ", phaseName, stream);
}

} // namespace llvm_support
} // namespace retdec
