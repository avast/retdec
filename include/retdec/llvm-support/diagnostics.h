/**
* @file include/retdec/llvm-support/diagnostics.h
* @brief Functions concerning emission of diagnostics messages, like error or
*        warning messages.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVM_SUPPORT_DIAGNOSTICS_H
#define RETDEC_LLVM_SUPPORT_DIAGNOSTICS_H

#include <string>

#include <llvm/Support/raw_ostream.h>

namespace retdec {
namespace llvm_support {

/// @name Internal (For Internal Use Only)
/// @{

/**
* @brief A base case for printInto(). For internal use only.
*/
inline void printInto(llvm::raw_ostream &) {}

/**
* @brief Prints the given arguments to the given stream. For internal use only.
*/
template<typename T, typename... Args>
void printInto(llvm::raw_ostream &stream, T &&arg, Args &&... args) {
	stream << arg;
	printInto(stream, std::forward<Args>(args)...);
}

/**
* @brief Prints a colored line with the given arguments to the given stream.
*        For internal use only.
*/
template<typename... Args>
void printColoredLine(llvm::raw_ostream &stream, llvm::raw_ostream::Colors color,
		bool bold, Args &&... args) {
	stream.changeColor(color, bold);
	printInto(stream, std::forward<Args>(args)...);
	stream.resetColor();
	stream << "\n";
}

/// @}

/// @name Phases
/// @{

void printPhase(const std::string &phaseName,
	llvm::raw_ostream &stream = llvm::outs());
void printSubPhase(const std::string &phaseName,
	llvm::raw_ostream &stream = llvm::outs());
void printSubSubPhase(const std::string &phaseName,
	llvm::raw_ostream &stream = llvm::outs());
void printSubSubSubPhase(const std::string &phaseName,
	llvm::raw_ostream &stream = llvm::outs());

/// @}

/// @name Messages
/// @{

/**
* @brief Prints the given error message to the standard error.
*
* A new line is automatically appended after the message.
*
* Usage example:
* @code
* printErrorMessage("Function ", funcName, " does not exist."));
* @endcode
*/
template<typename... Args>
void printErrorMessage(const std::string &message, Args &&... args) {
	printColoredLine(llvm::errs(), llvm::raw_ostream::RED, /* bold */ false,
		"Error: ", message, std::forward<Args>(args)...);
}

/**
* @brief Prints the given warning message to the standard error.
*
* A new line is automatically appended after the message.
*
* Usage example:
* @code
* printWarningMessage("Function ", funcName, " does not exist."));
* @endcode
*/
template<typename... Args>
void printWarningMessage(const std::string &message, Args &&... args) {
	printColoredLine(llvm::errs(), llvm::raw_ostream::CYAN, /* bold */ false,
		"Warning: ", message, std::forward<Args>(args)...);
}

/**
* @brief Prints the given info message to the standard error.
*
* A new line is automatically appended after the message.
*
* Usage example:
* @code
* printInfoMessage("Function ", funcName, " does not exist."));
* @endcode
*/
template<typename... Args>
void printInfoMessage(const std::string &message, Args &&... args) {
	printColoredLine(llvm::errs(), llvm::raw_ostream::GREEN, /* bold */ false,
		"Info: ", message, std::forward<Args>(args)...);
}

/// @}

} // namespace llvm_support
} // namespace retdec

#endif
