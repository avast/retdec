/**
* @file src/llvmir2hll/hll/hll_writer.cpp
* @brief Implementation of HLLWriter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>
#include <cstddef>
#include <sstream>

#include "retdec/llvmir2hll/hll/bracket_manager.h"
#include "retdec/llvmir2hll/hll/hll_writer.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/string_type.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/unary_op_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/global_vars_sorter.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/utils/string.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/utils/time.h"

using namespace std::string_literals;

using retdec::utils::getCurrentDate;
using retdec::utils::getCurrentTime;
using retdec::utils::getCurrentYear;
using retdec::utils::hasItem;
using retdec::utils::joinStrings;
using retdec::utils::split;
using retdec::utils::startsWith;
using retdec::utils::toHex;
using retdec::utils::toString;

namespace retdec {
namespace llvmir2hll {

namespace {

/// Spaces to indent a single level of nesting.
const std::string LEVEL_INDENT = "    ";

/// Default indentation level (for global values).
const std::string DEFAULT_LEVEL_INDENT = "";

/// Maximal length of a section header comment.
const std::size_t MAX_SECTION_HEADER_LENGTH = 58;

/// Separating character in a section header comment.
const char SECTION_COMMENT_SEP_CHAR = '-';

/**
* @brief Comparator of functions based on line information from debug
*        information.
*/
class LineInfoFuncComparator {
public:
	/**
	* @brief Constructs a new comparator.
	*
	* @param[in] module The current module.
	*
	* @par Preconditions
	*  - all functions in @a module have available line information
	*/
	explicit LineInfoFuncComparator(ShPtr<Module> module):
		module(module) {}

	/**
	* @brief Returns @c true if @a f1 starts on a smaller line number than @a
	*        f2, @c false otherwise.
	*/
	bool operator()(ShPtr<Function> f1, ShPtr<Function> f2) {
		auto f1LineRange = module->getLineRangeForFunc(f1);
		auto f2LineRange = module->getLineRangeForFunc(f2);
		return f1LineRange.first < f2LineRange.first;
	}

private:
	/// The current module.
	ShPtr<Module> module;
};

/**
* @brief Comparator of functions based on address ranges.
*/
class AddressRangeFuncComparator {
public:
	/**
	* @brief Constructs a new comparator.
	*
	* @param[in] module The current module.
	*
	* @par Preconditions
	*  - all functions in @a module have available address ranges
	*/
	explicit AddressRangeFuncComparator(ShPtr<Module> module):
		module(module) {}

	/**
	* @brief Returns @c true if @a f1 starts on a smaller address than @a f2,
	* @c false otherwise.
	*/
	bool operator()(ShPtr<Function> f1, ShPtr<Function> f2) {
		auto f1AddressRange = module->getAddressRangeForFunc(f1);
		auto f2AddressRange = module->getAddressRangeForFunc(f2);
		return f1AddressRange.first < f2AddressRange.first;
	}

private:
	/// The current module.
	ShPtr<Module> module;
};

} // anonymous namespace

/**
* @brief Constructs a new writer.
*
* @param[in] out Output stream into which the HLL code will be emitted.
*/
HLLWriter::HLLWriter(llvm::raw_ostream &out):
	out(out), emitConstantsInStructuredWay(false),
	optionEmitDebugComments(true), optionKeepAllBrackets(false),
	optionEmitTimeVaryingInfo(true), optionUseCompoundOperators(true),
	currFuncGotoLabelCounter(1), currentIndent(DEFAULT_LEVEL_INDENT) {}

/**
* @brief Destructs the writer.
*/
HLLWriter::~HLLWriter() {}

/**
* @brief Enables/disables the emission of debug comments.
*
* @param[in] emit If @c true, enables the emission of debug comments. If @c
*                 false, disables the emission of debug comments.
*/
void HLLWriter::setOptionEmitDebugComments(bool emit) {
	optionEmitDebugComments = emit;
}

/**
* @brief Enables/disables the keeping of all brackets.
*
* @param[in] keep If @c true, all brackets will be kept. If @c false, redundant
*                 brackets will be eliminated.
*/
void HLLWriter::setOptionKeepAllBrackets(bool keep) {
	optionKeepAllBrackets = keep;
}

/**
* @brief Enables/disables emission of time-varying information, like dates.
*
* @param[in] emit If @c true, time-varying information, like dates, will be
*                 emitted.
*/
void HLLWriter::setOptionEmitTimeVaryingInfo(bool emit) {
	optionEmitTimeVaryingInfo = emit;
}

/**
* @brief Enables/disables usage of compound operators (like @c +=) instead of
*        assignments.
*
* @param[in] use If @c true, compound operators will be used.
*/
void HLLWriter::setOptionUseCompoundOperators(bool use) {
	optionUseCompoundOperators = use;
}

/**
* @brief Emits the code from the given module.
*
* @param[in] module Module to be written.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* The functions prints the code blocks in the following order (by calling
* appropriate emit*() functions):
*  - file header
*  - function prototypes header, function prototypes, function prototypes footer
*  - global header, global variables, global footer
*  - functions header, functions, functions footer
*  - external functions header, external functions, external functions footer
*    (there are many types of external functions; a separate section is emitted
*    for each type)
*  - meta-information header, meta-information, meta-information footer
*  - file footer
*
* Each block is separated by a blank line. A subclass of this class can just
* override the appropriate emit*() functions. To change the order of blocks,
* override this function.
*/
bool HLLWriter::emitTargetCode(ShPtr<Module> module) {
	this->module = module;
	bool codeEmitted = false;
	namesOfFuncsWithFixedIR = module->getNamesOfFuncsFixedWithLLVMIRFixer();

	if (emitFileHeader()) { codeEmitted = true; out << "\n"; }

	//
	// Classes
	//
	if (emitClassesHeader()) { codeEmitted = true; out << "\n";}
	if (emitClasses()) { codeEmitted = true; out << "\n";}
	if (emitClassesFooter()) { codeEmitted = true; out << "\n"; }

	//
	// Function prototypes
	//
	if (emitFunctionPrototypesHeader()) { codeEmitted = true; out << "\n";}
	if (emitFunctionPrototypes()) { codeEmitted = true; out << "\n";}
	if (emitFunctionPrototypesFooter()) { codeEmitted = true; out << "\n"; }

	//
	// Global variables
	//
	// Note: Global variables have to be emitted after function prototypes
	// because there may be a global variable initialized with a function from
	// the module. For example,
	//
	//   void (*fp)(void) = func;
	//   void func(void);
	//
	// is semantically invalid (from the view of C99) while
	//
	//   void func(void);
	//   void (*fp)(void) = func;
	//
	// is OK.
	if (emitGlobalVariablesHeader()) { codeEmitted = true; out << "\n"; }
	if (emitGlobalVariables()) { codeEmitted = true; out << "\n"; }
	if (emitGlobalVariablesFooter()) { codeEmitted = true; out << "\n"; }

	//
	// Functions
	//
	if (emitFunctionsHeader()) { codeEmitted = true; out << "\n"; }
	if (emitFunctions()) { codeEmitted = true; out << "\n"; }
	if (emitFunctionsFooter()) { codeEmitted = true; out << "\n"; }

	//
	// Statically linked functions
	//
	if (emitStaticallyLinkedFunctionsHeader()) { codeEmitted = true; out << "\n"; }
	if (emitStaticallyLinkedFunctions()) { codeEmitted = true; out << "\n"; }
	if (emitStaticallyLinkedFunctionsFooter()) { codeEmitted = true; out << "\n"; }

	//
	// Dynamically linked functions
	//
	if (emitDynamicallyLinkedFunctionsHeader()) { codeEmitted = true; out << "\n"; }
	if (emitDynamicallyLinkedFunctions()) { codeEmitted = true; out << "\n"; }
	if (emitDynamicallyLinkedFunctionsFooter()) { codeEmitted = true; out << "\n"; }

	//
	// Syscall functions
	//
	if (emitSyscallFunctionsHeader()) { codeEmitted = true; out << "\n"; }
	if (emitSyscallFunctions()) { codeEmitted = true; out << "\n"; }
	if (emitSyscallFunctionsFooter()) { codeEmitted = true; out << "\n"; }

	//
	// Instruction-idiom functions
	//
	if (emitInstructionIdiomFunctionsHeader()) { codeEmitted = true; out << "\n"; }
	if (emitInstructionIdiomFunctions()) { codeEmitted = true; out << "\n"; }
	if (emitInstructionIdiomFunctionsFooter()) { codeEmitted = true; out << "\n"; }

	//
	// Meta-information
	//
	if (emitMetaInfoHeader()) { codeEmitted = true; out << "\n"; }
	if (emitMetaInfo()) { codeEmitted = true; out << "\n"; }
	if (emitMetaInfoFooter()) { codeEmitted = true; out << "\n"; }

	if (emitFileFooter()) { codeEmitted = true; }

	return codeEmitted;
}

/**
* @brief Comments the given code.
*
* If @a code spans over multiple lines, this function makes sure that the
* whole block is properly commented.
*
* By default, it comments all lines by prefixing them with getCommentPrefix().
*/
std::string HLLWriter::comment(const std::string &code) {
	std::string commentPrefix(getCommentPrefix());

	// If there are no newlines, the situation is easy.
	if (code.find_first_of("\n") == std::string::npos) {
		return commentPrefix + " " + code;
	}

	// We split the code by newlines and comment them separately.
	StringVector codeLines(split(code, '\n', false));

	// Do not comment the last empty line (if any).
	if (!codeLines.empty() && codeLines.back().empty()) {
		codeLines.pop_back();
	}

	std::string result;
	for (const auto &line : codeLines) {
		// Insert a space between the comment prefix and the code only if the
		// code is non-empty to prevent trailing spaces.
		result += commentPrefix + (!line.empty() ? " " + line : line) + "\n";
	}
	return result;
}

/**
* @brief Increases the indentation level.
*/
void HLLWriter::increaseIndentLevel() {
	currentIndent += LEVEL_INDENT;
}

/**
* @brief Decreases the indentation level.
*/
void HLLWriter::decreaseIndentLevel() {
	currentIndent.resize(currentIndent.size() - LEVEL_INDENT.size());
}

/**
* @brief Returns the current indentation (to indent the current block).
*/
std::string HLLWriter::getCurrentIndent() const {
	return currentIndent;
}

/**
* @brief Returns the single level of indentation.
*
* The returned value is the string that is used in increaseIndentLevel() and
* decreaseIndentLevel() to increase and decrease the current indentation,
* respectively.
*/
std::string HLLWriter::getSingleLevelIndent() const {
	return LEVEL_INDENT;
}

/**
* @brief Returns indentation for a goto label.
*/
std::string HLLWriter::getIndentForGotoLabel() const {
	// Goto labels are emitted in the following form:
	//
	//     # ...
	//   label:
	//     # ...
	//
	// In words, we put the goto label half of one indentation level to the
	// left. For example, if the indentation level is 4, we put the label 2
	// spaces before the current indent.
	return std::string(
		getCurrentIndent().size() - getSingleLevelIndent().size() / 2,
		' '
	);
}

/**
* @brief Emits the file header.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits the default header.
*/
bool HLLWriter::emitFileHeader() {
	// Prepare the header.
	std::ostringstream header;
	header << "\n";
	header << "This file was generated by the Retargetable Decompiler\n";
	header << "Website: https://retdec.com\n";
	header << "Copyright (c)";
	if (optionEmitTimeVaryingInfo) {
		header << " " << getCurrentYear();
	}
	header << " Retargetable Decompiler <info@retdec.com>\n";
	header << "\n";

	// Emit it.
	out << comment(header.str());

	return true;
}

/**
* @brief Emits the file footer.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitFileFooter() {
	return false;
}

/**
* @brief Emits the header of the <em>classes</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool HLLWriter::emitClassesHeader() {
	if (module->hasClasses()) {
		emitSectionHeader("Classes");
		return true;
	}
	return false;
}

/**
* @brief Emits classes.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it calls emitClass() for each class.
*/
bool HLLWriter::emitClasses() {
	bool somethingEmitted = false;
	for (const auto &className : module->getClassNames()) {
		somethingEmitted |= emitClass(className);
	}
	return somethingEmitted;
}

/**
* @brief Emits the class with the given name.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool HLLWriter::emitClass(const std::string &className) {
	std::ostringstream classInfo;

	// Name of the class.
	classInfo << getReadableClassName(className);

	// Names of base classes.
	auto baseClassNames = module->getBaseClassNames(className);
	if (!baseClassNames.empty()) {
		classInfo << " (base classes: " <<
			joinStrings(getReadableClassNames(baseClassNames)) << ")";
	}

	out << comment(classInfo.str() + "\n");
	return true;
}

/**
* @brief Emits the footer of the <em>classes</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitClassesFooter() {
	return false;
}

/**
* @brief Emits the header of the <em>global variables</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitGlobalVariablesHeader() {
	if (module->hasGlobalVars()) {
		emitSectionHeader("Global Variables");
		return true;
	}
	return false;
}

/**
* @brief Emits all global variables in the module.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it it calls emitGlobalVariable() on
* each global variable in the module.
*/
bool HLLWriter::emitGlobalVariables() {
	auto globalVars = GlobalVarsSorter::sortByInterdependencies(
		{module->global_var_begin(), module->global_var_end()}
	);
	for (const auto &var : globalVars) {
		emitGlobalVariable(var);
	}
	return !globalVars.empty();
}

/**
* @brief Emits the given global variable, including the ending newline.
*
* @param[in] varDef Definition of the variable.
*
* @par Preconditions
*  - @a varDef is non-null
*
* By default (if it is not overridden), it calls @c varDef->accept(this) and
* returns @c true.
*/
bool HLLWriter::emitGlobalVariable(ShPtr<GlobalVarDef> varDef) {
	emitDetectedCryptoPatternForGlobalVarIfAvailable(varDef->getVar());
	varDef->accept(this);
	return true;
}

/**
* @brief Emits the footer of the <em>global variables</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitGlobalVariablesFooter() {
	return false;
}

/**
* @brief Emits the header of the <em>function prototypes</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitFunctionPrototypesHeader() {
	return false;
}

/**
* @brief Emits function prototypes.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitFunctionPrototypes() {
	return false;
}

/**
* @brief Emits the footer of the <em>function prototypes</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitFunctionPrototypesFooter() {
	return false;
}

/**
* @brief Emits the header of the <em>functions</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool HLLWriter::emitFunctionsHeader() {
	if (module->hasFuncDefinitions()) {
		emitSectionHeader("Functions");
		return true;
	}
	return false;
}

/**
* @brief Emits functions in the module.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it tries to sort the functions in the
* module and calls emitFunction() on each of them.
*/
bool HLLWriter::emitFunctions() {
	FuncVector funcs(module->func_definition_begin(), module->func_definition_end());
	sortFuncsForEmission(funcs);
	bool somethingEmitted = false;
	for (const auto &func : funcs) {
		if (somethingEmitted) {
			// To produce an empty line between functions.
			out << "\n";
		}
		somethingEmitted |= emitFunction(func);
	}
	return somethingEmitted;
}

/**
* @brief Emits the given function, including the ending newline.
*
* @param[in] func Function to be emitted.
*
* By default, it emits information about @a func (like address range, module,
* etc., if available), and then calls @c func->accept(this).
*
* @par Preconditions
*  - @a func is non-null
*/
bool HLLWriter::emitFunction(ShPtr<Function> func) {
	PRECONDITION_NON_NULL(func);

	currFunc = func;
	currFuncGotoLabelCounter = 0;

	emitModuleNameForFuncIfAvailable(func);
	emitAddressRangeForFuncIfAvailable(func);
	emitLineRangeForFuncIfAvailable(func);
	// TODO Disable emission of wrapper info until #189 is solved.
	// emitWrapperInfoForFuncIfAvailable(func);
	emitClassInfoIfAvailable(func);
	emitDemangledNameIfAvailable(func);
	emitDetectedCryptoPatternsForFuncIfAvailable(func);
	emitLLVMIRFixerWarningForFuncIfAny(func);
	// The comment HAS to be put as the LAST info, right before the function's
	// signature. IDA plugin relies on that.
	emitCommentIfAvailable(func);

	func->accept(this);

	currFunc.reset();

	return true;
}

/**
* @brief Emits the footer of the <em>functions</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitFunctionsFooter() {
	return false;
}

/**
* @brief Emits the header of the <em>statically linked functions</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool HLLWriter::emitStaticallyLinkedFunctionsHeader() {
	if (module->hasStaticallyLinkedFuncs()) {
		emitSectionHeader("Statically Linked Functions");
		return true;
	}
	return false;
}

/**
* @brief Emits statically linked functions in the module.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it sort all statically linked functions
* in the module by their name and calls emitExternalFunction() on each of them.
*/
bool HLLWriter::emitStaticallyLinkedFunctions() {
	return emitExternalFunctions(module->getStaticallyLinkedFuncs());
}

/**
* @brief Emits the footer of the <em>dynamically linked functions</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitStaticallyLinkedFunctionsFooter() {
	return false;
}

/**
* @brief Emits the header of the <em>dynamically linked functions</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool HLLWriter::emitDynamicallyLinkedFunctionsHeader() {
	if (module->hasDynamicallyLinkedFuncs()) {
		emitSectionHeader("Dynamically Linked Functions");
		return true;
	}
	return false;
}

/**
* @brief Emits dynamically linked functions in the module.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it sort all dynamically linked
* functions in the module by their name and calls emitExternalFunction() on
* each of them.
*/
bool HLLWriter::emitDynamicallyLinkedFunctions() {
	return emitExternalFunctions(module->getDynamicallyLinkedFuncs());
}

/**
* @brief Emits the footer of the <em>dynamically linked functions</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitDynamicallyLinkedFunctionsFooter() {
	return false;
}

/**
* @brief Emits the header of the <em>syscall functions</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool HLLWriter::emitSyscallFunctionsHeader() {
	if (module->hasSyscallFuncs()) {
		emitSectionHeader("System-Call Functions");
		return true;
	}
	return false;
}

/**
* @brief Emits syscall functions in the module.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it sort all syscall functions in the
* module by their name and calls emitExternalFunction() on each of them.
*/
bool HLLWriter::emitSyscallFunctions() {
	return emitExternalFunctions(module->getSyscallFuncs());
}

/**
* @brief Emits the footer of the <em>syscall functions</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitSyscallFunctionsFooter() {
	return false;
}

/**
* @brief Emits the header of the <em>instruction-idiom functions</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool HLLWriter::emitInstructionIdiomFunctionsHeader() {
	if (module->hasInstructionIdiomFuncs()) {
		emitSectionHeader("Instruction-Idiom Functions");
		return true;
	}
	return false;
}

/**
* @brief Emits instruction-idiom functions in the module.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it sort all instruction-idiom functions
* in the module by their name and calls emitExternalFunction() on each of them.
*/
bool HLLWriter::emitInstructionIdiomFunctions() {
	return emitExternalFunctions(module->getInstructionIdiomFuncs());
}

/**
* @brief Emits the footer of the <em>instruction-idiom functions</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitInstructionIdiomFunctionsFooter() {
	return false;
}

/**
* @brief Emits the given external functions.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it sort all the given functions and
* calls emitExternalFunction() on each of them.
*/
bool HLLWriter::emitExternalFunctions(const FuncSet &funcs) {
	FuncVector toEmit(funcs.begin(), funcs.end());
	sortByName(toEmit);
	bool somethingEmitted = false;
	for (auto &func : toEmit) {
		somethingEmitted |= emitExternalFunction(func);
	}
	return somethingEmitted;
}

/**
* @brief Emits the given linked function, including the ending newline.
*
* @param[in] func Linked function to be emitted.
*
* @par Preconditions
*  - @a func is non-null
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitExternalFunction(ShPtr<Function> func) {
	return false;
}

/**
* @brief Emits the header of the <em>meta-information</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitMetaInfoHeader() {
	emitSectionHeader("Meta-Information");
	return true;
}

/**
* @brief Emits meta-information.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits several meta-information
* concerning the generated code.
*/
bool HLLWriter::emitMetaInfo() {
	bool codeEmitted = false;
	codeEmitted |= emitMetaInfoDetectedCompilerOrPacker();
	codeEmitted |= emitMetaInfoDetectedLanguage();
	codeEmitted |= emitMetaInfoNumberOfDetectedFuncs();
	codeEmitted |= emitMetaInfoSelectedButNotFoundFuncs();
	if (optionEmitTimeVaryingInfo) {
		codeEmitted |= emitMetaInfoDecompilationDate();
	}
	codeEmitted |= emitMetaInfoFuncsRemovedDueErrors();
	codeEmitted |= emitMetaInfoNumberOfDecompilationErrors();
	return codeEmitted;
}

/**
* @brief Emits the footer of the <em>meta-information</em> block.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* By default (if it is not overridden), it emits nothing.
*/
bool HLLWriter::emitMetaInfoFooter() {
	return false;
}

/**
* @brief Emits the given expression with brackets around it (if needed).
*/
void HLLWriter::emitExprWithBracketsIfNeeded(ShPtr<Expression> expr) {
	bool bracketsAreNeeded = bracketsManager->areBracketsNeeded(expr);
	if (bracketsAreNeeded) {
		out << "(";
	}
	expr->accept(this);
	if (bracketsAreNeeded) {
		out << ")";
	}
}

/**
* @brief Emits the given unary expression.
*
* @param[in] opRepr Textual representation of the operator (including spaces).
* @param[in] expr Expression to be emitted.
*
* Brackets are emitted when needed. Use this function if you simply need to
* emit the operator without any specialties.
*/
void HLLWriter::emitUnaryOpExpr(const std::string &opRepr,
		ShPtr<UnaryOpExpr> expr) {
	out << opRepr;
	emitExprWithBracketsIfNeeded(expr->getOperand());
}

/**
* @brief Emits the given binary expression.
*
* @param[in] opRepr Textual representation of the operator (including spaces).
* @param[in] expr Expression to be emitted.
*
* Brackets are emitted when needed. Use this function if you simply need to
* emit the operator without any specialties.
*/
void HLLWriter::emitBinaryOpExpr(const std::string &opRepr,
		ShPtr<BinaryOpExpr> expr) {
	bool bracketsAreNeeded = bracketsManager->areBracketsNeeded(expr);
	if (bracketsAreNeeded) {
		out << "(";
	}
	expr->getFirstOperand()->accept(this);
	out << opRepr;
	expr->getSecondOperand()->accept(this);
	if (bracketsAreNeeded) {
		out << ")";
	}
}

/**
* @brief Emits a description of the detected cryptographic pattern for the
*        given global variable.
*
* The description is emitted in a comment and ended with an new line.
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitDetectedCryptoPatternForGlobalVarIfAvailable(ShPtr<Variable> var) {
	auto pattern = module->getDetectedCryptoPatternForGlobalVar(var);
	if (pattern.empty()) {
		return false;
	}

	std::ostringstream info;
	info << "Detected cryptographic pattern: " << pattern << "\n";
	out << comment(info.str());
	return true;
}

/**
* @brief If there is a module name from debug information assigned to the
*        function, emit it in a comment.
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitModuleNameForFuncIfAvailable(ShPtr<Function> func) {
	auto moduleName = module->getDebugModuleNameForFunc(func);
	if (moduleName.empty()) {
		return false;
	}

	std::ostringstream info;
	info << "From module:   " << moduleName << "\n";
	out << comment(info.str());
	return true;
}

/**
* @brief Emits address range for the given function (if available).
*
* If there is address range available, emit it in a comment.
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitAddressRangeForFuncIfAvailable(ShPtr<Function> func) {
	auto addressRange = module->getAddressRangeForFunc(func);
	if (addressRange == NO_ADDRESS_RANGE) {
		return false;
	}

	std::ostringstream info;
	info << "Address range: " << "0x" + toHex(addressRange.first) +
		" - 0x" + toHex(addressRange.second) << "\n";
	out << comment(info.str());
	return true;
}

/**
* @brief Emits line range for the given function (if available).
*
* If there is line information available, emit the line range in a comment.
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitLineRangeForFuncIfAvailable(ShPtr<Function> func) {
	auto lineRange = module->getLineRangeForFunc(func);
	if (lineRange == NO_LINE_RANGE) {
		return false;
	}

	std::ostringstream info;
	info << "Line range:    " << lineRange.first << " - "
		<< lineRange.second << "\n";
	out << comment(info.str());
	return true;
}

/**
* @brief Emits wrapper-related information for the given function (if
*        available).
*
* See the description of Module::getWrappedFuncName() for more details.
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitWrapperInfoForFuncIfAvailable(ShPtr<Function> func) {
	auto wrappedFunc = module->getWrappedFuncName(func);
	if (wrappedFunc.empty()) {
		return false;
	}

	out << comment("Wraps:         " + wrappedFunc + "\n");
	return true;
}

/**
* @brief Emits class-related information for the given function (if available).
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitClassInfoIfAvailable(ShPtr<Function> func) {
	auto className = module->getClassForFunc(func);
	if (className.empty()) {
		return false;
	}

	out << comment("From class:    " + getReadableClassName(className) + "\n");
	auto funcType = module->getTypeOfFuncInClass(func, className);
	if (!funcType.empty()) {
		out << comment("Type:          " + funcType + "\n");
	}
	return true;
}

/**
* @brief Emits demangled name of the given function (if available).
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitDemangledNameIfAvailable(ShPtr<Function> func) {
	auto demangledName = module->getDemangledNameOfFunc(func);
	if (demangledName.empty()) {
		return false;
	}

	out << comment("Demangled:     " + demangledName + "\n");
	return true;
}

/**
* @brief Emits a comment of the given function (if available).
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitCommentIfAvailable(ShPtr<Function> func) {
	auto funcComment = module->getCommentForFunc(func);
	if (funcComment.empty()) {
		return false;
	}

	// When there are no line breaks in the comment, we can emit it on a single
	// line:
	//
	//     // Comment: This is a single-line comment.
	//
	// Otherwise, emit the comment in a block:
	//
	//     // Comment:
	//     //     This is a
	//     //     multi-line
	//     //     comment.
	//
	// The reason is that our IDA plugin uses this format when the user updates
	// the comment, so we should be consistent.
	//
	// Config::getCommentForFunc() unified line breaks to LF (\n), so we can
	// use it as a separator.
	auto parts = split(funcComment, '\n', /*trimWhitespace=*/false);
	if (parts.size() == 1) {
		out << comment("Comment:       " + funcComment + "\n");
	} else {
		// A multi-line comment.
		out << comment("Comment:\n");
		for (const auto &part : parts) {
			// Our IDA plugin uses four spaces for indentation, so be
			// consistent.
			out << comment("    " + part + "\n");
		}
	}

	return true;
}

/**
* @brief Emits a list of detected cryptographic patterns for the given function
*        (if available).
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitDetectedCryptoPatternsForFuncIfAvailable(ShPtr<Function> func) {
	auto patterns = module->getDetectedCryptoPatternsForFunc(func);
	if (patterns.empty()) {
		return false;
	}

	std::ostringstream usedPatterns;
	usedPatterns << "Used cryptographic patterns:\n";
	for (auto &pattern : patterns) {
		usedPatterns << " - " << pattern << "\n";
	}
	out << comment(usedPatterns.str());
	return true;
}

/**
* @brief Emits a warning from LLVM IR fixing script (if any).
*
* If the function's body was fixed by the LLVM IR fixing script, put
* this information in to the generated code as a comment.
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitLLVMIRFixerWarningForFuncIfAny(ShPtr<Function> func) {
	if (!hasItem(namesOfFuncsWithFixedIR, func->getName())) {
		return false;
	}

	out << comment(
		"Warning: There were some errors during the decompilation of the following\n"
		"         function. Therefore, its body may be incomplete.\n");
	return true;
}

/**
* @brief Emits a section header comment.
*
* @param[in] sectionName Name of the section.
*
* The emitted comment is ended with a newline.
*/
void HLLWriter::emitSectionHeader(const std::string &sectionName) {
	// The section header is of the following form:
	//
	//     -------------------- Section Name ---------------------
	//
	// Compute the proper number of '-'s.
	auto nameLength = sectionName.size();
	auto separatorLength = (MAX_SECTION_HEADER_LENGTH - nameLength) / 2;
	auto leftSeparator = std::string(separatorLength, SECTION_COMMENT_SEP_CHAR);
	auto rightSeparator = leftSeparator;
	if (nameLength % 2 != 0) {
		// Compensation for an odd length of the section name.
		rightSeparator += SECTION_COMMENT_SEP_CHAR;
	}

	// Emit the comment.
	auto section = leftSeparator + " " + sectionName + " " + rightSeparator;
	out << getCurrentIndent() << comment(section) << "\n";
}

/**
* @brief Sort the given list of functions for emission.
*
* If there is line information from debug information available, the functions
* are sorted by their position in the original source code. If line information
* is not available but there are address ranges, they are sorted by them.
* Otherwise, the order is left untouched.
*/
void HLLWriter::sortFuncsForEmission(FuncVector &funcs) {
	if (module->allFuncDefinitionsHaveLineRange()) {
		std::sort(funcs.begin(), funcs.end(), LineInfoFuncComparator(module));
		return;
	}

	if (module->allFuncDefinitionsHaveAddressRange()) {
		std::sort(funcs.begin(), funcs.end(), AddressRangeFuncComparator(module));
		return;
	}
}

/**
* @brief Tries to emit a comment with the information about the given variable.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* If the emission of debug comments is disabled, this function does nothing and
* returns @c false;
*/
bool HLLWriter::tryEmitVarInfoInComment(ShPtr<Variable> var) {
	if (!optionEmitDebugComments) {
		return false;
	}

	// Both local and global variables can have an address.
	bool infoEmitted = tryEmitVarAddressInComment(var);
	if (infoEmitted) {
		return true;
	}

	if (module->isGlobalVar(var)) {
		// For global variables, emit the name of the register this global
		// variable represents (e.g. ebx). This is helpful because it shows
		// which global variable corresponds to which register.
		auto registerName = module->getRegisterForGlobalVar(var);
		if (!registerName.empty()) {
			out << " " << comment(registerName);
			return true;
		}
		return false;
	}

	auto globalVarName = module->comesFromGlobalVar(currFunc, var);
	if (!globalVarName.empty()) {
		// It is a local variable comming from a global variable. We want to
		// emit the global variable's name in a comment so we know from which
		// global variable this local variable comes from.
		out << " " << comment(globalVarName);
		return true;
	}

	// It is a local variable, which can have an offset (global variables
	// don't have offsets).
	infoEmitted = tryEmitVarOffsetInComment(var);
	if (infoEmitted) {
		return true;
	}

	return false;
}

/**
* @brief Tries to emit the address of the given variable into a comment.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool HLLWriter::tryEmitVarAddressInComment(ShPtr<Variable> var) {
	// The address or offset is stored in the initial name of the variable.
	std::string varAddress(getAddressFromName(var->getInitialName()));
	if (varAddress.empty()) {
		return false;
	}

	out << " " << comment(varAddress);
	return true;
}

/**
* @brief Tries to emit the offset of the given variable into a comment.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool HLLWriter::tryEmitVarOffsetInComment(ShPtr<Variable> var) {
	// The offset is stored in the initial name of the variable.
	std::string varOffset(getOffsetFromName(var->getInitialName()));
	if (varOffset.empty()) {
		return false;
	}

	out << " " << comment("bp" + varOffset);
	return true;
}

/**
* @brief Returns @c true if the given constant should be emitted in hexa, @c
*        false otherwise.
*
* @par Preconditions
*  - @a constant is non-null
*/
bool HLLWriter::shouldBeEmittedInHexa(ShPtr<ConstInt> constant) const {
	PRECONDITION_NON_NULL(constant);

	// Originally, we used
	//
	//    constant->isMoreReadableInHexa()
	//
	// However, we have decided to emit all numbers whose hexadecimal
	// representation is greater than 0xfff = 4095 (i.e. three hexa digits) in
	// hexa.
	std::size_t hexaSize(constant->toString(16).size());
	return hexaSize > (constant->isNegative() ? 4U : 3U);
}

/**
* @brief Checks whether the given @a array should be emitted in a structured
*        way.
*/
bool HLLWriter::shouldBeEmittedInStructuredWay(ShPtr<ConstArray> array) const {
	if (!emitConstantsInStructuredWay) {
		return false;
	}

	// Only arrays of more complex types should be emitted in a structured way.
	// That is, do not emit arrays of integers or floats in a structured way
	// because they look better when emitted inline.
	ShPtr<Type> containedType(array->getContainedType());
	if (isa<IntType>(containedType) || isa<FloatType>(containedType)) {
		return false;
	}

	return true;
}

/**
* @brief Checks whether the given @a structure should be emitted in a
*        structured way.
*/
bool HLLWriter::shouldBeEmittedInStructuredWay(ShPtr<ConstStruct> structure) const {
	return emitConstantsInStructuredWay;
}

/**
* @brief Returns the textual representation of a null pointer.
*
* By default, it returns @c "NULL".
*/
std::string HLLWriter::getConstNullPointerTextRepr() const {
	return "NULL";
}

/**
* @brief Returns the goto label for the given statement.
*/
std::string HLLWriter::getGotoLabel(ShPtr<Statement> stmt) {
	// By prefixing the raw label, we ensure that it is valid in C (labels
	// in C are required to start with either a letter on an underscore).
	auto rawLabel = getRawGotoLabel(stmt);
	return startsWith(rawLabel, "lab") ? rawLabel : "lab_" + rawLabel;
}

/**
* @brief Emits the detected compiler or packer (if any).
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitMetaInfoDetectedCompilerOrPacker() {
	auto compilerOrPacker = module->getDetectedCompilerOrPacker();
	if (compilerOrPacker.empty()) {
		return false;
	}

	out << comment("Detected compiler/packer: " + compilerOrPacker) << "\n";
	return true;
}

/**
* @brief Emits the detected language (if any).
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitMetaInfoDetectedLanguage() {
	std::string language(module->getDetectedLanguage());
	if (language.empty()) {
		return false;
	}

	out << comment("Detected language: " + language) << "\n";
	return true;
}

/**
* @brief Emits the number of detected functions.
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitMetaInfoNumberOfDetectedFuncs() {
	std::ostringstream funcCount;
	funcCount << "Detected functions: " << module->getNumOfFuncDefinitions();
	out << comment(funcCount.str()) << "\n";
	return true;
}

/**
* @brief Emits functions that were selected to be decompiled but were not
*        found (if any).
*/
bool HLLWriter::emitMetaInfoSelectedButNotFoundFuncs() {
	auto notFoundFuncs = module->getSelectedButNotFoundFuncs();
	if (notFoundFuncs.empty()) {
		return false;
	}

	out << comment(
		"Functions selected to be decompiled but not found: " +
		joinStrings(notFoundFuncs) +
		"\n"
	);
	return true;
}

/**
* @brief Emits the decompilation date.
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitMetaInfoDecompilationDate() {
	std::ostringstream decompDate;
	decompDate << "Decompilation date: " << getCurrentDate() <<
		" " << getCurrentTime() << "\n";
	out << comment(decompDate.str());
	return true;
}

/**
* @brief Emits functions that were removed due to decompilation errors (if
*        any).
*/
bool HLLWriter::emitMetaInfoFuncsRemovedDueErrors() {
	std::ostringstream funcsRemovedDueErrors;
	funcsRemovedDueErrors << "Functions removed due to errors: ";
	std::size_t numOfFuncsRemovedDueErrors = 0;
	for (auto &funcName : namesOfFuncsWithFixedIR) {
		// We include only functions which do not exist in the module. Existing
		// functions have attached a warning comment to their bodies.
		if (!module->getFuncByName(funcName)) {
			if (numOfFuncsRemovedDueErrors > 0) {
				funcsRemovedDueErrors << ", ";
			}
			funcsRemovedDueErrors << funcName;
			numOfFuncsRemovedDueErrors = true;
		}
	}
	funcsRemovedDueErrors << "\n";
	if (numOfFuncsRemovedDueErrors > 0) {
		out << comment(funcsRemovedDueErrors.str());
		return true;
	}
	return false;
}

/**
* @brief Emits the number of decompilation errors (if any).
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool HLLWriter::emitMetaInfoNumberOfDecompilationErrors() {
	if (namesOfFuncsWithFixedIR.empty()) {
		return false;
	}

	auto totalNumberOfFuncs = module->getNumberOfFuncsDetectedInFrontend();
	std::ostringstream numberOfDecompilationErrors;
	numberOfDecompilationErrors <<
		"Number of decompilation errors: " <<
		namesOfFuncsWithFixedIR.size() <<
		" (out of " << totalNumberOfFuncs << " function" <<
		(totalNumberOfFuncs != 1 ? "s" : "") <<
		")\n";
	out << comment(numberOfDecompilationErrors.str());
	return true;
}

/**
* @brief Returns a "raw" goto label for the given statement.
*
* "raw" means without any prefix.
*/
std::string HLLWriter::getRawGotoLabel(ShPtr<Statement> stmt) {
	if (stmt->hasLabel()) {
		return stmt->getLabel();
	}

	// If the statement has attached metadata of the form of a label in LLVM
	// IR, use this label. This string should be the original label of the
	// corresponding block in the input LLVM IR. This makes the emitted code
	// more readable.
	auto metadata = stmt->getMetadata();
	if (LLVMSupport::isBasicBlockLabel(metadata)) {
		return metadata;
	}

	// Fall-back.
	return "generated_" + toString(currFuncGotoLabelCounter++);
}

/**
* @brief Returns the most readable name of the given class.
*/
std::string HLLWriter::getReadableClassName(const std::string &cl) const {
	auto demangledName = module->getDemangledNameOfClass(cl);
	return !demangledName.empty() ? demangledName : cl;
}

/**
* @brief Returns the most readable names of the given classes.
*/
StringVector HLLWriter::getReadableClassNames(const StringVector &classes) const {
	StringVector readableNames;
	for (auto &cl : classes) {
		readableNames.push_back(getReadableClassName(cl));
	}
	return readableNames;
}

} // namespace llvmir2hll
} // namespace retdec
