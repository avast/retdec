/**
* @file include/retdec/llvmir2hll/hll/hll_writer.h
* @brief A base class of all HLL writers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_HLL_WRITER_H
#define RETDEC_LLVMIR2HLL_HLL_HLL_WRITER_H

#include <cstddef>
#include <string>

#include <llvm/Support/raw_ostream.h>

#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitor.h"
#include "retdec/utils/non_copyable.h"
#include "retdec/utils/string.h"

namespace retdec {
namespace llvmir2hll {

class BinaryOpExpr;
class BracketManager;
class UnaryOpExpr;

//==============================================================================

class MyOut
{
	// Ctors, dtors, configuration methods.
	//
	public:
		MyOut(llvm::raw_ostream& out) : _out(out) {}
		void setCommentPrefix(const std::string& prefix)
		{
			_commentPrefix = prefix;
		}

	// Tokens.
	//
	public:
		// any whitespace
		void space(const std::string& space = " ") { _out << space; }
		// (){}[];
		void punctiation(char p) { _out << p; }
		// == - + * -> .
		void operatorX(const std::string& op, bool spaceBefore = false, bool spaceAfter = false)
		{
			if (spaceBefore) space();
			_out << op;
			if (spaceAfter) space();
		}
		// identifiers
		void variableId(const std::string& id) { _out << id; }
		void memberId(const std::string& id) { _out << id; }
		void labelId(const std::string& id) { _out << id; }
		void functionId(const std::string& id) { _out << id; }
		void parameterId(const std::string& id) { _out << id; }
		//
		void keyword(const std::string& k) { _out << k; }
		void dataType(const std::string& t) { _out << t; }
		void preprocessor(const std::string& p){ _out << p; }
		void include(const std::string& i){ _out << "<" << i << ">"; }
		// constants
		void constantBool(const std::string& c) { _out << c; }
		void constantInt(const std::string& c) { _out << c; }
		void constantFloat(const std::string& c) { _out << c; }
		void constantString(const std::string& c) { _out << c; }
		void constantSymbol(const std::string& s) { _out << s; }
		void constantPointer(const std::string& s) { _out << s; }
		// Adds comment to and existing line, does not end it.
		void comment(
			const std::string& comment,
			const std::string& indent = "")
		{
			_out << indent << _commentPrefix << " "
				<< utils::replaceCharsWithStrings(comment, '\n', " ");
		}

	// Line manipulation methods.
	//
	public:
		// 1) Ends the current line.
		// 2) Starts a new empty line that can be filled.
		void newLine(uint64_t addr = 0)
		{
			_out << "\n";
		}
		// 1) Ends the current line.
		// 2) Inserts a new empty line.
		// 3) Starts a new empty line that can be filled.
		void emptyLine(uint64_t addr = 0)
		{
			_out << "\n";
		}
		// Creates a new line.
		void commentLine(
			const std::string& comment,
			const std::string& indent = "",
			uint64_t addr = 0)
		{
			MyOut::comment(comment);
			newLine();
		}

	// Helpers to create more complex lines.
	public:
		// [indent]#include <include>[ // comment]
		void includeLine(
			const std::string& header,
			const std::string& indent = "",
			const std::string& comment = "")
		{
			space(indent);
			preprocessor("#include");
			space();
			include(header);
			if (!comment.empty()) MyOut::comment(comment, " ");
			newLine();
		}
		// [indent]typedef t1 t2;
		void typedefLine(
			const std::string& indent,
			const std::string& t1,
			const std::string& t2)
		{
			space(indent);
			keyword("typedef");
			space();
			dataType(t1);
			space();
			dataType(t2);
			punctiation(';');
			newLine();
		}

	// Special methods.
	public:
		// Any token added to the end of the line is going to be a
		// string comment.
		void commentModifier(const std::string& indent = "")
		{
			_out << indent << "// ";
		}

	private:
		llvm::raw_ostream& _out;
		std::string _commentPrefix;
};

//==============================================================================

/**
* @brief A base class of all HLL writers.
*
* Every HLL writer should subclass this class and override at least the needed
* protected emit*() functions. If the writer needs to do some more magic, like
* changing the order in which the blocks are emitted, then override
* emitTargetCode().
*
* Instances of this class have reference object semantics.
*/
class HLLWriter: public Visitor, private retdec::utils::NonCopyable {
public:
	virtual ~HLLWriter() override;

	/**
	* @brief Returns the ID of the writer.
	*/
	virtual std::string getId() const = 0;

	virtual bool emitTargetCode(ShPtr<Module> module);

	/// @name Options
	/// @{
	void setOptionEmitDebugComments(bool emit = true);
	void setOptionKeepAllBrackets(bool keep = true);
	void setOptionEmitTimeVaryingInfo(bool emit = true);
	void setOptionUseCompoundOperators(bool use = true);
	/// @}

protected:
	HLLWriter(llvm::raw_ostream &out);

	/// @name Commenting
	/// @{
	/**
	* @brief Returns the prefix of comments in the given language.
	*
	* For example, in C, it should return @c "//".
	*/
	virtual std::string getCommentPrefix() = 0;
	/// @}

	/// @name Indentation
	/// @{
	void increaseIndentLevel();
	void decreaseIndentLevel();
	std::string getCurrentIndent() const;
	std::string getSingleLevelIndent() const;
	std::string getIndentForGotoLabel() const;
	/// @}

	/// @name Emission
	/// @{
	virtual bool emitFileHeader();
	virtual bool emitFileFooter();

	virtual bool emitGlobalVariablesHeader();
	virtual bool emitGlobalVariables();
	virtual bool emitGlobalVariable(ShPtr<GlobalVarDef> varDef);
	virtual bool emitGlobalVariablesFooter();

	virtual bool emitClassesHeader();
	virtual bool emitClasses();
	virtual bool emitClass(const std::string &className);
	virtual bool emitClassesFooter();

	virtual bool emitFunctionPrototypesHeader();
	virtual bool emitFunctionPrototypes();
	virtual bool emitFunctionPrototypesFooter();

	virtual bool emitFunctionsHeader();
	virtual bool emitFunctions();
	virtual bool emitFunction(ShPtr<Function> func);
	virtual bool emitFunctionsFooter();

	virtual bool emitStaticallyLinkedFunctionsHeader();
	virtual bool emitStaticallyLinkedFunctions();
	virtual bool emitStaticallyLinkedFunctionsFooter();

	virtual bool emitDynamicallyLinkedFunctionsHeader();
	virtual bool emitDynamicallyLinkedFunctions();
	virtual bool emitDynamicallyLinkedFunctionsFooter();

	virtual bool emitSyscallFunctionsHeader();
	virtual bool emitSyscallFunctions();
	virtual bool emitSyscallFunctionsFooter();

	virtual bool emitInstructionIdiomFunctionsHeader();
	virtual bool emitInstructionIdiomFunctions();
	virtual bool emitInstructionIdiomFunctionsFooter();

	virtual bool emitExternalFunctions(const FuncSet &funcs);
	virtual bool emitExternalFunction(ShPtr<Function> func);

	virtual bool emitMetaInfoHeader();
	virtual bool emitMetaInfo();
	virtual bool emitMetaInfoFooter();

	virtual void emitExprWithBracketsIfNeeded(ShPtr<Expression> expr);
	void emitUnaryOpExpr(const std::string &opRepr, ShPtr<UnaryOpExpr> expr);
	void emitBinaryOpExpr(const std::string &opRepr, ShPtr<BinaryOpExpr> expr,
			bool spaceBefore = true, bool spaceAfter = true);

	bool emitDetectedCryptoPatternForGlobalVarIfAvailable(ShPtr<Variable> var);
	bool emitModuleNameForFuncIfAvailable(ShPtr<Function> func);
	bool emitAddressRangeForFuncIfAvailable(ShPtr<Function> func);
	bool emitLineRangeForFuncIfAvailable(ShPtr<Function> func);
	bool emitWrapperInfoForFuncIfAvailable(ShPtr<Function> func);
	bool emitClassInfoIfAvailable(ShPtr<Function> func);
	bool emitDemangledNameIfAvailable(ShPtr<Function> func);
	bool emitCommentIfAvailable(ShPtr<Function> func);
	bool emitDetectedCryptoPatternsForFuncIfAvailable(ShPtr<Function> func);
	bool emitLLVMIRFixerWarningForFuncIfAny(ShPtr<Function> func);

	void emitSectionHeader(const std::string &sectionName);

	/**
	* @brief Emits the given sequence @a seq by calling @c accept on every value.
	*        Separator = ','
	*
	* @param[in] seq     Sequence of values to be emitted.
	* @param[in] space   Space to insert after separator.
	* @param[in] newline If @c true, newline is inserted after separator and
	*                    before space.
	*
	* @tparam ContainerType Container of Visitable values.
	*/
	template<class ContainerType>
	void emitSequenceWithAccept(const ContainerType &seq,
			const std::string& space = " ",	bool newline = false) {
		bool first = true;
		for (const auto &item : seq) {
			if (!first) {
				out.operatorX(",");
				if (newline) out.newLine();
				out.space(space);
			}
			item->accept(this);
			first = false;
		}
	}
	/// @}

	/// @name Representations
	/// @{
	virtual std::string getConstNullPointerTextRepr() const;
	/// @}

	void sortFuncsForEmission(FuncVector &funcs);
	bool tryEmitVarInfoInComment(ShPtr<Variable> var);
	bool tryEmitVarAddressInComment(ShPtr<Variable> var);
	bool tryEmitVarOffsetInComment(ShPtr<Variable> var);
	bool shouldBeEmittedInHexa(ShPtr<ConstInt> constant) const;
	bool shouldBeEmittedInStructuredWay(ShPtr<ConstArray> array) const;
	bool shouldBeEmittedInStructuredWay(ShPtr<ConstStruct> structure) const;

	std::string getGotoLabel(ShPtr<Statement> stmt);

protected:
	/// The module to be written.
	ShPtr<Module> module;

	/// Stream, where the resulting code will be generated.
	MyOut out;

	/// Recognizes which brackets around expressions are needed.
	ShPtr<BracketManager> bracketsManager;

	/// Should we emit constants in a structured way?
	/// This variable is used to structure large initializations so that they
	/// are properly generated over multiple lines, not on a single line.
	bool emitConstantsInStructuredWay;

	/// Emit also debug comments?
	bool optionEmitDebugComments;

	/// Keep all (even redundant) brackets?
	bool optionKeepAllBrackets;

	/// Emit time-varying information, like dates?
	bool optionEmitTimeVaryingInfo; // TODO: default = TRUE, fix hacks

	/// Use compound operators (like @c +=) instead of assignments?
	bool optionUseCompoundOperators;

	/// Names of functions that were fixed by the LLVM IR fixing script.
	StringSet namesOfFuncsWithFixedIR;

	/// The currently emitted function definition (if any).
	ShPtr<Function> currFunc;

	/// Counter for goto labels for the current function.
	std::size_t currFuncGotoLabelCounter;

private:
	/// @name Emission of Meta-Information
	/// @{
	bool emitMetaInfoDetectedCompilerOrPacker();
	bool emitMetaInfoDetectedLanguage();
	bool emitMetaInfoNumberOfDetectedFuncs();
	bool emitMetaInfoSelectedButNotFoundFuncs();
	bool emitMetaInfoDecompilationDate();
	bool emitMetaInfoFuncsRemovedDueErrors();
	bool emitMetaInfoNumberOfDecompilationErrors();
	/// @}

	std::string getRawGotoLabel(ShPtr<Statement> stmt);
	std::string getReadableClassName(const std::string &cl) const;
	StringVector getReadableClassNames(const StringVector &classes) const;

private:
	/// Spaces to indent the current block.
	std::string currentIndent;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
