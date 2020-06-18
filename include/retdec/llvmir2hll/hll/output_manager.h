/**
* @file include/retdec/llvmir2hll/hll/output_manager.h
* @brief A base class of all output managers.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_OUTPUT_MANAGER_H
#define RETDEC_LLVMIR2HLL_HLL_OUTPUT_MANAGER_H

#include <string>

#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
 *
 */
class OutputManager
{
	// Ctors, dtros.
	public:
		virtual ~OutputManager();
		virtual void finalize();

	// Configuration methods.
	//
	public:
		void setCommentPrefix(const std::string& prefix);
		const std::string& getCommentPrefix() const;

		void setOutputLanguage(const std::string& lang);
		const std::string& getOutputLanguage() const;

	// Tokens.
	//
	public:
		// new line
		virtual void newLine() = 0;
		// any whitespace
		virtual void space(const std::string& space = " ") = 0;
		// e.g. (){}[];
		virtual void punctuation(char p) = 0;
		// e.g. == - + * -> .
		virtual void operatorX(const std::string& op) = 0;
		// identifiers
		virtual void globalVariableId(const std::string& id) = 0;
		virtual void localVariableId(const std::string& id) = 0;
		virtual void memberId(const std::string& id) = 0;
		virtual void labelId(const std::string& id) = 0;
		virtual void functionId(const std::string& id) = 0;
		virtual void parameterId(const std::string& id) = 0;
		// other
		virtual void keyword(const std::string& k) = 0;
		virtual void dataType(const std::string& t) = 0;
		virtual void preprocessor(const std::string& p) = 0;
		virtual void include(const std::string& i) = 0;
		// constants
		virtual void constantBool(const std::string& c) = 0;
		virtual void constantInt(const std::string& c) = 0;
		virtual void constantFloat(const std::string& c) = 0;
		virtual void constantString(const std::string& c) = 0;
		virtual void constantSymbol(const std::string& c) = 0;
		virtual void constantPointer(const std::string& c) = 0;
		// comment_prefix comment
		virtual void comment(
			const std::string& comment) = 0;

	// Special methods.
	//
	public:
		// Any token added to the end of the line is going to be a comment.
		virtual void commentModifier() = 0;

		/// Associates all subsequently added tokens with the passed address.
		/// Intended to be used in pair with \c addressPop().
		/// Every addressPush() must have a corresponding addressPop() that
		/// always gets executed (e.g. cannot be skipped because of early
		/// function return or similar).
		/// Together, these methods are designed to recursively encapsulate
		/// token blocks with the same address.
		virtual void addressPush(Address a) = 0;
		/// Associates all subsequently added tokens with address that was used
		/// before the last addressPush(addr).
		virtual void addressPop() = 0;

	// Helpers to create more complex token sequences.
	//
	public:
		// [space]op[space]
		virtual void operatorX(
			const std::string& op,
			bool spaceBefore,
			bool spaceAfter);
		// indent// comment
		virtual void comment(
			const std::string& comment,
			const std::string& indent);
		// [indent]// comment\n
		virtual void commentLine(
			const std::string& comment,
			const std::string& indent = "");
		// [indent]#include <include>[ // comment]
		virtual void includeLine(
			const std::string& header,
			const std::string& indent = "",
			const std::string& comment = "");
		// [indent]typedef t1 t2;
		virtual void typedefLine(
			const std::string& indent,
			const std::string& t1,
			const std::string& t2);

	// Data.
	//
	private:
		std::string _commentPrefix;
		std::string _outLanguage;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
