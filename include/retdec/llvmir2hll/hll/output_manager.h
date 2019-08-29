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
        virtual void newLine(Address a = Address::Undefined) = 0;
        // any whitespace
        virtual void space(const std::string& space = " ", Address a = Address::Undefined) = 0;
        // e.g. (){}[];
        virtual void punctuation(char p, Address a = Address::Undefined) = 0;
        // e.g. == - + * -> .
        virtual void operatorX(const std::string& op, Address a = Address::Undefined) = 0;
        // identifiers
        virtual void variableId(const std::string& id, Address a = Address::Undefined) = 0;
        virtual void memberId(const std::string& id, Address a = Address::Undefined) = 0;
        virtual void labelId(const std::string& id, Address a = Address::Undefined) = 0;
        virtual void functionId(const std::string& id, Address a = Address::Undefined) = 0;
        virtual void parameterId(const std::string& id, Address a = Address::Undefined) = 0;
        // other
        virtual void keyword(const std::string& k, Address a = Address::Undefined) = 0;
        virtual void dataType(const std::string& t, Address a = Address::Undefined) = 0;
        virtual void preprocessor(const std::string& p, Address a = Address::Undefined) = 0;
        virtual void include(const std::string& i, Address a = Address::Undefined) = 0;
        // constants
        virtual void constantBool(const std::string& c, Address a = Address::Undefined) = 0;
        virtual void constantInt(const std::string& c, Address a = Address::Undefined) = 0;
        virtual void constantFloat(const std::string& c, Address a = Address::Undefined) = 0;
        virtual void constantString(const std::string& c, Address a = Address::Undefined) = 0;
        virtual void constantSymbol(const std::string& c, Address a = Address::Undefined) = 0;
        virtual void constantPointer(const std::string& c, Address a = Address::Undefined) = 0;
        // comment_prefix comment
        virtual void comment(
            const std::string& comment, Address a = Address::Undefined) = 0;

    // Special methods.
    //
	public:
		// Any token added to the end of the line is going to be a comment.
		virtual void commentModifier(Address a = Address::Undefined) = 0;
        // Modifies address for all subsequent tokens.
        virtual void addressModifier(Address a) = 0;

    // Helpers to create more complex token sequences.
    //
    public:
        // [space]op[space]
        virtual void operatorX(
            const std::string& op,
            bool spaceBefore,
            bool spaceAfter,
            Address addr = Address::Undefined);
        // indent// comment
        virtual void comment(
            const std::string& comment,
            const std::string& indent,
            Address addr = Address::Undefined);
        // [indent]// comment\n
        virtual void commentLine(
			const std::string& comment,
			const std::string& indent = "",
			Address addr = Address::Undefined);
		// [indent]#include <include>[ // comment]
		virtual void includeLine(
			const std::string& header,
			const std::string& indent = "",
			const std::string& comment = "",
            Address addr = Address::Undefined);
		// [indent]typedef t1 t2;
		virtual void typedefLine(
			const std::string& indent,
			const std::string& t1,
			const std::string& t2,
            Address addr = Address::Undefined);

    // Data.
    //
    private:
        std::string _commentPrefix;
        std::string _outLanguage;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
