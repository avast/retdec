/**
* @file include/retdec/llvmir2hll/hll/output_managers/json_manager.h
* @brief A JSON output manager class.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_OUTPUT_MANAGERS_JSON_MANAGER_H
#define RETDEC_LLVMIR2HLL_HLL_OUTPUT_MANAGERS_JSON_MANAGER_H

#include <json/json.h>

#include <llvm/Support/raw_ostream.h>

#include "retdec/llvmir2hll/hll/output_manager.h"

namespace retdec {
namespace llvmir2hll {

class OutputManager;

class JsonOutputManager : public OutputManager
{
    public:
        JsonOutputManager(llvm::raw_ostream& out, bool humanReadable = false);
        virtual ~JsonOutputManager();

    // JSON-output-manager-specific configuration.
    //
    public:
        void setHumanReadable(bool b);
        /// Manager is NOT set to produce human readable output by default.
        bool isHumanReadable() const;

    public:
        virtual void newLine(Address a = Address::Undefined) override;
        virtual void space(const std::string& space = " ", Address a = Address::Undefined) override;
        virtual void punctuation(char p, Address a = Address::Undefined) override;
        virtual void operatorX(const std::string& op, Address a = Address::Undefined) override;
        virtual void variableId(const std::string& id, Address a = Address::Undefined) override;
        virtual void memberId(const std::string& id, Address a = Address::Undefined) override;
        virtual void labelId(const std::string& id, Address a = Address::Undefined) override;
        virtual void functionId(const std::string& id, Address a = Address::Undefined) override;
        virtual void parameterId(const std::string& id, Address a = Address::Undefined) override;
        virtual void keyword(const std::string& k, Address a = Address::Undefined) override;
        virtual void dataType(const std::string& t, Address a = Address::Undefined) override;
        virtual void preprocessor(const std::string& p, Address a = Address::Undefined) override;
        virtual void include(const std::string& i, Address a = Address::Undefined) override;
        virtual void constantBool(const std::string& c, Address a = Address::Undefined) override;
        virtual void constantInt(const std::string& c, Address a = Address::Undefined) override;
        virtual void constantFloat(const std::string& c, Address a = Address::Undefined) override;
        virtual void constantString(const std::string& c, Address a = Address::Undefined) override;
        virtual void constantSymbol(const std::string& c, Address a = Address::Undefined) override;
        virtual void constantPointer(const std::string& c, Address a = Address::Undefined) override;
        virtual void comment(const std::string& comment, Address a = Address::Undefined) override;

	public:
		virtual void commentModifier(Address a = Address::Undefined) override;

    private:
        Json::Value jsonToken(
            const std::string& k,
            const std::string& v,
            Address a = Address::Undefined) const;

    private:
        llvm::raw_ostream& _out;
        bool _humanReadable = true;
        Json::Value _tokens;
        /**
         * Used to implement commentModifier():
         *   1. commentModifier() sets _commentModifierOn flag to true.
         *   2. All token generators check if the flag is set.
         *   3. If it is not, they generate JSON token entry as usual.
         *   4. If it is, instead of generating JSON token entry,
         *      they serialize token value to string and concatenate it to
         *      _runningComment.
         *   5. Before generating newline token, the newline() token generator
         *      checks the flag and if it is set, it generates comment token
         *      from _runningComment and resets the flag and _runningComment.
         */
        bool _commentModifierOn = false;
        std::string _runningComment;
        Address _commentModifierAddr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
