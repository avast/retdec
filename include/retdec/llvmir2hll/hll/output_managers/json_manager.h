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
        JsonOutputManager(llvm::raw_ostream& out);
        virtual ~JsonOutputManager();

    // JSON-output-manager-specific configuration.
    //
    public:
        void setHumanReadable(bool b);
        /// Manager is NOT set to produce human readable output by default.
        bool isHumanReadable() const;

    public:
        virtual void space(const std::string& space = " ") override;
        virtual void punctuation(char p) override;
        virtual void operatorX(
            const std::string& op,
            bool spaceBefore = false,
            bool spaceAfter = false) override;
        virtual void variableId(const std::string& id) override;
        virtual void memberId(const std::string& id) override;
        virtual void labelId(const std::string& id) override;
        virtual void functionId(const std::string& id) override;
        virtual void parameterId(const std::string& id) override;
        virtual void keyword(const std::string& k) override;
        virtual void dataType(const std::string& t) override;
        virtual void preprocessor(const std::string& p) override;
        virtual void include(const std::string& i) override;
        virtual void constantBool(const std::string& c) override;
        virtual void constantInt(const std::string& c) override;
        virtual void constantFloat(const std::string& c) override;
        virtual void constantString(const std::string& c) override;
        virtual void constantSymbol(const std::string& c) override;
        virtual void constantPointer(const std::string& c) override;
        virtual void comment(
            const std::string& comment,
            const std::string& indent = "");

    public:
        virtual void newLine(Address addr = Address::getUndef) override;

	public:
		virtual void commentModifier(const std::string& indent = "") override;

    public:
        struct JsonKeyPair
        {
            std::string defaultKey;
            std::string humanKey;
        };
    private:
        const std::string& getJsonKey(const JsonKeyPair& k) const;
        Json::Value jsonToken(const JsonKeyPair& k, const std::string& v) const;

    private:
        llvm::raw_ostream& _out;
        bool _humanReadable = false;
        Json::Value _lines;
        Json::Value _line;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
