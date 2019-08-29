/**
* @file include/retdec/llvmir2hll/hll/output_managers/plain_manager.h
* @brief A plain output manager class.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_OUTPUT_MANAGERS_PLAIN_MANAGER_H
#define RETDEC_LLVMIR2HLL_HLL_OUTPUT_MANAGERS_PLAIN_MANAGER_H

#include <llvm/Support/raw_ostream.h>

#include "retdec/llvmir2hll/hll/output_manager.h"

namespace retdec {
namespace llvmir2hll {

class PlainOutputManager : public OutputManager
{
    public:
        PlainOutputManager(llvm::raw_ostream& out);
        virtual ~PlainOutputManager();

    public:
        virtual void newLine(Address = Address::Undefined) override;
        virtual void space(const std::string& space = " ", Address = Address::Undefined) override;
        virtual void punctuation(char p, Address = Address::Undefined) override;
        virtual void operatorX(const std::string& op, Address = Address::Undefined) override;
        virtual void variableId(const std::string& id, Address = Address::Undefined) override;
        virtual void memberId(const std::string& id, Address = Address::Undefined) override;
        virtual void labelId(const std::string& id, Address = Address::Undefined) override;
        virtual void functionId(const std::string& id, Address = Address::Undefined) override;
        virtual void parameterId(const std::string& id, Address = Address::Undefined) override;
        virtual void keyword(const std::string& k, Address = Address::Undefined) override;
        virtual void dataType(const std::string& t, Address = Address::Undefined) override;
        virtual void preprocessor(const std::string& p, Address = Address::Undefined) override;
        virtual void include(const std::string& i, Address = Address::Undefined) override;
        virtual void constantBool(const std::string& c, Address = Address::Undefined) override;
        virtual void constantInt(const std::string& c, Address = Address::Undefined) override;
        virtual void constantFloat(const std::string& c, Address = Address::Undefined) override;
        virtual void constantString(const std::string& c, Address = Address::Undefined) override;
        virtual void constantSymbol(const std::string& c, Address = Address::Undefined) override;
        virtual void constantPointer(const std::string& c, Address = Address::Undefined) override;
        virtual void comment(const std::string& comment, Address = Address::Undefined) override;

	public:
		virtual void commentModifier(Address = Address::Undefined) override;

    private:
        llvm::raw_ostream& _out;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
