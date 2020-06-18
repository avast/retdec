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

	public:
		virtual void newLine() override;
		virtual void space(const std::string& space = " ") override;
		virtual void punctuation(char p) override;
		virtual void operatorX(const std::string& op) override;
		virtual void globalVariableId(const std::string& id) override;
		virtual void localVariableId(const std::string& id) override;
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
		virtual void comment(const std::string& comment) override;

	public:
		virtual void commentModifier() override;
		virtual void addressPush(Address a) override;
		virtual void addressPop() override;

	private:
		llvm::raw_ostream& _out;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
