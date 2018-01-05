/**
 * @file include/retdec/bin2llvmir/providers/lti.h
 * @brief Library type information provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_LTI_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_LTI_H

#include <llvm/IR/Module.h>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/visitor.h"
#include "retdec/ctypesparser/json_ctypes_parser.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class ToLlvmTypeVisitor: public retdec::ctypes::Visitor
{
	public:
		ToLlvmTypeVisitor(llvm::Module* m, Config* c);
		virtual ~ToLlvmTypeVisitor() override;

		virtual void visit(
				const std::shared_ptr<retdec::ctypes::ArrayType>&) override;
		virtual void visit(
				const std::shared_ptr<retdec::ctypes::EnumType>&) override;
		virtual void visit(
				const std::shared_ptr<retdec::ctypes::FloatingPointType>&) override;
		virtual void visit(
				const std::shared_ptr<retdec::ctypes::FunctionType>&) override;
		virtual void visit(
				const std::shared_ptr<retdec::ctypes::IntegralType>&) override;
		virtual void visit(
				const std::shared_ptr<retdec::ctypes::PointerType>&) override;
		virtual void visit(
				const std::shared_ptr<retdec::ctypes::StructType>&) override;
		virtual void visit(
				const std::shared_ptr<retdec::ctypes::TypedefedType>&) override;
		virtual void visit(
				const std::shared_ptr<retdec::ctypes::UnionType>&) override;
		virtual void visit(
				const std::shared_ptr<retdec::ctypes::UnknownType>&) override;
		virtual void visit(
				const std::shared_ptr<retdec::ctypes::VoidType>&) override;

		llvm::Type* getLlvmType() const;

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		llvm::Type* _type = nullptr;
};

class Lti
{
	public:
		using FunctionPair = std::pair<
				llvm::Function*,
				std::shared_ptr<retdec::ctypes::Function>>;

	public:
		Lti(
				llvm::Module* m,
				Config* c,
				retdec::loader::Image* objf);

		bool hasLtiFunction(const std::string& name);
		std::shared_ptr<retdec::ctypes::Function> getLtiFunction(
				const std::string& name);
		llvm::FunctionType* getLlvmFunctionType(const std::string& name);
		FunctionPair getPairFunctionFree(const std::string& name);
		llvm::Function* getLlvmFunctionFree(const std::string& name);
		FunctionPair getPairFunction(const std::string& name);
		llvm::Function* getLlvmFunction(const std::string& name);

	private:
		void loadLtiFile(const std::string& filePath);
		llvm::Type* getLlvmType(std::shared_ptr<retdec::ctypes::Type> type);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		retdec::loader::Image* _image = nullptr;
		std::unique_ptr<retdec::ctypes::Module> _ltiModule;
		ctypesparser::JSONCTypesParser _ltiParser;
};

class LtiProvider
{
	public:
		static Lti* addLti(
				llvm::Module* m,
				Config* c,
				retdec::loader::Image* objf);
		static Lti* getLti(llvm::Module* m);
		static bool getLti(llvm::Module* m, Lti*& lti);
		static void clear();

	private:
		static std::map<llvm::Module*, Lti> _module2lti;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
