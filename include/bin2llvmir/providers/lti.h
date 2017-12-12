/**
 * @file include/bin2llvmir/providers/lti.h
 * @brief Library type information provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_PROVIDERS_LTI_H
#define BIN2LLVMIR_PROVIDERS_LTI_H

#include <llvm/IR/Module.h>

#include "ctypes/context.h"
#include "ctypes/module.h"
#include "ctypes/type.h"
#include "ctypes/visitor.h"
#include "ctypesparser/json_ctypes_parser.h"
#include "bin2llvmir/providers/config.h"
#include "bin2llvmir/providers/fileimage.h"

namespace bin2llvmir {

class ToLlvmTypeVisitor: public ctypes::Visitor
{
	public:
		ToLlvmTypeVisitor(llvm::Module* m, Config* c);
		virtual ~ToLlvmTypeVisitor() override;

		virtual void visit(
				const std::shared_ptr<ctypes::ArrayType>&) override;
		virtual void visit(
				const std::shared_ptr<ctypes::EnumType>&) override;
		virtual void visit(
				const std::shared_ptr<ctypes::FloatingPointType>&) override;
		virtual void visit(
				const std::shared_ptr<ctypes::FunctionType>&) override;
		virtual void visit(
				const std::shared_ptr<ctypes::IntegralType>&) override;
		virtual void visit(
				const std::shared_ptr<ctypes::PointerType>&) override;
		virtual void visit(
				const std::shared_ptr<ctypes::StructType>&) override;
		virtual void visit(
				const std::shared_ptr<ctypes::TypedefedType>&) override;
		virtual void visit(
				const std::shared_ptr<ctypes::UnionType>&) override;
		virtual void visit(
				const std::shared_ptr<ctypes::UnknownType>&) override;
		virtual void visit(
				const std::shared_ptr<ctypes::VoidType>&) override;

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
				std::shared_ptr<ctypes::Function>>;

	public:
		Lti(
				llvm::Module* m,
				Config* c,
				loader::Image* objf);

		bool hasLtiFunction(const std::string& name);
		std::shared_ptr<ctypes::Function> getLtiFunction(
				const std::string& name);
		llvm::FunctionType* getLlvmFunctionType(const std::string& name);
		FunctionPair getPairFunctionFree(const std::string& name);
		llvm::Function* getLlvmFunctionFree(const std::string& name);
		FunctionPair getPairFunction(const std::string& name);
		llvm::Function* getLlvmFunction(const std::string& name);

	private:
		void loadLtiFile(const std::string& filePath);
		llvm::Type* getLlvmType(std::shared_ptr<ctypes::Type> type);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		loader::Image* _image = nullptr;
		std::unique_ptr<ctypes::Module> _ltiModule;
		ctypesparser::JSONCTypesParser _ltiParser;
};

class LtiProvider
{
	public:
		static Lti* addLti(
				llvm::Module* m,
				Config* c,
				loader::Image* objf);
		static Lti* getLti(llvm::Module* m);
		static bool getLti(llvm::Module* m, Lti*& lti);
		static void clear();

	private:
		static std::map<llvm::Module*, Lti> _module2lti;
};

} // namespace bin2llvmir

#endif
