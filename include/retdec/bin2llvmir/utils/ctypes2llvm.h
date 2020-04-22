/**
* @file include/retdec/bin2llvmir/utils/ctypes2llvm.h
* @brief Ctypes to LLVM IR converter.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES2LLVM_H
#define RETDEC_CTYPES2LLVM_H

#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace bin2llvmir {

class Ctypes2LlvmTypeVisitor: public retdec::ctypes::Visitor
{
public:
	Ctypes2LlvmTypeVisitor(llvm::Module* m, Config* c);
	virtual ~Ctypes2LlvmTypeVisitor() override = default;

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
		const std::shared_ptr<retdec::ctypes::NamedType>&) override;
	virtual void visit(
		const std::shared_ptr<retdec::ctypes::PointerType>&) override;
	virtual void visit(
		const std::shared_ptr<retdec::ctypes::ReferenceType>&) override;
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

}
}

#endif //RETDEC_CTYPES_TO_LLVM_H
