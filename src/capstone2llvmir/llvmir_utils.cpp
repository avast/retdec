/**
 * @file src/capstone2llvmir/llvmir_utils.cpp
 * @brief LLVM IR utilities.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "capstone2llvmir/llvmir_utils.h"

namespace retdec {
namespace capstone2llvmir {

llvm::Value* generateValueNegate(llvm::IRBuilder<>& irb, llvm::Value* val)
{
	return irb.CreateXor(val, llvm::ConstantInt::getSigned(val->getType(), -1));
}

llvm::IntegerType* getIntegerTypeFromByteSize(llvm::Module* module, unsigned sz)
{
	auto& ctx = module->getContext();
	switch (sz)
	{
		case 1: return llvm::Type::getInt8Ty(ctx);
		case 2: return llvm::Type::getInt16Ty(ctx);
		case 4: return llvm::Type::getInt32Ty(ctx);
		case 6: return llvm::Type::getIntNTy(ctx, 48);
		case 8: return llvm::Type::getInt64Ty(ctx);
		default:
			assert(false);
			return llvm::Type::getInt32Ty(ctx);
	}
}

llvm::Type* getFloatTypeFromByteSize(llvm::Module* module, unsigned sz)
{
	auto& ctx = module->getContext();
	switch (sz)
	{
		case 2: return llvm::Type::getHalfTy(ctx);
		case 4: return llvm::Type::getFloatTy(ctx);
		case 8: return llvm::Type::getDoubleTy(ctx);
		case 10: return llvm::Type::getX86_FP80Ty(ctx);
		case 16: return llvm::Type::getFP128Ty(ctx);
		default:
			assert(false);
			return llvm::Type::getFloatTy(ctx);
	}
}

llvm::IRBuilder<> _generateIfThen(
		llvm::Value* cond,
		llvm::IRBuilder<>& irb,
		bool reverse)
{
	if (auto* ci = llvm::dyn_cast<llvm::ConstantInt>(cond))
	{
		if (ci->isZero())
		{
			if (reverse)
			{
				// llvm::BranchInst::Create(after, body, cond, ipBb->getTerminator());
				// cond == false -> never jump to after -> body always executed
				return irb;
			}
			else
			{
				// llvm::BranchInst::Create(body, after, cond, ipBb->getTerminator());
				// todo: cond == false -> never jump to body -> body never executed
			}
		}
		else
		{
			if (reverse)
			{
				// llvm::BranchInst::Create(after, body, cond, ipBb->getTerminator());
				// todo: cond == true -> always jump to after -> body never executed
			}
			else
			{
				// llvm::BranchInst::Create(body, after, cond, ipBb->getTerminator());
				// cond == true -> always jump to body -> body always executed
				return irb;
			}
		}
	}

	auto* ipBb = irb.GetInsertBlock();
	auto ipIt = irb.GetInsertPoint();
	assert(ipIt != ipBb->end());
	llvm::Instruction* ip = &(*ipIt);

	auto* body = ipBb->splitBasicBlock(ip);
	auto* after = body->splitBasicBlock(ip);

	if (reverse)
	{
		llvm::BranchInst::Create(after, body, cond, ipBb->getTerminator());
	}
	else
	{
		llvm::BranchInst::Create(body, after, cond, ipBb->getTerminator());
	}
	ipBb->getTerminator()->eraseFromParent();
	irb.SetInsertPoint(ip);

	return llvm::IRBuilder<>(body->getTerminator());
}

llvm::IRBuilder<> generateIfThen(
		llvm::Value* cond,
		llvm::IRBuilder<>& irb)
{
	return _generateIfThen(cond, irb, false);
}

llvm::IRBuilder<> generateIfNotThen(
		llvm::Value* cond,
		llvm::IRBuilder<>& irb)
{
	return _generateIfThen(cond, irb, true);
}

std::pair<llvm::IRBuilder<>, llvm::IRBuilder<>> generateIfThenElse(
		llvm::Value* cond,
		llvm::IRBuilder<>& irb)
{
	auto* ipBb = irb.GetInsertBlock();
	auto ipIt = irb.GetInsertPoint();
	assert(ipIt != ipBb->end());
	llvm::Instruction* ip = &(*ipIt);

	auto* bodyIf = ipBb->splitBasicBlock(ip);
	auto* bodyElse = bodyIf->splitBasicBlock(ip);
	auto* after = bodyElse->splitBasicBlock(ip);

	llvm::BranchInst::Create(bodyIf, bodyElse, cond, ipBb->getTerminator());
	ipBb->getTerminator()->eraseFromParent();

	llvm::BranchInst::Create(after, bodyIf->getTerminator());
	bodyIf->getTerminator()->eraseFromParent();

	irb.SetInsertPoint(ip);

	return std::make_pair(
			llvm::IRBuilder<>(bodyIf->getTerminator()),
			llvm::IRBuilder<>(bodyElse->getTerminator()));
}

std::pair<llvm::IRBuilder<>, llvm::IRBuilder<>> generateWhile(
		llvm::BranchInst*& branch,
		llvm::IRBuilder<>& irb)
{
	auto* ipBb = irb.GetInsertBlock();
	auto ipIt = irb.GetInsertPoint();
	assert(ipIt != ipBb->end());
	llvm::Instruction* ip = &(*ipIt);

	auto* before = ipBb->splitBasicBlock(ip);
	auto* body = before->splitBasicBlock(ip);
	auto* after = body->splitBasicBlock(ip);

	branch = llvm::BranchInst::Create(
			body,
			after,
			irb.getTrue(),
			before->getTerminator());
	before->getTerminator()->eraseFromParent();

	llvm::BranchInst::Create(before, body->getTerminator());
	body->getTerminator()->eraseFromParent();

	irb.SetInsertPoint(ip);

	return std::make_pair(
			llvm::IRBuilder<>(before->getTerminator()),
			llvm::IRBuilder<>(body->getTerminator()));
}

} // namespace capstone2llvmir
} // namespace retdec
