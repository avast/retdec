/**
 * @file src/bin2llvmir/utils/instruction.cpp
 * @brief LLVM instruction utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/utils/container.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/instruction.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace retdec::llvm_support;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/**
 * @return Parent functions for @a user if it exists, @c nullptr otherwise.
 */
std::set<llvm::Function*> getParentFuncsFor(llvm::User* user)
{
	std::set<llvm::Function*> ret;

	if (auto* i = dyn_cast_or_null<Instruction>(user))
	{
		ret.insert(i->getFunction());
	}
	else if (auto* e = dyn_cast_or_null<ConstantExpr>(user))
	{
		for (auto* u : e->users())
		{
			auto r = getParentFuncsFor(u);
			ret.insert(r.begin(), r.end());
		}
	}

	return ret;
}

/**
 * @return @c True if @a inst calls function directly, @c false otherwise.
 */
bool isDirectCall(const llvm::CallInst& inst)
{
	return inst.getCalledFunction() != nullptr;
}

/**
 * @return @c True if @a inst calls function directly, @c false otherwise.
 */
bool isDirectCall(const llvm::CallInst* inst)
{
	return inst ? isDirectCall(*inst) : false;
}

/**
 * @return @c True if @a inst calls function indirectly, @c false otherwise.
 */
bool isIndirectCall(const llvm::CallInst& inst)
{
	return inst.getCalledFunction() == nullptr;
}
/**
 * @return @c True if @a inst calls function indirectly, @c false otherwise.
 */
bool isIndirectCall(const llvm::CallInst* inst)
{
	return inst ? isIndirectCall(*inst) : false;
}

/**
 * @return @c True if @a inst calls declared function directly,
 *         @c false otherwise.
 */
bool isFncDeclarationCall(const llvm::CallInst& inst)
{
	return isDirectCall(inst) && inst.getCalledFunction()->isDeclaration();
}

/**
 * @return @c True if @a inst calls declared function directly,
 *         @c false otherwise.
 */
bool isFncDeclarationCall(const llvm::CallInst* inst)
{
	return inst ? isFncDeclarationCall(*inst) : false;
}

/**
 * @return @c True if @a inst calls defined function directly,
 *         @c false otherwise.
 */
bool isFncDefinitionCall(const llvm::CallInst& inst)
{
	return isDirectCall(inst) && !inst.getCalledFunction()->isDeclaration();
}

/**
 * @return @c True if @a inst calls defined function directly,
 *         @c false otherwise.
 */
bool isFncDefinitionCall(const llvm::CallInst* inst)
{
	return inst ? isFncDefinitionCall(*inst) : false;
}

/**
 * @return @c True if @a def was localized using the @a RDA results and @c type
 *         data type.
 */
bool localizeDefinition(
		const ReachingDefinitionsAnalysis& RDA,
		const llvm::Instruction* def,
		llvm::Type* type)
{
	return localizeDefinition(RDA.getDef(def), type);
}

/**
 * @return @c True if @a def was localized using @c type data type.
 */
bool localizeDefinition(
		const Definition* def,
		llvm::Type* type)
{
	if (def == nullptr || def->uses.empty())
	{
		return false;
	}

	StoreInst* s = dyn_cast<StoreInst>(def->def);
	if (s == nullptr)
	{
		assert("only stores are expected");
		return false;
	}
	auto* val = s->getPointerOperand();

	for (auto* u : def->uses)
	{
		if (u->defs.size() > 1)
		{
			return false;
		}
	}

	auto* fnc = def->def->getFunction();
	auto* fncFirst = &(fnc->getEntryBlock().getInstList().front());
	auto* t = type ? type : val->getType()->getPointerElementType();
	auto* localVar = new AllocaInst(
			t,
			"",
			fncFirst);
	auto* c1 = convertValueToType(s->getValueOperand(), t, s);
	new StoreInst(
			c1,
			localVar,
			s);

	for (auto* us : def->uses)
	{
		auto* u = us->use;
		auto* c2 = convertValueToType(localVar, val->getType(), u);
		u->replaceUsesOfWith(val, c2);
	}

	return true;
}

/**
 * Modify return instruction @c ret to return @c val value.
 * @c val value is casted to parent function's return type. If you want to
 * avoid casts, make sure parent function's type is modified before this
 * function is called.
 *
 * At the moment, this will create a new return instruction which replaces the
 * old one. The new return is returned as return value. The old call is
 * destroyed. Therefore, users must be careful not to store pointers to it.
 * Maybe, it would be possible to modify return operands inplace
 * as implemented in @c PHINode::growOperands(). However, this looks very
 * hackish and dangerous.
 */
llvm::ReturnInst* modifyReturnInst(llvm::ReturnInst* ret, llvm::Value* val)
{
	auto* f = ret->getFunction();
	assert(f);
	auto* cast = convertValueToType(val, f->getReturnType(), ret);
	auto* nret = ReturnInst::Create(ret->getContext(), cast, ret);
	auto* rv = dyn_cast_or_null<Instruction>(ret->getReturnValue());
	ret->eraseFromParent();
	if (rv && rv->user_empty())
	{
		rv->eraseFromParent();
	}
	return nret;
}

/**
 * Modify @a call instruction to call @a calledVal value with @a args arguments.
 *
 * At the moment, this will create a new call instruction which replaces the old
 * one. The new call is returned as return value. The old call is destroyed.
 * Therefore, users must be careful not to store pointers to it.
 * Maybe, it would be possible to modify call operands (arguments) inplace
 * as implemented in @c PHINode::growOperands(). However, this looks very
 * hackish and dangerous.
 */
llvm::CallInst* _modifyCallInst(
		llvm::CallInst* call,
		llvm::Value* calledVal,
		llvm::ArrayRef<llvm::Value*> args)
{
	std::set<Instruction*> toEraseCast;
	auto* newCall = CallInst::Create(calledVal, args, "", call);
	if (call->getNumUses())
	{
		if (!newCall->getType()->isVoidTy())
		{
			auto* cast = convertValueToType(newCall, call->getType(), call);
			call->replaceAllUsesWith(cast);
		}
		else
		{
			std::set<StoreInst*> toErase;

			for (auto* u : call->users())
			{
				if (auto* s = dyn_cast<StoreInst>(u))
				{
					toErase.insert(s);
				}
				// TODO: solve better.
				else if (auto* c = dyn_cast<CastInst>(u))
				{
					assert(c->getNumUses() == 1);
					auto* s = dyn_cast<StoreInst>(*c->users().begin());
					assert(s);
					toErase.insert(s);
					toEraseCast.insert(c);
				}
				else
				{
					assert(false);
				}
			}

			for (auto* i : toErase)
			{
				// TODO: erasing here is dangerous. Call result stores may be
				// used somewhere else -- e.g. entries in param_return analysis.
				//
//				i->eraseFromParent();
				auto* conf = ConfigProvider::getConfig(call->getModule());
				auto* c = convertValueToType(
						conf->getGlobalDummy(),
						i->getValueOperand()->getType(),
						i);
				i->replaceUsesOfWith(i->getValueOperand(), c);
			}
		}
	}
	for (auto* i : toEraseCast)
	{
		i->eraseFromParent();
	}
	call->eraseFromParent();
	return newCall;
}

/**
 * Modify call instruction:
 *   - Old called value is casted to new function pointer type derived from
 *     return value and arguments. This is done even if called value is
 *     function. If you want to avoid casts, make sure called function's type is
 *     modified before this function is called and that arguments passed in
 *     @c args have same types as called function -- they will not be casted,
 *     if they differ, function is casted to function pointer derived from them.
 *   - New function pointer type value is used to modify call instruction.
 * Notes:
 *   - If @a ret is nullptr, call's return value is left unchanged.
 *     Pass @c void type in @c ret if you want the call to return no value.
 *   - If @a args is empty, call will have zero arguments.
 * @return New call instruction which replaced the old @c call.
 *         See @c _modifyCallInst() comment for details.
 */
llvm::CallInst* modifyCallInst(
		llvm::CallInst* call,
		llvm::Type* ret,
		llvm::ArrayRef<llvm::Value*> args)
{
	ret = ret ? ret : call->getType();
	std::vector<llvm::Type*> argTypes;
	for (auto* v : args)
	{
		argTypes.push_back(v->getType());
	}
	auto* t = llvm::PointerType::get(
			llvm::FunctionType::get(
					ret,
					argTypes,
					false), // isVarArg
			0);
	auto* conv = convertValueToType(call->getCalledValue(), t, call);

	return _modifyCallInst(call, conv, args);
}

/**
 * Modify only call instruction's return type. Arguments are left unchanged.
 */
llvm::CallInst* modifyCallInst(
		llvm::CallInst* call,
		llvm::Type* ret)
{
	std::vector<llvm::Value*> args(call->arg_operands().begin(), call->arg_operands().end());
	return modifyCallInst(call, ret, args);
}

/**
 * Modify only call instruction's arguments. Return type is left unchanged.
 */
llvm::CallInst* modifyCallInst(
		llvm::CallInst* call,
		llvm::ArrayRef<llvm::Value*> args)
{
	return modifyCallInst(call, nullptr, args);
}

/**
 * Add arguments @a args to variadic function call @a call.
 * @return New call instruction which replaced the old @c call.
 */
llvm::CallInst* addToVariadicCallInst(
		llvm::CallInst* call,
		llvm::ArrayRef<llvm::Value*> args)
{
	std::vector<llvm::Value*> as;
	as.reserve(call->getNumArgOperands() + args.size());
	as.insert( as.end(), call->arg_operands().begin(), call->arg_operands().end() );
	as.insert( as.end(), args.begin(), args.end() );

	return _modifyCallInst(call, call->getCalledFunction(), as);
}

void _modifyFunctionArguments(
		llvm::Function* fnc,
		llvm::ArrayRef<llvm::Type*> args)
{
	for (auto* a : args)
	{
		new llvm::Argument(a, "", fnc);
	}
}

/**
 * Inspired by ArgPromotion::DoPromotion().
 * Steps performed in ArgPromotion::DoPromotion() that are not done here:
 *   - Patch the pointer to LLVM function in debug info descriptor.
 *   - Some attribute magic.
 *   - Update alias analysis.
 *   - Update call graph info.
 * @return New function that replaced the old one. Function type cannot be
 * changed in situ -> we create an entirely new function with the desired type.
 */
FunctionPair modifyFunction(
		Config* config,
		llvm::Function* fnc,
		llvm::Type* ret,
		std::vector<llvm::Type*> args,
		bool isVarArg,
		const std::map<llvm::ReturnInst*, llvm::Value*>& rets2vals,
		const std::map<llvm::CallInst*, std::vector<llvm::Value*>>& calls2vals,
		llvm::Value* retVal,
		const std::vector<llvm::Value*>& argStores,
		const std::vector<std::string>& argNames)
{
	auto* cf = config->getConfigFunction(fnc);

	if (!FunctionType::isValidReturnType(ret))
	{
		ret = getDefaultType(fnc->getParent());
	}
	for (Type*& t : args)
	{
		if (!FunctionType::isValidArgumentType(t))
		{
			t = getDefaultType(fnc->getParent());
		}
	}

	// New function type.
	//
	ret = ret ? ret : fnc->getReturnType();
	llvm::FunctionType* newFncType = llvm::FunctionType::get(
			ret,
			args,
			isVarArg);

	// New function.
	//
	Function *nf = nullptr;
	if (newFncType == fnc->getFunctionType())
	{
		nf = fnc;
	}
	else
	{
		nf = Function::Create(
				newFncType,
				fnc->getLinkage(),
				fnc->getName());
		nf->copyAttributesFrom(fnc);

		fnc->getParent()->getFunctionList().insert(fnc->getIterator(), nf);
		nf->takeName(fnc);
		nf->getBasicBlockList().splice(nf->begin(), fnc->getBasicBlockList());
	}

	// Rename arguments.
	//
	auto nIt = argNames.begin();
	auto oi = fnc->arg_begin();
	auto oie = fnc->arg_end();
	std::size_t idx = 1;
	for (auto i = nf->arg_begin(), e = nf->arg_end(); i != e; ++i, ++idx)
	{
		if (nIt != argNames.end() && !nIt->empty())
		{
			i->setName(*nIt);
		}
		else
		{
			if (oi != oie && !oi->getName().empty())
			{
				if (nf != fnc)
				{
					i->setName(oi->getName());
				}
			}
			else
			{
				std::string n = "arg" + std::to_string(idx);
				i->setName(n);
			}
		}

		if (nIt != argNames.end())
		{
			++nIt;
		}
		if (oi != oie)
		{
			++oi;
		}
	}

	// Set arguments to config function.
	//
	if (cf)
	{
		cf->parameters.clear();
		std::size_t idx = 0;
		for (auto i = nf->arg_begin(), e = nf->arg_end(); i != e; ++i, ++idx)
		{
			std::string n = i->getName();
			assert(!n.empty());
			auto s = retdec::config::Storage::undefined();
			retdec::config::Object arg(n, s);
			if (argNames.size() > idx)
			{
				arg.setRealName(argNames[idx]);
				arg.setIsFromDebug(true);
			}
			arg.type.setLlvmIr(llvmObjToString(i->getType()));

			// TODO: hack, we need to propagate type's wide string property.
			// but how?
			//
			if (i->getType()->isPointerTy()
					&& i->getType()->getPointerElementType()->isIntegerTy()
					&& retdec::utils::contains(nf->getName(), "wprintf"))
			{
				arg.type.setIsWideString(true);
			}
			cf->parameters.insert(arg);
		}
	}

	// Replace uses of old arguments in function body for new arguments.
	//
	for (auto i = fnc->arg_begin(), e = fnc->arg_end(), i2 = nf->arg_begin();
			i != e; ++i, ++i2)
	{
		auto* a1 = &(*i);
		auto* a2 = &(*i2);
		if (a1->getType() == a2->getType())
		{
			a1->replaceAllUsesWith(a2);
		}
		else
		{
			auto uIt = i->user_begin();
			while (uIt != i->user_end())
			{
				Value* u = *uIt;
				uIt++;

				auto* inst = dyn_cast<Instruction>(u);
				assert(inst && "we need an instruction here");

				auto* conv = convertValueToType(a2, a1->getType(), inst);
				inst->replaceUsesOfWith(a1, conv);
			}
		}

		a2->takeName(a1);
	}

	// Store arguments into allocated objects (stacks, registers) at the
	// beginning of function body.
	//
	auto asIt = argStores.begin();
	auto asEndIt = argStores.end();
	for (auto aIt = nf->arg_begin(), eIt = nf->arg_end();
			aIt != eIt && asIt != asEndIt;
			++aIt, ++asIt)
	{
		auto* a = &(*aIt);
		auto* v = *asIt;

		assert(v->getType()->isPointerTy());
		auto* conv = convertValueToType(
				a,
				v->getType()->getPointerElementType(),
				&nf->front().front());

		auto* s = new StoreInst(conv, v);

		if (auto* alloca = dyn_cast<AllocaInst>(v))
		{
			s->insertAfter(alloca);
		}
		else
		{
			if (conv == a)
			{
				s->insertBefore(&nf->front().front());
			}
			else
			{
				s->insertAfter(cast<Instruction>(conv));
			}
		}
	}

	// Update returns in function body.
	//
//	if (nf->getReturnType() != fnc->getReturnType())
	{
		auto it = inst_begin(nf);
		auto eit = inst_end(nf);
		while (it != eit)
		{
			auto* i = &(*it);
			++it;

			if (auto* retI = dyn_cast<ReturnInst>(i))
			{
				auto fIt = rets2vals.find(retI);
				if (nf->getReturnType()->isVoidTy())
				{
					ReturnInst::Create(nf->getContext(), nullptr, retI);
					retI->eraseFromParent();
				}
				else if (fIt != rets2vals.end())
				{
					auto* conv = convertValueToType(
							fIt->second,
							nf->getReturnType(),
							retI);
					if (auto* val = retI->getReturnValue())
					{
						retI->replaceUsesOfWith(val, conv);
					}
					else
					{
						ReturnInst::Create(nf->getContext(), conv, retI);
						retI->eraseFromParent();
					}
				}
				else if (auto* val = retI->getReturnValue())
				{
					auto* conv = convertValueToType(
							val,
							nf->getReturnType(),
							retI);
					retI->replaceUsesOfWith(val, conv);
				}
				else
				{
					auto* conv = convertConstantToType(
							config->getGlobalDummy(),
							nf->getReturnType());
					ReturnInst::Create(nf->getContext(), conv, retI);
					retI->eraseFromParent();
				}
			}
		}
	}

	// Update function users (calls, etc.).
	//
	auto uIt = fnc->user_begin();
	while (uIt != fnc->user_end())
	{
		Value* u = *uIt;
		uIt++;

		if (CallInst* call = dyn_cast<CallInst>(u))
		{
			std::vector<Value*> args;

			auto fIt = calls2vals.find(call);
			if (fIt != calls2vals.end())
			{
				auto vIt = fIt->second.begin();
				for (auto fa = nf->arg_begin(); fa != nf->arg_end(); ++fa)
				{
					if (vIt != fIt->second.end())
					{
						auto* conv = convertValueToType(
								*vIt,
								fa->getType(),
								call);
						args.push_back(conv);
						++vIt;
					}
					else
					{
						auto* conv = convertValueToType(
								config->getGlobalDummy(),
								fa->getType(),
								call);
						args.push_back(conv);
					}
				}
				while (isVarArg && vIt != fIt->second.end())
				{
					args.push_back(*vIt);
					++vIt;
				}
			}
			else
			{
				unsigned ai = 0;
				unsigned ae = call->getNumArgOperands();
				for (auto fa = nf->arg_begin(); fa != nf->arg_end(); ++fa)
				{
					if (ai != ae)
					{
						auto* conv = convertValueToType(
								call->getArgOperand(ai),
								fa->getType(),
								call);
						args.push_back(conv);
						++ai;
					}
					else
					{
						auto* conv = convertValueToType(
								config->getGlobalDummy(),
								fa->getType(),
								call);
						args.push_back(conv);
					}
				}
			}
			assert(isVarArg || args.size() == nf->arg_size());

			auto* nc = _modifyCallInst(
					call,
					nf,
					args);

			if (!ret->isVoidTy() && retVal)
			{
				auto* n = nc->getNextNode();
				assert(n);
				auto* conv = convertValueToType(
						nc,
						retVal->getType()->getPointerElementType(),
						n);
				new StoreInst(conv, retVal, n);
			}
		}
		else if (StoreInst* s = dyn_cast<StoreInst>(u))
		{
			auto* conv = convertValueToType(nf, fnc->getType(), s);
			s->replaceUsesOfWith(fnc, conv);
		}
		else if (auto* c = dyn_cast<CastInst>(u))
		{
			auto* conv = convertValueToType(nf, fnc->getType(), c);
			c->replaceUsesOfWith(fnc, conv);
		}
		else if (isa<Constant>(u))
		{
			// will be replaced by replaceAllUsesWith()
		}
		else
		{
			// we could do generic convertValueToType() and hope for the best,
			// but we would prefer to know about such cases -> throw assert.
			errs() << "unhandled use : " << *u << "\n";
			assert(false && "unhandled use");
		}
	}

	if (nf->getType() != fnc->getType())
	{
		auto* conv = convertConstantToType(nf, fnc->getType());
		fnc->replaceAllUsesWith(conv);
	}

	// Even when fnc->user_empty() && fnc->use_empty() it still fails here.
	// No ide why.
//	fnc->eraseFromParent();

	return {nf, cf};
}

/**
 * @return New argument -- function type cannot be changed in situ, we created
 * an entirely new fuction with desired argument type.
 */
llvm::Argument* modifyFunctionArgumentType(
		Config* config,
		llvm::Argument* arg,
		llvm::Type* type)
{
	auto* f = arg->getParent();
	std::vector<Type*> args;
	for (auto& a : f->args())
	{
		args.push_back(&a == arg ? type : a.getType());
	}
	auto* nf = modifyFunction(config, f, f->getReturnType(), args).first;
	auto& al = nf->getArgumentList();
	std::size_t i = 0;
	for (auto& a : al)
	{
		if (i == arg->getArgNo())
		{
			return &a;
		}
		++i;
	}
	return nullptr;
}

/**
 * Insert instruction @a i at the beginning of basic block @a bb.
 */
void insertAtBegin(llvm::Instruction* i, llvm::BasicBlock* bb)
{
	if (bb->empty())
	{
		IRBuilder<> builder(bb);
		builder.Insert(i);
	}
	else
	{
		i->insertBefore(&bb->front());
	}
}

/**
 * Split the function into two functions at the specified instruction.
 * The original function stays valid -- pointer to it can be used.
 * At the moment, this does no checks if split can be done correctly,
 * i.e. no value before the instruction have users after the instruction.
 * @param inst    Instruction to split on. It will be the first instruction
 *                in the new function.
 * @param fncName Optional name of the new function.
 * @return New function.
 */
llvm::Function* splitFunctionOn(
		llvm::Instruction* inst,
		const std::string& fncName)
{
	Function* old = inst->getFunction();
	BasicBlock* newBb = inst->getParent();
	BasicBlock* oldBb = inst->getParent();
	newBb = inst->getParent()->splitBasicBlock(inst);

	BasicBlock* prevBb = newBb->getPrevNode();
	assert(prevBb);
	auto* term = prevBb->getTerminator();
	term->eraseFromParent();
	if (old->getReturnType()->isVoidTy())
	{
		ReturnInst::Create(inst->getContext(), prevBb);
	}
	else
	{
		auto* ci = ConstantInt::get(getDefaultType(inst->getModule()), 0);
		auto* retVal = convertConstantToType(ci, old->getReturnType());
		ReturnInst::Create(inst->getContext(), retVal, prevBb);
	}

	Function* newFnc = Function::Create(
			llvm::FunctionType::get(old->getReturnType(), false),
			old->getLinkage(),
			fncName);
	old->getParent()->getFunctionList().insertAfter(old->getIterator(), newFnc);

	newFnc->getBasicBlockList().splice(
			newFnc->begin(),
			old->getBasicBlockList(),
			newBb->getIterator(),
			old->getBasicBlockList().end());

	std::list<User*> users(oldBb->users().begin(), oldBb->users().end());
	for (auto* u : users)
	{
		auto* inst = dyn_cast<Instruction>(u);
		assert(inst);

		if (inst->getFunction() == newFnc)
		{
			inst->replaceUsesOfWith(oldBb, newBb);
		}
	}

	if (!newBb->user_empty())
	{
		auto* sbb = BasicBlock::Create(
				inst->getModule()->getContext(),
				"",
				newFnc,
				newBb);
		BranchInst::Create(newBb, sbb);
	}

	return newFnc;
}

} // namespace bin2llvmir
} // namespace retdec
