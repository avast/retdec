/**
 * @file src/bin2llvmir/utils/ir_modifier.cpp
 * @brief Modify both LLVM IR and config.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/InstIterator.h>

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace llvm;

//
//==============================================================================
// Local functions.
//==============================================================================
//

namespace {

using namespace retdec::bin2llvmir;

Instruction* insertBeforeAfter(Instruction* i, Instruction* b, Instruction* a)
{
	if (b)
	{
		i->insertBefore(b);
	}
	else
	{
		i->insertAfter(a);
	}
	return i;
}

Value* convertToType(
		Value* val,
		Type* type,
		Instruction* before,
		Instruction* after,
		bool constExpr)
{
	if (val == nullptr
			|| type == nullptr
			|| (!constExpr && before == nullptr && after == nullptr))
	{
		return nullptr;
	}

	auto* cval = dyn_cast<Constant>(val);
	if (constExpr)
	{
		assert(cval);
	}

	auto& ctx = type->getContext();
	Value* conv = nullptr;

	if (val->getType() == type)
	{
		conv = val;
	}
	else if (val->getType()->isPointerTy() && type->isPointerTy())
	{
		if (constExpr)
		{
			conv = ConstantExpr::getBitCast(cval, type);
		}
		else
		{
			auto* i = new BitCastInst(val, type, "");
			conv = insertBeforeAfter(i, before, after);
		}
	}
	else if (val->getType()->isPointerTy() && type->isIntegerTy())
	{
		if (constExpr)
		{
			conv = ConstantExpr::getPtrToInt(cval, type);
		}
		else
		{
			auto* i = new PtrToIntInst(val, type, "");
			conv = insertBeforeAfter(i, before, after);
		}
	}
	else if (val->getType()->isIntegerTy() && type->isPointerTy())
	{
		if (constExpr)
		{
			conv = ConstantExpr::getIntToPtr(cval, type);
		}
		else
		{
			auto* i = new IntToPtrInst(val, type, "");
			conv = insertBeforeAfter(i, before, after);
		}
	}
	else if (val->getType()->isIntegerTy() && type->isIntegerTy())
	{
		if (constExpr)
		{
			conv = ConstantExpr::getIntegerCast(cval, type, true);
		}
		else
		{
			auto* i = CastInst::CreateIntegerCast(val, type, true, "");
			conv = insertBeforeAfter(i, before, after);
		}
	}
	else if (val->getType()->isIntegerTy() && type->isFloatingPointTy())
	{
		auto* toInt = Type::getIntNTy(ctx, type->getPrimitiveSizeInBits());
		auto* szConv = convertToType(val, toInt, before, after, constExpr);

		if (constExpr)
		{
			conv = ConstantExpr::getBitCast(cast<Constant>(szConv), type);
		}
		else
		{
			auto* i = new BitCastInst(szConv, type, "");
			auto* a = val == szConv ? after : cast<Instruction>(szConv);
			conv = insertBeforeAfter(i, before, a);
		}
	}
	else if (val->getType()->isPointerTy() && type->isFloatingPointTy())
	{
		auto* toInt = Type::getIntNTy(ctx, type->getPrimitiveSizeInBits());
		auto* intConv = convertToType(val, toInt, before, after, constExpr);
		auto* a = dyn_cast<Instruction>(intConv);
		conv = convertToType(intConv, type, before, a, constExpr);
	}
	else if (val->getType()->isFloatingPointTy() && type->isIntegerTy())
	{
		Type* ft = nullptr;
		IntegerType* intT = cast<IntegerType>(type);
		switch (intT->getBitWidth())
		{
			case 16: ft = Type::getHalfTy(ctx); break;
			case 32: ft = Type::getFloatTy(ctx); break;
			case 64: ft = Type::getDoubleTy(ctx); break;
			case 80: ft = Type::getX86_FP80Ty(ctx); break;
			default:
			{
				auto* fpConv = convertToType(
						val,
						Type::getInt32Ty(ctx),
						before,
						after,
						constExpr);
				auto* a = dyn_cast<Instruction>(fpConv);
				conv = convertToType(fpConv, intT, before, a, constExpr);
				return conv;
			}
		}

		if (val->getType() != ft)
		{
			auto* fpConv = convertToType(val, ft, before, after, constExpr);
			auto* a = dyn_cast<Instruction>(fpConv);
			conv = convertToType(fpConv, intT, before, a, constExpr);
		}
		else
		{
			if (constExpr)
			{
				conv = ConstantExpr::getBitCast(cval, intT);
			}
			else
			{
				auto* i = new BitCastInst(val, intT, "");
				conv = insertBeforeAfter(i, before, after);
			}
		}
	}
	else if (val->getType()->isFloatingPointTy() && type->isPointerTy())
	{
		auto* toInt = Type::getIntNTy(
				ctx,
				val->getType()->getPrimitiveSizeInBits());
		auto* intConv = convertToType(val, toInt, before, after, constExpr);
		auto* a = dyn_cast<Instruction>(intConv);
		conv = convertToType(intConv, type, before, a, constExpr);
	}
	else if (val->getType()->isFloatingPointTy() && type->isFloatingPointTy())
	{
		if (constExpr)
		{
			conv = ConstantExpr::getFPCast(cval, type);
		}
		else
		{
			auto* i = CastInst::CreateFPCast(val, type, "");
			conv = insertBeforeAfter(i, before, after);
		}
	}
	// TODO: this is too late, it would be the best if loads/stores that
	// load/store entire aggregate types were not created at all.
	// Such complex load/stores are not possible at ASM level.
	// Something like util function createSafe{Load,Store}() that would
	// check if loaded/stored value is not aggregate and if it is, it would
	// do the same this as here.
	//
	else if (isa<LoadInst>(val) && val->getType()->isAggregateType() && !constExpr)
	{
		auto* l = cast<LoadInst>(val);
		auto* c = cast<Instruction>(convertToType(
				l->getPointerOperand(),
				PointerType::get(type, 0),
				before,
				after,
				constExpr));
		auto* nl = new LoadInst(c);
		nl->insertAfter(c);
		conv = nl;
	}
	else if (val->getType()->isAggregateType())
	{
		std::vector<unsigned> idxs = { 0 };
		Value* toSimple = nullptr;
		if (constExpr)
		{
			toSimple = ConstantExpr::getExtractValue(
					cval,
					ArrayRef<unsigned>(idxs));
		}
		else
		{
			auto* i = ExtractValueInst::Create(
					val,
					ArrayRef<unsigned>(idxs),
					"");
			toSimple = insertBeforeAfter(i, before, after);
		}
		auto* a = dyn_cast<Instruction>(toSimple);
		conv = convertToType(toSimple, type, before, a, constExpr);
	}
	else if (CompositeType* cmp = dyn_cast<CompositeType>(type))
	{
		assert(!cmp->isEmptyTy());
		std::vector<unsigned> idxs = { 0 };
		auto* idxt = cmp->getTypeAtIndex(0u);
		auto* tmp = convertToType(val, idxt, before, after, constExpr);

		if (constExpr)
		{
			auto* c = dyn_cast<Constant>(tmp);
			assert(c);
			conv = ConstantExpr::getInsertValue(
					UndefValue::get(cmp),
					c,
					ArrayRef<unsigned>(idxs));
		}
		else
		{
			auto* i = InsertValueInst::Create(
					UndefValue::get(cmp),
					tmp,
					ArrayRef<unsigned>(idxs),
					"");
			auto* a = val == tmp ? after : cast<Instruction>(tmp);
			conv = insertBeforeAfter(i, before, a);
		}
	}
	else
	{
		errs() << "\nconvertValueToType(): unhandled type conversion\n";
		errs() << *val << "\n";
		errs() << *type << "\n\n";
		assert(false);
		conv = nullptr;
	}

	return conv;
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
			auto* cast = IrModifier::convertValueToType(newCall, call->getType(), call);
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
				auto* c = IrModifier::convertValueToType(
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
 * Check if we can initialize the given global variable @c gv at address @c addr
 * with initializer @c c read from object file @c objf -- initialization will
 * not create init cycle.
 * @return Original constant @c c if cycle is not detected, integer value if
 * cycle is detected, @c nullptr if integer value can not be read.
 */
Constant* detectGlobalVariableInitializerCycle(
		Module* module,
		GlobalVariable* gv,
		Constant* c,
		FileImage* objf,
		retdec::utils::Address addr)
{
	if (gv == nullptr || c == nullptr || objf == nullptr || addr.isUndefined())
	{
		return nullptr;
	}
	if (c == gv)
	{
		return objf->getConstant(Abi::getDefaultType(module), addr);
	}

	auto* cgv = dyn_cast<GlobalVariable>(c);
	while (cgv)
	{
		if (cgv == gv)
		{
			c = objf->getConstant(Abi::getDefaultType(module), addr);
			break;
		}
		if (cgv->hasInitializer())
		{
			cgv = dyn_cast<GlobalVariable>(cgv->getInitializer());
		}
		else
		{
			cgv = nullptr;
		}
	}

	return c;
}

bool globalVariableCanBeCreated(
		Module* module,
		Config* config,
		FileImage* objf,
		retdec::utils::Address &addr,
		bool strict = false)
{
	if (module == nullptr || objf == nullptr || addr.isUndefined())
	{
		return false;
	}
	if (!objf->getImage()->hasDataOnAddress(addr))
	{
		return false;
	}
	auto* seg = objf->getImage()->getSegmentFromAddress(addr);

	// TODO: it would be greate to use this info here, but vtable analysis
	// can not handle it at the moment -> some features.cpp tests fail.
	//
	std::string str;
	auto* fnc = config->getLlvmFunction(addr);
	if (fnc || (seg && seg->getSecSeg() && seg->getSecSeg()->isCode()))
	{
		if (!(objf->getImage()->getNTBS(addr, str) && retdec::utils::isNiceString(str, 1.0)))
		{
			uint64_t val = 0;
			if (objf->getImage()->getWord(addr, val))
			{
				if (objf->getImage()->hasDataOnAddress(val))
				{
					return true;
				}
			}
			if (objf->getImage()->getWord(
					addr + objf->getImage()->getBytesPerWord(),
					val))
			{
				if (objf->getImage()->hasDataOnAddress(val))
				{
					return true;
				}
			}
			if (objf->getImage()->getWord(
					addr - objf->getImage()->getBytesPerWord(),
					val))
			{
				if (objf->getImage()->hasDataOnAddress(val))
				{
					return true;
				}
			}

			// ARM has data after functions, Pic32 does not bother to mark data (e.g. rodata) as data.
			if ((config->getConfig().architecture.isArmOrThumb()
					|| config->getConfig().architecture.isPic32())
					&& !strict)
			{
				return true;
			}

			return false;
		}
	}

	return true;
}

} // anonymous namespace

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// IrModifier.
//==============================================================================
//

IrModifier::IrModifier(llvm::Module* m, Config* c) :
		_module(m),
		_config(c)
{

}

IrModifier::FunctionPair IrModifier::renameFunction(
		llvm::Function* fnc,
		const std::string& fncName)
{
	auto* cf = _config->getConfigFunction(fnc);
	auto n = retdec::utils::normalizeNamePrefix(fncName);
	if (n == fnc->getName())
	{
		return {fnc, cf};
	}

	fnc->setName(n);
	if (cf)
	{
		cf = _config->renameFunction(cf, fnc->getName());
	}
	else
	{
		cf = _config->insertFunction(fnc);
	}
	return {fnc, cf};
}

/**
 * Get or create&get stack variable.
 * @param fnc    Function owning the stack variable.
 * @param offset Stack varibale's offset.
 * @param type   Stack varibale's type.
 * @param name   Stack varibale's name in IR. If not set default name is used.
 *               Offset is always appended to this name. If you want to get
 *               this name to output C, set it as a real name to returned
 *               config stack variable entry.
 * @return Pair of LLVM stack var (Alloca instruction) and associated config
 *         stack var.
 */
IrModifier::StackPair IrModifier::getStackVariable(
		llvm::Function* fnc,
		int offset,
		llvm::Type* type,
		const std::string& name)
{
	if (!PointerType::isValidElementType(type))
	{
		type = Abi::getDefaultType(fnc->getParent());
	}

	std::string n = name.empty() ? "stack_var" : name;
	n += "_" + std::to_string(offset);
	AllocaInst* ret = _config->getLlvmStackVariable(fnc, offset);
	if (ret)
	{
		auto* csv = _config->getConfigStackVariable(ret);
		assert(csv);
		return {ret, csv};
	}

	ret = new AllocaInst(type, n);

	auto it = inst_begin(fnc);
	assert(it != inst_end(fnc)); // -> create bb, insert alloca.
	ret->insertBefore(&*it);

	auto* csv = _config->insertStackVariable(ret, offset);

	return {ret, csv};
}

/**
 * Get global variable from the given address @a addr in @a objf input file.
 * @param objf Object file.
 * @param dbgf Debug file.
 * @param addr Address of the global variable in the @a objf.
 * @param strict Be stricter when determining if variable can be created.
 * @param name Name to use. Global's address is always appended to this name.
 * @return Global variable on the given address, or @c nullptr.
 *
 * TODO: there is many more things to do here:
 * - create second similar method taking global variable type, or add default
 *   parameter to this method. if type specified, it is forced.
 * - check that such global variable does not already exist, config is needed,
 *   if so, do not create new, use the old one
 * - check debug info for variable on the specified address, if it exists,
 *   use name, type, ...
 * - add/update info about this variable into config
 */
GlobalVariable* IrModifier::getGlobalVariable(
		FileImage* objf,
		DebugFormat* dbgf,
		retdec::utils::Address addr,
		bool strict,
		std::string name)
{
	if (!globalVariableCanBeCreated(_module, _config, objf, addr, strict))
	{
		return nullptr;
	}

	retdec::utils::appendHex(name, addr);

	if (auto* gv = _config->getLlvmGlobalVariable(name, addr))
	{
		return gv;
	}

	Constant* c = nullptr;
	Type* t = Abi::getDefaultType(_module);
	bool isConstant = objf->getImage()->hasReadOnlyDataOnAddress(addr);
	bool isFromDebug = false;
	std::string realName;

	auto* dgv = dbgf ? dbgf->getGlobalVar(addr) : nullptr;
	if (dgv)
	{
		auto* dt = llvm_utils::stringToLlvmType(_module->getContext(), dgv->type.getLlvmIr());
		t = dt ? dt : t;
		c = objf->getConstant(t, addr);
		name = dgv->getName();
		realName = dgv->getName();
		isFromDebug = true;
	}

	auto* cgv = _config->getConfigGlobalVariable(addr);
	if (cgv)
	{
		auto* dt = llvm_utils::stringToLlvmType(_module->getContext(), cgv->type.getLlvmIr());
		t = dt ? dt : t;
		c = objf->getConstant(t, addr);
		name = cgv->getName();
		realName = cgv->getName();
		isFromDebug = true;
	}

	std::string cryptoName;
	std::string cryptoDesc;
	Type* cryptoType = nullptr;
	if (_config->getCryptoPattern(
			addr,
			cryptoName,
			cryptoDesc,
			cryptoType))
	{
		if (!isFromDebug)
		{
			t = cryptoType;
			c = objf->getConstant(t, addr);
			name = cryptoName;
			realName = std::move(cryptoName);
			isFromDebug = true;
		}
	}

	auto* gv = new GlobalVariable(
			*_module,
			t,
			isConstant,
			GlobalValue::ExternalLinkage,
			c,
			name);

	if (c == nullptr)
	{
		c = objf->getConstant(_config, dbgf, addr);
		c = detectGlobalVariableInitializerCycle(_module, gv, c, objf, addr);
		if (c == nullptr)
		{
			_config->insertGlobalVariable(
					gv,
					addr,
					isFromDebug,
					realName,
					cryptoDesc);
			return nullptr;
		}

		auto* ngv = new GlobalVariable(
				*_module,
				c->getType(),
				isConstant,
				GlobalValue::ExternalLinkage,
				c,
				name);

		auto* conv = IrModifier::convertConstantToType(ngv, gv->getType());
		if (conv != ngv)
		{
			gv->replaceAllUsesWith(conv);
		}
		gv->eraseFromParent();
		gv = ngv;
	}

	_config->insertGlobalVariable(
			gv,
			addr,
			isFromDebug,
			realName,
			cryptoDesc);

	return gv;
}

/**
 * Change @c val declaration to @c toType. Only the object type is changed,
 * not its usages. Because of this, it is not safe to use this function alone.
 * This function is not public, i.e. accessible from other modules.
 * @param objf   Object file for this object -- needed to initialize it values.
 * @param val    Value which type to change.
 * @param toType Type to change it to.
 * @param init   Initializer constant.
 * @param wideString Is type a wide string?
 * @return New value with a desired type. This may be the same as @a val if
 * value's type can be mutated, or a new object if it cannot.
 */
llvm::Value* IrModifier::changeObjectDeclarationType(
		FileImage* objf,
		llvm::Value* val,
		llvm::Type* toType,
		llvm::Constant* init,
		bool wideString)
{
	if (val->getType() == toType)
	{
		return val;
	}

	if (auto* alloca = dyn_cast<AllocaInst>(val))
	{
		auto* ret = new AllocaInst(toType, alloca->getName(), alloca);
		ret->takeName(alloca);
		return ret;
	}
	else if (auto* ogv = dyn_cast<GlobalVariable>(val))
	{
		if (init == nullptr)
		{
			init = objf->getConstant(
					toType,
					_config->getGlobalAddress(ogv),
					wideString);
		}

		auto* old = ogv;
		ogv = new GlobalVariable(
				*_module,
				init ? init->getType() : toType,
				old->isConstant(),
				old->getLinkage(),
				init,
				old->getName());
		ogv->takeName(old);

		auto* ecgv = _config->getConfigGlobalVariable(ogv);
		if (ecgv)
		{
			retdec::config::Object cgv(
					ecgv->getName(),
					ecgv->getStorage());
			cgv.type.setLlvmIr(
					llvmObjToString(ogv->getType()->getPointerElementType()));
			cgv.type.setIsWideString(wideString);
			_config->getConfig().globals.insert(cgv);
		}

		return ogv;
	}
	else if (auto* arg = dyn_cast<Argument>(val))
	{
		return modifyFunctionArgumentType(arg, toType);
	}
	else
	{
		errs() << "unhandled value type : " << *val << "\n";
		assert(false && "unhandled value type");
		return val;
	}
}

/**
 * Change @c val type to @c toType and fix all its uses.
 * @param objf   Object file for this object -- needed to initialize it values.
 * @param val    Value which type to change.
 * @param toType Type to change it to.
 * @param init   Initializer constant.
 * @param instToErase Some instructions may become obsolete. If pointer to this
 *                    container is provided, function adds such instructions to
 *                    it and it is up to the caller to erase them. Otherwise,
 *                    function erases such instructions from parent.
 *                    If caller does not have instructions saved, it is save
 *                    to erase them here -- pass nullptr.
 *                    If caller is performing some analysis where it has
 *                    instructions stored in internal structures and it is
 *                    possible that they will be used after they would
 *                    have been erased, it should pass pointer to container
 *                    here and erase instructions when it is finished.
 * @param dbg    Flag to enable debug messages.
 * @param wideString Is type a wide string?
 */
llvm::Value* IrModifier::changeObjectType(
		FileImage* objf,
		Value* val,
		Type* toType,
		Constant* init,
		std::unordered_set<llvm::Instruction*>* instToErase,
		bool dbg,
		bool wideString)
{
	if (!(isa<AllocaInst>(val)
			|| isa<GlobalVariable>(val)
			|| isa<Argument>(val)))
	{
		assert(false && "only globals, allocas and arguments can be changed");
		return val;
	}

	if (val->getType() == toType)
	{
		return val;
	}

	Type* origType = val->getType();
	auto* nval = changeObjectDeclarationType(
			objf,
			val,
			toType,
			init,
			wideString);
	Constant* newConst = dyn_cast<Constant>(nval);

	// For some reason, iteration using val->user_begin() and val->user_end()
	// may break -- there are many uses, but after modifying one of them,
	// iteration ends before visiting all of them. Even when we increment
	// iterator before modification.
	// Example: @glob_var_0 in arm-elf-059c1a6996c630386b5067c2ccc6ddf2
	// Therefore, we store all uses to our own container.
	//
	std::list<User*> users;
	for (const auto& U : val->users())
	{
		users.push_back(U);
	}

	for (auto* user : users)
	{
		Constant* c = dyn_cast<Constant>(user);
		auto* gvDeclr = dyn_cast<GlobalVariable>(user);

		if (auto* store = dyn_cast<StoreInst>(user))
		{
			Value* src = store->getValueOperand();
			Value* dst = store->getPointerOperand();

			if (val == dst)
			{
				PointerType* ptr = dyn_cast<PointerType>(nval->getType());
				assert(ptr);
				auto* conv = IrModifier::convertValueToType(src, ptr->getElementType(), store);
				store->setOperand(0, conv);
				store->setOperand(1, nval);
			}
			else
			{
				auto* conv = IrModifier::convertValueToType(nval, origType, store);
				store->setOperand(0, conv);
			}
		}
		else if (auto* load = dyn_cast<LoadInst>(user))
		{
			assert(val == load->getPointerOperand());

			auto* newLoad = new LoadInst(nval);
			newLoad->insertBefore(load);

			// load->getType() stays unchanged even after loaded object's type is mutated.
			// we can use it here as a target type, but the origianl load instruction can
			// not be used afterwards, because its type is incorrect.
			auto* conv = IrModifier::convertValueToType(newLoad, load->getType(), load);

			if (conv != load)
			{
				load->replaceAllUsesWith(conv);
				if (instToErase)
				{
					instToErase->insert(load);
				}
				else
				{
					load->eraseFromParent();
				}
			}
		}
		else if (auto* cast = dyn_cast<CastInst>(user))
		{
			if (nval->getType() == cast->getType())
			{
				if (val != cast)
				{
					cast->replaceAllUsesWith(nval);
					if (instToErase)
					{
						instToErase->insert(cast);
					}
					else
					{
						cast->eraseFromParent();
					}
				}
			}
			else
			{
				auto* conv = IrModifier::convertValueToType(nval, cast->getType(), cast);
				if (cast != conv)
				{
					cast->replaceAllUsesWith(conv);
					if (instToErase)
					{
						instToErase->insert(cast);
					}
					else
					{
						cast->eraseFromParent();
					}
				}
			}
		}
		// maybe GetElementPtrInst should be specially handled?
		else if (auto* instr = dyn_cast<Instruction>(user))
		{
			auto* conv = IrModifier::convertValueToType(nval, origType, instr);
			if (val != conv)
			{
				instr->replaceUsesOfWith(val, conv);
			}
		}
		else if (newConst && gvDeclr)
		{
			auto* conv = IrModifier::convertConstantToType(
					newConst,
					gvDeclr->getType()->getPointerElementType());
			if (gvDeclr != conv)
			{
				gvDeclr->replaceUsesOfWith(val, conv);
			}
		}
		// Needs to be at the very end, many objects can be casted to Constant.
		//
		else if (newConst && c)
		{
			auto* conv = IrModifier::convertConstantToType(newConst, c->getType());
			if (c != conv)
			{
				c->replaceAllUsesWith(conv);
			}
		}
		else
		{
			errs() << "unhandled use : " << *user << " -> " << *toType << "\n";
			assert(false && "unhandled use");
		}
	}

	return nval;
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
IrModifier::FunctionPair IrModifier::modifyFunction(
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
	auto* cf = _config->getConfigFunction(fnc);

	if (!FunctionType::isValidReturnType(ret))
	{
		ret = Abi::getDefaultType(fnc->getParent());
	}
	for (Type*& t : args)
	{
		if (!FunctionType::isValidArgumentType(t))
		{
			t = Abi::getDefaultType(fnc->getParent());
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

				auto* conv = IrModifier::convertValueToType(a2, a1->getType(), inst);
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
		auto* conv = IrModifier::convertValueToType(
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
					auto* conv = IrModifier::convertValueToType(
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
					auto* conv = IrModifier::convertValueToType(
							val,
							nf->getReturnType(),
							retI);
					retI->replaceUsesOfWith(val, conv);
				}
				else
				{
					auto* conv = IrModifier::convertConstantToType(
							_config->getGlobalDummy(),
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
		++uIt;

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
						auto* conv = IrModifier::convertValueToType(
								*vIt,
								fa->getType(),
								call);
						args.push_back(conv);
						++vIt;
					}
					else
					{
						auto* conv = IrModifier::convertValueToType(
								_config->getGlobalDummy(),
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
						auto* conv = IrModifier::convertValueToType(
								call->getArgOperand(ai),
								fa->getType(),
								call);
						args.push_back(conv);
						++ai;
					}
					else
					{
						auto* conv = IrModifier::convertValueToType(
								_config->getGlobalDummy(),
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
				auto* conv = IrModifier::convertValueToType(
						nc,
						retVal->getType()->getPointerElementType(),
						n);
				new StoreInst(conv, retVal, n);
			}
		}
		else if (StoreInst* s = dyn_cast<StoreInst>(u))
		{
			auto* conv = IrModifier::convertValueToType(nf, fnc->getType(), s);
			s->replaceUsesOfWith(fnc, conv);
		}
		else if (auto* c = dyn_cast<CastInst>(u))
		{
			auto* conv = IrModifier::convertValueToType(nf, fnc->getType(), c);
			c->replaceUsesOfWith(fnc, conv);
		}
		else if (isa<Constant>(u))
		{
			// will be replaced by replaceAllUsesWith()
		}
		else
		{
			// we could do generic IrModifier::convertValueToType() and hope for the best,
			// but we would prefer to know about such cases -> throw assert.
			errs() << "unhandled use : " << *u << "\n";
			assert(false && "unhandled use");
		}
	}

	if (nf->getType() != fnc->getType())
	{
		auto* conv = IrModifier::convertConstantToType(nf, fnc->getType());
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
llvm::Argument* IrModifier::modifyFunctionArgumentType(
		llvm::Argument* arg,
		llvm::Type* type)
{
	auto* f = arg->getParent();
	std::vector<Type*> args;
	for (auto& a : f->args())
	{
		args.push_back(&a == arg ? type : a.getType());
	}
	auto* nf = modifyFunction(f, f->getReturnType(), args).first;
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

//
//==============================================================================
// IrModifier static methods.
//==============================================================================
//

llvm::AllocaInst* IrModifier::createAlloca(
		llvm::Function* fnc,
		llvm::Type* ty,
		const std::string& name)
{
	if (fnc->empty() || fnc->getEntryBlock().empty())
	{
		return nullptr;
	}

	return new AllocaInst(ty, name, &fnc->getEntryBlock().front());
}

/**
 * Create type conversion from provided value to provided type.
 * Created instructions are inserted before the specified instruction.
 * @param val Value to convert.
 * @param type Type to convert to.
 * @param before Instruction before which created conversion instructions
 *        are inserted.
 * @return Final value of the specified type.
 */
Value* IrModifier::convertValueToType(Value* val, Type* type, Instruction* before)
{
	return convertToType(val, type, before, nullptr, false);
}

/**
 * Create type conversion from provided value to provided type.
 * Created instructions are inserted after the specified instruction.
 * @param val Value to convert.
 * @param type Type to convert to.
 * @param after Instruction after which created conversion instructions
 *        are inserted.
 * @return Final value of the specified type.
 */
llvm::Value* IrModifier::convertValueToTypeAfter(
		llvm::Value* val,
		llvm::Type* type,
		llvm::Instruction* after)
{
	return convertToType(val, type, nullptr, after, false);
}

/**
 * This is the same as @c convertValueToType() but working with constants.
 * It does not insert constant expressions (type casts) to any particular place
 * in the IR. It just returns the created constant expressions.
 * @param val  Constant value to convert.
 * @param type Type to convert to.
 * @return Constant expression representing type conversion.
 */
Constant* IrModifier::convertConstantToType(Constant* val, Type* type)
{
	auto* v = convertToType(val, type, nullptr, nullptr, true);
	auto* c = dyn_cast_or_null<Constant>(v);
	if (v)
	{
		assert(c);
	}
	return c;
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
llvm::CallInst* IrModifier::modifyCallInst(
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
	auto* conv = IrModifier::convertValueToType(call->getCalledValue(), t, call);

	return _modifyCallInst(call, conv, args);
}

} // namespace bin2llvmir
} // namespace retdec
