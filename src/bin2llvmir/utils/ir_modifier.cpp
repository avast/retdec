/**
 * @file src/bin2llvmir/utils/ir_modifier.cpp
 * @brief Modify both LLVM IR and config.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>

#include "retdec/utils/string.h"
#include "retdec/utils/math.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"

#define debug_enabled false

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
			if (val->getType()->getPointerAddressSpace() == type->getPointerAddressSpace())
				conv = ConstantExpr::getBitCast(cval, type);
			else
				conv = ConstantExpr::getAddrSpaceCast(cval, type);
		}
		else
		{
			if (val->getType()->getPointerAddressSpace() == type->getPointerAddressSpace())
			{
				auto* i = new BitCastInst(val, type, "");
				conv = insertBeforeAfter(i, before, after);
			}
			else
			{
				auto* i = new AddrSpaceCastInst(val, type, "");
				conv = insertBeforeAfter(i, before, after);
			}
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
	else if (isa<LoadInst>(val) && type->isAggregateType())
	{
		conv = val;
		//std::cout << "type: " << llvmObjToString(type) << std::endl;
		//std::cout << "EXITTING" << std::endl;
		exit(1);
	}
	else if (val->getType()->isAggregateType())
	{
		auto* strType = dyn_cast<StructType>(val->getType());
		Instruction* gep = GetElementPtrInst::CreateInBounds(strType, val, {0}, "", before);
		conv = gep;
	}
	else if (CompositeType* cmp = dyn_cast<CompositeType>(type))
	{
		//std::cout << "The val: " << llvmObjToString(val) << std::endl;
		//std::cout << "Type: " << llvmObjToString(type) << std::endl;
		assert(!isa<Instruction>(val) && "This should not happen! Please rethink convertion.");
		exit(2);
		conv = nullptr;
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
	//std::cout << "call: " << llvmObjToString(call) << std::endl;
	//std::cout << "args: " << args.size() << std::endl;
	for (auto a: args)
	{
		std::cout << "\tnarg: " << llvmObjToString(a) << std::endl;
	}

	std::set<Instruction*> toEraseCast;
	auto* newCall = CallInst::Create(calledVal, args, "", call);
	//std::cout << "newCall: " << llvmObjToString(newCall) << std::endl;
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
			if ((config->getConfig().architecture.isArm32OrThumb()
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
	if (!PointerType::isValidElementType(type) || !type->isSized())
	{
		type = Abi::getDefaultType(fnc->getParent());
	}

	std::string n = name.empty() ? "stack_var" : name;
	n += "_"+std::to_string(offset);
	AllocaInst* ret = _config->getLlvmStackVariable(fnc, offset);
	if (ret)
	{
		auto* csv = _config->getConfigStackVariable(ret);
		assert(csv);
		return {ret, csv};
	}

	ret = new AllocaInst(type, Abi::DEFAULT_ADDR_SPACE, n);

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
	retdec::utils::appendHex(name, addr);
	if (auto* gv = _config->getLlvmGlobalVariable(name, addr))
	{
		return gv;
	}

	if (!globalVariableCanBeCreated(_module, _config, objf, addr, strict))
	{
		return nullptr;
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
			return gv;
		}

		auto* ngv = new GlobalVariable(
				*_module,
				c->getType(),
				isConstant,
				GlobalValue::ExternalLinkage,
				c,
				name);

		auto* conv = IrModifier::convertConstantToType(ngv, gv->getType());
		if (conv != gv)
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

	if (auto* strt = dyn_cast<StructType>(dyn_cast<PointerType>(gv->getType())->getElementType()))
	{
		return convertToStructure(gv, strt, addr);
	}

	return gv;
}

std::size_t IrModifier::getAlignment(StructType* st) const
{
	auto a = AbiProvider::getAbi(_module);
	std::size_t alignment = 0;
	for (auto e: st->elements())
	{
		std::size_t eSize = 0;

		if (auto* st = dyn_cast<StructType>(e))
			eSize = getAlignment(st);

		else
			eSize = a->getTypeByteSize(e);

		//TODO: did we tought through arrays?

		if (eSize > alignment)
			alignment = eSize;
	}

	return alignment;
}

Instruction* IrModifier::getArrayElement(llvm::Value* v, std::size_t idx) const
{
	auto* var = dyn_cast<PointerType>(v->getType());
	assert(var && "Expects variable.");

	auto eIdx= ConstantInt::get(IntegerType::get(_module->getContext(), 32), idx);

	return GetElementPtrInst::Create(var->getElementType(), v, {eIdx});
}


Instruction* IrModifier::getElement(llvm::Value* v, std::size_t idx) const
{
	auto* var = dyn_cast<PointerType>(v->getType());
	assert(var && "Expects variable.");
	auto* strType = dyn_cast<StructType>(var->getElementType());

	auto zero = ConstantInt::get(IntegerType::get(_module->getContext(), 32), 0);
	auto eIdx= ConstantInt::get(IntegerType::get(_module->getContext(), 32), idx);

	return GetElementPtrInst::CreateInBounds(strType, v, {zero, eIdx});
}

Instruction* IrModifier::getElement(llvm::Value* v, const std::vector<Value*> &idxs) const
{
	auto* var = dyn_cast<PointerType>(v->getType());
	assert(var && "Expects variable.");

	return GetElementPtrInst::CreateInBounds(var->getPointerElementType(), v, idxs);
}

void IrModifier::replaceElementWithStrIdx(llvm::Value* element, llvm::Value* str, std::size_t idx)
{
	auto structType = dyn_cast<PointerType>(str->getType())->getElementType();
	std::vector<User*> uses;

	for (auto* u: element->users())
	{
		uses.push_back(u);
	}

	for (auto& u: uses) {
		if (auto* ld = dyn_cast<LoadInst>(u))
		{
			auto elemVal = getElement(str, idx);
			elemVal->insertBefore(ld);
			if (elemVal->getType() != ld->getPointerOperand()->getType())
				elemVal = CastInst::CreatePointerCast(elemVal, ld->getPointerOperand()->getType(), "", ld);

			auto* tp = dyn_cast<PointerType>(elemVal->getType());
			Instruction* load = new LoadInst(tp->getElementType(), elemVal, "", ld);
			ld->replaceAllUsesWith(load);
			ld->eraseFromParent();
		}
		else if (auto* st = dyn_cast<StoreInst>(u))
		{
			auto elemVal = getElement(str, idx);
			elemVal->insertBefore(st);
			if (elemVal->getType() != st->getPointerOperand()->getType())
				elemVal = CastInst::CreatePointerCast(elemVal, st->getPointerOperand()->getType(), "", st);

			auto* s = new StoreInst(st->getValueOperand(), elemVal);
			s->insertAfter(st);
			st->eraseFromParent();
		}
		else if (auto* ep = dyn_cast<GetElementPtrInst>(u))
		{
			auto zero = ConstantInt::get(IntegerType::get(_module->getContext(), 32), 0);
			auto eIdx = ConstantInt::get(IntegerType::get(_module->getContext(), 32), idx);
			std::vector<Value*> idxs = {zero, eIdx};
			bool isFirst = true;
			for (auto& i : ep->indices())
			{
				if (!isFirst)
					idxs.push_back(i.get());
				else
					isFirst = false;
			}

			auto elem = getElement(str, idxs);
			elem->insertBefore(ep);
			ep->replaceAllUsesWith(elem);
			ep->eraseFromParent();
		}
		else if (auto* i = dyn_cast<PtrToIntInst>(u))
		{
			auto zero = ConstantInt::get(IntegerType::get(_module->getContext(), 32), 0);
			auto eIdx = ConstantInt::get(IntegerType::get(_module->getContext(), 32), idx);

			auto elem = getElement(str, {zero, eIdx});

			elem->insertBefore(i);
			i->replaceAllUsesWith(convertValueToType(elem, i->getDestTy(), i));
			i->eraseFromParent();
		}
	}

	if (!isa<Constant>(str))
	{
		//TODO: should initialize
		return;
	}

	auto zero = ConstantInt::get(IntegerType::get(_module->getContext(), 32), 0);
	auto eIdx = ConstantInt::get(IntegerType::get(_module->getContext(), 32), idx);
	auto elem = ConstantExpr::getGetElementPtr(structType, dyn_cast<Constant>(str), ArrayRef<Constant*>{zero, eIdx});

	//TODO: some constants are not replaced
	LOG << "Constant uses" << std::endl;
	for (auto * u: element->users())
	{
		LOG << "\t" << llvmObjToString(u) << std::endl;
	}

	element->replaceAllUsesWith(elem);

	LOG << "Replaced uses" << std::endl;
	for (auto * u: elem->users())
	{
		LOG << "\t" << llvmObjToString(u) << std::endl;
	}


	//initializeGlobalWithGetElementPtr(element, str, idx);
}

void IrModifier::initializeGlobalWithGetElementPtr(
		Value* element,
		Value* str,
		std::size_t idx)
{
	// 1. Create constant getelementptr getelementptr
	// 2. Call changeObjectType with constant getelementpr

	auto zero = ConstantInt::get(IntegerType::get(_module->getContext(), 32), 0);
	auto eIdx= ConstantInt::get(IntegerType::get(_module->getContext(), 32), idx);
	assert(isa<Constant>(str) && "Dealing with something that is not global");
	ArrayRef<Constant*> af = {zero, eIdx};
	auto* s = dyn_cast<PointerType>(str->getType())->getElementType();
	auto* ce = ConstantExpr::getGetElementPtr(s, dyn_cast<Constant>(str), af);
	auto image = FileImageProvider::getFileImage(_module);
	element = changeObjectDeclarationType(
			image,
			element,
			PointerType::get(ce->getType(), 0),
			ce);
}

size_t IrModifier::getNearestPowerOfTwo(size_t num) const
{
	if (!num)
		return 0;

	size_t bits = 0;
	while (num >>= 1)
		bits++;

	return 1 << bits;
}

/**
 * 1. Find all elemets and their addresses
 * 2. Go through these elements
 *   a. for each determine its maximum possible size
 *   b. go through its usage
 *      - change its usage to shifts of structure element.
 * 3. initialize global variable to point inside element.
 */
void IrModifier::correctElementsInTypeSpace(
		const retdec::utils::Address& start,
		const retdec::utils::Address& end,
		llvm::Value* structure,
		size_t currentIdx)
{
	if (start >= end)
	{
		return;
	}

	std::vector<GlobalVariable*> globals = searchAddressRangeForGlobals(start+1, end);

	for (auto i = globals.begin(); i != globals.end(); i++)
	{
		// Determine element size
		std::size_t elemSize = 0;
		std::size_t supElemSize = end - start;
		auto elemAddr = _config->getGlobalAddress(*i);
		if (i+1 == globals.end())
		{
			elemSize = end - elemAddr;
		}
		else
		{
			auto nxtElemAddr = _config->getGlobalAddress(*(i+1));
			elemSize = nxtElemAddr - elemAddr;
		}

		elemSize = getNearestPowerOfTwo(elemSize);

		auto _abi = AbiProvider::getAbi(_module);
		elemSize = elemSize < _abi->getWordSize() ? elemSize:_abi->getWordSize();

		Value* global = *i;
		auto nType = IntegerType::getIntNTy(_module->getContext(), elemSize*8);
		auto image = FileImageProvider::getFileImage(_module);
		global = changeObjectType(image, global, nType);

		// Users will be changed so we must save all of the first
		std::vector<User*> users;
		for (auto* u: global->users())
			users.push_back(u);

		std::size_t elemOffset = elemAddr - start;
		std::size_t origSize = end - start;

		for (auto* u: users)
		{
			if (auto* ld = dyn_cast<LoadInst>(u))
			{
				// [ |x| |x]
				// shr = origSize - typeSize - offset
				// shl = offset

				auto* gep = getElement(structure, currentIdx);
				gep->insertBefore(ld);
				auto* origType = dyn_cast<PointerType>(gep->getType())->getElementType();
				if (!origType->isIntegerTy()) {
					auto* intRep = IntegerType::getIntNTy(
								_module->getContext(),
								_abi->getTypeBitSize(origType));
					gep = CastInst::CreateBitOrPointerCast(gep, PointerType::get(intRep, 0), "", ld);
					origType = intRep;
				}

				std::size_t shl = (origSize - elemSize - elemOffset)*8;
				auto* lOff = ConstantInt::get(_module->getContext(), APInt(_abi->getTypeBitSize(origType), shl, false));

				Instruction* load = new LoadInst(origType, gep, "", ld);

				if (shl)
					load = BinaryOperator::CreateLShr(load, lOff, "", ld);

				auto* trunc = CastInst::CreateTruncOrBitCast(load, nType, "", ld);

				ld->replaceAllUsesWith(trunc);
				ld->eraseFromParent();
			}
			else if (auto * st = dyn_cast<StoreInst>(u))
			{
				// X  = [x|x]
				// Y  = [ |x|x| | ]
				//
				// Xr = Ysize - off
				// Xl = off + Xsize
				// Yd = (Y >> Xr) << Xr;
				// Yu = (Y << Xl) >> Xl;
				// Y  = Yd | Yu
				// X  = extend(X, Ysize)
				// X  >>= off
				// Y = Y | X

				// X
				auto* saved = st->getValueOperand();
				// Y
				auto* gep = getElement(structure, currentIdx);
				gep->insertBefore(st);

				auto* origType = dyn_cast<PointerType>(gep->getType())->getElementType();
				if (!origType->isIntegerTy())
				{
					auto* intRep = IntegerType::getIntNTy(
								_module->getContext(),
								_abi->getTypeBitSize(origType));
					gep = CastInst::CreateBitOrPointerCast(gep, PointerType::get(intRep, 0), "", st);
					origType = intRep;
				}

				if (!saved->getType()->isIntegerTy())
				{
					auto* intRep = IntegerType::getIntNTy(
								_module->getContext(),
								_abi->getTypeBitSize(saved->getType()));
					saved = CastInst::CreateBitOrPointerCast(saved, intRep, "", st);
				}

				Instruction* gepLoad = new LoadInst(origType, gep, "", st);

				// Xr
				std::size_t ro = (supElemSize - elemOffset)*8;
				// Xl
				std::size_t lo = (elemOffset + elemSize)*8;
				auto* rOff = ConstantInt::get(_module->getContext(), APInt(_abi->getTypeBitSize(origType), ro, false));
				auto* lOff = ConstantInt::get(_module->getContext(), APInt(_abi->getTypeBitSize(origType), lo, false));
				auto* eOff = ConstantInt::get(_module->getContext(), APInt(_abi->getTypeBitSize(origType), elemOffset*8, false));

				llvm::Instruction* lgap = nullptr, * rgap = nullptr;
				// Yd
				if (ro){
					rgap = BinaryOperator::CreateLShr(gepLoad, rOff, "", st);
					rgap = BinaryOperator::CreateShl(rgap, rOff, "", st);
				}
				// Yu
				if (lo != supElemSize*8) {
					lgap = BinaryOperator::CreateShl(gepLoad, lOff, "", st);
					lgap = BinaryOperator::CreateLShr(lgap, lOff, "", st);
				}

				// Y = Yd | Yu
				if (lgap && rgap)
				{
					gepLoad = BinaryOperator::CreateOr(rgap, lgap, "", st);
				}
				else
				{
					gepLoad = rgap ? rgap : lgap;
				}

				saved = CastInst::CreateZExtOrBitCast(saved, origType, "", st);
				saved = BinaryOperator::CreateLShr(saved, eOff, "", st);
				saved = BinaryOperator::CreateOr(saved, gepLoad, "", st);

				new StoreInst(saved, gep, st);
				st->eraseFromParent();
			}
			else if (auto* gp = dyn_cast<GetElementPtrInst>(u))
			{
				// TODO: this should not happen, please check.
				assert(false);
			}

			// TODO:
			// initialize global variable with constant getelementptr.
			// replace all usage with constant getelementptr
		}
	}
}

void IrModifier::correctStackElementsInTypeSpace(
		int startOffset,
		int endOffset,
		llvm::Value* structure,
		size_t currentIdx)
{
	//TODO
}

// TODO: move this to config
std::vector<GlobalVariable*> IrModifier::searchAddressRangeForGlobals(
		const retdec::utils::Address& start,
		const retdec::utils::Address& end)
{
	std::vector<GlobalVariable*> globals;
	for (auto i = start; i < end; i++)
	{
		if (auto* gv = _config->getLlvmGlobalVariable(i))
		{
			globals.push_back(gv);
		}
	}

	return globals;
}

/**
 * 1. Find all elements in padding (and addresses)
 * 2. Cast prev structure element to char*
 * 3. Go through elements and
 *   a. determine for each its max size
 *   b. access prev element with gelemptrinst
 *   c. go through usage of this global
 * 4. initialize global var to point on particular padding char.
 *
 * @param start address on which padding starts
 * @param end   address on which padding ends
 */
void IrModifier::correctElementsInPadding(
		const retdec::utils::Address& start,
		const retdec::utils::Address& end,
		llvm::Value* structure,
		size_t lastIdx)
{
	if (start > end)
	{
		return;
	}
	// Find all elements between range
	std::vector<GlobalVariable*> globals = searchAddressRangeForGlobals(start, end);

	for (auto i = globals.begin(); i != globals.end(); i++)
	{
		// Determine element size
		std::size_t elemSize = 0;
		auto elemAddr = _config->getGlobalAddress(*i);
		if (i+1 == globals.end())
		{
			elemSize = end - elemAddr;
		}
		else
		{
			auto nxtElemAddr = _config->getGlobalAddress(*(i+1));
			elemSize = nxtElemAddr - elemAddr;
		}

		elemSize = getNearestPowerOfTwo(elemSize);

		auto _abi = AbiProvider::getAbi(_module);
		elemSize = elemSize < _abi->getWordSize() ? elemSize:_abi->getWordSize();
		// TODO: only powers of 2

		Value* global = *i;
		auto nType = IntegerType::getIntNTy(_module->getContext(), elemSize*8);
		auto nTypePtr = PointerType::getIntNPtrTy(_module->getContext(), elemSize*8);
		auto image = FileImageProvider::getFileImage(_module);
		global = changeObjectType(image, global, nType);

		// Users will be changed so we must save all of the first
		std::vector<User*> users;
		for (auto* u: global->users())
			users.push_back(u);

		for (auto* u: users)
		{
			if (auto* ld = dyn_cast<LoadInst>(u))
			{
				auto *gep = getElement(structure, lastIdx);
				gep->insertBefore(ld);
				auto *chptr = PointerType::getInt8PtrTy(_module->getContext());
				auto *cast = BitCastInst::CreatePointerCast(gep, chptr);
				cast->insertBefore(ld);
				gep = getArrayElement(cast, elemAddr-start+1);
				gep->insertBefore(ld);
				cast = BitCastInst::CreatePointerCast(gep, nTypePtr);
				cast->insertBefore(ld);

				auto load = new LoadInst(nType, cast, "", ld);
				ld->replaceAllUsesWith(load);
				ld->eraseFromParent();
			}
			else if (auto * st = dyn_cast<StoreInst>(u))
			{
				auto *gep = getElement(structure, lastIdx);
				gep->insertBefore(st);
				auto *chptr = PointerType::getInt8PtrTy(_module->getContext());
				auto *cast = BitCastInst::CreatePointerCast(gep, chptr);
				cast->insertBefore(st);
				gep = getArrayElement(cast, elemAddr-start+1);
				gep->insertBefore(st);
				cast = BitCastInst::CreatePointerCast(gep, nTypePtr);
				cast->insertBefore(st);

				new StoreInst(st->getValueOperand(), cast, st);
				st->eraseFromParent();
			}
			else if (auto* gp = dyn_cast<GetElementPtrInst>(u))
			{
				// TODO: this should not happen, please check.
				assert(false);
			}

			// TODO:
			// initialize global variable with constant getelementptr.
			// replace all usage with constant getelementptr
		}
	}
}

void IrModifier::correctStackElementsInPadding(
		int startOffset,
		int endOffset,
		llvm::Value* structure,
		size_t lastIdx)
{
	/* TODO
	if (startOffset > endOffset)
	{
		return;
	}
	// Find all elements between range
	std::vector<AllocaInst*> globals = searchAddressRangeForLocals(startOffset, endOffset);

	for (auto i = globals.begin(); i != globals.end(); i++)
	{
		// Determine element size
		std::size_t elemSize = 0;
		auto elemAddr = _config->getGlobalAddress(*i);
		if (i+1 == globals.endOffset())
		{
			elemSize = endOffset - elemAddr;
		}
		else
		{
			auto nxtElemAddr = _config->getGlobalAddress(*(i+1));
			elemSize = nxtElemAddr - elemAddr;
		}

		elemSize = getNearestPowerOfTwo(elemSize);

		auto _abi = AbiProvider::getAbi(_module);
		elemSize = elemSize < _abi->getWordSize() ? elemSize:_abi->getWordSize();
		// TODO: only powers of 2

		Value* global = *i;
		auto nType = IntegerType::getIntNTy(_module->getContext(), elemSize*8);
		auto nTypePtr = PointerType::getIntNPtrTy(_module->getContext(), elemSize*8);
		auto image = FileImageProvider::getFileImage(_module);
		global = changeObjectType(image, global, nType);

		// Users will be changed so we must save all of the first
		std::vector<User*> users;
		for (auto* u: global->users())
			users.push_back(u);

		for (auto* u: users)
		{
			if (auto* ld = dyn_cast<LoadInst>(u))
			{
				auto *gep = getElement(structure, lastIdx);
				gep->insertBefore(ld);
				auto *chptr = PointerType::getInt8PtrTy(_module->getContext());
				auto *cast = BitCastInst::CreatePointerCast(gep, chptr);
				cast->insertBefore(ld);
				gep = getArrayElement(cast, elemAddr-startOffset+1);
				gep->insertBefore(ld);
				cast = BitCastInst::CreatePointerCast(gep, nTypePtr);
				cast->insertBefore(ld);

				auto load = new LoadInst(nType, cast, "", ld);
				ld->replaceAllUsesWith(load);
				ld->eraseFromParent();
			}
			else if (auto * st = dyn_cast<StoreInst>(u))
			{
				auto *gep = getElement(structure, lastIdx);
				gep->insertBefore(st);
				auto *chptr = PointerType::getInt8PtrTy(_module->getContext());
				auto *cast = BitCastInst::CreatePointerCast(gep, chptr);
				cast->insertBefore(st);
				gep = getArrayElement(cast, elemAddr-startOffset+1);
				gep->insertBefore(st);
				cast = BitCastInst::CreatePointerCast(gep, nTypePtr);
				cast->insertBefore(st);

				new StoreInst(st->getValueOperand(), cast, st);
				st->eraseFromParent();
			}
			else if (auto* gp = dyn_cast<GetElementPtrInst>(u))
			{
				// TODO: this should not happen, please check.
				assert(false);
			}

			// TODO:
			// initialize global variable with constant getelementptr.
			// replace all usage with constant getelementptr
		}
	}
	*/
}

Value* IrModifier::convertToPointer(
		Value* obj,
		std::size_t ptrDepth)
{
	//std::cout << "Converting to pointer: " << llvmObjToString(obj) << std::endl;
	//std::cout << "Desired pointer length: " << ptrDepth << std::endl;
	auto* ptrType = obj->getType();
	for (std::size_t i = 0; i < ptrDepth; i++)
	{
		ptrType = PointerType::get(ptrType, 0);
	}

	std::list<User*> users;

//	auto image = FileImageProvider::getFileImage(_module);
	auto* nobj = obj;//changeObjectDeclarationType(image, obj, ptrType);
	//std::cout << "New Object: " << llvmObjToString(nobj) << std::endl;

	for (const auto& U : obj->users())
	{
		users.push_back(U);
	}

	for (auto* u: users)
	{
		//std::cout << "u: " << llvmObjToString(u) << std::endl;
		auto first = ConstantInt::get(IntegerType::get(_module->getContext(), 32), ptrDepth);
		std::vector<Value*> idxs(1, first);
		
		if (auto* gep = dyn_cast<GetElementPtrInst>(u))
		{
			bool first = true;
			for (auto& i : gep->indices())
			{
				if (!first)
					idxs.push_back(i.get());
				else
					first = false;
			}
		}
		//std::cout << "using" << std::endl;
		for (auto i: idxs)
		{
			//std::cout << llvmObjToString(i) << std::endl;
		}

		if (auto* i = dyn_cast<Instruction>(u))
		{
			auto* ni = GetElementPtrInst::CreateInBounds(obj->getType()->getPointerElementType(), nobj, idxs);
			//std::cout << "New get elem ptr: " << llvmObjToString(ni) << std::endl;
			ni->insertBefore(i);
			i->replaceAllUsesWith(ni);
			i->eraseFromParent();
		}
		else
		{
			assert(false && "This should not happen!");
		}
	}

	return nobj;
}


Value* IrModifier::convertToStructure(
		Value* obj,
		StructType* strType)
{
	if (auto* gv = dyn_cast<GlobalVariable>(obj))
	{
		auto addr = _config->getGlobalAddress(gv);
		return convertToStructure(gv, strType, addr);
	}
	else if (_config->isStackVariable(obj))
	{
		auto offset = _config->getStackVariableOffset(obj);
		return convertToStructure(dyn_cast<AllocaInst>(obj), strType, offset);
	}

	// TODO: should return casted object
	return obj;
}

Value* IrModifier::createStructureFromStacks(
		AllocaInst* startStack,
		StructType* strType,
		int offset,
		Instruction* before,
		InsertValueInst* newStructure,
		std::vector<unsigned int>idxs)
{
	assert(_config->isStackVariable(startStack) && "Invalid usage of function!");

	auto alignment = getAlignment(strType);
	auto padding = alignment;

	// Create copy of local variable.

	auto* fnc = startStack->getFunction();

	std::size_t idx = 0;
	for (auto elem: strType->elements())
	{
		auto elemIdxs = idxs;
		elemIdxs.push_back(idx++);

		if (auto* eStrType = dyn_cast<StructType>(elem))
		{
			auto newAlignment = getAlignment(eStrType);
			if (alignment > padding) {
				int nOffset = offset+(padding)%newAlignment;
				// TODO: find in padding
				offset = nOffset;
			}

			padding = alignment;

			AllocaInst* structElement = getStackVariable(fnc, offset, elem).first;
			createStructureFromStacks(structElement, eStrType, offset, before, newStructure, elemIdxs);
			continue;
		}

		auto a = AbiProvider::getAbi(_module);
		auto elemSize = a->getTypeByteSize(elem);
		if (padding < elemSize) {
			//TODO: search padding
			offset += padding;
			padding = alignment;
		}

		AllocaInst* structElement = getStackVariable(fnc, offset, elem).first;	
		//TODO: is this way of load/convert correct? should investigate
		Value* conv = convertValueToType(structElement, PointerType::get(elem, 0), before);
		conv = new LoadInst(elem, conv, "", before);

		//TODO: dummy if not found
		newStructure = InsertValueInst::Create(
				newStructure ?
					static_cast<Value*>(newStructure)
					: UndefValue::get(strType),
				conv,
				elemIdxs,
				"",
				before);

		//TODO: serach type space of primitive
		padding -= elemSize;
		offset += elemSize;
	}

	// In case of recursive structures we must align
	// space for correct address.
	padding = padding%alignment;
	if (padding)
	{
		//TODO: search padding
		offset += padding; // (addr-oldAddr)%alignment
	}

	return newStructure;
}

llvm::GlobalVariable* IrModifier::convertToStructure(
		GlobalVariable* gv,
		StructType* strType,
		retdec::utils::Address& addr)
{
	auto alignment = getAlignment(strType);
	auto padding = alignment;
	auto origAddr = addr;

	auto cgv = new GlobalVariable(
			*_module,
			dyn_cast<PointerType>(gv->getType())->getElementType(),
			gv->isConstant(),
			gv->getLinkage(),
			gv->getInitializer());


	auto image = FileImageProvider::getFileImage(_module);
	auto dbgf = DebugFormatProvider::getDebugFormat(_module);

	// This way we will have initializer converted too.
	cgv = dyn_cast<GlobalVariable>(changeObjectDeclarationType(image, cgv, strType));

	std::size_t idx = 0;
	for (auto elem: strType->elements())
	{
		if (auto* eStrType = dyn_cast<StructType>(elem))
		{
			auto newAlignment = getAlignment(eStrType);
			if (alignment > padding) {
				auto naddr = addr+(padding)%newAlignment;
				correctElementsInPadding(addr, naddr, cgv, idx-1);
				addr = naddr;
			}

			padding = alignment;

			GlobalVariable* structElement = getGlobalVariable(image, dbgf, addr);
			auto* origType = dyn_cast<PointerType>(structElement->getType())->getElementType();
			auto* val = changeObjectDeclarationType(image, structElement, eStrType);
			correctUsageOfModifiedObject(structElement, val, origType);

			structElement = dyn_cast<GlobalVariable>(val);
			structElement = convertToStructure(structElement, eStrType, addr);
			replaceElementWithStrIdx(structElement, cgv, idx++);

			continue;
		}

		auto a = AbiProvider::getAbi(_module);
		auto elemSize = a->getTypeByteSize(elem);
		if (padding < elemSize) {
			correctElementsInPadding(addr, addr+padding, cgv, idx-1);
			addr += padding;
			padding = alignment;
		}

		auto structElement = getGlobalVariable(image, dbgf, addr);
		if (structElement == nullptr)
		{
			padding -= elemSize;
			addr += elemSize;
			continue;
		}
		// TODO:
		// following 3 linses of code can go into replaceElementWithStrIdx.
		auto* origType = dyn_cast<PointerType>(structElement->getType())->getElementType();
		auto* val = changeObjectDeclarationType(image, structElement, elem);
		correctUsageOfModifiedObject(structElement, val, origType);

		structElement = dyn_cast<GlobalVariable>(val);

		correctElementsInTypeSpace(addr, addr+elemSize, cgv, idx);
		replaceElementWithStrIdx(structElement, cgv, idx++);
		padding -= elemSize;
		addr += elemSize;
	}

	// During computation will be original global variable changed.
	auto origStr = _config->getLlvmGlobalVariable(origAddr);
	cgv->takeName(origStr);

	//TODO
	//is this necessary?
	auto* econfv = _config->getConfigGlobalVariable(cgv);
	if (econfv)
	{
		retdec::config::Object confv(
				econfv->getName(),
				econfv->getStorage());
		confv.type.setLlvmIr(
				llvmObjToString(cgv->getType()->getPointerElementType()));
		_config->getConfig().globals.insert(confv);
	}

	// Here might lay some elements

	// In case of recursive structures we must align
	// space for correct address.
	padding = padding%alignment;
	if (padding)
	{
		correctElementsInPadding(addr, addr+padding, cgv, idx-1);
		addr += padding; // (addr-oldAddr)%alignment
	}

	return cgv;
}

AllocaInst* IrModifier::convertToStructure(
		AllocaInst* sv,
		StructType* strType,
		int offset)
{
	auto alignment = getAlignment(strType);
	auto padding = alignment;
	int origOffset = offset;

	// Create copy of local variable.
	auto* stCopy = new AllocaInst(strType, Abi::DEFAULT_ADDR_SPACE);
	auto* fnc = sv->getFunction();

	auto it = inst_begin(fnc);
	assert(it != inst_end(fnc));
	stCopy->insertBefore(&*it);

	auto image = FileImageProvider::getFileImage(_module);

	std::size_t idx = 0;
	for (auto elem: strType->elements())
	{
		LOG << "Correcting element: " << llvmObjToString(elem) << std::endl;
		LOG << "offset: " << offset << std::endl;
		if (auto* eStrType = dyn_cast<StructType>(elem))
		{
			auto newAlignment = getAlignment(eStrType);
			if (alignment > padding) {
				int nOffset = offset+(padding)%newAlignment;
				correctStackElementsInPadding(offset, nOffset, stCopy, idx-1);
				offset = nOffset;
			}

			padding = alignment;

			LOG << "Retrieving stack at off: " << offset << std::endl;
			AllocaInst* structElement = getStackVariable(fnc, offset, elem).first;
			LOG << "Retrieved: " << llvmObjToString(structElement) << std::endl;
			auto* origType = dyn_cast<PointerType>(structElement->getType())->getElementType();
			if (origType != elem)
			{
				auto* val = changeObjectDeclarationType(image, structElement, eStrType);
				correctUsageOfModifiedObject(structElement, val, origType);
				structElement = dyn_cast<AllocaInst>(val);
			}

			structElement = convertToStructure(structElement, eStrType, offset);
			replaceElementWithStrIdx(structElement, stCopy, idx++);

			continue;
		}

		auto a = AbiProvider::getAbi(_module);
		auto elemSize = a->getTypeByteSize(elem);
		if (padding < elemSize) {
			correctStackElementsInPadding(offset, offset+padding, stCopy, idx-1);
			offset += padding;
			padding = alignment;
		}

		LOG << "Retrieving stack at off: " << offset << std::endl;
		AllocaInst* structElement = getStackVariable(fnc, offset, elem).first;
		LOG << "Retrieved: " << llvmObjToString(structElement) << std::endl;
		// TODO:
		// following 3 linses of code can go into replaceElementWithStrIdx.
		auto* origType = structElement->getType()->getPointerElementType();
		if (origType != elem) {
			auto* val = changeObjectDeclarationType(image, structElement, elem);
			correctUsageOfModifiedObject(structElement, val, origType);
			structElement = dyn_cast<AllocaInst>(val);
		}

		correctStackElementsInTypeSpace(offset, offset+elemSize, stCopy, idx);
		replaceElementWithStrIdx(structElement, stCopy, idx++);
		padding -= elemSize;
		offset += elemSize;
	}

	// During computation will be original global variable changed.
	auto origStr = _config->getLlvmStackVariable(fnc, origOffset);
	stCopy->takeName(origStr);

	// In case of recursive structures we must align
	// space for correct address.
	padding = padding%alignment;
	if (padding)
	{
		correctStackElementsInPadding(offset, offset+padding, stCopy, idx-1);
		offset += padding; // (addr-oldAddr)%alignment
	}

	return stCopy;
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
	//if (dyn_cast<PointerType>(val->getType())->getElementType() == toType)
	//if (val->getType() == toType)
	//{
	//	return val;
	//}

	if (auto* alloca = dyn_cast<AllocaInst>(val))
	{
		auto* ret = new AllocaInst(
				toType,
				Abi::DEFAULT_ADDR_SPACE,
				alloca->getName(),
				alloca);
		ret->takeName(alloca);
		return ret;
	}
	else if (auto* ogv = dyn_cast<GlobalVariable>(val))
	{
		if (init == nullptr)
		{
			if (objf)
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

void IrModifier::correctUsageOfModifiedObject(Value* val, Value* nval, Type* origType, std::unordered_set<llvm::Instruction*>* instToErase)
{
	// For some reason, iteration using val->user_begin() and val->user_end()
	// may break -- there are many uses, but after modifying one of them,
	// iteration ends before visiting all of them. Even when we increment
	// iterator before modification.
	// Example: @glob_var_0 in arm-elf-059c1a6996c630386b5067c2ccc6ddf2
	// Therefore, we store all uses to our own container.
	//
	std::list<User*> users;
	Constant* newConst = dyn_cast<Constant>(nval);
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
				dst = nval;
				if (nval->getType()->getPointerElementType()->isStructTy())
				{
					auto* gep = getElement(nval, 0);
					gep->insertBefore(store);
					dst = gep;
				}
				PointerType* ptr = dyn_cast<PointerType>(dst->getType());
				assert(ptr);
				src = IrModifier::convertValueToType(src, ptr->getElementType(), store);
				store->setOperand(0, src);
				store->setOperand(1, dst);
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
		else if (auto* gep = dyn_cast<GetElementPtrInst>(user))
		{
			//TODO: we should do this generally with pointers.

			if (nval->getType() == PointerType::get(gep->getPointerOperandType(), 0))
			{
				auto* newLoad = new LoadInst(nval);
				newLoad->insertBefore(gep);
				
				gep->setOperand(0, newLoad);
			}
			else
			{
				auto* conv = IrModifier::convertValueToType(nval, gep->getType(), gep);
				gep->replaceAllUsesWith(conv);
				gep->eraseFromParent();
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
			errs() << "unhandled use : " << *user << " -> " << *val->getType() << "\n";
			assert(false && "unhandled use");
		}
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

	if (val->getType()->getPointerElementType() == toType)
	{
		return val;
	}

	//if (dyn_cast<PointerType>(val->getType())->getElementType() == toType)
	//{
	//	return val;
	//}

	Type* origType = val->getType();
	auto* nval = changeObjectDeclarationType(
			objf,
			val,
			toType,
			init,
			wideString);

	correctUsageOfModifiedObject(val, nval, origType, instToErase);

	// If it is global structure we need to correct elements usage.
	if (auto* strType = dyn_cast<StructType>(toType))
	{
		return convertToStructure(nval, strType);
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
		llvm::Value* retVal,
		const std::vector<ArgumentEntry::Ptr>& args,
		const std::map<llvm::ReturnInst*, llvm::Value*>& rets2vals,
		const std::map<llvm::CallInst*, std::vector<ArgumentEntry::Ptr>>& calls2args,
		bool isVarArg)
{
	//std::cout << "Modifying function " << std::endl;
	//std::cout << fnc << std::endl;
	auto _abi = AbiProvider::getAbi(_module);
	//std::cout << "Her!" << std::endl;
	auto* cf = _config->getConfigFunction(fnc);

	//std::cout << "Her!" << std::endl;
	//std::cout << ret << std::endl;

	if (!FunctionType::isValidReturnType(ret))
	{ 
		//std::cout << "This is bad" << std::endl;
		ret = Abi::getDefaultType(fnc->getParent());
	}

	//std::cout << "what" << std::endl;
	std::vector<ArgumentEntry::Ptr> templArgs = args;
	//std::cout << "no copy!" << std::endl;
	if (args.empty() && !isVarArg && !calls2args.empty())
	{
		//std::cout << "Suicide!" << std::endl;
		templArgs = calls2args.begin()->second;
	}

	//std::cout << "Types:" << std::endl;
	std::vector<Type*> argTypes;
	for (auto& arg: templArgs)
	{
		//std::cout << "at: " << llvmObjToString(arg->getType(fnc, *_abi)) << std::endl;
		argTypes.push_back(arg->getType(fnc, *_abi));
	}

	// New function type.
	//
	ret = ret ? ret : fnc->getReturnType();
	llvm::FunctionType* newFncType = llvm::FunctionType::get(
			ret,
			argTypes,
			isVarArg);

	//std::cout << "Created new function " << std::endl;

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
	
	//std::cout << "Renaming args of new function " << std::endl;

	std::size_t idx = 0;
	std::vector<std::string> argnames;
	for (auto i = nf->arg_begin(), e = nf->arg_end(); i != e; ++i, ++idx)
	{
		llvm::Value* argValue;
		std::string argName;
		std::tie(argValue, argName) = templArgs[idx]->get(nf, *_abi, std::to_string(idx));

		//std::cout << "New arg: " << argName << std::endl;

		if (_abi->isStackVariable(argValue) && argValue->getName() == argName)
		{
			i->takeName(argValue);
		}
		else
		{
			i->setName(argName);
			
		}

		argnames.push_back(argName);
	}

	//std::cout << "Setting args to config function " << std::endl;

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

			arg.setRealName(argnames[idx]);
			arg.setIsFromDebug(true);
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

	//std::cout << "Replacing uses of old args in func body." << std::endl;

	// Replace uses of old arguments in function body for new arguments.
	//
	for (auto i = fnc->arg_begin(), e = fnc->arg_end(), i2 = nf->arg_begin();
			i != e; ++i, ++i2)
	{
		//std::cout << "This happening?" << std::endl;
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
	//std::cout << "Finished" << std::endl;

	// Store arguments into allocated objects (stacks, registers) at the
	// beginning of function body.
	//
	idx = 0;
	bool hasDefinitionArgs = false;
	for (auto& a: args)
	{
		//std::cout << "Perhaps this?" << std::endl;
		if (a->isDefined(nf, *_abi))
		{
			hasDefinitionArgs = true;
		}

		//std::cout << "I knew it!" << std::endl;
	}
	//std::cout << "Found out that function definition is defined? " << hasDefinitionArgs << std::endl; 
	//TODO: check from llvm

	for (auto i = nf->arg_begin(), e = nf->arg_end(); hasDefinitionArgs && i != e; ++i, ++idx)
	{
		auto* v = args[idx]->getValue(nf, *_abi);
		auto* a = &(*i);

		assert(v->getType()->isPointerTy());

		auto primitiveType = a->getType();
		size_t pointerDepth = 0;

		while (primitiveType->isPointerTy())
		{
			primitiveType = primitiveType->getPointerElementType();
			pointerDepth++;
		}

		std::cout << "Converting to primitive" << std::endl;

		//TODO: do not change dewclaration if -> declaration
		Value* conv = v;
		Value* aconv = a;

		if (_config->isStackVariable(conv))
		{
			if (auto* strType = dyn_cast<StructType>(primitiveType))
			{
				//std::cout << "Converting to structure" << std::endl;
				conv = convertToStructure(v, strType);
			}
			else
			{
				conv = changeObjectType(
					FileImageProvider::getFileImage(_module),
					v,
					primitiveType);
			}

			std::cout << "Convering to type" << std::endl;

			//std::cout << "Vhangeing objet type: " << std::endl;
			conv = changeObjectType(
					FileImageProvider::getFileImage(_module),
					conv,
					a->getType());
			std::cout << "Generatinbg store" << std::endl;

			std::cout << "Well conv := " << llvmObjToString(conv) << std::endl;
			std::cout << "Should be pointer of " << llvmObjToString(a) << std::endl;
		}
		else
		{
			aconv = convertValueToType(a, conv->getType()->getPointerElementType(), &nf->front().front());
		}


		auto* s = new StoreInst(aconv, conv);

		std::cout << "generated" << std::endl;

		if (auto* alloca = dyn_cast<AllocaInst>(conv))
		{
			s->insertAfter(alloca);
		}
		else
		{
			if (a == aconv)
			{
				s->insertBefore(&nf->front().front());
			}
			else
			{
				s->insertAfter(cast<Instruction>(aconv));
			}
		}

		std::cout << "Done1" << std::endl;
	}

	std::cout << "Updating returns" << std::endl;

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

	std::cout << "Preparing calls" << nf->getName().str() << std::endl;
	std::map<CallInst*, std::vector<Value*>> preparedCalls;
	// Alter calls
	for (auto ce: calls2args)
	{
		CallInst* call = ce.first;
		std::vector<Value*> args;
		for (auto& arg: ce.second)
		{
			Value* v; Type* t;
			std::tie(v, t) = arg->get(call->getFunction(), *_abi); 
			Value* conv = v;
			std::cout << "\tObject passed as arg: " << llvmObjToString(conv) << std::endl;

			auto* strType = dyn_cast<StructType>(t);
			if (strType && _config->isStackVariable(v))
			{
				conv = createStructureFromStacks(
					dyn_cast<AllocaInst>(conv),
					strType,
					_config->getStackVariableOffset(conv),
					call);
			}
			else if (!t->isPointerTy())
			{
				conv = IrModifier::convertValueToType(conv, PointerType::get(t, 0), call);
				auto* l = new LoadInst(t, conv);
				l->insertBefore(call);
				conv = l;
			}
			else
			{
				auto* l = new LoadInst(conv);
				l->insertBefore(call);
				conv = IrModifier::convertValueToType(l, t, call);
			}
			std::cout << "\tObject passed as arg: " << llvmObjToString(conv) << std::endl;
			args.push_back(conv);
		}

		preparedCalls[call] = args;
	}

	//std::cout << "Preparing other users" << std::endl;

	// Update function users (calls, etc.).
	//
	auto uIt = fnc->user_begin();
	while (uIt != fnc->user_end())
	{
		Value* u = *uIt;
		++uIt;

		if (CallInst* call = dyn_cast<CallInst>(u))
		{
			if (!calls2args.count(call))
			{
				std::vector<Value*> args;
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
				preparedCalls[call] = args;
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

	//std::cout << "Modifing calls and other users" << std::endl;

	for (auto cv: preparedCalls)
	{
		CallInst* call = cv.first;

		//std::cout << "Modifying call" << std::endl;

		auto* nc = _modifyCallInst(
				call,
				nf,
				cv.second);

		//std::cout << "Setting return" << std::endl;

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

	//std::cout << "Changing ret type" << std::endl;

	if (nf->getType() != fnc->getType())
	{
		auto* conv = IrModifier::convertConstantToType(nf, fnc->getType());
		fnc->replaceAllUsesWith(conv);
	}

	// Even when fnc->user_empty() && fnc->use_empty() it still fails here.
	// No ide why.
//	fnc->eraseFromParent();

	//std::cout << "All ok!" << std::endl;
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
	std::vector<ArgumentEntry::Ptr> args;
	std::size_t idx = 0;
	for (auto& a : f->args())
	{
		args.push_back(ArgumentEntry::Ptr(
				new FunctionArgumentEntry(idx, &a == arg ? type : a.getType())));
		idx++;
	}
	auto* nf = modifyFunction(f, f->getReturnType(), nullptr, args).first;
	std::size_t i = 0;
	for (auto& a : nf->args())
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

	return new AllocaInst(
			ty,
			Abi::DEFAULT_ADDR_SPACE,
			name,
			&fnc->getEntryBlock().front());
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
