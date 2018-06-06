/**
* @file src/bin2llvmir/optimizations/simple_types/simple_types.cpp
* @brief Simple type reconstruction analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iomanip>
#include <iostream>
#include <queue>
#include <set>
#include <string>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/utils/time.h"
#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/optimizations/simple_types/simple_types.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

using namespace retdec::utils;
using namespace llvm;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

std::string priority2string(eSourcePriority p)
{
	if (p == eSourcePriority::PRIORITY_NONE) return "PRIORITY_NONE";
	else if (p == eSourcePriority::PRIORITY_LTI) return "PRIORITY_LTI";
	else if (p == eSourcePriority::PRIORITY_DEBUG) return "PRIORITY_DEBUG";
	else return "PRIORITY_UNKNOWN";
}

//
//=============================================================================
//  SimpleTypesAnalysis
//=============================================================================
//

char SimpleTypesAnalysis::ID = 0;

static RegisterPass<SimpleTypesAnalysis> X(
		"simple-types",
		"Simple types recovery optimization",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

SimpleTypesAnalysis::SimpleTypesAnalysis() :
		ModulePass(ID)
{

}

void SimpleTypesAnalysis::getAnalysisUsage(AnalysisUsage& AU) const
{

}

bool SimpleTypesAnalysis::runOnModule(Module& M)
{
	if (!ConfigProvider::getConfig(&M, config))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}
	if (!FileImageProvider::getFileImage(&M, objf))
	{
		LOG << "[ABORT] object file is not available\n";
		return false;
	}
	module = &M;
	_specialGlobal = AsmInstruction::getLlvmToAsmGlobalVariable(module);

	static bool first = true;

	if (first)
	{
		RDA.runOnModule(M, AbiProvider::getAbi(&M));
		buildEqSets(M);
		buildEquations();
		eqSets.propagate(module);
		eqSets.apply(module, config, objf, instToErase);
		eraseObsoleteInstructions();
		setGlobalConstants();
		first = false;
		RDA.clear();
	}
	else
	{
		instToErase.clear();

		IrModifier irModif(module, config);

		std::vector<GlobalVariable*> gvs;
		for (auto& glob : M.getGlobalList())
		{
			gvs.push_back(&glob);
		}

		for (auto* glob : gvs)
		{
			auto* cgv = config->getConfig().globals.getObjectByName(glob->getName());
			if (cgv == nullptr)
			{
				continue;
			}
			if (glob == _specialGlobal)
			{
				continue;
			}

			for (auto* u : glob->users())
			{
				bool done = false;
				if (auto* ce = dyn_cast<ConstantExpr>(u))
				{
					for (auto* uu : ce->users())
					{
						if (auto* call = dyn_cast<CallInst>(uu))
						{
							auto* cfg = config->getConfigFunction(call->getCalledFunction());
							if (cfg == nullptr)
							{
								continue;
							}

							std::size_t n = 0;
							for (auto& a : call->arg_operands())
							{
								if (a == ce)
								{
									break;
								}
								++n;
							}

							if (cfg->parameters.size() <= n)
							{
								continue;
							}

							auto& ca = cfg->parameters[n];
							bool isWide = ca.type.isWideString();

							if (isWide)
							{
								irModif.changeObjectType(objf, glob, ce->getType(), nullptr, &instToErase, false, isWide);
								done = true;
								break;
							}

							if (!llvm_utils::isStringArrayPointeType(glob->getType()) && llvm_utils::isCharPointerType(ce->getType()))
							{
								auto* c = objf->getConstantCharArrayNice(cgv->getStorage().getAddress());
								if (c)
								{
									irModif.changeObjectType(objf, glob, c->getType(), c, &instToErase);
									done = true;
									break;
								}
							}
						}
					}
				}
				else if (auto* call = dyn_cast<CallInst>(u))
				{
					auto* cfg = config->getConfigFunction(call->getCalledFunction());
					if (cfg == nullptr)
					{
						continue;
					}

					std::size_t n = 0;
					for (auto& a : call->arg_operands())
					{
						if (a == glob)
						{
							break;
						}
						++n;
					}

					if (cfg->parameters.size() <= n)
					{
						continue;
					}

					auto& ca = cfg->parameters[n];
					bool isWide = ca.type.isWideString();

					if (isWide)
					{
						irModif.changeObjectType(objf, glob, glob->getType()->getPointerElementType(), nullptr, &instToErase, false, isWide);
						done = true;
						break;
					}
				}

				if (done)
				{
					break;
				}
			}
		}

		eraseObsoleteInstructions();
	}

	return false;
}

void SimpleTypesAnalysis::setGlobalConstants()
{
	for (auto& glob : module->getGlobalList())
	{
		if (config->getConfig().globals.getObjectByName(glob.getName()) == nullptr)
		{
			continue;
		}
		if (!glob.hasInitializer())
		{
			continue;
		}
		auto* cda = dyn_cast<ConstantDataArray>(glob.getInitializer());
		if (cda == nullptr|| (!cda->isString() && !cda->isCString()))
		{
			continue;
		}

		bool c = true;
		for (auto* u : glob.users())
		{
			auto* s = dyn_cast_or_null<StoreInst>(u);
			if (s && s->getPointerOperand() == &glob)
			{
				c = false;
				break;
			}

			for (auto* uu : u->users())
			{
				auto* ss = dyn_cast_or_null<StoreInst>(uu);
				if (ss && ss->getPointerOperand() == u)
				{
					c = false;
					break;
				}

				for (auto* uuu : uu->users())
				{
					auto* sss = dyn_cast_or_null<StoreInst>(uuu);
					if (sss && sss->getPointerOperand() == uu)
					{
						c = false;
						break;
					}
				}

				if (c == false)
				{
					break;
				}
			}

			if (c == false)
			{
				break;
			}
		}
		if (c)
		{
			glob.setConstant(true);
		}
	}
}

void SimpleTypesAnalysis::buildEqSets(Module& M)
{
	for (auto& glob : M.getGlobalList())
	{
		if (config->getConfig().globals.getObjectByName(glob.getName()) == nullptr)
		{
			continue;
		}
		if (&glob == _specialGlobal)
		{
			continue;
		}

		processRoot(&glob);
	}

	for (auto &F : M.getFunctionList())
	{
		LOG << "[FUNCTION]: " << F.getName().str() << " : " << llvmObjToString(F.getType()) << std::endl;

		if (F.empty() || F.isDeclaration())
		{
			continue;
		}

		for (auto& arg : F.getArgumentList())
		{
			processRoot(&arg);
		}

		for (auto &B : F)
		for (auto &I : B)
		{
			if (isa<AllocaInst>(I))
			{
				processRoot(&I);
			}
		}
	}
}

void SimpleTypesAnalysis::processRoot(Value* root)
{
	if (processedObjs.find(root) == processedObjs.end())
	{
		auto& eqSet = eqSets.createEmptySet();
		LOG << "[ROOT #" << eqSet.id << "]: " << llvmObjToString(root) << std::endl;
		std::queue<Value*> toProcess;
		toProcess.push(root);
		processValue(toProcess, eqSet);

		if (eqSet.valSet.size() <= 1 && eqSet.typeSet.size() <= 1 && eqSet.equationSet.size() <= 1)
		{
			eqSets.eqSets.pop_back();
		}
	}
}

/**
 * While not empty, pop value from @p toProcess queue and add it to @p eqSet.
 * Go through all users of this value and based on their instruction types do one of the following:
 * (1) Nothing.
 * (2) Add some value(s) directly to @p eqSet -- user of this value will not be processed.
 * (3) Add some value(s) to @p toProcess -- value will be added to @p eqSet when popped and its
 *     users will be processed.
 *
 * @param toProcess Queue of values to process.
 * @param eqSet Equivalence set to create.
 */
void SimpleTypesAnalysis::processValue(std::queue<Value*>& toProcess, EqSet& eqSet)
{
	while (!toProcess.empty())
	{
		auto current = toProcess.front();
		toProcess.pop();

		if (processedObjs.find(current) != processedObjs.end())
		{
			continue;
		}

		LOG << "\t[CURRENT]: " << llvmObjToString(current) << std::endl;

		eqSet.insert(config, current);
		processedObjs.insert({current, &eqSet});

		for (auto uIt = current->user_begin(); uIt != current->user_end(); ++uIt)
		{
			processUse(current, *uIt, toProcess, eqSet);
		}
	}
}

void SimpleTypesAnalysis::processUse(llvm::Value* current, Value* u, std::queue<Value*>& toProcess, EqSet& eqSet)
{
	if (auto* eu = dyn_cast<ConstantExpr>(u))
	{
		LOG << "\t\t[EU]: " << llvmObjToString(eu) << " -> " << llvmObjToString(eu->getType()) << std::endl;

		for (auto uIt = eu->user_begin(); uIt != eu->user_end(); ++uIt)
		{
			toProcess.push(*uIt);

			if (auto* store = dyn_cast<StoreInst>(*uIt))
			{
				Value* ptr = store->getPointerOperand();

				if (isa<GlobalVariable>(ptr))
				{
					if (config->getConfig().globals.getObjectByName(ptr->getName()))
					{
						toProcess.push(ptr);
					}
					else
					{
						auto uses = RDA.usesFromDef(store);
						for (auto* u : uses)
						{
							toProcess.push(u->use);
						}
					}
				}
				// There is a difference between:
				// #1: store i32 %X, i32* %tmp
				// #2: store i32 %X, i32* @global || store i32 %X, i32* %allocated_local
				// In #2, objects are allocated in LLVM (pointers). We store some value in them -> real object type
				// (i.e. beneath the pointer) is the same as stored value type.
				// In #1, %tmp variable is a pointer (probably created by inttoptr), stored value is not of the same type.
				// TODO: in #1, we should probably create equation: type(%tmp) == type(pointer(%X)).
				//
				else if (isa<AllocaInst>(ptr) || isa<GlobalObject>(ptr)) // anything alse should be processed?
				{
					toProcess.push(ptr);
				}
			}
		}
	}

	Instruction *user = dyn_cast<Instruction>(u);
	if (!user)
	{
		return;
	}

	LOG << "\t\t[USER]: " << llvmObjToString(user) << std::endl;

	//
	// Unhandled:
	// Invoke, Resume, Unreachable, Fence, AtomicCmpXchg, AtomicRMW, AddrSpaceCast, PHI,
	// UserOp1, UserOp2, VAArg, ExtractElement, InsertElement, ShuffleVector, LandingPad,
	// IndirectBr
	//

	if (isa<ReturnInst>(user))
	{
		auto* fnc = user->getParent()->getParent();
		auto* cf = config->getConfig().functions.getFunctionByName(fnc->getName());

		eSourcePriority p = eSourcePriority::PRIORITY_NONE;
		if (cf && cf->isFromDebug())
		{
			p = eSourcePriority::PRIORITY_DEBUG;
		}
		else if (cf && (cf->isDynamicallyLinked() || cf->isIdiom() || cf->isStaticallyLinked() || cf->isSyscall()))
		{
			p = eSourcePriority::PRIORITY_LTI;
		}

		eqSet.insert(fnc->getReturnType(), p);
	}
	else if (isa<BranchInst>(user))
	{
		// br i1 <cond>, label <iftrue>, label <iffalse>
		// br label <dest>          ; Unconditional branch
	}
	else if (isa<SwitchInst>(user))
	{
		// switch <intty> <value>, label <defaultdest> [ <intty> <val>, label <dest> ... ]
	}
	else if (user->getOpcode() == Instruction::Add || user->getOpcode() == Instruction::Sub)
	{
		// TODO - 2 sets (result, operands) are in relation (but not equivalence) that could propagate pointers.
		// this is not critical.
	}
	// TODO - pri sireni pointru mozno bude problem to, ze sme tu nastavili ze op0 == op1
	// pri niektorych operaciach (Shl, And, ...).
	else if (user->getOpcode() == Instruction::FAdd ||
			 user->getOpcode() == Instruction::FSub ||
			 user->getOpcode() == Instruction::Mul ||
			 user->getOpcode() == Instruction::FMul ||
			 user->getOpcode() == Instruction::UDiv ||
			 user->getOpcode() == Instruction::SDiv ||
			 user->getOpcode() == Instruction::FDiv ||
			 user->getOpcode() == Instruction::URem ||
			 user->getOpcode() == Instruction::SRem ||
			 user->getOpcode() == Instruction::Shl ||
			 user->getOpcode() == Instruction::LShr ||
			 user->getOpcode() == Instruction::AShr ||
			 user->getOpcode() == Instruction::And ||
			 user->getOpcode() == Instruction::Or ||
			 user->getOpcode() == Instruction::Xor)
	{
		Value *op0 = user->getOperand(0);
		if (isa<Instruction>(op0)) toProcess.push( op0 );

		Value *op1 = user->getOperand(1);
		if (isa<Instruction>(op1)) toProcess.push( op1 );

		// do not propagate to result, result might be casted to some other type
		// but arguments may not be of this type.
		// example -- integer and operation may be performed on floats (one operand and result
		// are floats, second operand is some integer constant).
	}
	else if (isa<AllocaInst>(user))
	{
		// Alloca probably can not be in uses, but who knows.
		toProcess.push(user);
	}
	else if (auto* load = dyn_cast<LoadInst>(user))
	{
		// See comment for store operation.
		// This should either be solved sooner -- before adding user to list,
		// or we should always get here, but create type(%tmp) == type(pointer(%X))
		// equation if pointer is not an allocated object.
		//
		Value* p = load->getPointerOperand();
		if (isa<AllocaInst>(p) || isa<GlobalObject>(p))
			toProcess.push(user);
	}
	else if (auto* store = dyn_cast<StoreInst>(user))
	{
		Value* ptr = store->getPointerOperand();

		if (isa<GlobalVariable>(ptr))
		{
			if (config->getConfig().globals.getObjectByName(ptr->getName()))
			{
				toProcess.push(ptr);
			}
			else
			{
				auto uses = RDA.usesFromDef(user);
				for (auto* u : uses)
				{
					toProcess.push(u->use);
				}
			}
		}
		// There is a difference between:
		// #1: store i32 %X, i32* %tmp
		// #2: store i32 %X, i32* @global || store i32 %X, i32* %allocated_local
		// In #2, objects are allocated in LLVM (pointers). We store some value in them -> real object type
		// (i.e. beneath the pointer) is the same as stored value type.
		// In #1, %tmp variable is a pointer (probably created by inttoptr), stored value is not of the same type.
		// TODO: in #1, we should probably create equation: type(%tmp) == type(pointer(%X)).
		//
		else if (isa<AllocaInst>(ptr) || isa<GlobalObject>(ptr)) // anything alse should be processed?
		{
			toProcess.push(ptr);
		}
	}
	else if (user->getOpcode() == Instruction::GetElementPtr)
	{
		// TODO
	}
	else if (user->getOpcode() == Instruction::ExtractValue)
	{
		// TODO
	}
	else if (user->getOpcode() == Instruction::InsertValue)
	{
		// TODO
	}
	// a = binary i32 op op1, op2
	// store i32 a, eax
	// b = trunc a, i8
	// c = i8 @llvm.ctpop.i8(i8 b)
	// d = c -> i1
	// store i1 d, pf
	//
	else if (user->getOpcode() == Instruction::Trunc
			&& !user->user_empty()
			&& *user->user_begin() == user->user_back()
			&& isa<CallInst>(user->user_back())
			&& cast<CallInst>(user->user_back())->getCalledFunction()
			&& cast<CallInst>(user->user_back())->getCalledFunction()->isIntrinsic())
	{
		// nothing
	}
	else if (user->getOpcode() == Instruction::Trunc ||
			 user->getOpcode() == Instruction::ZExt ||
			 user->getOpcode() == Instruction::SExt)
	{
		toProcess.push(user);
	}
	else if (user->getOpcode() == Instruction::FPToUI)
	{
		// TODO
	}
	else if (user->getOpcode() == Instruction::FPToSI)
	{
		// TODO
	}
	else if (user->getOpcode() == Instruction::UIToFP)
	{
		// TODO
	}
	else if (user->getOpcode() == Instruction::SIToFP)
	{
		// TODO
	}
	else if (user->getOpcode() == Instruction::FPTrunc)
	{
		// TODO
	}
	else if (user->getOpcode() == Instruction::FPExt)
	{
		// TODO
	}
	else if (user->getOpcode() == Instruction::PtrToInt ||
	         user->getOpcode() == Instruction::BitCast)
	{
		// TODO: propagation problem: %conv_8048572_0 = ptrtoint i32* %stack_var_-16 to i32
		// here, we store pointer to %stack_var_-16 into %conv_8048572_0.
		// %conv_8048572_0 is probably used as a pointer (it contains address of %stack_var_-16).
		// if we put both objects into single eq set, %stack_var_-16 becomes also a pointer,
		// which may not be a case -- features.idioms.current.Test (idioms.c -a x86 -f pe -c gcc -C -O0)
		// However, we ourselves generate PtrToInt in utils convertValueToType() -- in this case,
		// we probably want a propagation.
		// Possible solutions:
		// #1 maybe propagate only if operand is not allocated memory (taking pointer to memory).
		// #2 do not propagate and rely on -type-conversions pass to remove unnecessary conversions.
		auto* op = user->getOperand(0);
		if (!isa<AllocaInst>(op) && !isa<GlobalObject>(op))
		{
			toProcess.push(user);
		}
		else if (isa<GlobalObject>(op))
		{
			val2PtrVal.push_back({user, op});
		}
		else
		{
			LOG << "\t\t\tskipped: (PtrToInt || BitCast) from allocated obj" << std::endl;
		}
	}
	else if (user->getOpcode() == Instruction::IntToPtr)
	{
		toProcess.push(user);
	}
	else if (user->getOpcode() == Instruction::ICmp)
	{
		// TODO
	}
	else if (user->getOpcode() == Instruction::FCmp)
	{
		// TODO
	}
	else if (user->getOpcode() == Instruction::Select)
	{
		// TODO - op0 i1, op1 = op2
	}
	else if (auto* call = dyn_cast<CallInst>(user))
	{
		Function* fnc = call->getCalledFunction();
		if (fnc == nullptr)
			return;

		// If called function is not user defined, we can probably rely
		// on its parameter types -> set LTI.
		//
		auto* cf = config->getConfig().functions.getFunctionByName(fnc->getName());
		if (cf && (cf->isFromDebug()
				|| cf->isDynamicallyLinked()
				|| cf->isIdiom()
				|| cf->isStaticallyLinked()
				|| cf->isSyscall()))
		{
			for (auto& tmp : call->arg_operands())
			{
				if (tmp == current && tmp->getType() != Abi::getDefaultType(module))
				{
					eqSet.insert(tmp->getType(), eSourcePriority::PRIORITY_LTI);
					break;
				}
			}
		}
	}
	else
	{
		LOG << "\t\t\tUNHANDLED" << std::endl;
	}
}

void SimpleTypesAnalysis::buildEquations()
{
	LOG << "\nbuildEquations():" << std::endl;

	for (auto& p : val2PtrVal)
	{
		auto fIt1 = processedObjs.find(p.first);
		auto fIt2 = processedObjs.find(p.second);

		LOG << "\t" << llvmObjToString(p.first) << "(" << (fIt1 != processedObjs.end()) << ")"
				<< "  ->  "
				<< llvmObjToString(p.second) << " (" << (fIt2 != processedObjs.end()) << ")"
				<< std::endl;

		if (fIt1 == processedObjs.end() || fIt2 == processedObjs.end())
		{
			LOG << "\t\tskipped" << std::endl;
			continue;
		}

		fIt1->second->equationSet.insert( EquationEntry::otherIsPtrToThis(fIt2->second) );
		LOG << "\t\t#" << fIt1->second->id << " otherIsPtrToThis #" << fIt2->second->id << std::endl;
	}
}

void SimpleTypesAnalysis::eraseObsoleteInstructions()
{
	for (auto* v : instToErase)
	{
		v->eraseFromParent();
	}
}

//
//=============================================================================
//  EqSetContainer
//=============================================================================
//

EqSet& EqSetContainer::createEmptySet()
{
	eqSets.push_back( EqSet() );
	return eqSets.back();
}

void EqSetContainer::propagate(llvm::Module* module)
{
	for (auto& eq : eqSets)
	{
		eq.propagate(module);
	}
}

void EqSetContainer::apply(
		llvm::Module* module,
		Config* config,
		FileImage* objf,
		std::unordered_set<llvm::Instruction*>& instToErase)
{
	for (auto& eq : eqSets)
	{
		eq.apply(module, config, objf, instToErase);
	}
}

std::ostream& operator<<(std::ostream& out, const EqSetContainer& eqs)
{
	out << std::endl << "equation sets:" << std::endl;
	for (auto &eq : eqs.eqSets)
	{
		out << "\tEQ SET #" << eq.id << ":" << std::endl;
		out << eq << std::endl;
	}
	return out;
}

//
//=============================================================================
//  EqSet
//=============================================================================
//

unsigned EqSet::newUID = 0;

EqSet::EqSet() :
		id(newUID++)
{

}

void EqSet::insert(Config* config, llvm::Value* v, eSourcePriority p)
{
	auto& conf = config->getConfig();

	if (p != eSourcePriority::PRIORITY_NONE)
	{
		valSet.insert( {v,p} );
	}
	else
	{
		if (auto* fnc = dyn_cast<Function>(v))
		{
			auto* cf = conf.functions.getFunctionByName(fnc->getName());
			if (cf && cf->isFromDebug())
			{
				p = eSourcePriority::PRIORITY_DEBUG;
			}
		}
		else if (auto* alloca = dyn_cast<AllocaInst>(v))
		{
			assert(alloca->getParent());
			assert(alloca->getParent()->getParent());
			auto* fnc = alloca->getParent()->getParent();

			auto* cf = conf.functions.getFunctionByName(fnc->getName());
			if (cf)
			{
				auto* local = cf->locals.getObjectByName(alloca->getName());
				if (local && local->isFromDebug())
				{
					p = eSourcePriority::PRIORITY_DEBUG;
				}
			}
		}
		else if (auto* global = dyn_cast<GlobalVariable>(v))
		{
			auto* cg = conf.globals.getObjectByName(global->getName());
			if (cg && cg->isFromDebug())
			{
				p = eSourcePriority::PRIORITY_DEBUG;
			}
		}
		else if (auto* param = dyn_cast<Argument>(v))
		{
			assert(param->getParent());
			auto* fnc = param->getParent();

			auto* cf = conf.functions.getFunctionByName(fnc->getName());
			if (cf)
			{
				auto* cp = cf->parameters.getObjectByName(param->getName());
				if (cp && cp->isFromDebug())
				{
					p = eSourcePriority::PRIORITY_DEBUG;
				}
			}
		}

		valSet.insert( {v,p} );
	}
}

void EqSet::insert(llvm::Type* t, eSourcePriority p)
{
	typeSet.insert( {t,p} );
}

/**
 * See @c getHigherPriorityTypePrivate() comment.
 */
Type* EqSet::getHigherPriorityType(llvm::Module* module, Type* t1, Type* t2)
{
	std::unordered_set<llvm::Type*> seen;
	return getHigherPriorityTypePrivate(module, t1, t2, seen);
}

/**
 * This method defines ordering of types. It takes 2 types and return a 'higher'
 * of them.
 * @param module Module used to get bitsize of type values.
 * @param t1 First type.
 * @param t2 Second type.
 * @param seen Set of all already seen types. Used to protect itself against
 *             infinite recursion.
 * @return Higher of the two types, or first of them if they are equal.
 */

llvm::Type* EqSet::getHigherPriorityTypePrivate(
		llvm::Module* module,
		llvm::Type* t1,
		llvm::Type* t2,
		std::unordered_set<llvm::Type*>& seen)
{
	if (seen.count(t1) || seen.count(t2))
	{
		return t1;
	}
	else
	{
		seen.insert(t1);
		seen.insert(t2);
	}

	if (t1 == t2)
	{
		return t1;
	}
	else if (t1 == nullptr)
	{
		return t2;
	}
	else if (t2 == nullptr)
	{
		return t1;
	}

	// Pointer.
	//
	if (t1->isPointerTy() && t2->isPointerTy())
	{
		auto* t1p = t1->getPointerElementType();
		auto* t2p = t2->getPointerElementType();
		auto* thp = getHigherPriorityTypePrivate(module, t1p, t2p, seen);
		return thp == t1p ? t1 : t2;
	}
	else if (t1->isPointerTy())
	{
		if (t1 == Abi::getDefaultPointerType(module) && t2->isFloatingPointTy())
		{
			return t2;
		}
		else
		{
			return t1;
		}
	}
	else if (t2->isPointerTy())
	{
		if (t2 == Abi::getDefaultPointerType(module) && t1->isFloatingPointTy())
		{
			return t1;
		}
		else
		{
			return t2;
		}
	}
	// Function
	//
	else if (t1->isFunctionTy() && t2->isFunctionTy())
	{
		auto sz1 = t1->getFunctionNumParams();
		auto sz2 = t2->getFunctionNumParams();
		if (sz1 > sz2)
		{
			return t1;
		}
		else if (sz1 < sz2)
		{
			return t2;
		}
		else // sz1 == sz2
		{
			for (unsigned i = 0; i < sz1; ++i)
			{
				auto* t1p = t1->getFunctionParamType(i);
				auto* t2p = t2->getFunctionParamType(i);
				auto* thp1 = getHigherPriorityTypePrivate(module, t1p, t2p, seen);
				auto* thp2 = getHigherPriorityTypePrivate(module, t2p, t1p, seen);
				if (thp1 == thp2 && thp2 == t1p)
				{
					return t1;
				}
				else if (thp1 == thp2 && thp2 == t2p)
				{
					return t2;
				}
			}

			return t1;
		}
	}
	else if (t1->isFunctionTy())
	{
		return t1;
	}
	else if (t2->isFunctionTy())
	{
		return t2;
	}
	// Structure.
	//
	else if (t1->isStructTy() && t2->isStructTy())
	{
		auto sz1 = t1->getStructNumElements();
		auto sz2 = t2->getStructNumElements();
		if (sz1 > sz2)
		{
			return t1;
		}
		else if (sz1 < sz2)
		{
			return t2;
		}
		else // sz1 == sz2
		{
			for (unsigned i = 0; i < sz1; ++i)
			{
				auto* t1p = t1->getStructElementType(i);
				auto* t2p = t2->getStructElementType(i);
				auto* thp1 = getHigherPriorityTypePrivate(module, t1p, t2p, seen);
				auto* thp2 = getHigherPriorityTypePrivate(module, t2p, t1p, seen);
				if (thp1 == thp2 && thp2 == t1p)
				{
					return t1;
				}
				else if (thp1 == thp2 && thp2 == t2p)
				{
					return t2;
				}
			}

			auto* s1 = dyn_cast<StructType>(t1);
			auto* s2 = dyn_cast<StructType>(t2);
			if (s1 && s2)
			{
				std::string s1n = s1->getName().str();
				std::string s2n = s2->getName().str();
				if (s1n > s2n)
				{
					return t1;
				}
				else if (s2n > s1n)
				{
					return s2;
				}
			}

			return t1;
		}
	}
	else if (t1->isStructTy())
	{
		return t1;
	}
	else if (t2->isStructTy())
	{
		return t2;
	}
	// Array.
	//
	else if (t1->isArrayTy() && t2->isArrayTy())
	{
		auto* t1p = t1->getArrayElementType();
		auto* t2p = t2->getArrayElementType();
		auto* thp = getHigherPriorityTypePrivate(module, t1p, t2p, seen);
		return thp == t1p ? t1 : t2;
	}
	else if (t1->isArrayTy())
	{
		return t1;
	}
	else if (t2->isArrayTy())
	{
		return t2;
	}
	// Vector.
	//
	else if (t1->isVectorTy() && t2->isVectorTy())
	{
		auto* t1p = t1->getVectorElementType();
		auto* t2p = t2->getVectorElementType();
		auto* thp = getHigherPriorityTypePrivate(module, t1p, t2p, seen);
		return thp == t1p ? t1 : t2;
	}
	else if (t1->isVectorTy())
	{
		return t1;
	}
	else if (t2->isVectorTy())
	{
		return t2;
	}
	// X86 MMX.
	//
	else if (t1->isX86_MMXTy() && t2->isX86_MMXTy())
	{
		auto sz1 = module->getDataLayout().getTypeSizeInBits(t1);
		auto sz2 = module->getDataLayout().getTypeSizeInBits(t2);
		return sz1 >= sz2 ? t1 : t2;
	}
	else if (t1->isX86_MMXTy())
	{
		return t1;
	}
	else if (t2->isX86_MMXTy())
	{
		return t2;
	}
	// Floating point.
	//
	if (t1->isFloatingPointTy() && t2->isFloatingPointTy())
	{
		auto sz1 = module->getDataLayout().getTypeSizeInBits(t1);
		auto sz2 = module->getDataLayout().getTypeSizeInBits(t2);
		return sz1 >= sz2 ? t1 : t2;
	}
	else if (t1->isFloatingPointTy())
	{
		return t1;
	}
	else if (t2->isFloatingPointTy())
	{
		return t2;
	}
	// Integer.
	//
	else if (t1->isIntegerTy() && t2->isIntegerTy())
	{
		auto sz1 = module->getDataLayout().getTypeSizeInBits(t1);
		auto sz2 = module->getDataLayout().getTypeSizeInBits(t2);
		auto defSz = Abi::getDefaultType(module)->getBitWidth();

		if (sz1 == defSz)
		{
			return t2;
		}
		else if (sz2 == defSz)
		{
			return t1;
		}
		else
		{
			return sz1 >= sz2 ? t1 : t2;
		}
	}
	else if (t1->isIntegerTy())
	{
		return t1;
	}
	else if (t2->isIntegerTy())
	{
		return t2;
	}
	// Void.
	//
	else if (t1->isVoidTy())
	{
		return t1;
	}
	else if (t2->isVoidTy())
	{
		return t2;
	}
	// Label.
	else if (t1->isLabelTy())
	{
		return t1;
	}
	else if (t2->isLabelTy())
	{
		return t2;
	}
	// Metadata.
	else if (t1->isMetadataTy())
	{
		return t1;
	}
	else if (t2->isMetadataTy())
	{
		return t2;
	}
	// Default.
	else
	{
		return t1;
	}
}

void EqSet::propagate(llvm::Module* module)
{
	if (valSet.empty())
		return;

	LOG << "\npropagate BEGIN " << id << " =============================\n";

	for (auto& vs : valSet)
	{
		Type* valueType = vs.getTypeForPropagation();

		if (vs.priority < masterType.priority)
		{
			continue;
		}
		else if (vs.priority == masterType.priority)
		{
			if (valueType != masterType.type && masterType.priority != eSourcePriority::PRIORITY_NONE)
			{
				LOG << "[WARNING] same priority types differ: "
					<< llvmObjToString(valueType) << " vs. "
					<< llvmObjToString(masterType.type) << std::endl;
			}

			auto* r = getHigherPriorityType(module, masterType.type, valueType);
			if (r == valueType)
			{
				masterType.type = valueType;
			}
		}
		else if (vs.priority > masterType.priority)
		{
			masterType.priority = vs.priority;
			masterType.type = valueType;
		}
	}
	for (auto& ts : typeSet)
	{
		if (ts.priority < masterType.priority)
		{
			continue;
		}
		else if (ts.priority == masterType.priority)
		{
			if (ts.type != masterType.type && masterType.priority != eSourcePriority::PRIORITY_NONE)
			{
				LOG << "[WARNING] same priority types differ: "
					<< llvmObjToString(ts.type) << " vs. "
					<< llvmObjToString(masterType.type) << std::endl;
			}

			auto* r = getHigherPriorityType(module, masterType.type, ts.type);
			if (r == ts.type)
			{
				masterType.type = ts.type;
			}
		}
		else if (ts.priority > masterType.priority)
		{
			masterType.priority = ts.priority;
			masterType.type = ts.type;
		}
	}

	LOG << *this;
	LOG << "\npropagate END   " << id << " =============================\n";
}

void EqSet::apply(
		llvm::Module* module,
		Config* config,
		FileImage* objf,
		std::unordered_set<llvm::Instruction*>& instToErase)
{
	if (valSet.empty())
		return;

	LOG << "\napply BEGIN " << id << " =============================\n";

	static auto &conf = config->getConfig();

	IrModifier irModif(module, config);
	for (auto& vs : valSet)
	{
		if (!(isa<AllocaInst>(vs.value) || isa<GlobalVariable>(vs.value) || isa<Argument>(vs.value)))
		{
			continue;
		}
		if (vs.getTypeForPropagation() == masterType.type
				|| masterType.type == nullptr
				|| (vs.priority >= masterType.priority && vs.priority > eSourcePriority::PRIORITY_NONE)
				|| vs.getTypeForPropagation()->isAggregateType())
		{
			continue;
		}
		if (conf.registers.getObjectByName(vs.value->getName()))
		{
			continue;
		}
		if (masterType.type->isPointerTy())
		{
			llvm::Value* vsv = vs.value;
			if (vsv->getType()->isPointerTy())
			{
				llvm::Type* ptr = vsv->getType()->getPointerElementType();
				if (ptr->isPointerTy() || ptr->isArrayTy())
				{
					continue;
				}
			}
		}

		LOG << "\t" << vs << "  ==>  " << llvmObjToString(masterType.type) << std::endl;

		irModif.changeObjectType(objf, vs.value, masterType.type, nullptr, &instToErase);
	}

	LOG << "\napply END   " << id << " =============================\n";
}

std::ostream& operator<<(std::ostream &out, const EqSet &eq)
{
	out << "\t\tTYPE = " << eq.masterType << std::endl;

	out << std::endl << "\t\tVALUES:" << std::endl;
	for (auto &e : eq.valSet)
	{
		out << "\t\t\t" << e << std::endl;
	}
	out << std::endl << "\t\tTYPES:" << std::endl;
	for (auto &t : eq.typeSet)
	{
		out << "\t\t\t" << t << std::endl;
	}
	out << std::endl << "\t\tEQUATIONS:" << std::endl;
	for (auto &e : eq.equationSet)
	{
		out << "\t\t\t" << e << std::endl;
	}

	return out;
}

//
//=============================================================================
//  ValueEntry
//=============================================================================
//

ValueEntry::ValueEntry(Value* v, eSourcePriority p) :
		value(v),
		priority(p)
{

}

/**
 * We want to proapgate true type of this entry.
 * However, object allocated on stack (@c AllocaInst),
 * and object in global memory (@c GlobalVariable),
 * are considered pointers on their own by LLVM.
 * Therefore we must subtract one pointer level to get the
 * type we need.
 */
llvm::Type* ValueEntry::getTypeForPropagation() const
{
	if (isa<AllocaInst>(value) || isa<GlobalVariable>(value))
	{
		if (value->getType()->isPointerTy())
		{
			auto* elem = value->getType()->getPointerElementType();
			if (elem->isArrayTy())
			{
				return PointerType::get(elem->getArrayElementType(), 0);
			}
			else if (elem->isPointerTy() && elem->getPointerElementType()->isArrayTy())
			{
				return PointerType::get(elem->getPointerElementType()->getArrayElementType(), 0);
			}
			else
			{
				return elem; // original
			}
		}
	}
	else if (Function* fnc = dyn_cast<Function>(value))
	{
		return fnc->getReturnType();
	}

	return value->getType();
}

bool ValueEntry::operator==(const ValueEntry &o) const
{
	return value == o.value;
}

bool ValueEntry::operator<(const ValueEntry &o) const
{
	return value < o.value;
}

std::size_t ValueEntry::hash() const
{
	std::hash<Value*> f;
	return f(value);
}

std::ostream& operator<<(std::ostream &out, const ValueEntry &ve)
{
	out << ve.value->getName().str() << " : "
		<< "propagation = " << llvmObjToString(ve.getTypeForPropagation())
		<< ", "
		<< "real = " << llvmObjToString(ve.value->getType())
		<< " (" << priority2string(ve.priority) << ")";
	return out;
}

//
//=============================================================================
//  TypeEntry
//=============================================================================
//

TypeEntry::TypeEntry(Type* t, eSourcePriority p) :
		type(t),
		priority(p)
{

}

bool TypeEntry::operator==(const TypeEntry &o) const
{
	return type == o.type;
}

bool TypeEntry::operator<(const TypeEntry &o) const
{
	return type < o.type;
}

std::size_t TypeEntry::hash() const
{
	std::hash<Type*> f;
	return f(type);
}

std::ostream& operator<<(std::ostream &out, const TypeEntry &te)
{
	out << llvmObjToString(te.type)
		<< " (" << priority2string(te.priority) << ")";
	return out;
}

//
//=============================================================================
//  EquationEntry
//=============================================================================
//

EquationEntry::EquationEntry(EqSet* o, eqType t) :
		other(o),
		type(t)
{
	assert(other);
}

EquationEntry EquationEntry::otherIsPtrToThis(EqSet* o)
{
	return EquationEntry(o, eqType::otherIsPtrToThis);
}

EquationEntry EquationEntry::thisIsPtrToOther(EqSet* o)
{
	return EquationEntry(o, eqType::thisIsPtrToOther);
}

bool EquationEntry::operator==(const EquationEntry& o) const
{
	return other == o.other;
}

bool EquationEntry::operator<(const EquationEntry& o) const
{
	return other < o.other;
}

std::size_t EquationEntry::hash() const
{
	std::hash<EqSet*> f;
	return f(other);
}

bool EquationEntry::isOtherIsPtrToThis()
{
	return type == eqType::otherIsPtrToThis;
}

bool EquationEntry::isThisIsPtrToOther()
{
	return type == eqType::thisIsPtrToOther;
}

std::ostream& operator<<(std::ostream& out, const EquationEntry& ee)
{
	std::string eq;
	switch (ee.type)
	{
		case EquationEntry::eqType::otherIsPtrToThis: eq = "otherIsPtrToThis"; break;
		case EquationEntry::eqType::thisIsPtrToOther: eq = "thisIsPtrToOther"; break;
		default: eq = "unknown"; break;
	}

	out << eq << "(other = #" << ee.other->id << ")";
	return out;
}

} // namespace bin2llvmir
} // namespace retdec
