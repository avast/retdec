/**
* @file src/bin2llvmir/optimizations/types_propagator/types_propagator.cpp
* @brief Data type propagation.
* @copyright (c) 2020 Avast Software, licensed under the MIT license
*/

#include <optional>
#include <queue>

#include "retdec/utils/io/log.h"
#include "retdec/bin2llvmir/optimizations/types_propagator/types_propagator.h"

using namespace retdec::utils::io;

namespace retdec {
namespace bin2llvmir {

char TypesPropagator::ID = 0;

static llvm::RegisterPass<TypesPropagator> X(
		"retdec-types-propagation",
		"Data types propagation",
		false, // Only looks at CFG
		false // Analysis Pass
);

TypesPropagator::TypesPropagator() :
		ModulePass(ID)
{

}

bool TypesPropagator::runOnModule(llvm::Module& m)
{
	_module = &m;
	_abi = AbiProvider::getAbi(_module);
	return run();
}

bool TypesPropagator::runOnModuleCustom(
		llvm::Module& m,
		Abi* abi)
{
	_module = &m;
	_abi = abi;
	return run();
}

bool TypesPropagator::run()
{
	if (_module == nullptr)
	{
		return false;
	}

	bool changed = false;

	_RDA.runOnModule(*_module, _abi, false);
	buildEquationSets();

unsigned cntr = 0;
for (auto& eq : _eqSets)
{
	Log::info() << "set #" << cntr++ << std::endl;
	for (auto& v : eq)
	{
		if (llvm::isa<llvm::Function>(v))
			Log::info() << "\t\t" << v->getName().str() << std::endl;
		else
			Log::info() << "\t\t" << llvmObjToString(v) << std::endl;
	}
}
exit(1);

	return changed;
}

void TypesPropagator::buildEquationSets()
{
	// for (auto& global : _module->globals())
	// {
	// 	processRoot(&global);
	// }

	for (auto& fnc : _module->functions())
	{
if (fnc.getName() != "_func") continue;
		for (auto& arg : fnc.args())
		{
			processRoot(&arg);
		}
		for (auto& bb : fnc)
		for (auto& insn : bb)
		{
			processRoot(&insn);
		}
	}
}

bool TypesPropagator::skipRootProcessing(llvm::Value* val)
{
	auto* special = AsmInstruction::getLlvmToAsmGlobalVariable(_module);
	return val == special
			|| _abi->isRegister(val)
			// || (llvm::isa<llvm::Instruction>(val)
			// 		&& !llvm::isa<llvm::AllocaInst>(val))
			|| AsmInstruction::isLlvmToAsmInstruction(val)
			|| wasProcessed(val);
}

void TypesPropagator::processRoot(llvm::Value* val)
{
	if (skipRootProcessing(val))
	{
		return;
	}

	auto& eqSet = _eqSets.emplace_back(EqSet());
	std::queue<llvm::Value*> toProcess({val});
	processValue(toProcess, eqSet);

	if (eqSet.size() <= 1)
	{
		_eqSets.pop_back();
	}
}

void TypesPropagator::processValue(
		std::queue<llvm::Value*>& toProcess,
		EqSet& eqSet)
{
	while (!toProcess.empty())
	{
		auto val = toProcess.front();
		toProcess.pop();
		if (wasProcessed(val))
		{
			continue;
		}

		eqSet.insert(val);
		_val2eqSet.insert({val, &eqSet});

		for (auto user : val->users())
		{
			if (auto* insn = llvm::dyn_cast<llvm::Instruction>(user))
			{
				processUserInstruction(val, insn, toProcess, eqSet);
			}
		}
	}
}

void TypesPropagator::processUserInstruction(
		llvm::Value* val,
		llvm::Instruction* user,
		std::queue<llvm::Value*>& toProcess,
		EqSet& eqSet)
{
	if (auto* ret = llvm::dyn_cast<llvm::ReturnInst>(user))
	{
		addToProcessQueue(ret, toProcess);
		addToProcessQueue(ret->getFunction(), toProcess);
		// No need to add op, this is its user -> it was alreadu processed.
	}
	else if (user->getOpcode() == llvm::Instruction::Add ||
			user->getOpcode() == llvm::Instruction::Sub ||
			user->getOpcode() == llvm::Instruction::FAdd ||
			user->getOpcode() == llvm::Instruction::FSub ||
			user->getOpcode() == llvm::Instruction::Mul ||
			user->getOpcode() == llvm::Instruction::FMul ||
			user->getOpcode() == llvm::Instruction::UDiv ||
			user->getOpcode() == llvm::Instruction::SDiv ||
			user->getOpcode() == llvm::Instruction::FDiv ||
			user->getOpcode() == llvm::Instruction::URem ||
			user->getOpcode() == llvm::Instruction::SRem ||
			user->getOpcode() == llvm::Instruction::Shl ||
			user->getOpcode() == llvm::Instruction::LShr ||
			user->getOpcode() == llvm::Instruction::AShr ||
			user->getOpcode() == llvm::Instruction::And ||
			user->getOpcode() == llvm::Instruction::Or ||
			user->getOpcode() == llvm::Instruction::Xor)
	{
		addToProcessQueue(user, toProcess);
		addToProcessQueue(user->getOperand(0), toProcess);
		addToProcessQueue(user->getOperand(1), toProcess);
	}
	else if (user->getOpcode() == llvm::Instruction::Trunc
			|| user->getOpcode() == llvm::Instruction::ZExt
			|| user->getOpcode() == llvm::Instruction::SExt)
	{
		addToProcessQueue(user, toProcess);
	}
	else if (auto* load = llvm::dyn_cast<llvm::LoadInst>(user))
	{
		// TODO
	}
	else if (auto* store = llvm::dyn_cast<llvm::StoreInst>(user))
	{
		// TODO
	}
	else if (auto* p2i = llvm::dyn_cast<llvm::PtrToIntInst>(user))
	{
		// TODO
	}
	else if (auto* i2p = llvm::dyn_cast<llvm::IntToPtrInst>(user))
	{
		// TODO
	}
	else if (auto* call = llvm::dyn_cast<llvm::CallInst>(user))
	{
		auto* fnc = call->getCalledFunction();
		if (fnc == nullptr)
		{
			return;
		}

		auto callIt = call->arg_begin();
		auto callEnd = call->arg_end();
		auto fncIt = fnc->arg_begin();
		auto fncEnd = fnc->arg_end();
		for (; callIt != callEnd && fncIt != fncEnd; ++callIt, ++fncIt)
		{
			if (val == *callIt)
			{
				addToProcessQueue(fncIt, toProcess);
				break;
			}
		}
	}
}

TypesPropagator::EqSet* TypesPropagator::getEqSetForValue(
		llvm::Value* val)
{
	auto fit = _val2eqSet.find(val);
	return fit != _val2eqSet.end() ? fit->second : nullptr;
}

bool TypesPropagator::wasProcessed(llvm::Value* val)
{
	return _val2eqSet.find(val) != _val2eqSet.end();
}

void TypesPropagator::addToProcessQueue(
		llvm::Value* val,
		std::queue<llvm::Value*>& toProcess)
{
	if (!llvm::isa<llvm::ConstantData>(val))
	{
		toProcess.push(val);
	}
}

} // namespace bin2llvmir
} // namespace retdec
