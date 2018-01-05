/**
* @file src/bin2llvmir/optimizations/never_returning_funcs/never_returning_funcs.cpp
* @brief Implementation of NeverReturningFuncs optimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/Statistic.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

#include "retdec/bin2llvmir/optimizations/never_returning_funcs/never_returning_funcs.h"
#include "retdec/bin2llvmir/providers/config.h"

#define OPTIMIZATION_NAME "never-returning-funcs"
#define DEBUG_TYPE OPTIMIZATION_NAME

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/**
* @brief Adds new @a arg to @a func.
*/
void addNewArgument(Function *func, Argument *arg) {
	func->getArgumentList().push_back(arg);
}

/**
* @brief Returns @c true if both @a first and @a second are @c IntegerType,
*        otherwise @c false.
*/
bool areBothIntegerTypes(const Type &first, const Type &second) {
	return first.isIntegerTy() && second.isIntegerTy();
}

/**
* @brief Returns @c true if types of @a typeInFuncToCheck are equal with
*        @a typeInFuncNeverReturns, otherwise @c false.
*
* This comparison of type is a little bit different. We consider equal types
* like this:
* - int32 is equal with int64. We just compare only if both are IntegerType.
* - If in @a typeInFuncNeverReturns is metadata type we consider both types
*   as equal. It is needed because we use metadata type for non specific types.
* - All other types are compared by @c ==.
*/
bool hasEqType(const Type &typeInFuncToCheck,
		const Type &typeInFuncNeverReturns) {
	if (typeInFuncNeverReturns.isMetadataTy()) {
		// We use metadata type for non specific types. So we consider this
		// as that types are equal.
		return true;
	}

	// We can have for example 32 bit integer or 64 bit integer and so on.
	// But in this situation we need to check only if we have Integer type
	// for this situation.
	return areBothIntegerTypes(typeInFuncToCheck, typeInFuncNeverReturns) ||
		&typeInFuncToCheck == &typeInFuncNeverReturns;
}

/**
* @brief Returns @c true if @a funcToCheck has equal parameters with
*        @a funcNeverReturns, otherwise @c false.
*
* We consider equal types little bit different as is common. For more
* information @c see hasEqType().
*/
bool hasEqParams(const Function &funcToCheck,
		const Function &funcNeverReturns) {
	if (funcToCheck.arg_size() != funcNeverReturns.getArgumentList().size()) {
		// Do not refactor funcNeverReturns.getArgumentList().size() to
		// funcNeverReturns.arg_size(). It gives different results because
		// we don't add attributes to create our function because we don't use
		// attributes. So arg_size() always return zero.

		// Different number of parameters.
		return false;
	}

	auto argOfFuncToCheck(funcToCheck.arg_begin());
	auto argOfFuncNeverReturns(funcNeverReturns.arg_begin());
	while (argOfFuncToCheck != funcToCheck.arg_end()) {
		if (!hasEqType(*argOfFuncToCheck->getType(),
				*argOfFuncNeverReturns->getType())) {
			// Different parameters type.
			return false;
		}
		++argOfFuncToCheck;
		++argOfFuncNeverReturns;
	}

	return true;
}

/**
* @brief Returns @c true if @a funcToCheck is equal with @a funcNeverReturns,
*        otherwise @c false.
*/
bool isEqWithFuncNeverReturns(const Function &funcToCheck,
		const Function &funcNeverReturns) {
	if (funcToCheck.getName() != funcNeverReturns.getName()) {
		return false;
	}

	if (!hasEqType(*funcToCheck.getReturnType(),
			*funcNeverReturns.getReturnType())) {
		// Different return type.
		return false;
	}

	return hasEqParams(funcToCheck, funcNeverReturns);
}

/**
* @brief Removes instruction in @a toRemove from module.
*/
void removeInsts(const InstSet &toRemove) {
	for (Instruction *instToRemove : toRemove) {
		instToRemove->replaceAllUsesWith(UndefValue::get(instToRemove->
			getType()));
		instToRemove->eraseFromParent();
	}
}

/**
* @brief Removes predecessors basic block @a bbToRemove in all PHI nodes in
*        basic block @a removeIn.
*/
void removeBBPredFromPHIFor(BasicBlock &removeIn, BasicBlock &bbToRemove) {
	for (auto i = removeIn.begin(), e = removeIn.end(); i != e; ) {
		if (PHINode *phiNode = dyn_cast<PHINode>(i)) {
			// Need to increment iterator before remove incoming value because
			// when we remove last predecessor node from phi node that function
			// remove the phi instruction and our iterator will be invalid.
			++i;
			phiNode->removeIncomingValue(&bbToRemove, true);
		} else {
			return;
		}
	}
}

/**
* @brief Updates PHI nodes if is needed.
*
* It is needed when terminator instruction is a branch or switch instruction
* and we update PHI nodes in this successors that are jumped from these
* instructions. Update is removing predecessors block from PHI nodes.
* Predecessor block which is removed is specified by parent basic block for
* @a termInst.
*
* @param[in] termInst Terminator instruction which we use for make a decision.
*/
void updatePHINodesIfNeeded(TerminatorInst &termInst) {
	for (int i = 0, e = termInst.getNumSuccessors(); i != e; ++i) {
		removeBBPredFromPHIFor(*termInst.getSuccessor(i),
			*termInst.getParent());
	}
}

} // anonymous namespace

// It is the address of the variable that matters, not the value, so we can
// initialize the ID to anything.
char NeverReturningFuncs::ID = 0;

const char *NeverReturningFuncs::NAME = OPTIMIZATION_NAME;
StringVecFuncMap NeverReturningFuncs::funcNeverReturnsMap;

RegisterPass<NeverReturningFuncs> NeverReturningFuncsRegistered(
	NeverReturningFuncs::getName(), "Never-returning-functions optimization",
	false, false);

STATISTIC(NumUnreachableInstAdded, "Number of added unreachable instructions");

/**
* @brief Created a new optimizer for functions that never return.
*/
NeverReturningFuncs::NeverReturningFuncs(): FunctionPass(ID), module(nullptr) {}

void NeverReturningFuncs::visitCallInst(CallInst &callInst) {
	if (neverReturns(callInst.getCalledFunction())) {
		addInstsThatWillBeRemoved(callInst);
		instsToReplace.insert(callInst.getParent()->getTerminator());
	}
}

/**
* @brief Initiates the optimization before analyzing the function.
*/
void NeverReturningFuncs::initBeforeRun() {
	auto* c = ConfigProvider::getConfig(module);
	if (c)
	{
		c->getConfig().parameters.completedFrontendPasses.insert(getName());
	}

	// We want save instruction to remove and replace only for one function.
	// It is need because when we don't do it we will remove same instructions
	// for all functions which causes segmentation fault.
	instsToRemove.clear();
	instsToReplace.clear();
}

/**
* @brief Initializes @c funcNeverReturnsMap.
*/
void NeverReturningFuncs::initFuncNeverReturnsMap() {
	LLVMContext &context = module->getContext();

	// Currently, we only list the functions about which we actually know that
	// they never return. In created functions doesn't matter on number of bits
	// of integer type used in return types and parameters.
	//
	// We are mapping function to a vector of functions because we can have
	// for function with same name more than one possible declarations.

	//// C90
	// void exit(int status)
	Function *exit(
		Function::Create(FunctionType::get(
			Type::getVoidTy(context), false),
			GlobalValue::ExternalLinkage, "exit")
	);
	addNewArgument(exit, new Argument(Type::getInt32Ty(context)));
	funcNeverReturnsMap["exit"] = {exit};

	// void abort(void)
	Function *abort(
		Function::Create(FunctionType::get(
			Type::getVoidTy(context), false),
			GlobalValue::ExternalLinkage, "abort")
	);
	funcNeverReturnsMap["abort"] = {abort};

	// void longjmp(jmp_buf env, int val)
	Function *longjmp(
		Function::Create(FunctionType::get(
			Type::getVoidTy(context), false),
			GlobalValue::ExternalLinkage, "longjmp")
	);
	// We use here metadata type for jmp_buf because we don't have type for this
	// type. But we can be sure that metadata type is not used in functions
	// that never returns.
	addNewArgument(longjmp, new Argument(Type::getMetadataTy(context)));
	addNewArgument(longjmp, new Argument(Type::getInt32Ty(context)));
	funcNeverReturnsMap["longjmp"] = {longjmp};

	//// C99
	// void _Exit(int status)
	Function *_Exit(
		Function::Create(FunctionType::get(
			Type::getVoidTy(context), false),
			GlobalValue::ExternalLinkage, "_Exit")
	);
	addNewArgument(_Exit, new Argument(Type::getInt32Ty(context)));
	funcNeverReturnsMap["_Exit"] = {_Exit};

	//// C11
	// void quick_exit(int status)
	Function *quick_exit(
		Function::Create(FunctionType::get(
			Type::getVoidTy(context), false),
			GlobalValue::ExternalLinkage, "quick_exit")
	);
	addNewArgument(quick_exit, new Argument(Type::getInt32Ty(context)));
	funcNeverReturnsMap["quick_exit"] = {quick_exit};

	// void thrd_exit(int res)
	Function *thrd_exit(
		Function::Create(FunctionType::get(
			Type::getVoidTy(context), false),
			GlobalValue::ExternalLinkage, "thrd_exit")
	);
	addNewArgument(thrd_exit, new Argument(Type::getInt32Ty(context)));
	funcNeverReturnsMap["thrd_exit"] = {thrd_exit};

	//// Windows API
	// VOID WINAPI ExitProcess(_In_ UINT uExitCode);
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682658(v=vs.85).aspx
	Function *ExitProcess(
		Function::Create(FunctionType::get(
			Type::getVoidTy(context), false),
			GlobalValue::ExternalLinkage, "ExitProcess")
	);
	addNewArgument(ExitProcess, new Argument(Type::getInt32Ty(context)));
	funcNeverReturnsMap["ExitProcess"] = {ExitProcess};

	// VOID WINAPI ExitThread(_In_ DWORD dwExitCode);
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682658(v=vs.85).aspx
	Function *ExitThread(
		Function::Create(FunctionType::get(
			Type::getVoidTy(context), false),
			GlobalValue::ExternalLinkage, "ExitThread")
	);
	addNewArgument(ExitThread, new Argument(Type::getInt32Ty(context)));
	funcNeverReturnsMap["ExitThread"] = {ExitThread};
}

/**
* @brief De-initializes @c funcNeverReturnsMap.
*/
void NeverReturningFuncs::deinitFuncNeverReturnsMap() {
	for (auto &item : funcNeverReturnsMap) {
		for (auto func : item.second) {
			delete func;
		}
	}
}

bool NeverReturningFuncs::doInitialization(llvm::Module &module) {
	this->module = &module;
	initFuncNeverReturnsMap();
	return true;
}

bool NeverReturningFuncs::doFinalization(llvm::Module &module) {
	deinitFuncNeverReturnsMap();
	return true;
}

bool NeverReturningFuncs::runOnFunction(Function &func) {
	return run(func);
}

bool NeverReturningFuncs::runOnFunctionCustom(llvm::Function &func) {
	return run(func);
}

bool NeverReturningFuncs::run(llvm::Function &func) {
	initBeforeRun();

	visit(func);

	// Need to do this at the end, because we don't want erasing instructions
	// when we visiting them.
	removeInsts(instsToRemove);

	// Need to do this at the end, because we don't want replacing instructions
	// when we visiting them.
	replaceTerminatorInstsWithUnreachableInst(instsToReplace);

	NumUnreachableInstAdded = static_cast<unsigned int>(instsToReplace.size());
	return NumUnreachableInstAdded > 0;
}

/**
* @brief Adds instructions that are in basic block after @a inst to set of
*        instruction to remove.
*/
void NeverReturningFuncs::addInstsThatWillBeRemoved(Instruction &inst) {
	BasicBlock *parentBB(inst.getParent());
	Instruction *instToRemove(inst.getNextNode());
	while (instToRemove != parentBB->getTerminator()) {
		instsToRemove.insert(instToRemove);
		instToRemove = instToRemove->getNextNode();
	}
}

/**
* @brief Replaces terminator instructions in @a toReplace with unreachable
*        instructions.
*
* Also updates PHI Nodes in successors that are jumped by branch or switch
* instruction.
*/
void NeverReturningFuncs::replaceTerminatorInstsWithUnreachableInst(
		const NeverReturningFuncs::TerminatorInstSet &toReplace) {
	for (TerminatorInst *instToReplace : toReplace) {
		updatePHINodesIfNeeded(*instToReplace);
		UnreachableInst *unreachableInst(new UnreachableInst(
			module->getContext()));
		ReplaceInstWithInst(instToReplace, unreachableInst);
	}
}

/**
* @brief Returns @c true if @a funcToCheck is equal to some function that never
*        returns, otherwise @c false.
*/
bool NeverReturningFuncs::neverReturns(const Function *func) {
	if (!func) {
		// Indirect call.
		return false;
	}

	if (!func->isDeclaration()) {
		// We consider only functions that don't have definitions.
		return false;
	}

	auto it(funcNeverReturnsMap.find(func->getName()));
	if (it == funcNeverReturnsMap.end()) {
		return false;
	}

	for (const Function *funcNeverReturns : it->second) {
		if (isEqWithFuncNeverReturns(*func, *funcNeverReturns)) {
			return true;
		}
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
