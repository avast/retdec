/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter.cpp
* @brief Implementation of OrigLLVMIR2BIRConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cstddef>
#include <vector>

#include <llvm/Analysis/LoopInfo.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/CallSite.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/value.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/llvm/llvm_debug_info_obtainer.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converter_factory.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/labels_handler.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/llvm_branch_info.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/llvm_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/vars_handler.h"
#include "retdec/llvmir2hll/llvm/string_conversions.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expression_negater.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/utils/string.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gens/num_var_name_gen.h"
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"

using namespace retdec::llvm_support;
using namespace std::string_literals;

using retdec::utils::hasItem;
using retdec::utils::mapHasKey;

namespace retdec {
namespace llvmir2hll {

namespace {

REGISTER_AT_FACTORY("orig", ORIG_LLVMIR2BIR_CONVERTER_ID, LLVMIR2BIRConverterFactory,
	OrigLLVMIR2BIRConverter::create);

/// Vector of PHI nodes.
using PHINodesVector = std::vector<llvm::PHINode *>;

/**
* @brief Returns @c true if @a phiNode1 depends on @a phiNode2, @c false
*        otherwise.
*
* @e Depends means that @a phiNode2 sets a variable which is used in @a
* phiNode1. For example, in the following code, the second PHI node depends on
* the first one:
* @code
* %A = phi i32 [ %D, %label ], [ 10, %0 ]
* %B = phi i32 [ %A, %label ], [ 66, %0 ]
* @endcode
* So, <tt>dependsOn(first, second)</tt> returns @c false and
* <tt>dependsOn(second, first)</tt> returns @c true.
*/
bool dependsOn(llvm::PHINode *phiNode1, llvm::PHINode *phiNode2) {
	// We assume that every variable has a name. To ensure this, the -instnamer
	// pass has to be used when optimizing the LLVM IR in bin2llvmir.
	const std::string &var2Name(phiNode2->getName());
	for (unsigned i = 0, e = phiNode1->getNumIncomingValues(); i < e; ++i) {
		llvm::Value *incValue(phiNode1->getIncomingValue(i));
		if (incValue->getName() == var2Name) {
			return true;
		}
	}
	return false;
}

/**
* @brief Returns all PHI nodes in the given basic block.
*/
PHINodesVector getPHINodes(llvm::BasicBlock &bb) {
	PHINodesVector phiNodes;
	// In LLVM IR, PHI nodes precede all other instructions. Therefore, we can
	// stop when we reach the first non-PHI instruction.
	for (auto i = bb.begin(); llvm::isa<llvm::PHINode>(i); ++i) {
		phiNodes.push_back(llvm::cast<llvm::PHINode>(&*i));
	}
	return phiNodes;
}

/**
* @brief Returns @c true if the given PHI nodes can be ordered, @c false
*        otherwise.
*
* Two PHI nodes can be ordered if and only if there are no distinct nodes @c A
* and @c B such that @c A (transitively) depends on @c B and @c B
* (transitively) depends on @c A.
*/
bool canBeOrdered(const PHINodesVector &phiNodes) {
	// For every PHI node...
	for (std::size_t i = 0, e = phiNodes.size(); i != e; ++i) {
		// Follow the dependency relation for the current PHI node and check
		// that there is no cycle in the dependency graph.
		std::set<llvm::PHINode *> checkedNodes{phiNodes[i]};
		std::size_t k = i, j = 0, f = phiNodes.size();
		while (j != f) {
			if (k != j && dependsOn(phiNodes[k], phiNodes[j])) {
				if (hasItem(checkedNodes, phiNodes[j])) {
					// We have encountered a PHI node that depends on a node
					// that we have already checked. This means that there is a
					// cycle in the dependency graph.
					return false;
				}
				checkedNodes.insert(phiNodes[j]);
				k = j;
				j = 0;
			} else {
				++j;
			}
		}
	}
	return true;
}

/**
* @brief Returns @c true if @a srcNode is reachable from @a dstNode in the
*        given basic block @a bb, @c false otherwise.
*/
bool isReachable(llvm::PHINode *dstNode, llvm::PHINode *srcNode,
		llvm::BasicBlock &bb) {
	bool srcNodeFound(false);
	// In LLVM IR, PHI nodes precede all other instructions. Therefore, we can
	// stop when we reach the first non-PHI instruction.
	for (auto i = bb.begin(); llvm::isa<llvm::PHINode>(i); ++i) {
		if (&*i == srcNode) {
			srcNodeFound = true;
		}
		if (srcNodeFound && &*i == dstNode) {
			return true;
		}
	}
	return false;
}

/**
* @brief Performs the ordering of the given PHI nodes in the given basic block
*        according to their dependencies.
*
* @par Preconditions
*  - the PHI nodes can be ordered (see canBeOrdered())
*/
void performOrderingOfDependentPHINodes(const PHINodesVector &phiNodes,
		llvm::BasicBlock &bb) {
	bool changed;
	do {
		changed = false;
		for (std::size_t i = 0, e = phiNodes.size(); i != e; ++i) {
			for (std::size_t j = 0, f = phiNodes.size(); j != f; ++j) {
				if (i != j && dependsOn(phiNodes[i], phiNodes[j]) &&
						!isReachable(phiNodes[j], phiNodes[i], bb)) {
					phiNodes[i]->moveBefore(phiNodes[j]);
					changed = true;
				}
			}
		}
	} while (changed);
}

/**
* @brief Orders PHI nodes in the given basic block according to their
*        dependencies.
*
* For a description of what this function does, see orderDependentPHINodes()
* for llvm::Module.
*/
void orderDependentPHINodes(llvm::BasicBlock &bb) {
	PHINodesVector phiNodes(getPHINodes(bb));
	if (phiNodes.size() < 2) {
		return;
	}

	if (!canBeOrdered(phiNodes)) {
		printWarningMessage("Cannot order PHI nodes of basic block ", bb.getName(),
			" in function ", bb.getParent()->getName(), "().");
		return;
	}

	performOrderingOfDependentPHINodes(phiNodes, bb);
}

/**
* @brief Orders PHI nodes in the given function according to their dependencies.
*
* For a description of what this function does, see orderDependentPHINodes()
* for llvm::Module.
*/
void orderDependentPHINodes(llvm::Function &func) {
	for (auto &bb : func) {
		orderDependentPHINodes(bb);
	}
}

/**
* @brief Orders PHI nodes in the given LLVM module according to their
*        dependencies.
*
* Before we convert LLVM IR to BIR, we need to order PHI nodes according to
* their interdependencies. Consider the following two PHI nodes:
* @code
* %A = phi i32 [ %D, %label ], [ 10, %0 ]
* %B = phi i32 [ %A, %label ], [ 66, %0 ]
* @endcode
* The semantics of PHI nodes dictates that both these instructions should be
* evaluated in parallel. Therefore, @c %B gets the old value of @c %A, not the
* updated one. However, in BIR, we want the evaluation to be sequential. To
* this end, in this function, we try to order the PHI nodes in such a way that
* allows easy conversion into BIR. In the example above, we swap the two PHI
* nodes.
*
* If the nodes cannot be ordered (i.e. there are two nodes that depend on each
* other), it prints an error message.
*/
void orderDependentPHINodes(llvm::Module &module) {
	// For every function in the module...
	for (auto &func : module) {
		orderDependentPHINodes(func);
	}
}

/**
* @brief Checks if the given global variable is internal.
*
* See Variable::isInternal() for more details.
*/
bool isInternal(const llvm::GlobalVariable *gv) {
	// Consider also private linkage as internal linkage.
	return gv->hasInternalLinkage() || gv->hasPrivateLinkage();
}

/**
* @brief Checks if the given global variable is external.
*
* See Variable::isExternal() for more details.
*/
bool isExternal(const llvm::GlobalVariable *gv) {
	return !isInternal(gv);
}

} // anonymous namespace

/**
* @brief Constructs a new converter.
*
* See create() for the description of parameters.
*/
OrigLLVMIR2BIRConverter::OrigLLVMIR2BIRConverter(llvm::Pass *basePass):
	LLVMIR2BIRConverter(basePass), llvmModule(nullptr), resModule(), varsHandler(),
	converter(), branchInfo(), labelsHandler(), processedBBs(), bbStmtMap(),
	gotoStmtsToPatch(), currLoopBB(nullptr), lastLoopExitBB(nullptr),
	generatingSwitchStmt(false) {}

/**
* @brief Creates a new instance of LLVMIR2BIRConverter.
*
* @param[in] basePass Pass that instantiates this converter.
*
* @par Preconditions
*  - @a basePass is non-null
*/
ShPtr<LLVMIR2BIRConverter> OrigLLVMIR2BIRConverter::create(llvm::Pass *basePass) {
	PRECONDITION_NON_NULL(basePass);

	return ShPtr<LLVMIR2BIRConverter>(new OrigLLVMIR2BIRConverter(basePass));
}

std::string OrigLLVMIR2BIRConverter::getId() const {
	return ORIG_LLVMIR2BIR_CONVERTER_ID;
}

ShPtr<Module> OrigLLVMIR2BIRConverter::convert(llvm::Module *llvmModule,
		const std::string &moduleName, ShPtr<Semantics> semantics,
		ShPtr<Config> config, bool enableDebug) {
	PRECONDITION_NON_NULL(llvmModule);
	PRECONDITION_NON_NULL(semantics);

	if (enableDebug) {
		printSubPhase("ordering dependent PHI nodes");
	}
	orderDependentPHINodes(*llvmModule);

	this->llvmModule = llvmModule;
	this->enableDebug = enableDebug;
	resModule = ShPtr<Module>(new Module(llvmModule, moduleName, semantics, config));
	varsHandler = ShPtr<VarsHandler>(new VarsHandler(resModule,
		NumVarNameGen::create()));
	converter = ShPtr<LLVMConverter>(new LLVMConverter(llvmModule,
		resModule, varsHandler));
	converter->setOptionStrictFPUSemantics(optionStrictFPUSemantics);
	branchInfo = ShPtr<LLVMBranchInfo>(new LLVMBranchInfo(
		converter, varsHandler));
	labelsHandler = std::make_unique<LabelsHandler>();

	// Function declarations have to be added to the module before any function
	// or global variable definition. The reason is that if there is an
	// assignment or call of a function whose declaration hasn't been added to
	// the module yet, we'll run into troubles.
	visitAndAddFunctionDeclarations();
	visitAndAddGlobalVariables();
	visitAndAddFunctions();

	makeIdentifiersValid();

	return resModule;
}

/**
* @brief Visits and adds all functions in the module.
*
* Only function definitions are considered.
*/
void OrigLLVMIR2BIRConverter::visitAndAddFunctions() {
	for (auto &f : *llvmModule) {
		// Do not convert 'available_externally' functions because they have
		// definitions outside the translation unit. Also, skip function
		// declarations since they've been already added into the resulting
		// module.
		if (f.hasAvailableExternallyLinkage() || f.isDeclaration()) {
			continue;
		}

		if (enableDebug) {
			printSubPhase("converting "s + std::string(f.getName()) + "()"s);
		}

		// Initialization of all per-function lists, maps, etc.
		varsHandler->reset();
		branchInfo->init(
			&basePass->getAnalysis<llvm::LoopInfoWrapperPass>(f).getLoopInfo()
		);
		lastLoopExitBB = nullptr;

		// Generate the IR for the function.
		visitAndAddFunction(f);
	}
}

/**
* @brief Visits global variables of the current module and stores them into
*        the resulting module.
*/
void OrigLLVMIR2BIRConverter::visitAndAddGlobalVariables() {
	varsHandler->startConvertingGlobalVars();

	// For each global variable...
	for (auto i = llvmModule->global_begin(), e = llvmModule->global_end();
			i != e; ++i) {
		// Ignore global constants storing string literals.
		if (resModule->isGlobalVarStoringStringLiteral(i->getName()) ||
				stores8BitStringLiteral(&*i)) {
			continue;
		}

		// Create and add the variable.
		ShPtr<Type> varType;
		ShPtr<Expression> varInit;

		if (i->hasInitializer()) {
			// Check whether the variable represents a string, and if so,
			// convert it into a string.
			llvm::ConstantDataArray *cda = llvm::dyn_cast<llvm::ConstantDataArray>(
				i->getInitializer());
			if (cda && cda->isString()) {
				varType = ArrayType::create(
					converter->llvmTypeToType(cda->getElementType()),
					ArrayType::Dimensions(1, cda->getNumElements()));
				varInit = toConstString(cda);
			} else {
				// Not a string, so just convert the initializer.
				varInit = converter->llvmValueToExpression(i->getInitializer());
			}
		}

		// Default conversion.
		if (!varType) {
			varType = converter->llvmTypeToType(i->getType()->getContainedType(0));
		}
		if (!varInit) {
			varInit = converter->getInitializer(&*i);
		}

		std::string varName(varsHandler->getValueName(&*i));
		ShPtr<Variable> var(varsHandler->getVariableByName(varName));
		var->setType(varType);
		if (isExternal(&*i)) {
			var->markAsExternal();
		}
		resModule->addGlobalVar(var, varInit);
	}

	varsHandler->stopConvertingGlobalVars();
}

/**
* @brief Visits function declarations of the current module and stores them into
*        the resulting module.
*/
void OrigLLVMIR2BIRConverter::visitAndAddFunctionDeclarations() {
	// For each function...
	for (auto &f : *llvmModule) {
		// Add only a declaration.
		visitAndAddFunction(f, true);
	}
}

/**
* @brief Visits the given function and stores it into the resulting module.
*
* @param[in] f Function to be visited.
* @param[in] onlyDeclaration If @c true, only the declaration of @a f is added.
*/
void OrigLLVMIR2BIRConverter::visitAndAddFunction(llvm::Function &f,
		bool onlyDeclaration) {
	// Gather all the needed information about the function.
	ShPtr<Type> funcRetType = converter->llvmTypeToType(f.getReturnType());
	std::string funcName = varsHandler->getValueName(&f);
	VarVector funcParams = getFunctionParams(f);
	ShPtr<Statement> funcBody = onlyDeclaration ?
		ShPtr<Statement>() : getFunctionBody(f);
	VarSet localVars = varsHandler->getLocalVars();
	bool isVarArg = llvm::cast<llvm::FunctionType>(f.getFunctionType())->isVarArg();

	// When the function already exists, we have to update it, not replace it
	// (some code may already use the original function, e.g. via function
	// pointers).
	ShPtr<Function> func;
	if ((func = resModule->getFuncByName(funcName))) {
		func->setRetType(funcRetType);
		func->setParams(funcParams);
		func->setLocalVars(localVars);
		func->setBody(funcBody);
		func->setVarArg(isVarArg);
	} else {
		func = Function::create(
			funcRetType, funcName, funcParams, localVars, funcBody, isVarArg
		);
	}

	// If the function is a definition, insert VarDefStmts at the beginning of
	// the function.
	if (func->isDefinition()) {
		// To produce a deterministic output, sort the local variables by their
		// name. Indeed, recall that variables are stored in a set that orders
		// them by their address which may differ from run to run.
		VarSet localVarsSet(func->getLocalVars());
		VarVector localVarsVector(localVarsSet.begin(), localVarsSet.end());
		sortByName(localVarsVector);

		// Insert VarDefStmts at the beginning of the function. Notice that to
		// sort the emitted VarDefStmts from A to Z, we have to do this in
		// reverse. We use prependStatement() to do this.
		for (auto i = localVarsVector.rbegin(), e = localVarsVector.rend();
				i != e; ++i) {
			func->getBody()->prependStatement(VarDefStmt::create(*i));
		}
	}

	resModule->addFunc(func);
}

/**
* @brief Makes all identifiers valid by replacing invalid characters with valid
*        characters.
*
* TODO This should probably be HLL specific.
*/
void OrigLLVMIR2BIRConverter::makeIdentifiersValid() {
	// For every global variable...
	for (auto i = resModule->global_var_begin(),
			e = resModule->global_var_end(); i != e; ++i) {
		(*i)->getVar()->setName(makeIdentifierValid((*i)->getVar()->getName()));
	}

	// For every function...
	for (auto i = resModule->func_begin(), e = resModule->func_end();
			i != e; ++i) {
		// Function name.
		(*i)->setName(makeIdentifierValid((*i)->getName()));

		// Local variables, including parameters.
		VarSet localVars((*i)->getLocalVars(true));
		for (auto &var : localVars) {
			var->setName(makeIdentifierValid(var->getName()));
		}
	}
}

/**
* @brief Generates missing statements into the given function's body.
*/
void OrigLLVMIR2BIRConverter::generateMissingStatements(ShPtr<Statement> funcBody) {
	// We need to create a copy of gotoStmtsToPatch because it can be extended
	// during the generation of the missing statements.
	GotoStmtsToPatch gotoStmtsToPatchCopy;
	do {
		gotoStmtsToPatchCopy = gotoStmtsToPatch;

		// Generate statements for every goto target for which we do not have a
		// corresponding statement yet.
		for (const auto &p : gotoStmtsToPatchCopy) {
			if (isBBMissingStatements(p.second)) {
				generateMissingStatementsForBB(funcBody, p.second);
			}
		}
	} while (gotoStmtsToPatch.size() != gotoStmtsToPatchCopy.size());
}

/**
* @brief Returns @c true if there are missing statements for @a bb.
*/
bool OrigLLVMIR2BIRConverter::isBBMissingStatements(llvm::BasicBlock *bb) {
	return !mapHasKey(bbStmtMap, bb);
}

/**
* @brief Generates missing statements for the given basic block into the given
*        function's body.
*/
void OrigLLVMIR2BIRConverter::generateMissingStatementsForBB(
		ShPtr<Statement> funcBody, llvm::BasicBlock *bb) {
	ShPtr<Statement> missingStmts(visitBasicBlockOrLoop(bb));

	// We put the generated statements after the current function's body.
	Statement::mergeStatements(funcBody, missingStmts);
}

/**
* @brief Adds a goto target to be patched.
*/
void OrigLLVMIR2BIRConverter::addGotoStmtToPatch(ShPtr<GotoStmt> gotoStmt,
		llvm::BasicBlock *bb) {
	// Add it only if it has not yet been added.
	auto p = std::make_pair(gotoStmt, bb);
	if (!hasItem(gotoStmtsToPatch, p)) {
		gotoStmtsToPatch.push_back(std::move(p));
	}
}

/**
* @brief Patches the targets of goto statements.
*/
void OrigLLVMIR2BIRConverter::patchTargetsOfGotoStmts() {
	for (const auto &p : gotoStmtsToPatch) {
		auto targetStmtIter = bbStmtMap.find(p.second);
		ASSERT_MSG(targetStmtIter != bbStmtMap.end(),
			"There is no BIR statement for LLVM basic block `" <<
			p.second->getName() << "`.");
		p.first->setTarget(targetStmtIter->second);
		setGotoTargetLabel(targetStmtIter->second, p.second);
	}
	gotoStmtsToPatch.clear();
}

/**
* @brief Sets a proper label of a goto target that is in the given basic block.
*/
void OrigLLVMIR2BIRConverter::setGotoTargetLabel(ShPtr<Statement> target,
		const llvm::BasicBlock *targetBB) {
	labelsHandler->setGotoTargetLabel(target, targetBB);
}

/**
* @brief Returns all the parameters of the given function.
*
* It doesn't matter whether @a f is a declaration or a definition.
*
* If @a f is a definition, this function also stores all @a f's parameters
* into @c varHandlers' local variables list.
*/
VarVector OrigLLVMIR2BIRConverter::getFunctionParams(llvm::Function &f) {
	VarVector funcParams;
	// For each parameter...
	for (auto i = f.arg_begin(), e = f.arg_end(); i != e; ++i) {
		std::string varName = varsHandler->getValueName(&*i);
		ShPtr<Variable> var(Variable::create(varName,
			converter->llvmTypeToType(i->getType())));
		varsHandler->addLocalVar(var);
		funcParams.push_back(var);
	}
	return funcParams;
}

/**
* @brief Returns the body of the given function.
*
* If the function is a declaration, the null pointer is returned.
*/
ShPtr<Statement> OrigLLVMIR2BIRConverter::getFunctionBody(llvm::Function &f) {
	if (f.isDeclaration()) {
		return ShPtr<Statement>();
	}

	// Store the types of all local variables allocated by allocas. This is
	// needed to properly generate the function's body.
	for (auto i = inst_begin(f), e = inst_end(f); i != e; ++i) {
		if (const llvm::AllocaInst *ai = LLVMSupport::isDirectAlloca(&*i)) {
			varsHandler->addAllocatedVarType(&*i, ai->getAllocatedType());
		}
	}

	ShPtr<Statement> funcBody(visitBasicBlockOrLoop(&f.front()));
	generateMissingStatements(funcBody);
	patchTargetsOfGotoStmts();
	return funcBody;
}

/**
* @brief Generates the end of a loop.
*
* @param[in] currBB Current basic block, from which the emission of the loop
*                   end is done.
* @param[in] loopHeader Header of the loop.
* @param[in] loopEnd End of the loop.
* @param[in] cond `if` condition (if it is satisfied, do another loop
*                 iteration).
* @param[in] isCondNegated @c true if @a cond should be negated, @c false
*                          otherwise.
* @param[in] justPHICopies @c true if just PHI copies should be generated (no
*                          `if`s etc.), @c false otherwise.
*
* This function should be only called from visitBranchInst().
*
* @par Preconditions
*  - @a loopHeader, @a loopEnd, and @a cond are non-null
*/
ShPtr<Statement> OrigLLVMIR2BIRConverter::getLoopEnd(llvm::BasicBlock *currBB,
		llvm::BasicBlock *loopHeader, llvm::BasicBlock *loopEnd,
		llvm::Value *cond, bool isCondNegated, bool justPHICopies) {
	PRECONDITION_NON_NULL(loopHeader);
	PRECONDITION_NON_NULL(loopEnd);
	PRECONDITION_NON_NULL(cond);

	// Store the information about the loop end (we need to generate it after
	// the loop).
	lastLoopExitBB = loopEnd;

	// We are going to generate the following structure:
	//
	//     if [not] cond: // not iff isCondNegated
	//         PHI copies for loopEnd
	//         break
	//     PHI copies for loopHeader
	//     continue
	//

	// If loopEnd contains just an unconditional branch to X, we will need to
	// generate also PHI copies for X. This has to be done because of the
	// simplification of loop exits in the IndVarSimplify pass. To this end,
	// use the following variable loopEndSucc to determine whether additional
	// PHI copies have to be generated (they have to be generated iff
	// loopEndSucc is not the null pointer).
	llvm::BasicBlock *loopEndSucc = nullptr;
	if (llvm::BranchInst *bi = llvm::dyn_cast<llvm::BranchInst>(&*(loopEnd->begin()))) {
		if (bi->getNumSuccessors() == 1) {
			loopEndSucc = bi->getSuccessor(0);
		}
	}

	ShPtr<Statement> phiCopiesHeader(getPHICopiesForSuccessor(currBB,
		loopHeader));
	ShPtr<Statement> phiCopiesEnd;
	if (loopEndSucc) {
		phiCopiesEnd = getPHICopiesForSuccessor(loopEnd, loopEndSucc);
	} else {
		phiCopiesEnd = getPHICopiesForSuccessor(currBB, loopEnd);
	}

	if (justPHICopies) {
		// Generate just PHI copies without any additional code.
		ShPtr<Statement> phiCopies = Statement::mergeStatements(
			phiCopiesHeader, phiCopiesEnd);
		return addDebugCommentToStatement(phiCopies, "PHI copies at the loop end");
	}

	// `if` part
	ShPtr<Expression> ifCond(converter->llvmValueToExpression(cond));
	if (isCondNegated) {
		ifCond = ExpressionNegater::negate(ifCond);
	}

	// Depending on the current location (are we in a loop/switch and the
	// target is another loop/switch?), we either generate `break` or `goto`.
	ShPtr<Statement> endOfIfPart;
	std::string ifTargetAddress(labelsHandler->getLabel(loopEnd));
	if (loopHeader == currLoopBB && !generatingSwitchStmt) {
		// Breaking out of the current loop while not being in a switch
		// statement -> generate a `break` statement.
		endOfIfPart = BreakStmt::create();
		endOfIfPart->setMetadata("break -> " + ifTargetAddress);
	} else {
		// Breaking out of some outer loop or we are in a switch statement ->
		// generate a `goto` statement.
		endOfIfPart = GotoStmt::create(EmptyStmt::create());
		addGotoStmtToPatch(ucast<GotoStmt>(endOfIfPart), loopEnd);
		endOfIfPart->setMetadata("break (via goto) -> " + ifTargetAddress);
	}
	ShPtr<Statement> ifBody(Statement::mergeStatements(
		phiCopiesEnd, endOfIfPart));

	// after `if` part
	// The following `continue` or `goto` statements HAVE to be generated
	// because there may be some code after them (after a previous
	// if/else-branch). For example, consider the following code.
	//
	//   if c1:
	//       if c2:
	//           ...
	//           break
	//       ...
	//       continue # This `continue` has to be generated.
	//   ...
	//   return 0
	//
	// Of course, they may be removed in subsequent optimizations.
	ShPtr<Statement> afterIf;
	std::string afterIfTargetAddress(labelsHandler->getLabel(loopHeader));
	if (loopHeader == currLoopBB) {
		// Going to the beginning of the current loop -> generate a `continue`
		// statement.
		afterIf = ContinueStmt::create();
		afterIf->setMetadata("continue -> " + afterIfTargetAddress);
	} else {
		// Going to the beginning of some outer loop -> generate a `goto`
		// statement.
		//
		// We cannot generate a `continue` statement because doing so would
		// make the program go to the beginning of the current loop, not to the
		// beginning of the current loop.
		//
		// Since the outer loop is not available at the time of generating this
		// statement (we use recursion to do the conversion of LLVM IR to BIR),
		// we need to use some stub target, and patch the target statement
		// afterwards.
		afterIf = GotoStmt::create(EmptyStmt::create());
		addGotoStmtToPatch(ucast<GotoStmt>(afterIf), loopHeader);
		afterIf->setMetadata("continue (via goto) -> " + afterIfTargetAddress);
	}
	afterIf = Statement::mergeStatements(phiCopiesHeader, afterIf);

	return IfStmt::create(ifCond, ifBody, afterIf);
}

/**
* @brief Returns PHI copies for the given basic block and its successor.
*
* @return @c true if some PHI copies were generated, @c false otherwise.
*
* PHI copies for induction variables (if there are any) are not generated
* because they are useless. This is, however, done only if
* isOptimizableToForLoop() returns @c true.
*
* @par Preconditions
*  - both @a currBB and @a succ are non-null
*/
ShPtr<Statement> OrigLLVMIR2BIRConverter::getPHICopiesForSuccessor(
		llvm::BasicBlock *currBB, llvm::BasicBlock *succ) const {
	PRECONDITION_NON_NULL(currBB);
	PRECONDITION_NON_NULL(succ);

	// First, check whether currBB is a predecessor of succ; otherwise, do
	// not generate anything.
	if (!LLVMSupport::isPredecessorOf(currBB, succ)) {
		return ShPtr<Statement>();
	}

	// Generate all the needed PHI copies.
	ShPtr<Statement> phiCopies;
	ShPtr<Statement> lastPHICopy;
	// For each PHI node in succ...
	for (auto i = succ->begin(); llvm::isa<llvm::PHINode>(i); ++i) {
		llvm::PHINode *pn = llvm::cast<llvm::PHINode>(i);
		llvm::Value *iv = pn->getIncomingValueForBlock(currBB);
		if (llvm::isa<llvm::UndefValue>(iv)) {
			continue;
		}

		// Do not generate PHI copies for induction variables.
		if (llvm::Loop *l = branchInfo->getLoopFor(succ)) {
			if (branchInfo->isOptimizableToForLoop(l) &&
					l->getCanonicalInductionVariable() == pn) {
				continue;
			}
		}

		ShPtr<Variable> lhs(varsHandler->getVariableByName(
				varsHandler->getValueName(&*i)));
		ShPtr<Expression> rhs(converter->llvmValueToExpression(iv));
		ShPtr<AssignStmt> phiCopy(AssignStmt::create(lhs, rhs));
		if (!phiCopies) {
			phiCopies = phiCopy;
			lastPHICopy = phiCopy;
		} else {
			lastPHICopy->setSuccessor(phiCopy);
			lastPHICopy = phiCopy;
		}
	}
	return phiCopies;
}

/**
* @brief Generates an `if` statement for a conditional branch to @a bb1 and @a
*        bb2, depending on @a cond, including a `goto` statement(s).
*
* @param[in] bb1 First target of the branch instruction.
* @param[in] bb2 Second target of the branch instruction.
* @param[in] source Source basic block from which we are branching to @a bb1
*                   and @a bb2.
* @param[in] cond Branch condition.
* @param[in] negateCond If @c true, it negates @a cond.
*
* If a `goto` to @a bb2 is also required, it is generated instead of generating
* @a bb2 directly.
*
* @par Preconditions
*  - mapHasKey(bbStmtMap, bb1)
*  - branchInfo->isGotoNecessary(source, bb1)
*/
ShPtr<Statement> OrigLLVMIR2BIRConverter::generateGotoForConditionalBranch(
		llvm::BasicBlock *bb1, llvm::BasicBlock *bb2, llvm::BasicBlock *source,
		llvm::Value *cond, bool negateCond) {
	// We are going to generate the following structure:
	//
	//     if cond: // possibly negated, depending on negateCond
	//        PHI copies for bb1
	//        goto bb1
	//     PHI copies for bb2
	//     bb2
	//
	// If there should be a goto to bb2 instead of bb2, we generate a goto.
	//
	ShPtr<Expression> ifCond(converter->llvmValueToExpression(cond));
	if (negateCond) {
		ifCond = ExpressionNegater::negate(ifCond);
	}

	// Generate code for bb1.
	ShPtr<Statement> phiCopiesBB1(getPHICopiesForSuccessor(source, bb1));
	auto gotoTarget = bbStmtMap[bb1];
	ShPtr<Statement> ifBody(Statement::mergeStatements(phiCopiesBB1,
		GotoStmt::create(gotoTarget)));
	setGotoTargetLabel(gotoTarget, bb1);
	ShPtr<IfStmt> ifStmt(IfStmt::create(ifCond, ifBody));

	// Generate code for bb2.
	ShPtr<Statement> phiCopiesBB2(getPHICopiesForSuccessor(source, bb2));
	ShPtr<Statement> afterIf;
	if (mapHasKey(bbStmtMap, bb2) &&
			branchInfo->isGotoNecessary(source, bb2)) {
		// A goto is necessary for bb2, too.
		auto gotoTarget = bbStmtMap[bb2];
		afterIf = Statement::mergeStatements(phiCopiesBB2,
			GotoStmt::create(gotoTarget));
		setGotoTargetLabel(gotoTarget, bb2);
	} else {
		// No goto is needed for bb2, so generate it directly after the if
		// statement.
		afterIf = Statement::mergeStatements(phiCopiesBB2,
			visitBasicBlockOrLoop(bb2));
	}
	ifStmt->setSuccessor(afterIf);

	return ifStmt;
}

/**
* @brief Returns the initial value of the induction variable of the given loop.
*
* If the loop does not have a unique induction variable, it returns the null
* pointer.
*
* @par Preconditions
*  - @a l is non-null
*/
llvm::Value *OrigLLVMIR2BIRConverter::getInitialValueOfIndVar(const llvm::Loop *l) const {
	PRECONDITION_NON_NULL(l);

	if (!l->getCanonicalInductionVariable()) {
		// No induction variable.
		return nullptr;
	}

	// Get the pre-header of l.
	llvm::BasicBlock *preHeader = nullptr;
	llvm::BasicBlock *header = l->getBlocks()[0];
	for (auto i = pred_begin(header), e = pred_end(header); i != e; ++i) {
		if (branchInfo->getLoopFor(*i) != l) {
			preHeader = *i;
			break;
		}
	}
	ASSERT_MSG(preHeader, "every loop has to have a pre-header");

	// Get the initial value of the induction variable.
	llvm::PHINode *pn = llvm::cast<llvm::PHINode>(l->getCanonicalInductionVariable());
	return pn->getIncomingValueForBlock(preHeader);
}

/**
* @brief Generates the given basic block either as a loop (if it is a loop), or
*        as a normal basic block (in the case it is not a loop).
*
* @param[in] bb Basic block.
* @param[in] genTerm If @c true, then it also generates the terminator.
*                    TODO What about loops?
*
* @par Preconditions
*  - @a bb is non-null
*/
ShPtr<Statement> OrigLLVMIR2BIRConverter::visitBasicBlockOrLoop(llvm::BasicBlock *bb,
		bool genTerm) {
	PRECONDITION_NON_NULL(bb);

	// Check whether bb has been processed too many times. If so, then do not
	// process it again to obviate a possible infinite loop. Even though the
	// basic support of goto statements is done, it may work improperly in some
	// cases. This is why there is the following check to avoid infinite
	// recursion. The number 25 below has no greater meaning; it's just a
	// number that popped into my mind (and all backend tests pass correctly).
	if (++processedBBs[bb] > 25) {
		ShPtr<Statement> emptyStmt(EmptyStmt::create());
		addDebugCommentToStatement(emptyStmt,
			"Detected a possible infinite recursion (goto support failed); quitting...");
		return emptyStmt;
	}

	if (llvm::Loop *l = branchInfo->getLoopFor(bb)) {
		if (l->getHeader() == bb) {
			return visitLoop(l);
		}
	}
	return visitBasicBlock(bb, genTerm);
}

/**
* @brief Adds @a stmtToAdd to a block of statements starting with @a firstStmt.
*
* @param[in] stmtToAdd Statement to be added.
* @param[out] firstStmt First statement of the block.
* @param[in,out] prevStmt Predecessor of @a stmtToAdd.
*
* After this function is called, @a prevStmt and @a firstStmt are properly set,
* depending on whether @a prevStmt is the null pointer.
*
* If @a stmtToAdd has successors, they are also added to the block.
*/
void OrigLLVMIR2BIRConverter::addStatementToStatementBlock(ShPtr<Statement> stmtToAdd,
		ShPtr<Statement> &firstStmt, ShPtr<Statement> &prevStmt) {
	// Move to the end of stmtToAdd to properly set prevStmt (stmtToAdd may
	// have successors).
	ShPtr<Statement> lastStmt(Statement::getLastStatement(stmtToAdd));

	// Properly set prevStmt and firstStmt.
	if (!prevStmt) {
		firstStmt = stmtToAdd;
	} else {
		prevStmt->setSuccessor(stmtToAdd);
	}
	prevStmt = lastStmt;
}

/**
* @brief Adds @a debugComment to @a stmt.
*
* @param[in] stmt Statement to which @a debugComment is added.
* @param[in] debugComment Debug comment to be added.
*
* @return A statement with @a debugComment attached to it.
*
* If @a stmt already has an attached debug message, it creates a new empty
* statement, attaches @a debugComment to it, and prepends the new statement to
* @a stmt.
*
* If @a stmt is the null pointer, it creates a new empty statement and attaches
* @a debugComment to it.
*/
ShPtr<Statement> OrigLLVMIR2BIRConverter::addDebugCommentToStatement(
		ShPtr<Statement> stmt, std::string debugComment) {
	if (!stmt) {
		ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
		emptyStmt->setMetadata(debugComment);
		return emptyStmt;
	}

	if (!stmt->getMetadata().empty()) {
		// stmt already has a debug message.
		ShPtr<EmptyStmt> emptyStmt(EmptyStmt::create());
		emptyStmt->setMetadata(debugComment);
		return Statement::mergeStatements(emptyStmt, stmt);
	}

	// stmt doesn't have any attached debug message.
	stmt->setMetadata(debugComment);
	return stmt;
}

/**
* @brief Returns the default switch block for @a bb.
*
* @param[in] bb Basic block representing the default switch block.
* @param[in] succ Successor of @a bb (if there is any), the null pointer
*                 otherwise.
*
* @par Preconditions
*  - @a bb is non-null
*/
ShPtr<Statement> OrigLLVMIR2BIRConverter::getDefaultSwitchBlock(
		llvm::BasicBlock *bb, llvm::BasicBlock *succ) {
	PRECONDITION_NON_NULL(bb);

	// Is there a fall-through?
	llvm::BranchInst *bi = llvm::dyn_cast<llvm::BranchInst>(bb->getTerminator());
	if (bi && bi->getSuccessor(0) == succ) {
		// There is a fall-through. However, if the successor begins with a PHI
		// node and ends with a return/unreachable statement, do not generate the
		// fall-through.
		//
		// The following example illustrates the problem.
		// switch expr:
		//     default:
		//         ...
		//         result = tea // PHI copy.
		//     case 1:
		//         result = 0 // PHI copy.
		//         ...
		//         return result
		//
		// TODO What if the successor doesn't end with a return/unreachable
		//      statement?
		if (llvm::isa<llvm::PHINode>(*succ->begin()) && LLVMSupport::endsWithRetOrUnreach(
				succ, true)) {
			ShPtr<Statement> defaultBlock = visitBasicBlockOrLoop(bb);
			return Statement::mergeStatements(defaultBlock,
				BreakStmt::create());
		}

		// Generate a fall-through.
		ShPtr<Statement> defaultBlock = visitBasicBlockOrLoop(bb, false);
		ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(bb, succ));
		return Statement::mergeStatements(defaultBlock, phiCopies);
	}

	// There is no fall-through.
	ShPtr<Statement> defaultBlock = visitBasicBlockOrLoop(bb);
	return Statement::mergeStatements(defaultBlock,
		BreakStmt::create());
}

/**
* @brief Returns an expression for the given switch-case value.
*/
ShPtr<Expression> OrigLLVMIR2BIRConverter::getSwitchCaseExpression(llvm::Value *v) {
	// Simple values, like integers, may be converted directly. This is new in
	// LLVM 3.4; prior to LLVM 3.4, the value was always an array (see the
	// comment below).
	if (llvm::ConstantInt *ci = llvm::dyn_cast<llvm::ConstantInt>(v)) {
		return converter->llvmValueToExpression(ci);
	}

	// As of LLVM 3.3 (or 3.2, I don't know exactly, but in 3.1, this is not
	// the case), the value is an array of the form
	//
	//     [<lowerBound, upperBound>, ...]
	//
	// That is, a case value is composed of ranges.
	//
	if (llvm::ConstantAggregateZero *caz = llvm::dyn_cast<llvm::ConstantAggregateZero>(v)) {
		// This indicates a zero.
		llvm::IntegerType *intType(llvm::dyn_cast<llvm::IntegerType>(
			caz->getType()->getContainedType(0)->getContainedType(0)));
		ASSERT_MSG(intType, "The type should be integral.");
		return ConstInt::create(0, intType->getBitWidth(), intType->getSignBit());
	}

	// It is a range.
	llvm::ConstantArray *ca = llvm::dyn_cast<llvm::ConstantArray>(v);
	ASSERT_MSG(ca, "The value should be an array.");
	if (ca->getNumOperands() != 1) {
		// TODO Handle this case (more than one range in a case).
		printWarningMessage("Found a switch instruction with more ranges in "
			"one of its cases (", *ca, ").");
	}
	llvm::ConstantDataSequential *switchCaseRange(llvm::dyn_cast<llvm::ConstantDataSequential>(
		ca->getOperand(0)));
	ASSERT_MSG(switchCaseRange, "The case range should be an array.");
	ShPtr<Expression> lowerBound(converter->llvmConstantToExpression(
		switchCaseRange->getElementAsConstant(0)));
	if (switchCaseRange->getElementAsConstant(1)) {
		ShPtr<Expression> upperBound(converter->llvmConstantToExpression(
			switchCaseRange->getElementAsConstant(1)));
		if (!lowerBound->isEqualTo(upperBound)) {
			// TODO Handle this case (the lower bound differs from the upper bound).
			printWarningMessage("Found a switch case with a range having its lower "
				"bound different from the upper bound (", *switchCaseRange, ").");
		}
	}
	return lowerBound;
}

/**
* @brief Generates code for the given basic block @a bb.
*
* @param[in] bb Basic block.
* @param[in] genTerm If @c true, then it also generates the terminator.
*
* @par Preconditions
*  - @a bb is non-null
*/
ShPtr<Statement> OrigLLVMIR2BIRConverter::visitBasicBlock(llvm::BasicBlock *bb,
		bool genTerm) {
	PRECONDITION_NON_NULL(bb);

	ShPtr<Statement> firstStmt; // The first statement.
	ShPtr<Statement> prevStmt; // The previous statement.
	ShPtr<Statement> currStmt; // The current statement.

	// Generate all the instructions in the basic block.
	for (auto i = bb->begin(), e = --bb->end(); i != e; ++i) {
		// Skip PHI nodes.
		if (llvm::isa<llvm::PHINode>(*i)) {
			continue;
		}

		// If the instruction accesses a local variable allocated by an alloca
		// instruction which hasn't been defined yet, define it.
		if (llvm::isa<llvm::LoadInst>(i) || llvm::isa<llvm::GetElementPtrInst>(i) ||
				llvm::isa<llvm::BitCastInst>(i) || llvm::isa<llvm::CallInst>(i)) {
			// Check all operands of the instruction.
			for (unsigned j = 0, e = i->getNumOperands(); j < e; ++j) {
				llvm::Value *varLLVM = i->getOperand(j);

				// Skip global variables.
				if (llvm::isa<llvm::GlobalVariable>(varLLVM)) {
					continue;
				}

				// Skip temporary variables, functions, and possibly other
				// types of variables.
				if (!LLVMSupport::isDirectAlloca(varLLVM)) {
					continue;
				}

				// Skip already defined local variables.
				std::string varName = varsHandler->getValueName(varLLVM);
				if (varsHandler->localVarExists(varName)) {
					continue;
				}

				// We have a winner, so generate a variable-definition
				// statement for it.

				// Get the variable's type. This needs to be obtained from the
				// alloca instruction; otherwise, the type might not match.
				llvm::Type *varType = varsHandler->getAllocatedVarType(varLLVM);

				// Define the variable.
				ShPtr<Variable> var(Variable::create(varName,
					converter->llvmTypeToType(varType)));
				varsHandler->addLocalVar(var);

				// Generate the statement.
				//
				// We create an AssignStmt instead of a VarDefStmt, and
				// optimize assignments to definitions later
				// (VarDefStmtOptimizer). This simplifies the conversion.
				ShPtr<Expression> init(converter->getDefaultInitializer(
					varType));
				currStmt = AssignStmt::create(var, init);

				// We want to prevent optimization of variables used in
				// volatile load/store operations, so mark such variables as
				// external.
				if (auto loadInst = llvm::dyn_cast<llvm::LoadInst>(i)) {
					if (loadInst->isVolatile()) {
						var->markAsExternal();
					}
				}

				// If we have just generated the first statement, map the
				// currently processed basic block's label to it.
				if (!firstStmt && !mapHasKey(bbStmtMap, bb)) {
					bbStmtMap[bb] = currStmt;
				}

				addStatementToStatementBlock(currStmt, firstStmt, prevStmt);
			}
		}

		// Skip inlinable instructions and direct allocas.
		if (LLVMSupport::isInlinableInst(&*i) || LLVMSupport::isDirectAlloca(&*i)) {
			continue;
		}

		// If (1) we're generating the body of a loop with an induction
		// variable and (2) the variable on the left-hand side is used
		// only in the exit condition for this loop, do not generate any
		// code.
		if (llvm::Loop *l = branchInfo->getLoopFor(bb)) {
			// TODO Is the following condition sufficient?
			if (branchInfo->isOptimizableToForLoop(l) && !llvm::isa<llvm::CallInst>(i) &&
					!llvm::isa<llvm::LoadInst>(i) && !llvm::isa<llvm::StoreInst>(i) && !i->hasName()) {
				unsigned usesExcludingExit = 0;
				for (auto j = i->user_begin(), e = i->user_end(); j != e; ++j) {
					if (*j == l->getCanonicalInductionVariable() ||
							// TODO HACK
							varsHandler->getValueName(*j).substr(0, 8) == "exitcond") {
						usesExcludingExit = 0;
						break;
					}
					usesExcludingExit++;
				}
				if (usesExcludingExit == 0) {
					continue;
				}
			}
		}

		if (llvm::StoreInst *si = llvm::dyn_cast<llvm::StoreInst>(i)) {
			// Mark the accessed variable as defined because after this
			// instruction, it has a value.
			llvm::Value *var = si->getOperand(1);
			std::string varName = varsHandler->getValueName(var);
			if (!llvm::isa<llvm::GlobalVariable>(var)) {
				varsHandler->addLocalVar(Variable::create(varName,
					converter->llvmTypeToType(var->getType()->getContainedType(0))));
			}
		}

		// If there is an l-value which is used later in the code, generate an
		// assignment statement; otherwise, generate whatever *i is.
		//
		// TODO
		// However, if the current instruction is an insertvalue instruction,
		// generate it separately; that is, use
		// converter->llvmInstructionToValue() rather than
		// converter->llvmValueToExpression(). This is because the visitation
		// function for this instruction creates two assignment statements.
		if (i->getType() != llvm::Type::getVoidTy(bb->getContext()) &&
				!LLVMSupport::isInlineAsm(&*i) && !llvm::isa<llvm::InsertValueInst>(*i)) {
			ShPtr<Expression> lhs(converter->llvmValueToExpression(&*i));
			ShPtr<Value> rhs(converter->llvmInstructionToValue(*i));
			// Since rhs might be an instance of CallStmt, we need to check
			// this. If this is the case, then we have to use the underlying
			// call instead.
			if (ShPtr<CallStmt> callStmt = cast<CallStmt>(rhs)) {
				if (i->user_begin() != i->user_end()) {
					// The left-hand side is used, so assign the result of the
					// call statement to the left-hand side.
					currStmt = AssignStmt::create(lhs, callStmt->getCall());
				} else {
					// There are no uses of the left-hand side, so generate
					// just the call statement, without the assignment.
					// Otherwise, we would introduce an unused assignment.
					currStmt = callStmt;
				}
			} else {
				currStmt = AssignStmt::create(lhs, cast<Expression>(rhs));
			}
		} else {
			currStmt = cast<Statement>(visit(*i));
		}

		// If we have just generated the first statement, map the
		// currently processed basic block's label to it.
		if (!firstStmt && !mapHasKey(bbStmtMap, bb)) {
			bbStmtMap[bb] = currStmt;
		}

		addStatementToStatementBlock(currStmt, firstStmt, prevStmt);
	}

	llvm::TerminatorInst *ti = bb->getTerminator();
	if (genTerm) {
		currStmt = cast<Statement>(visit(*ti));
		addStatementToStatementBlock(currStmt, firstStmt, prevStmt);
	} else if (llvm::BranchInst *bi = llvm::dyn_cast<llvm::BranchInst>(ti)) {
		if (!bi->isConditional()) {
			// Just for debugging purposes.
			currStmt = EmptyStmt::create();
			currStmt->setMetadata("branch -> " +
				labelsHandler->getLabel(bi->getSuccessor(0)));
			addStatementToStatementBlock(currStmt, firstStmt, prevStmt);
		}
	}

	firstStmt = addDebugCommentToStatement(firstStmt,
		labelsHandler->getLabel(bb));
	bbStmtMap[bb] = firstStmt;

	return firstStmt;
}

/**
* @brief Generates code for the given loop @a l.
*
* @par Preconditions
*  - @a l is non-null
*/
ShPtr<Statement> OrigLLVMIR2BIRConverter::visitLoop(llvm::Loop *l) {
	PRECONDITION_NON_NULL(l);

	// Get the loop's body.
	branchInfo->startGeneratingLoop(l);
	llvm::BasicBlock *bb = l->getBlocks()[0];
	llvm::Loop *bbLoop = branchInfo->getLoopFor(bb);
	ShPtr<Statement> loopBody;
	if (bbLoop == l) {
		// Since there may be nested loops, store the original basic block of
		// the currently generated loop.
		llvm::BasicBlock *oldCurrLoopBB = currLoopBB;

		// Set the new one.
		currLoopBB = bb;

		// Get the body.
		loopBody = visitBasicBlock(bb);

		// Restore the original basic block of the currently generated loop.
		currLoopBB = oldCurrLoopBB;
	} else if (bb == bbLoop->getHeader() && bbLoop->getParentLoop() == l) {
		loopBody = visitLoop(bbLoop);
	}
	branchInfo->endGeneratingLoop();

	// Get the basic block(s) after the loop (if there are any).
	ShPtr<Statement> afterLoop;
	if (lastLoopExitBB) {
		// We need to zero it before the emission.
		llvm::BasicBlock *exitBB = lastLoopExitBB;
		lastLoopExitBB = nullptr;
		afterLoop = visitBasicBlockOrLoop(exitBB);
	}

	// Create a loop of a proper type and return it.
	ShPtr<Statement> generatedLoop;
	if (branchInfo->isOptimizableToForLoop(l)) {
		// Return a for loop.
		llvm::PHINode *indVarLLVM = l->getCanonicalInductionVariable();
		std::string indVarName = varsHandler->getValueName(indVarLLVM);
		ShPtr<Variable> indVar(varsHandler->getVariableByName(indVarName));
		if (isa<UnknownType>(indVar->getType())) {
			indVar->setType(converter->llvmTypeToType(indVarLLVM->getType()));
		}

		llvm::Value *iv = getInitialValueOfIndVar(l);
		ShPtr<Expression> startValue(converter->llvmValueToExpression(iv));
		ShPtr<Expression> endCond(LtOpExpr::create(indVar,
			AddOpExpr::create(startValue, branchInfo->getTripCount(l))));

		// TODO Is the used number of bits (32) correct?
		ShPtr<Expression> step(ConstInt::create(1, 32));
		generatedLoop = ForLoopStmt::create(indVar,
			startValue, endCond, step, loopBody, afterLoop);
	} else {
		// We know neither the induction variable nor the trip count, so return
		// a general `while True` loop. It may be converted into a for loop in
		// subsequent optimizations.
		ShPtr<ConstBool> cond(ConstBool::create(true));
		generatedLoop = WhileLoopStmt::create(cond, loopBody, afterLoop);
	}
	bbStmtMap[bb] = generatedLoop;
	return generatedLoop;
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitCallInst(llvm::CallInst &i) {
	return converter->llvmCallInstToCallStmt(i);
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitGetElementPtrInst(llvm::GetElementPtrInst &i) {
	return converter->llvmGEPInstToExpression(i);
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitLoadInst(llvm::LoadInst &i) {
	return converter->llvmLoadInstToExpression(i);
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitStoreInst(llvm::StoreInst &i) {
	return converter->llvmStoreInstToAssignStmt(i);
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitAllocaInst(llvm::AllocaInst &i) {
	return converter->llvmAllocaInstToExpression(i);
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitCastInst(llvm::CastInst &i) {
	return converter->llvmInstructionToValue(i);
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitInsertValueInst(llvm::InsertValueInst &i) {
	return converter->llvmInsertValueInstToStatement(i);
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitExtractValueInst(llvm::ExtractValueInst &i) {
	return converter->llvmExtractValueInstToExpression(i);
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitUnreachableInst(llvm::UnreachableInst &i) {
	return UnreachableStmt::create();
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitInstruction(llvm::Instruction &i) {
	printErrorMessage("OrigLLVMIR2BIRConverter does not know about:", i);
	llvm_unreachable(0);
	return ShPtr<Value>();
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitBranchInst(llvm::BranchInst &i) {
	if (!i.isConditional()) {
		// An unconditional branch.
		llvm::BasicBlock *succ = i.getSuccessor(0);
		ShPtr<Statement> phiCopies = getPHICopiesForSuccessor(i.getParent(), succ);

		ShPtr<EmptyStmt> debugCommentStmt(EmptyStmt::create());
		debugCommentStmt->setMetadata("branch -> " +
			labelsHandler->getLabel(succ));
		phiCopies = Statement::mergeStatements(phiCopies, debugCommentStmt);

		// If the branch target is the header of the outer loop, generate just
		// 'break'.
		if (branchInfo->isSuccHeaderOfOuterLoop(i.getParent(), succ)) {
			ShPtr<BreakStmt> breakStmt(BreakStmt::create());
			return Statement::mergeStatements(phiCopies, breakStmt);
		}

		// If the branch target is the header of the current loop, generate just
		// 'continue'.
		if (branchInfo->isSuccHeaderOfInnerLoop(i.getParent(), succ)) {
			ShPtr<ContinueStmt> continueStmt(ContinueStmt::create());
			return Statement::mergeStatements(phiCopies, continueStmt);
		}

		// If the branch target ends with a return statement and we're in a
		// loop, generate it here.
		if (LLVMSupport::endsWithRetOrUnreach(succ) && branchInfo->generatingLoop()) {
			ShPtr<Statement> block(visitBasicBlockOrLoop(succ));
			return Statement::mergeStatements(phiCopies, block);
		}

		// If a goto statement is necessary, generate it. We also have to check
		// that there is a statement corresponding to the target; otherwise, we
		// just emit a fall-through.
		if (mapHasKey(bbStmtMap, succ) &&
				branchInfo->isGotoNecessary(i.getParent(), succ)) {
			auto gotoTarget = bbStmtMap[succ];
			ShPtr<GotoStmt> gotoStmt(GotoStmt::create(gotoTarget));
			setGotoTargetLabel(gotoTarget, succ);
			return Statement::mergeStatements(phiCopies, gotoStmt);
		}

		// If the branch target is not yet in a state of to be generated,
		// generate it here.
		if (branchInfo->branchStackTop() != succ) {
			ShPtr<Statement> block(visitBasicBlockOrLoop(succ));
			return Statement::mergeStatements(phiCopies, block);
		}

		// There should be a fall-through.
		return phiCopies;
	}

	// The conditional branch instruction is of the following form:
	//	 br cond, bb1, bb2
	llvm::Value *cond = i.getCondition();
	llvm::BasicBlock *bb1 = i.getSuccessor(0);
	llvm::BasicBlock *bb2 = i.getSuccessor(1);
	llvm::BasicBlock *cbd = branchInfo->findCommonBranchDestination(bb1, bb2);

	// First, check whether bb1 or bb2 is a jump to the header of a loop. If
	// so, then bb2 or bb1, respectively, has to be a jump to the end of the
	// loop.
	llvm::Loop *currLoop = branchInfo->getLoopFor(i.getParent());
	if (currLoop && branchInfo->isLoopHeader(bb1, currLoop)) {
		if (branchInfo->isOptimizableToForLoop(currLoop)) {
			ShPtr<Statement> loopEnd(getLoopEnd(i.getParent(), bb1,
				bb2, cond, true, true));

			// Put a continue statement, including a debug comment, after the
			// loop end.
			ShPtr<ContinueStmt> debugComment(ContinueStmt::create());
			debugComment->setMetadata("loop " +
				labelsHandler->getLabel(bb1) + " end");
			return Statement::mergeStatements(loopEnd, debugComment);
		} else {
			return getLoopEnd(i.getParent(), bb1, bb2, cond, true);
		}
	}
	// Likewise for bb2.
	else if (currLoop && branchInfo->isLoopHeader(bb2, currLoop)) {
		if (branchInfo->isOptimizableToForLoop(currLoop)) {
			ShPtr<Statement> loopEnd(getLoopEnd(i.getParent(), bb2, bb1,
				cond, false, true));

			// Put a continue statement, including a debug comment, after the
			// loop end.
			ShPtr<ContinueStmt> debugComment(ContinueStmt::create());
			debugComment->setMetadata("loop " +
				labelsHandler->getLabel(bb2) + " end");
			return Statement::mergeStatements(loopEnd, debugComment);
		} else {
			return getLoopEnd(i.getParent(), bb2, bb1, cond);
		}
	}

	// Check whether a goto statement is necessary for some of the branches.
	if (mapHasKey(bbStmtMap, bb1) &&
			branchInfo->isGotoNecessary(i.getParent(), bb1)) {
		// A goto is necessary for bb1.
		return generateGotoForConditionalBranch(bb1, bb2, i.getParent(), cond);
	} else if (mapHasKey(bbStmtMap, bb2) &&
			branchInfo->isGotoNecessary(i.getParent(), bb2)) {
		// A goto is necessary for bb2.
		return generateGotoForConditionalBranch(bb2, bb1, i.getParent(), cond, true);
	}

	// Handle special cases.

	// Special case (1)
	// ----------------
	// if cond:
	//	  bb1
	// bb2 == commonBranchDest from the previous branch
	if (bb2 == branchInfo->branchStackTop()) {
		// Generate only the body of bb1 since bb2 will be generated later.
		ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(i.getParent(), bb1));

		ShPtr<Statement> ifBody(visitBasicBlockOrLoop(bb1));
		ifBody = Statement::mergeStatements(phiCopies, ifBody);

		ShPtr<Expression> ifCond(converter->llvmValueToExpression(cond));
		ShPtr<IfStmt> ifStmt(IfStmt::create(ifCond, ifBody));

		// If there are some PHI nodes in the successor, generate PHI copies
		// for them into an else clause.
		if (llvm::isa<llvm::PHINode>(bb2->begin())) {
			ShPtr<Statement> elseBody(getPHICopiesForSuccessor(i.getParent(), bb2));
			ifStmt->setElseClause(elseBody);
		}

		return ifStmt;
	}
	// Special case (2)
	// ----------------
	// if cond:
	//	  bb2
	// bb1 == commonBranchDest from the previous branch
	else if (bb1 == branchInfo->branchStackTop()) {
		ShPtr<Expression> ifCond(ExpressionNegater::negate(
			converter->llvmValueToExpression(cond)));

		// Generate only the body of bb2 since bb1 will be generated later.
		ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(i.getParent(), bb2));

		ShPtr<Statement> ifBody(visitBasicBlockOrLoop(bb2));
		ifBody = Statement::mergeStatements(phiCopies, ifBody);

		ShPtr<IfStmt> ifStmt(IfStmt::create(ifCond, ifBody));

		// If there are some PHI nodes in the successor, generate PHI copies
		// for them into an else clause.
		if (llvm::isa<llvm::PHINode>(bb1->begin())) {
			ShPtr<Statement> elseBody(getPHICopiesForSuccessor(i.getParent(), bb1));
			ifStmt->setElseClause(elseBody);
		}

		// If the common branch destination is not in a state to be generated,
		// generate it here. More specifically, generate it if the branch stack
		// contains just cbd.
		// TODO PHI copies?
		ShPtr<Statement> afterIf;
		if (branchInfo->branchStackSize() == 1) {
			afterIf = visitBasicBlockOrLoop(branchInfo->branchStackTop());
		}
		ifStmt->setSuccessor(afterIf);
		return ifStmt;
	}
	// Special case (3)
	// ----------------
	// if cond:
	//	  bb1 that ends with return/unreachable
	// bb2 that ends with a branch to bb1
	else if (LLVMSupport::endsWithRetOrUnreach(bb1) &&
			llvm::isa<llvm::BranchInst>(bb2->getTerminator()) &&
			!llvm::dyn_cast<llvm::BranchInst>(bb2->getTerminator())->isConditional() &&
			llvm::dyn_cast<llvm::BranchInst>(bb2->getTerminator())->getSuccessor(0) == bb1) {
		// This pattern is rather irritating to decompile, so negate the
		// condition and switch bb1 with bb2.
		ShPtr<Expression> ifCond(ExpressionNegater::negate(
			converter->llvmValueToExpression(cond)));

		// Since we switched bb1 with bb2, generate bb2 first.
		ShPtr<Statement> ifBody(visitBasicBlockOrLoop(bb2, false));
		ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(bb2, bb1));
		if (phiCopies) {
			// There are some PHI copies, so we need to move the last empty
			// statement from ifBody after appended PHI copies. This way,
			// instead of generating, e.g.
			//
			//     tomato = lemon
			//     # branch -> block
			//     grape1 = tomato
			//
			// we generate
			//
			//     tomato = lemon
			//     grape1 = tomato
			//     # branch -> block
			//
			ShPtr<Statement> lastStmtFromIfBody(Statement::getLastStatement(
				ifBody));
			if (isa<EmptyStmt>(lastStmtFromIfBody)) {
				// To prevent loops in the resulting BIR, move the empty
				// statement only if there are also some other statements in
				// the if's body.
				if (ifBody != lastStmtFromIfBody) {
					Statement::removeStatement(lastStmtFromIfBody);
					ifBody = Statement::mergeStatements(ifBody, phiCopies);
					ifBody = Statement::mergeStatements(ifBody, lastStmtFromIfBody);
				} else {
					ifBody = Statement::mergeStatements(ifBody, phiCopies);
				}
			}
		} else {
			ifBody = Statement::mergeStatements(ifBody, phiCopies);
		}

		ShPtr<IfStmt> ifStmt(IfStmt::create(ifCond, ifBody));

		// If there are some PHI nodes in the successor, generate PHI copies
		// for them into an else clause.
		if (llvm::isa<llvm::PHINode>(bb1->begin())) {
			ShPtr<Statement> elseBody(getPHICopiesForSuccessor(i.getParent(), bb1));
			ifStmt->setElseClause(elseBody);
		}

		// Now generate bb1.
		ifStmt->setSuccessor(visitBasicBlockOrLoop(bb1));

		return ifStmt;
	}
	// Special case (4)
	// ----------------
	// if cond:
	//	  bb1 that ends with return/unreachable
	// bb2
	//
	// The call to endWithSameUncondBranch() is done to generate less amount of
	// redundant code.
	else if (LLVMSupport::endsWithRetOrUnreach(bb1, false) &&
			!LLVMSupport::endWithSameUncondBranch(bb1, bb2)) {
		ShPtr<Expression> ifCond(converter->llvmValueToExpression(cond));

		// Check whether bb2 starts with the same return statement
		// as bb1 ends. If so, then the return statement in bb1
		// is redundant, so do not generate it.
		bool genTerm = true;
		llvm::ReturnInst *ri1 = llvm::dyn_cast<llvm::ReturnInst>(bb1->getTerminator());
		llvm::ReturnInst *ri2 = llvm::dyn_cast<llvm::ReturnInst>(bb2->begin());
		if (ri1 && ri2) {
			llvm::Value *rv1 = ri1->getReturnValue();
			llvm::Value *rv2 = ri2->getReturnValue();
			if (rv1 && rv2 && rv1 == rv2) {
				genTerm = false;
			}
		}

		// Generate the body of the if statement (first basic block).
		ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(i.getParent(), bb1));

		ShPtr<Statement> ifBody(visitBasicBlockOrLoop(bb1, genTerm));
		ifBody = Statement::mergeStatements(phiCopies, ifBody);

		ShPtr<IfStmt> ifStmt(IfStmt::create(ifCond, ifBody));

		// If there are some PHI nodes in the successor, generate PHI copies
		// for them into an else clause.
		if (llvm::isa<llvm::PHINode>(bb2->begin())) {
			ShPtr<Statement> elseBody(getPHICopiesForSuccessor(i.getParent(), bb2));
			ifStmt->setElseClause(elseBody);
		}

		// Generate the second basic block.
		ShPtr<Statement> afterIf(visitBasicBlockOrLoop(bb2));
		ifStmt->setSuccessor(afterIf);
		return ifStmt;
	}
	// A general case
	// --------------
	// if cond:
	//    bb1
	//    ... (other basic blocks, possibly nested)
	// else:
	//    bb2
	//    ... (other basic blocks, possibly nested)
	// commonBranchDest
	else {
		// No goto statement is necessary.
		ShPtr<Statement> phiCopiesCBD;
		if (cbd) {
			phiCopiesCBD = getPHICopiesForSuccessor(i.getParent(), cbd);
		}

		ShPtr<IfStmt> ifStmt;

		// if cond:
		//     bb1 ending with a non-return instruction
		// else:
		//     bb2 ending with return
		// cbd
		if (cbd != bb1 && cbd != bb2 && llvm::isa<llvm::ReturnInst>(bb2->getTerminator()) &&
				!llvm::isa<llvm::ReturnInst>(bb1->getTerminator())) {
			// Since bb2 ends with a return instruction, negate the condition
			// and switch bb1 with bb2 to prevent emission of the following
			// type of code:
			//
			//   if c1:
			//       if c2:
			//           if c3:
			//               A
			//           else:
			//               B
			//               return
			//       else:
			//          C
			//           return
			//   else:
			//       D
			//       return
			//
			// Instead, we generate the following code:
			//
			//   if not c1:
			//       D
			//       return
			//   if not c2:
			//       C
			//       return
			//   if not c3:
			//       B
			//       return
			//   A
			//
			// This is done to decrease the nesting of `if` statements.
			ShPtr<Expression> ifCond(ExpressionNegater::negate(
				converter->llvmValueToExpression(cond)));

			ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(
				i.getParent(), bb2));
			// Since bb2 ends with a return instruction, we don't need to push
			// cbd onto the branch stack.
			ShPtr<Statement> ifBody(visitBasicBlockOrLoop(bb2));
			ifBody = Statement::mergeStatements(phiCopies, ifBody);

			ifStmt = IfStmt::create(ifCond, ifBody);

			// If there are some PHI nodes in the successor, generate PHI copies
			// for them after the if clause.
			ShPtr<Statement> phiCopiesBB1;
			if (llvm::isa<llvm::PHINode>(bb1->begin())) {
				phiCopiesBB1 = getPHICopiesForSuccessor(i.getParent(), bb1);
			}

			// Now generate bb1.
			ShPtr<Statement> afterIf(visitBasicBlockOrLoop(bb1));
			ifStmt->setSuccessor(Statement::mergeStatements(phiCopiesBB1, afterIf));
		} else if (cbd != bb1) {
			ShPtr<Expression> ifCond(converter->llvmValueToExpression(cond));

			ShPtr<Statement> phiCopiesBB1(getPHICopiesForSuccessor(i.getParent(), bb1));
			branchInfo->branchStackPush(cbd);
			ShPtr<Statement> ifBody(Statement::mergeStatements(
				phiCopiesBB1, visitBasicBlockOrLoop(bb1)));
			branchInfo->branchStackPop();

			ifStmt = IfStmt::create(ifCond, ifBody);

			if (cbd != bb2) {
				ShPtr<Statement> phiCopiesBB2(getPHICopiesForSuccessor(i.getParent(), bb2));
				branchInfo->branchStackPush(cbd);
				ShPtr<Statement> elseBody(Statement::mergeStatements(phiCopiesBB2,
					visitBasicBlockOrLoop(bb2)));
				branchInfo->branchStackPop();

				ifStmt->setElseClause(elseBody);
			}
		// cbd == bb1
		} else if (cbd != bb2) {
			ShPtr<Expression> ifCond(ExpressionNegater::negate(
				converter->llvmValueToExpression(cond)));

			ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(i.getParent(), bb2));
			branchInfo->branchStackPush(cbd);
			ShPtr<Statement> ifBody(visitBasicBlockOrLoop(bb2));
			ifBody = Statement::mergeStatements(phiCopies, ifBody);
			branchInfo->branchStackPop();

			ifStmt = IfStmt::create(ifCond, ifBody);
		// cbd == bb1 == bb2
		} else {
			FAIL("cbd == bb1 == bb2, this should never happen");
			return ShPtr<IfStmt>();
		}

		// Do not generate cbd if it is the header of the current loop.
		ShPtr<Statement> afterIf;
		if (cbd && !branchInfo->isSuccHeaderOfInnerLoop(i.getParent(), cbd)) {
			afterIf = visitBasicBlockOrLoop(cbd);
		}

		return Statement::mergeStatements(
			Statement::mergeStatements(phiCopiesCBD, ifStmt),
			afterIf);
	}
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitSwitchInst(llvm::SwitchInst &si) {
	// Find the common switch destination, i.e. which basic block is the
	// successor of the switch, no matter which case is taken. This information
	// is then used in the same way as when emitting nested if-else blocks.
	llvm::BasicBlock *csd = branchInfo->findCommonSwitchDestination(&si);
	branchInfo->branchStackPush(csd);

	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(
		converter->llvmValueToExpression(si.getCondition())));
	generatingSwitchStmt = true;

	// If the default branch has only a single predecessor, generate it as the
	// first clause of the switch statement. If it has two predecessors,
	// generate it after the second predecessor. Otherwise, if it has more than
	// one predecessor, generate it after the switch instruction.
	bool defaultBBGenerated = false;
	llvm::BasicBlock *defaultBB = si.getDefaultDest();
	if (defaultBB->getUniquePredecessor()) {
		switchStmt->addDefaultClause(getDefaultSwitchBlock(
			defaultBB, si.getNumOperands() >= 4 ?
				llvm::cast<llvm::BasicBlock>(si.getOperand(3)) : nullptr));
		defaultBBGenerated = true;
	}

	// Generate all cases in the switch. For every case, there are two operands:
	//     i:   the case condition
	//     i+1: the case body
	for (unsigned i = 2, e = si.getNumOperands(); i < e; i += 2) {
		// Case expression.
		ShPtr<Expression> caseExpr(getSwitchCaseExpression(si.getOperand(i)));

		// Case body.
		llvm::BasicBlock *bb = llvm::cast<llvm::BasicBlock>(si.getOperand(i + 1));
		llvm::Instruction *bbTerm = bb->getTerminator();
		if (LLVMSupport::endsWithRetOrUnreach(bb, false)) {
			// There is no need to generate a break statement.
			ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(si.getParent(), bb));
			ShPtr<Statement> block(Statement::mergeStatements(phiCopies,
				visitBasicBlockOrLoop(bb)));
			switchStmt->addClause(caseExpr, block);
		} else if (!defaultBBGenerated && llvm::isa<llvm::BranchInst>(bbTerm) &&
				llvm::cast<llvm::BranchInst>(bbTerm)->getSuccessor(0) == defaultBB &&
				LLVMSupport::getNumberOfUniquePredecessors(defaultBB) == 2) {
			// Fall through to the default case block.

			// Generate the case block.
			ShPtr<Statement> block(visitBasicBlockOrLoop(bb, false));
			ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(bb, defaultBB));
			switchStmt->addClause(caseExpr,
				Statement::mergeStatements(block, phiCopies));

			// Generate the default case block.
			ShPtr<Statement> defaultBlock(getDefaultSwitchBlock(defaultBB, (i + 2) < e ?
				llvm::cast<llvm::BasicBlock>(si.getOperand(i + 3)) : nullptr));
			switchStmt->addDefaultClause(defaultBlock);
			defaultBBGenerated = true;
		} else if ((i + 2) < e && llvm::isa<llvm::BranchInst>(bbTerm) &&
				llvm::cast<llvm::BranchInst>(bbTerm)->getSuccessor(0) == si.getOperand(i + 3)) {
			// Fall through to the next case (not the default one).
			ShPtr<Statement> block(visitBasicBlockOrLoop(bb, false));
			ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(bb,
				llvm::cast<llvm::BasicBlock>(si.getOperand(i + 3))));
			switchStmt->addClause(caseExpr,
				Statement::mergeStatements(block, phiCopies));
		} else {
			// There is no fall through, so also generate a break statement;
			// however, only if the instruction that bb ends with is not a
			// return statement (otherwise, it would be redundant).
			ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(si.getParent(), bb));
			ShPtr<Statement> block(Statement::mergeStatements(phiCopies,
				visitBasicBlockOrLoop(bb)));
			if (!llvm::isa<llvm::ReturnInst>(bb->getTerminator())) {
				block = Statement::mergeStatements(block,
					BreakStmt::create());
			}
			switchStmt->addClause(caseExpr, block);
		}
	}

	branchInfo->branchStackPop();

	// Check whether the default basic block has been generated.
	if (!defaultBBGenerated) {
		// It hasn't been generated yet. There are two known situations where
		// this may happen, (1) and (2), discussed next.
		if (defaultBB == si.getParent()) {
			// (1) The default basic block is the same basic block in which
			// this switch statement is. A goto statement is necessary here.
			ShPtr<GotoStmt> gotoStmt;
			if (mapHasKey(bbStmtMap, si.getParent())) {
				auto gotoTarget = bbStmtMap[si.getParent()];
				gotoStmt = GotoStmt::create(gotoTarget);
				setGotoTargetLabel(gotoTarget, si.getParent());
			} else if (defaultBB->getFirstNonPHI() == &si) {
				// The goto target is the switch statement itself.
				bbStmtMap[si.getParent()] = switchStmt;
				gotoStmt = GotoStmt::create(switchStmt);
				setGotoTargetLabel(switchStmt, si.getParent());
			} else {
				// We do not have a mapping of si.getParent() in bbStmtMap, so
				// the goto statement will need to be patched.
				gotoStmt = GotoStmt::create(EmptyStmt::create());
				addGotoStmtToPatch(ucast<GotoStmt>(gotoStmt), si.getParent());
			}

			ShPtr<Statement> phiCopies(getPHICopiesForSuccessor(si.getParent(),
				si.getParent()));
			ShPtr<Statement> defaultBlock(Statement::mergeStatements(
				phiCopies, gotoStmt));
			switchStmt->addDefaultClause(defaultBlock);
		} else {
			// (2) It is a common branch destination of some cases in the switch.
			// Therefore, generate it as the successor of the switch statement.
			// TODO PHI copies?
			switchStmt->setSuccessor(visitBasicBlockOrLoop(defaultBB));
		}
	} else if (csd && csd != defaultBB) {
		// TODO PHI copies?
		// Generate the basic blocks after the switch statement (if there are
		// any).
		switchStmt->setSuccessor(visitBasicBlockOrLoop(csd));
	}

	generatingSwitchStmt = false;

	// The switch statement has to be preceded by PHI copies for the default
	// clause.
	ShPtr<Statement> phiCopiesSwitch(getPHICopiesForSuccessor(si.getParent(),
		si.getDefaultDest()));
	return Statement::mergeStatements(phiCopiesSwitch, switchStmt);
}

ShPtr<Value> OrigLLVMIR2BIRConverter::visitReturnInst(llvm::ReturnInst &i) {
	return converter->llvmReturnInstToReturnStmt(i);
}

} // namespace llvmir2hll
} // namespace retdec
