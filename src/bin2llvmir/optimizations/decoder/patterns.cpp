/**
* @file src/bin2llvmir/optimizations/decoder/patterns.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/utils/capstone.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/**
 * \return \c True if function changed something in IR, \c false otherwise.
 */
bool Decoder::patternsRecognize()
{
	bool modified = false;

	modified |= patternTerminatingCalls();
	modified |= patternStaticallyLinked();

	return modified;
}

/**
 * \return \c True if function changed something in IR, \c false otherwise.
 */
bool Decoder::patternTerminatingCalls()
{
	bool modified = false;

	LOG << "\n splitOnTerminatingCalls():" << std::endl;

	// Find out all terminating functions.
	//
	LOG << "\tfind all terminating functions:" << std::endl;
	std::set<Instruction*> termCalls;
	std::set<Function*> nonTermFncs;
	auto oldSz = _terminatingFncs.size();
	do
	{
		oldSz = _terminatingFncs.size();

		// Potential terminating functions are those, that contain at least
		// one terminating call = call to terminating function.
		//
		std::set<Function*> potentialTermFncs;
		for (auto* f : _terminatingFncs)
		{
			for (auto* u : f->users())
			{
				if (auto* call = dyn_cast<CallInst>(u))
				{
					termCalls.insert(call);
					if (_terminatingFncs.count(call->getFunction()) == 0
							&& nonTermFncs.count(call->getFunction()) == 0)
					{
						potentialTermFncs.insert(call->getFunction());
					}
				}
			}
		}

		// Function is terminating if all paths from function start end up
		// in terminating call(s):
		// - There might be more the a single terminating call.
		// - They do not even have to call the same terminating function.
		// - There can not be a path that ends in normal return.
		//
		for (auto* f : potentialTermFncs)
		{
			LOG << "\t\tpotential term @ " << f->getName().str() << std::endl;

			std::queue<BasicBlock*> bbWorklist;
			std::set<BasicBlock*> bbSeen;
			bbWorklist.push(&f->front());
			bbSeen.insert(&f->front());

			bool terminating = true;
			while (!bbWorklist.empty())
			{
				auto* workBb = bbWorklist.front();
				bbWorklist.pop();

				bool reachEnd = true;
				for (Instruction& i : *workBb)
				{
					if (termCalls.count(&i))
					{
						reachEnd = false;
						break;
					}
					else if (isa<ReturnInst>(&i))
					{
						terminating = false;
						break;
					}
				}

				if (!terminating)
				{
					break;
				}
				if (reachEnd)
				{
					for (auto s = succ_begin(workBb), e = succ_end(workBb);
							s != e; ++s)
					{
						if (bbSeen.count(*s) == 0)
						{
							bbWorklist.push(*s);
							bbSeen.insert(*s);
						}
					}
				}
			}

			if (terminating)
			{
				LOG << "\t\t\t-> IS terminating" << std::endl;
				_terminatingFncs.insert(f);
			}
			else
			{
				LOG << "\t\t\t-> IS NOT terminating" << std::endl;
				nonTermFncs.insert(f);
			}
		}
	} while (oldSz != _terminatingFncs.size());

	// Split Bbs after terminating calls and insert returns after them.
	//
	LOG << "\tsplit BBs after terminating calls:" << std::endl;
	for (auto* call : termCalls)
	{
		auto* bb = call->getParent();
		AsmInstruction callAi(call);
		AsmInstruction nextAi = callAi.getNext();

		if (callAi.isInvalid()
				|| nextAi.isInvalid())
		{
			continue;
		}

		if (callAi.getBasicBlock() != nextAi.getBasicBlock())
		{
			auto* term = bb->getTerminator();
			auto* ui = new UnreachableInst(_module->getContext());
			ReplaceInstWithInst(term, ui);

			LOG << "\t\tbreak flow @ " << nextAi.getAddress() << std::endl;
			modified = true;
			continue;
		}

		auto* newBb = bb->splitBasicBlock(nextAi.getLlvmToAsmInstruction());
		auto* term = bb->getTerminator();
		auto* ui = new UnreachableInst(_module->getContext());
		ReplaceInstWithInst(term, ui);

		modified = true;

		LOG << "\t\tsplit @ " << nextAi.getAddress() << std::endl;

		AsmInstruction lastNop;
		AsmInstruction ai(newBb);
		while (ai.isValid() && ai.getBasicBlock() == newBb)
		{
			if (_abi->isNopInstruction(ai))
			{
				lastNop = ai;
				ai = ai.getNext();
			}
			else
			{
				break;
			}
		}

		if (lastNop.isValid())
		{
			AsmInstruction lastInNewBb(newBb->getTerminator());
			if (lastNop == lastInNewBb)
			{
				LOG << "\t\t\tremove entire BB of NOPs @ "
						<< nextAi.getAddress() << std::endl;

				newBb->eraseFromParent();
				newBb = nullptr;
			}
			else
			{
				LOG << "\t\t\tsplit @ " << lastNop.getNext().getAddress()
						<< std::endl;
				LOG << "\t\t\tremove NOPs @ " << nextAi.getAddress()
						<< std::endl;

				auto* tmpBb = newBb;
				newBb = tmpBb->splitBasicBlock(
						lastNop.getNext().getLlvmToAsmInstruction());
				tmpBb->eraseFromParent();
			}
		}

		if (newBb)
		{
			Address a = AsmInstruction::getBasicBlockAddress(newBb);
			newBb->setName(names::generateBasicBlockName(a));
			addBasicBlock(a, newBb);
		}
	}

	// Split functions after terminating calls if terminating call is the only
	// path from blocks before it to block after and vice versa.
	//
	LOG << "\tsplit functions after terminating calls:" << std::endl;
	for (auto* call : termCalls)
	{
		auto* f = call->getFunction();
		auto* b = call->getParent();
		auto* nextBb = b->getNextNode();
		if (nextBb == nullptr)
		{
			continue;
		}

		std::set<BasicBlock*> before;

		bool split = true;
		bool after = false;
		for (BasicBlock& bb : *f)
		{
			if (after)
			{
				for (auto* p : predecessors(&bb))
				{
					if (before.count(p))
					{
						split = false;
						break;
					}
				}

				if (!split)
				{
					break;
				}

				for (auto* s : successors(&bb))
				{
					if (before.count(s))
					{
						if (&f->front() != s)
						{
							split = false;
							break;
						}
					}
				}
			}
			else if (&bb == call->getParent())
			{
				after = true;
			}
			else
			{
				before.insert(&bb);
			}
		}

		if (split)
		{
			Address addr = getBasicBlockAddress(nextBb);
			assert(addr.isDefined());

			LOG << "\t\tsplit fnc @ " << addr << std::endl;

			splitFunctionOn(addr);
			modified = true;
		}
	}

	return modified;
}

/**
 * Sometimes, statically linked code detection does not recognize all statically
 * linked functions. We search for the following patterns:
 *
 * \code{.ll}
 * define <certain_fnc_name>()
 *     ...
 *     single function call in the whole body = call to statically linked fnc
 *     ...
 * \endcode
 */
bool Decoder::patternStaticallyLinked()
{
	bool modified = false;

	for (Function& f : *_module)
	{
		if (!(f.getName() == "scanf"
				|| f.getName() == "printf"))
		{
			continue;
		}

		auto fncAddr = getFunctionAddress(&f);
		if (fncAddr.isUndefined())
		{
			continue;
		}

		bool firstCall = true;
		bool ok = false;
		for (BasicBlock& b : f)
		for (Instruction& i : b)
		{
			if (auto* c = dyn_cast<CallInst>(&i))
			{
				if (_c2l->isAnyPseudoFunctionCall(c))
				{
					continue;
				}

				if (!firstCall)
				{
					ok = false;
					break;
				}
				firstCall = false;

				auto targetAddr = getFunctionAddress(c->getCalledFunction());
				if (targetAddr.isDefined()
						&& _staticFncs.count(targetAddr))
				{
					ok = true;
				}
				// TODO: the above is not enough
				// bugs.thumb-bitcnt-1-integration-test.Test
				else if (c->getCalledFunction()
						&& (c->getCalledFunction()->getName() == "vfprintf"
						|| c->getCalledFunction()->getName() == "__svfscanf_r"))
				{
					ok = true;
				}
				else
				{
					ok = false;
					break;
				}
			}
		}

		if (ok)
		{
			_staticFncs.emplace(fncAddr);
		}
	}

	return modified;
}

} // namespace bin2llvmir
} // namespace retdec
