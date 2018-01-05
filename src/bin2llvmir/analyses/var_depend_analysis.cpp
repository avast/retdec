/**
* @file src/bin2llvmir/analyses/var_depend_analysis.cpp
* @brief Implementation of VarDependAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <set>

#include <llvm/Support/raw_ostream.h>

#include "retdec/bin2llvmir/analyses/var_depend_analysis.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/**
* @brief Emits nodes to standard error.
*
* Only for debugging purposes.
*/
void VarDependAnalysis::print() {
	errs() << "[VarDependAnalysis] Debug info for nodes.\n";
	errs() << "*******************************************\n";
	for (auto &item : nodeMap) {
		errs() << "Node: '" << item.first << "'\n";
		item.second->print();
	}
	errs() << "*******************************************\n";
}

/**
* @brief Emits node to standard error.
*
* Only for debugging purposes.
*/
void VarDependAnalysis::Node::print() {
	errs() << "     Name of node: '" << name << "'\n";
	errs() << "     PHI: '" << *phiNode << "'\n";
	errs() << "     Sucessors:\n";
	for (auto &item : succMap) {
		errs() << "          Destination node of successor: '" << item.first <<
			"'\n";
		item.second.print();
	}
}

/**
* @brief Emits successor to standard error.
*
* Only for debugging purposes.
*/
void VarDependAnalysis::Node::Successor::print() {
	errs() << "               Name of node: '" << succ->name << "\n";
	errs() << "               Incoming basic blocks:\n";
	for (BasicBlock *bb : incBBs) {
		errs() << "                    Basic block: '" << bb->getName() << "'\n";
	}
}

/**
* @brief Constructs a new variable dependency analysis.
*/
VarDependAnalysis::VarDependAnalysis() {}

/**
* @brief Destructs the variable dependency analysis.
*/
VarDependAnalysis::~VarDependAnalysis() {
	clear();
}

/**
* @brief Clears all containers.
*/
void VarDependAnalysis::clear() {
	// Deallocate nodes.
	for (auto &item : nodeMap) {
		delete item.second;
	}

	// Clearing containers.
	nodeMap.clear();
	nodeVec.clear();
	resultForCycles.clear();
	resultOfNonCycle.clear();
}

/**
* @brief Creates edge that describes dependency of variables.
*
* For example:
* @code
* %A = [ %B, %.bb1].
* @endcode
* We create edge
* @code
* B -> A with label %.bb1(basic block)
* @endcode
* and saves PHI node to node A.
*
* @param[in] srcNodeName Name of source node.
* @param[in] dstNodeName Name of destination node.
* @param[in] incBB Basic block that describes relation.
* @param[in] phiNode PHI node that is used to create this edge.
*/
void VarDependAnalysis::addEdge(const std::string &srcNodeName,
		const std::string &dstNodeName, BasicBlock &incBB, PHINode *phiNode) {
	// Get source and destination node.
	Node &srcNode(findOrCreateNode(srcNodeName));
	Node &dstNode(findOrCreateNode(dstNodeName));

	// Add successor for source node.
	srcNode.addSucc(dstNode, incBB);

	// Add PHI node to destination node.
	dstNode.phiNode = phiNode;
}

/**
* @brief Tries to find @a nodeName in @c mapOfNodes. If it doesn't exist, it is
*        created.
*
* @param[in] nodeName Name of node to find.
*
* @return Found node and if not found return new created node.
*/
VarDependAnalysis::Node &VarDependAnalysis::findOrCreateNode
		(const std::string &nodeName) {
	// Try to find.
	auto nodeIt(nodeMap.find(nodeName));
	if (nodeIt != nodeMap.end()) {
		// We have found the node.
		return *nodeIt->second;
	}

	// The node doesn't exist -> create it
	Node *node = new Node(nodeName);
	nodeMap[nodeName] = node;
	nodeVec.push_back(node);
	return *node;
}

/**
* @brief Iterating over nodes and tries to detect cycles.
*
* @return PHI nodes that have to be optimized.
*/
const VarDependAnalysis::StringBBVecOfPHINodesMap &VarDependAnalysis::
		detectCycleVarDependency() {
	iterateThroughNodesCycleDetect();

	setAllNodesAsNotSolved();

	return resultForCycles;
}

/**
* @brief Iterates through nodes in @c mapOfNodes and visit them.
*/
void VarDependAnalysis::iterateThroughNodesCycleDetect() {
	for (Node *node : nodeVec) {
		if (!node->solved) {
			visitNodeCycleDetect(*node);
		}
	}
}

/**
* @brief Sets all nodes of @c mapOfNodes as not solved.
*/
void VarDependAnalysis::setAllNodesAsNotSolved() {
	for (auto &item : nodeMap) {
		item.second->markAsNotSolved();
	}
}

/**
* @brief Visit node also call visiting successors and tries to detect cycles.
*
* @param[in] node Node to visit.
*
* @return The null pointer if cycle was not detected, otherwise node in which
*         a cycle was detected.
*/
VarDependAnalysis::Node *VarDependAnalysis::visitNodeCycleDetect(Node &node) {
	if (node.visited) {
		// We found a cycle, so return this node.
		return &node;
	}

	node.markAsVisited();

	// Iterate through successors.
	auto it(node.succMap.begin());
	while (it != node.succMap.end()) {
		Node *retVal(visitNodeCycleDetect(*it->second.succ));
		if (retVal == &node) {
			// We are back in the node that causes a cycle. We save this to the
			// result and erase the edge that causes the cycle.
			addResultOfCycle(it->second);
			node.succMap.erase(it++);
		} else if (retVal != nullptr) {
			// Cycle detected, so go back to the node that causes the cycle.
			node.markAsNotVisited();
			return retVal;
		} else {
			// Nothing detected.
			++it;
		}
	}

	node.markAsSolvedAndNotVisited();

	return nullptr;
}

/**
* @brief Add one detected result of cycle detection.
*
* Key of map is predecessor basic block of PHI node and values are PHI nodes that
* have to be optimized, but optimization have to be made on incoming values with
* basic block that is key.
*
* @param[in] successor Detected result.
*/
void VarDependAnalysis::addResultOfCycle(Node::Successor &successor) {
	// Try to find if there exists a result with the same predecessor basic
	// block.
	for (BasicBlock *incBB : successor.incBBs) {
		auto it = resultForCycles.find(incBB->getName());

		if (it != resultForCycles.end()) {
			// Add new PHI node to this predecessor basic block.
			it->second.phiNodeVec.push_back(successor.succ->phiNode);
		} else {
			// Need to create a new vector of PHI nodes.
			resultForCycles.emplace(incBB->getName(), BBVecOfPHINodes(incBB,
				PHINodeVec{successor.succ->phiNode}));
		}
	}
}

/**
* @brief Detects a non-cycle variable dependency.
*
* @return Correct order of PHI nodes.
*/
const VarDependAnalysis::PHINodeVec &VarDependAnalysis::
		detectNonCycleVarDependency() {
	// Iterate over nodes and visit them.
	iterateThroughNodesNonCycleVarDependency();

	return resultOfNonCycle;
}

/**
* @brief Iterates through nodes in @c mapOfNodes and visit them.
*/
void VarDependAnalysis::iterateThroughNodesNonCycleVarDependency() {
	for (Node *node : nodeVec) {
		visitNodeNonCycleVarDependency(*node);
	}
}

/**
* @brief Visit node and detect variable dependency.
*
* @param[in] node Node to visit.
*/
void VarDependAnalysis::visitNodeNonCycleVarDependency(Node &node) {
	assert(!node.visited && "Cycle dependency occurred.");

	if (node.solved) {
		// This node was processed.
		return;
	}

	node.markAsVisited();

	iterateThroughSuccessorsAndVisitTheirNode(node);

	if (node.phiNode) {
		// Add this node to result.
		resultOfNonCycle.push_back(node.phiNode);
	}

	node.markAsSolvedAndNotVisited();
}

/**
* @brief Iterates through successors and visit their nodes.
*
* @param[in] node Node to iterate.
*/
void VarDependAnalysis::iterateThroughSuccessorsAndVisitTheirNode(Node &node) {
	for (auto &item : node.succMap) {
		// Visit successor node.
		visitNodeNonCycleVarDependency(*item.second.succ);
	}
}

/**
* @brief Constructor of node.
*
* @param[in] name Name of node.
* @param[in] phiNode PHI node for this node.
*/
VarDependAnalysis::Node::Node(const std::string &name, llvm::PHINode* phiNode):
		name(name), phiNode(phiNode), visited(false), solved(false) {}

/**
* Destructor of node.
*/
VarDependAnalysis::Node::~Node() {}

/**
* @brief Adds successor for node.
*
* @param[in] succ Successor node.
* @param[in] incBB Basic block as label of edge.
*/
void VarDependAnalysis::Node::addSucc(Node &succ, BasicBlock &incBB) {
	auto it(succMap.find(succ.name));
	if (it != succMap.end()) {
		it->second.incBBs.insert(&incBB);
	} else {
		succMap.emplace(succ.name, Successor(&succ, incBB));
	}
}

/**
* @brief Mark node as not visited.
*/
void VarDependAnalysis::Node::markAsNotVisited() {
	visited = false;
}

/**
* @brief Mark node as visited.
*/
void VarDependAnalysis::Node::markAsVisited() {
	visited = true;
}

/**
* @brief Mark node as not solved.
*/
void VarDependAnalysis::Node::markAsNotSolved() {
	solved = false;
}

/**
* @brief Mark node as solved.
*/
void VarDependAnalysis::Node::markAsSolved() {
	solved = true;
}

/**
* @brief Mark node as solved and not visited.
*/
void VarDependAnalysis::Node::markAsSolvedAndNotVisited() {
	markAsSolved();
	markAsNotVisited();
}

} // namespace bin2llvmir
} // namespace retdec
