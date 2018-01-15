/**
* @file src/llvmir2hll/support/struct_types_sorter.cpp
* @brief Implementation of StructTypesSorter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>

#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/struct_types_sorter.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Converts the given set of StructType into a vector.
*/
StructTypeVector toVector(const StructTypeSet &types) {
	return StructTypeVector(types.begin(), types.end());
}

/// Mapping of a structured type @c X into the set of structures that has to be
/// defined before @c X.
using Dependencies = std::map<ShPtr<StructType>, StructTypeSet>;

/**
* @brief Returns structured types that have to be defined before @c type.
*/
StructTypeSet findDependencies(ShPtr<StructType> type) {
	StructTypeSet dependencies;
	for (const auto &t : type->getElementTypes()) {
		// Directly contained structure.
		if (ShPtr<StructType> st = cast<StructType>(t)) {
			dependencies.insert(st);
		// Array of structures.
		} else if (ShPtr<ArrayType> at = cast<ArrayType>(t)) {
			if (ShPtr<StructType> st = cast<StructType>(at->getContainedType())) {
				dependencies.insert(st);
			}
		}
	}
	return dependencies;
}

/**
* @brief Returns the dependencies between the given structured types.
*/
Dependencies findDependencies(const StructTypeSet &types) {
	Dependencies dependencies;
	for (const auto &type : types) {
		dependencies[type] = findDependencies(type);
	}
	return dependencies;
}

/**
* @brief Comparator of StructType by using their names.
*/
class ByNameComp {
public:
	/**
	* @brief Returns @c true if <tt>st1 < st2</tt>, @c false otherwise.
	*/
	bool operator()(ShPtr<StructType> st1, ShPtr<StructType> st2) const {
		return st1->getName() < st2->getName();
	}
};

/**
* @brief Sorts @c types by using their names.
*/
void sortByName(StructTypeVector &types) {
	std::sort(types.begin(), types.end(), ByNameComp());
}

/**
* @brief Checks whether the given structure has satisfied all the given
*        dependencies.
*/
bool hasAllDependenciesSatisfied(ShPtr<StructType> st,
		const StructTypeSet &stDeps,
		const StructTypeVector &sortedTypes) {
	for (const auto &stDep : stDeps) {
		if (!hasItem(sortedTypes, stDep)) {
			return false;
		}
	}
	return true;
}

/**
* @brief Returns the next structure to be included into @a sortedTypes based on
*        @a remainingTypes.
*/
ShPtr<StructType> getNextStructToInclude(const Dependencies &dependencies,
		const StructTypeVector &remainingTypes,
		const StructTypeVector &sortedTypes) {
	for (const auto &type: remainingTypes) {
		const StructTypeSet &stDeps(dependencies.find(type)->second);
		if (hasAllDependenciesSatisfied(type, stDeps, sortedTypes)) {
			return type;
		}
	}

	FAIL("There is no next structure to be included"
		" (perhaps a circular dependency?).");
	return ShPtr<StructType>();
}

/**
* @brief Removes @a st from @a types.
*/
void removeFromVector(ShPtr<StructType> st, StructTypeVector &types) {
	types.erase(std::remove(types.begin(), types.end(), st), types.end());
}

/**
* @brief Sorts @c types by using their @a dependencies.
*/
void sortByDependencies(StructTypeVector &types, const Dependencies &dependencies) {
	StructTypeVector remainingTypes(types);
	StructTypeVector sortedTypes;

	while (!remainingTypes.empty()) {
		ShPtr<StructType> st(getNextStructToInclude(dependencies,
			remainingTypes, sortedTypes));
		sortedTypes.push_back(st);
		removeFromVector(st, remainingTypes);
	}

	types = sortedTypes;
}

} // anonymous namespace

/**
* @brief Sorts the given set of structured types according to their
*        names and dependencies.
*
* For example, if @a types contains the following three structures
* @code
* struct A { struct B b; };
* struct B { struct C c; };
* struct C {};
* @endcode
* then they are ordered in the following way
* @code
* struct C {};
* struct B { struct C c; };
* struct A { struct B b; };
* @endcode
* This is the order in which they have to be defined.
*
* Before the structures are compared based on dependencies, they are sorted by
* their names. This results into a more deterministic output.
*
* @par Preconditions
*  - the structures can be sorted, i.e. there are no dependency loops that
*    would prevent the structures from being sorted (standard C behavior)
*/
StructTypeVector StructTypesSorter::sort(const StructTypeSet &types) {
	StructTypeVector typesVector(toVector(types));
	sortByName(typesVector);
	sortByDependencies(typesVector, findDependencies(types));
	return typesVector;
}

} // namespace llvmir2hll
} // namespace retdec
