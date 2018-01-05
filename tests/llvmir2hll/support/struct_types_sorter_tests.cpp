/**
* @file tests/llvmir2hll/support/struct_types_sorter_tests.cpp
* @brief Tests for the @c struct_types_sorter module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/support/struct_types_sorter.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c struct_types_sorter module.
*/
class StructTypesSorterTests: public Test {};

TEST_F(StructTypesSorterTests,
ForNoStructTypeEmptyVectorIsReturned) {
	StructTypeSet structTypes;
	StructTypeVector refSortedStructTypes;

	EXPECT_EQ(refSortedStructTypes, StructTypesSorter::sort(structTypes));
}

TEST_F(StructTypesSorterTests,
SingleStructTypeIsConvertedToSingletonVector) {
	// Input:
	//
	// struct A {};
	//
	StructTypeSet structTypes;
	ShPtr<StructType> structA(StructType::create(StructType::ElementTypes(), "A"));
	structTypes.insert(structA);

	// Expected output:
	//
	// struct A {};
	//
	StructTypeVector refSortedStructTypes;
	refSortedStructTypes.push_back(structA);

	EXPECT_EQ(refSortedStructTypes, StructTypesSorter::sort(structTypes));
}

TEST_F(StructTypesSorterTests,
ThreeStructTypesWithoutDependenciesAreSortedByName) {
	// Input:
	//
	// struct A {};
	// struct B {};
	// struct C {};
	//
	StructTypeSet structTypes;
	ShPtr<StructType> structA(StructType::create(StructType::ElementTypes(), "A"));
	structTypes.insert(structA);
	ShPtr<StructType> structB(StructType::create(StructType::ElementTypes(), "B"));
	structTypes.insert(structB);
	ShPtr<StructType> structC(StructType::create(StructType::ElementTypes(), "C"));
	structTypes.insert(structC);

	// Expected output:
	//
	// struct A {};
	// struct B {};
	// struct C {};
	//
	StructTypeVector refSortedStructTypes;
	refSortedStructTypes.push_back(structA);
	refSortedStructTypes.push_back(structB);
	refSortedStructTypes.push_back(structC);

	EXPECT_EQ(refSortedStructTypes, StructTypesSorter::sort(structTypes));
}

TEST_F(StructTypesSorterTests,
ThreeStructTypesWithDependenciesAreProperlySorted) {
	// Input:
	//
	// struct C {};
	// struct B { struct C c; };
	// struct A { struct B b; };
	//
	StructTypeSet structTypes;
	ShPtr<StructType> structC(StructType::create(StructType::ElementTypes(), "C"));
	structTypes.insert(structC);
	StructType::ElementTypes structBElements;
	structBElements.push_back(structC);
	ShPtr<StructType> structB(StructType::create(structBElements, "B"));
	structTypes.insert(structB);
	StructType::ElementTypes structAElements;
	structAElements.push_back(structB);
	ShPtr<StructType> structA(StructType::create(structAElements, "A"));
	structTypes.insert(structA);

	// Expected output:
	//
	// struct C {};
	// struct B { struct C c; };
	// struct A { struct B b; };
	//
	StructTypeVector refSortedStructTypes;
	refSortedStructTypes.push_back(structC);
	refSortedStructTypes.push_back(structB);
	refSortedStructTypes.push_back(structA);

	EXPECT_EQ(refSortedStructTypes, StructTypesSorter::sort(structTypes));
}

TEST_F(StructTypesSorterTests,
ThreeStructTypesWithDependenciesInArraysAreProperlySorted) {
	// Input:
	//
	// struct C {};
	// struct B { struct C c[]; };
	// struct A { struct B b[]; };
	//
	StructTypeSet structTypes;
	ShPtr<StructType> structC(StructType::create(StructType::ElementTypes(), "C"));
	structTypes.insert(structC);
	StructType::ElementTypes structBElements;
	structBElements.push_back(ArrayType::create(structC, ArrayType::Dimensions()));
	ShPtr<StructType> structB(StructType::create(structBElements, "B"));
	structTypes.insert(structB);
	StructType::ElementTypes structAElements;
	structAElements.push_back(ArrayType::create(structB, ArrayType::Dimensions()));
	ShPtr<StructType> structA(StructType::create(structAElements, "A"));
	structTypes.insert(structA);

	// Expected output:
	//
	// struct C {};
	// struct B { struct C c[]; };
	// struct A { struct B b[]; };
	//
	StructTypeVector refSortedStructTypes;
	refSortedStructTypes.push_back(structC);
	refSortedStructTypes.push_back(structB);
	refSortedStructTypes.push_back(structA);

	EXPECT_EQ(refSortedStructTypes, StructTypesSorter::sort(structTypes));
}

TEST_F(StructTypesSorterTests,
FiveStructTypesWithSomeDependenciesAreProperlySortedByNameAndByDependencies) {
	// Input:
	//
	// struct C {};
	// struct B { struct C c; };
	// struct A { struct B b; };
	// struct D {};
	// struct E {};
	//
	StructTypeSet structTypes;
	ShPtr<StructType> structC(StructType::create(StructType::ElementTypes(), "C"));
	structTypes.insert(structC);
	StructType::ElementTypes structBElements;
	structBElements.push_back(structC);
	ShPtr<StructType> structB(StructType::create(structBElements, "B"));
	structTypes.insert(structB);
	StructType::ElementTypes structAElements;
	structAElements.push_back(structB);
	ShPtr<StructType> structA(StructType::create(structAElements, "A"));
	structTypes.insert(structA);
	ShPtr<StructType> structD(StructType::create(StructType::ElementTypes(), "D"));
	structTypes.insert(structD);
	ShPtr<StructType> structE(StructType::create(StructType::ElementTypes(), "E"));
	structTypes.insert(structE);

	// Expected output:
	//
	// struct C {};
	// struct B { struct C c; };
	// struct A { struct B b; };
	// struct D {};
	// struct E {};
	//
	StructTypeVector refSortedStructTypes;
	refSortedStructTypes.push_back(structC);
	refSortedStructTypes.push_back(structB);
	refSortedStructTypes.push_back(structA);
	refSortedStructTypes.push_back(structD);
	refSortedStructTypes.push_back(structE);

	EXPECT_EQ(refSortedStructTypes, StructTypesSorter::sort(structTypes));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
