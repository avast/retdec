/**
* @file src/llvmir2hll/var_name_gen/var_name_gens/fruit_var_name_gen.cpp
* @brief Implementation of FruitVarNameGen.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/StringExtras.h>

#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gen_factory.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gens/fruit_var_name_gen.h"
#include "retdec/utils/array.h"

using retdec::utils::arraySize;

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("fruit", FRUIT_VAR_NAME_GEN_ID, VarNameGenFactory,
	FruitVarNameGen::create);

namespace {

// A list of all available fruit names.
const char *AVAIL_FRUITS[] = {
	"apple",
	"banana",
	"lemon",
	"plum",
	"orange",
	"melon",
	"pear",
	"tea",
	"cherry",
	"grape",
	"apricot",
	"tomato",
	"abaca",
	"peach",
	"papaya",
	"grape",
	"tampoi",
	"lime",
	"nut",
	"mango",
	"avocado",
	"raspberry",
	"tangerine",
	"lulita",
	"raisin",
	"nectarine",
	"legume",
	"jambul",
	"durian",
	"lychee",
	"achira",
	"damson",
	"blackberry",
	"chickoo",
	"jackfruit",
	"luma",
	"salal",
	"taro",
	"manis",
	"rata",
	"tuna",
	"yucca",
	"duku",
	"eddo",
	"fig",
	"mape",
	// TODO
};

// Index of the last available fruit name.
const std::size_t LAST_FRUIT_INDEX = arraySize(AVAIL_FRUITS) - 1;

} // anonymous namespace

/**
* @brief Constructs a new generator.
*
* For more details, see create().
*/
FruitVarNameGen::FruitVarNameGen(std::string prefix):
		VarNameGen(prefix), nextFruitIndex(0) {}

/**
* @brief Creates a generator.
*
* @param[in] prefix Prefix of all returned variable names.
*/
UPtr<VarNameGen> FruitVarNameGen::create(std::string prefix) {
	return UPtr<VarNameGen>(new FruitVarNameGen(prefix));
}

std::string FruitVarNameGen::getId() const {
	return FRUIT_VAR_NAME_GEN_ID;
}

void FruitVarNameGen::restart() {
	nextFruitIndex = 0;
}

std::string FruitVarNameGen::getNextVarName() {
	if (nextFruitIndex == LAST_FRUIT_INDEX) {
		// No more available fruit names, so start from the beginning.
		restart();
		return getNextVarName();
	} else {
		return prefix + AVAIL_FRUITS[nextFruitIndex++];
	}
}

} // namespace llvmir2hll
} // namespace retdec
