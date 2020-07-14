/**
* @file tests/bin2llvmir/providers/tests/names_tests.cpp
* @brief Tests for the @c NamesProvider.
* @copyright (c) 2020 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/providers/lti.h"
#include "bin2llvmir/utils/llvmir_tests.h"


using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

//
//=============================================================================
//  NameTests
//=============================================================================
//

/**
 * @brief Tests for the @c Lti.
 */
class NameTests: public LlvmIrTests
{

};

TEST_F(NameTests, OperatorLessForEqualElements)
{
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);

	Name n1(&config, "strcmp", Name::eType::SYMBOL_FUNCTION);
	Name n2(&config, "strcmp", Name::eType::SYMBOL_FUNCTION);

	EXPECT_FALSE(n1 < n2);
	EXPECT_FALSE(n2 < n1);
}

TEST_F(NameTests, OperatorLessForEqualElementsWithDots)
{
	auto c = config::Config::fromJsonString(R"({
		"architecture" : {
			"bitSize" : 32,
			"endian" : "little",
			"name" : "x86"
		}
	})");
	auto config = Config::fromConfig(module.get(), c);

	Name n1(&config, ".strcmp", Name::eType::SYMBOL_FUNCTION);
	Name n2(&config, ".strcmp", Name::eType::SYMBOL_FUNCTION);

	EXPECT_FALSE(n1 < n2);
	EXPECT_FALSE(n2 < n1);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
