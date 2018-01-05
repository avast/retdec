/**
* @file tests/ctypesparser/json_ctypes_parser_tests.cpp
* @brief Tests for the @c JSONCTypes_parser module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/ctypes/array_type.h"
#include "retdec/ctypes/call_convention.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/enum_type.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/parameter.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/struct_type.h"
#include "retdec/ctypes/typedefed_type.h"
#include "retdec/ctypes/union_type.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/void_type.h"
#include "retdec/ctypesparser/json_ctypes_parser.h"

using namespace ::testing;

namespace retdec {
namespace ctypesparser {
namespace tests {

class JSONCTypesParserTests : public Test
{
	public:
		JSONCTypesParserTests() {}
	protected:
		JSONCTypesParser parser;
};

TEST_F(JSONCTypesParserTests,
ParsingBadInputThrowsException)
{
	std::stringstream json(R"(
		{
			"missing bracket": 1
	)");

	ASSERT_THROW(parser.parse(json), CTypesParseError);
}

TEST_F(JSONCTypesParserTests,
ParsingJSONWithoutFunctionsItemThrowsException)
{
	std::stringstream json(R"(
		{
			"types": "No functions here"
		}
	)");

	ASSERT_THROW(parser.parse(json), CTypesParseError);
}

TEST_F(JSONCTypesParserTests,
ParsingJSONWithoutTypesItemThrowsException)
{
	std::stringstream json(R"(
		{
			"functions": {
				"f1": "no types info"
			}
		}
	)");

	ASSERT_THROW(parser.parse(json), CTypesParseError);
}

TEST_F(JSONCTypesParserTests,
ParsingJSONCanParseEmptyFunctionsAndTypes)
{
	std::stringstream json(R"(
		{
			"functions": {},
			"types": {}
		}
	)");

	ASSERT_NO_THROW(parser.parse(json));
}

#if DEATH_TESTS_ENABLED
TEST_F(JSONCTypesParserTests,
ParseIntoCrashesOnNullptrModule)
{
	std::stringstream stream;
	std::unique_ptr<retdec::ctypes::Module> mod = nullptr;

	EXPECT_DEATH(
		parser.parseInto(stream, mod),
		"violated precondition - module cannot be null"
	);
}
#endif

TEST_F(JSONCTypesParserTests,
SafeGetArrayThrowsExceptionWhenArrayNotInJson)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	// missing "param" in function ff
	ASSERT_THROW(parser.parse(json), CTypesParseError);
}

TEST_F(JSONCTypesParserTests,
SafeGetStringThrowsExceptionWhenStringNotInJsonNorDefaultIsString)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": [],
					"header": "CHeader.h",
					"param": [],
					"name": "ff",
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				}
			}
		}
	)");

	// decl should be string
	ASSERT_THROW(parser.parse(json), CTypesParseError);
}

TEST_F(JSONCTypesParserTests,
SafeGetBoolThrowsExceptionWhenValueIsNotBool)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff();",
					"header": "CHeader.h",
					"param": [],
					"name": "ff",
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"vararg": "vararg should be bool, not string"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	// vararg value should be bool
	ASSERT_THROW(parser.parse(json), CTypesParseError);
}

TEST_F(JSONCTypesParserTests,
ParseIntoParsesFunctionsToPassedModule)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "b",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");
	auto module = std::make_unique<retdec::ctypes::Module>(std::make_shared<retdec::ctypes::Context>());
	parser.parseInto(json, module);
}

TEST_F(JSONCTypesParserTests,
ParseIntoWithExplicitTypeWidthsCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "b",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");
	JSONCTypesParser::TypeWidths typeWidths{{"int", 32}, {"long", 64}};
	auto module = std::make_unique<retdec::ctypes::Module>(std::make_shared<retdec::ctypes::Context>());

	parser.parseInto(json, module, typeWidths);
	auto func = module->getFunctionWithName("ff");

	EXPECT_EQ(32, func->getReturnType()->getBitWidth());
	EXPECT_EQ(32, func->getParameterType(1)->getBitWidth());
}

TEST_F(JSONCTypesParserTests,
ParsingFuncWithIntTypesCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "b",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");
	auto mod = parser.parse(json);

	ASSERT_TRUE(mod->hasFunctionWithName("ff"));

	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ("int", func->getReturnType()->getName());
	ASSERT_EQ(1, func->getParameterCount());
	EXPECT_EQ("b", func->getParameterName(1));
	EXPECT_EQ("int", func->getParameterType(1)->getName());
	EXPECT_FALSE(func->isVarArg());
}

TEST_F(JSONCTypesParserTests,
ParseUsingExplicitTypeWidthsCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "long ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "b",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "3338ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				},
				"3338ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "long",
					"type": "integral_type"
				}
			}
		}
	)");
	CTypesParser::TypeWidths typeWidths{{"int", 32}, {"long", 64}};

	auto mod = parser.parse(json, typeWidths);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(64, func->getReturnType()->getBitWidth());
	EXPECT_EQ(32, func->getParameterType(1)->getBitWidth());
}

TEST_F(JSONCTypesParserTests,
ParseUsingExplicitTypeWidthsSetsCorrectBitWidthsForLongAndLongDoubleWhenSet)
{
	// This test checks that "long" and "long double" are recognized as two
	// different types and that their bit withs are properly set.
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "long double ff(long b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "b",
							"type": "bd3027fa569ea15ca76d84db21c67e2d514c1a5a"
						}
					],
					"ret_type": "b5656629587221b8239b7141684c8f69c57c8f23"
				}
			},
			"types": {
				"bd3027fa569ea15ca76d84db21c67e2d514c1a5a": {
					"name": "long",
					"type": "integral_type"
				},
				"b5656629587221b8239b7141684c8f69c57c8f23": {
					"name": "long double",
					"type": "floating_point_type"
				}
			}
		}
	)");
	CTypesParser::TypeWidths typeWidths{{"long", 64}, {"long double", 80}};

	auto mod = parser.parse(json, typeWidths);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(80, func->getReturnType()->getBitWidth());
	EXPECT_EQ(64, func->getParameterType(1)->getBitWidth());
}

TEST_F(JSONCTypesParserTests,
ParseUsingDefaultTypeWidthsSetsZeroBitWidths)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "long ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "b",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "3338ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				},
				"3338ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "long",
					"type": "integral_type"
				}
			}
		}
	)");
	auto mod = parser.parse(json);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(0, func->getReturnType()->getBitWidth());
	EXPECT_EQ(0, func->getParameterType(1)->getBitWidth());
}

TEST_F(JSONCTypesParserTests,
DefaultTypeWidthSetInConstructorIsUsedWhenBitWidthNotInTypeWidthsMap)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "float ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "b",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "3338ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				},
				"3338ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "float",
					"type": "floating_point_type"
				}
			}
		}
	)");
	JSONCTypesParser parserDefaultBW = JSONCTypesParser(32);
	auto mod = parserDefaultBW.parse(json);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(32, func->getReturnType()->getBitWidth());
	EXPECT_EQ(32, func->getParameterType(1)->getBitWidth());
}

TEST_F(JSONCTypesParserTests,
ParsingUnsignedIntegralTypeTypeSetsCorrectSign)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "unsigned long ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "3338ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"3338ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "unsigned long",
					"type": "integral_type"
				}
			}
		}
	)");
	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	ASSERT_TRUE(retType->isIntegral());
	auto uLong = std::static_pointer_cast<retdec::ctypes::IntegralType>(retType);

	EXPECT_FALSE(uLong->isSigned());
}

TEST_F(JSONCTypesParserTests,
ParsingSignedIntegralTypeTypeSetsCorrectSign)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "long ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "3338ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"3338ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "long",
					"type": "integral_type"
				}
			}
		}
	)");
	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	ASSERT_TRUE(retType->isIntegral());
	auto sLong = std::static_pointer_cast<retdec::ctypes::IntegralType>(retType);

	EXPECT_TRUE(sLong->isSigned());
}

TEST_F(JSONCTypesParserTests,
ParsingFuncWithFloatTypeCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "float ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "685e80366130387cb75c055248326976d16fdf8d"
				}
			},
			"types": {
				"685e80366130387cb75c055248326976d16fdf8d": {
					"name": "float",
					"type": "floating_point_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ("float", func->getReturnType()->getName());
}

TEST_F(JSONCTypesParserTests,
ParsingFuncWithConstQualifierIgnoresConst)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "const float ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "685e80366130387cb75c055248326976d16fdf8d"
				}
			},
			"types": {
				"gg5e80366130387cb75c055248326976d16fdf8d": {
					"name": "float",
					"type": "floating_point_type"
				},
				"685e80366130387cb75c055248326976d16fdf8d": {
					"name": "const",
					"modified_type": "gg5e80366130387cb75c055248326976d16fdf8d",
					"type": "qualifier"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ("float", func->getReturnType()->getName());
}

TEST_F(JSONCTypesParserTests,
FuncWithVariableNumberOfParametersIsVarArg)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int b, ...);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "b",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"vararg": true
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_TRUE(func->isVarArg());
}

TEST_F(JSONCTypesParserTests,
FuncWithFixedNumberOfParametersIsNotVarArg)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "b",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_FALSE(func->isVarArg());
}

TEST_F(JSONCTypesParserTests,
ParsingFunctionSetsCorrectDeclaration)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto func = mod->getFunctionWithName("ff");
	std::string decl = func->getDeclaration();

	EXPECT_EQ("int ff();", decl);
}

TEST_F(JSONCTypesParserTests,
ParsingFunctionSetsCorrectHeaderFile)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff();",
					"header": "/usr/include/CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto func = mod->getFunctionWithName("ff");
	std::string header = func->getHeaderFile().getPath();

	EXPECT_EQ("/usr/include/CHeader.h", header);
}

TEST_F(JSONCTypesParserTests,
ParsingTypedefToUnknownTypeCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "MY_TYPE ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"type": "typedef",
					"typedefed_type": "unknown",
					"name": "MY_TYPE"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	EXPECT_EQ("MY_TYPE", retType->getName());
}

TEST_F(JSONCTypesParserTests,
ParseTypeReturnsUnknownTypeWhenTypeIsNotRecognized)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "MY_TYPE ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"type": "SthWeCannotParse"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	EXPECT_EQ(retdec::ctypes::UnknownType::create(), retType);
}

TEST_F(JSONCTypesParserTests,
ParsingFunctionTypeCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int(*)(int));",
					"header": "tx.h",
					"name": "ff",
					"params": [
						{
							"name": "",
							"type": "3c3d53921dd5483b5627bca319d79a6defc2bec5"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"3c3d53921dd5483b5627bca319d79a6defc2bec5": {
					"pointed_type": "ff960066816ea5557fd43a4d7bb814e635e6f13e",
					"type": "pointer"
				},
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				},
				"ff960066816ea5557fd43a4d7bb814e635e6f13e": {
					"params": [
						{
							"name": "",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"type": "function"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto paramType = mod->getFunctionWithName("ff")->getParameterType(1);

	ASSERT_TRUE(paramType->isPointer());
	auto ptrType = std::static_pointer_cast<retdec::ctypes::PointerType>(paramType);
	auto pointedType = ptrType->getPointedType();

	ASSERT_TRUE(pointedType->isFunction());
	auto funcType = std::static_pointer_cast<retdec::ctypes::FunctionType>(pointedType);

	ASSERT_NE(nullptr, funcType);
	EXPECT_EQ("int", funcType->getReturnType()->getName());
	EXPECT_EQ(1, funcType->getParameterCount());
	EXPECT_EQ("int", funcType->getParameter(1)->getName());
	EXPECT_FALSE(funcType->isVarArg());
}

TEST_F(JSONCTypesParserTests,
ParsingVarArgFunctionTypeCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int(*)(int, ...));",
					"header": "tx.h",
					"name": "ff",
					"params": [
						{
							"name": "",
							"type": "3c3d53921dd5483b5627bca319d79a6defc2bec5"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"3c3d53921dd5483b5627bca319d79a6defc2bec5": {
					"pointed_type": "ff960066816ea5557fd43a4d7bb814e635e6f13e",
					"type": "pointer"
				},
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				},
				"ff960066816ea5557fd43a4d7bb814e635e6f13e": {
					"params": [
						{
							"name": "",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"type": "function",
					"vararg": true
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto paramType = mod->getFunctionWithName("ff")->getParameterType(1);

	ASSERT_TRUE(paramType->isPointer());
	auto ptrType = std::static_pointer_cast<retdec::ctypes::PointerType>(paramType);
	auto pointedType = ptrType->getPointedType();

	ASSERT_TRUE(pointedType->isFunction());
	auto funcType = std::static_pointer_cast<retdec::ctypes::FunctionType>(pointedType);

	ASSERT_NE(nullptr, funcType);
	EXPECT_EQ("int", funcType->getReturnType()->getName());
	EXPECT_EQ(1, funcType->getParameterCount());
	EXPECT_EQ("int", funcType->getParameter(1)->getName());
	EXPECT_TRUE(funcType->isVarArg());
}

TEST_F(JSONCTypesParserTests,
ParsingVoidTypeCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "void ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"type": "void"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	EXPECT_EQ(retdec::ctypes::VoidType::create(), retType);
}

TEST_F(JSONCTypesParserTests,
ParsingPointerToIntTypeCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int * ff();",
					"header": "tx.h",
					"name": "ff",
					"params": [],
					"ret_type": "6f717fa96ee226c0f518056fe2cc081266103e1f"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				},
				"6f717fa96ee226c0f518056fe2cc081266103e1f": {
					"pointed_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"type": "pointer"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	EXPECT_EQ("", retType->getName());
}

TEST_F(JSONCTypesParserTests,
ParsingArrayTypeCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int a[10][1]);",
					"header": "tx.h",
					"name": "ff",
					"params": [
						{
						"name": "a",
						"type": "964c314c472ef91e32925f9f253da8b5a4a37886"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
					}
				},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				},
				"964c314c472ef91e32925f9f253da8b5a4a37886": {
					"dimensions": [10, 1],
					"element_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"type": "array"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto paramType = mod->getFunctionWithName("ff")->getParameter(1).getType();

	ASSERT_TRUE(paramType->isArray());
	auto arrayType = std::static_pointer_cast<retdec::ctypes::ArrayType>(paramType);
	auto twoDimensions = retdec::ctypes::ArrayType::Dimensions{10, 1};

	ASSERT_NE(nullptr, arrayType);
	EXPECT_EQ("int", arrayType->getElementType()->getName());
	EXPECT_EQ(2, arrayType->getDimensionCount());
	EXPECT_EQ(twoDimensions, arrayType->getDimensions());
}

TEST_F(JSONCTypesParserTests,
ParsingArrayWithUnknownDimensionsCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int a[][MACRO]);",
					"header": "tx.h",
					"name": "ff",
					"params": [
						{
						"name": "a",
						"type": "964c314c472ef91e32925f9f253da8b5a4a37886"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
					}
				},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				},
				"964c314c472ef91e32925f9f253da8b5a4a37886": {
					"dimensions": ["", "MACRO"],
					"element_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"type": "array"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto paramType = mod->getFunctionWithName("ff")->getParameter(1).getType();

	ASSERT_TRUE(paramType->isArray());
	auto arrayType = std::static_pointer_cast<retdec::ctypes::ArrayType>(paramType);

	EXPECT_EQ(
		retdec::ctypes::ArrayType::Dimensions(2, retdec::ctypes::ArrayType::UNKNOWN_DIMENSION),
		arrayType->getDimensions()
	);
}

TEST_F(JSONCTypesParserTests,
ParsingStructTypeCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "struct s ff();",
					"header": "tx.h",
					"name": "ff",
					"params": [],
					"ret_type": "41b426fb69c819c1f3a57bdc7ae4fe543fd971f1"
				}
			},
			"types": {
				"41b426fb69c819c1f3a57bdc7ae4fe543fd971f1": {
					"members": [
						{
							"name": "a",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"name": "s",
					"type": "structure"
				},
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	ASSERT_TRUE(retType->isStruct());
	auto structType = std::static_pointer_cast<retdec::ctypes::StructType>(retType);

	ASSERT_NE(nullptr, structType);
	EXPECT_EQ("s", structType->getName());
	EXPECT_EQ(1, structType->getMemberCount());
	EXPECT_EQ("a", structType->getMemberName(1));
	EXPECT_EQ("int", structType->getMemberType(1)->getName());
}

TEST_F(JSONCTypesParserTests,
ParsingStructWithPointerToSelfMemberCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "struct s ff();",
					"header": "tx.h",
					"name": "ff",
					"params": [],
					"ret_type": "41b426fb69c819c1f3a57bdc7ae4fe543fd971f1"
				}
			},
			"types": {
				"41b426fb69c819c1f3a57bdc7ae4fe543fd971f1": {
					"members": [
						{
							"name": "a",
							"type": "56f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"name": "s",
					"type": "structure"
				},
				"56f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"pointed_type": "41b426fb69c819c1f3a57bdc7ae4fe543fd971f1",
					"type": "pointer"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	ASSERT_TRUE(retType->isStruct());
	auto structType = std::static_pointer_cast<retdec::ctypes::StructType>(retType);
	ASSERT_TRUE(structType->getMemberType(1)->isPointer());
	auto structMember = std::static_pointer_cast<retdec::ctypes::PointerType>(
		structType->getMemberType(1));

	EXPECT_EQ("s", structType->getName());
	EXPECT_EQ(1, structType->getMemberCount());
	EXPECT_EQ("a", structType->getMemberName(1));
	EXPECT_EQ(structType, structMember->getPointedType());
}

TEST_F(JSONCTypesParserTests,
ParsingUnionTypeCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "union s ff();",
					"header": "tx.h",
					"name": "ff",
					"params": [],
					"ret_type": "41b426fb69c819c1f3a57bdc7ae4fe543fd971f1"
				}
			},
			"types": {
				"41b426fb69c819c1f3a57bdc7ae4fe543fd971f1": {
					"members": [
						{
							"name": "a",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"name": "s",
					"type": "union"
				},
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	ASSERT_TRUE(retType->isUnion());
	auto unionType = std::static_pointer_cast<retdec::ctypes::UnionType>(retType);

	ASSERT_NE(nullptr, unionType);
	EXPECT_EQ("s", unionType->getName());
	EXPECT_EQ(1, unionType->getMemberCount());
	EXPECT_EQ("a", unionType->getMemberName(1));
	EXPECT_EQ("int", unionType->getMemberType(1)->getName());
}

TEST_F(JSONCTypesParserTests,
ParsingEnumTypeCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "enum e ff();",
					"header": "tx.h",
					"name": "ff",
					"params": [],
					"ret_type": "fbcc2dc754f4fb1129298713946c4dd27ac850c8"
				}
			},
			"types": {
				"fbcc2dc754f4fb1129298713946c4dd27ac850c8": {
					"items": [
						{
							"name": "a",
							"value": 42
						}
					],
						"name": "e",
						"type": "enum"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	ASSERT_TRUE(retType->isEnum());
	auto enumType = std::static_pointer_cast<retdec::ctypes::EnumType>(retType);

	EXPECT_EQ("e", enumType->getName());
	EXPECT_EQ(1, enumType->getValueCount());
	EXPECT_EQ("a", enumType->getValue(1).getName());
	EXPECT_EQ(42, enumType->getValue(1).getValue());
}

TEST_F(JSONCTypesParserTests,
ParsingEnumWithUnknownValueSetsEnumDefaultValue)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "enum e ff();",
					"header": "tx.h",
					"name": "ff",
					"params": [],
					"ret_type": "fbcc2dc754f4fb1129298713946c4dd27ac850c8"
				}
			},
			"types": {
				"fbcc2dc754f4fb1129298713946c4dd27ac850c8": {
					"items": [
						{
							"name": "a",
							"value": "someMacro"
						}
					],
						"name": "e",
						"type": "enum"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto retType = mod->getFunctionWithName("ff")->getReturnType();

	ASSERT_TRUE(retType->isEnum());
	auto enumType = std::static_pointer_cast<retdec::ctypes::EnumType>(retType);

	EXPECT_EQ(retdec::ctypes::EnumType::DEFAULT_VALUE, enumType->getValue(1).getValue());
}

TEST_F(JSONCTypesParserTests,
ParserSetsEmptyCallConventionToFunctionbyDefault)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "void ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"type": "void"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(retdec::ctypes::CallConvention(""), func->getCallConvention());
}

TEST_F(JSONCTypesParserTests,
ParserPrefersCallConventionFromJsonToUserDefinedOne)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"call_conv": "cdecl",
					"decl": "void ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"type": "void"
				}
			}
		}
	)");

	auto mod = parser.parse(json, {}, retdec::ctypes::CallConvention("stdcall"));
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(retdec::ctypes::CallConvention("cdecl"), func->getCallConvention());
}

TEST_F(JSONCTypesParserTests,
ParserSetsUserDefinedConventionWhenFunctionDoesNotHaveOne)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "void ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"type": "void"
				}
			}
		}
	)");

	auto mod = parser.parse(json, {}, retdec::ctypes::CallConvention("stdcall"));
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(retdec::ctypes::CallConvention("stdcall"), func->getCallConvention());
}

TEST_F(JSONCTypesParserTests,
ParseIntoUsingCallConventionCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "void ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"type": "void"
				}
			}
		}
	)");

	auto module = std::make_unique<retdec::ctypes::Module>(std::make_shared<retdec::ctypes::Context>());
	parser.parseInto(json, module, {}, retdec::ctypes::CallConvention("fastcall"));
	auto func = module->getFunctionWithName("ff");

	EXPECT_EQ(retdec::ctypes::CallConvention("fastcall"), func->getCallConvention());
}

TEST_F(JSONCTypesParserTests,
ParseIntoWithExplicitTypeWidthsAndCallConventionCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "b",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");
	JSONCTypesParser::TypeWidths typeWidths{{"int", 32}, {"long", 64}};
	auto module = std::make_unique<retdec::ctypes::Module>(std::make_shared<retdec::ctypes::Context>());

	parser.parseInto(json, module, typeWidths, retdec::ctypes::CallConvention("cdecl"));
	auto func = module->getFunctionWithName("ff");

	EXPECT_EQ(32, func->getReturnType()->getBitWidth());
	EXPECT_EQ(32, func->getParameterType(1)->getBitWidth());
	EXPECT_EQ(retdec::ctypes::CallConvention("cdecl"), func->getCallConvention());
}

TEST_F(JSONCTypesParserTests,
ParseInAnnotationCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(_In_ int a);",
					"header": "tx.h",
					"name": "ff",
					"params": [
						{
							"annotations": "_In_",
							"name": "a",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json, {}, retdec::ctypes::CallConvention("stdcall"));
	auto func = mod->getFunctionWithName("ff");
	auto param = func->getParameter(1);

	EXPECT_TRUE(param.isIn());
}

TEST_F(JSONCTypesParserTests,
ParseOutAnnotationCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(_Out_ int a);",
					"header": "tx.h",
					"name": "ff",
					"params": [
						{
							"annotations": "_Out_",
							"name": "a",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json, {}, retdec::ctypes::CallConvention("stdcall"));
	auto func = mod->getFunctionWithName("ff");
	auto param = func->getParameter(1);

	EXPECT_TRUE(param.isOut());
}

TEST_F(JSONCTypesParserTests,
ParseInOutAnnotationCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(_Inout_ int a);",
					"header": "tx.h",
					"name": "ff",
					"params": [
						{
							"annotations": "_Inout_",
							"name": "a",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json, {}, retdec::ctypes::CallConvention("stdcall"));
	auto func = mod->getFunctionWithName("ff");
	auto param = func->getParameter(1);

	EXPECT_TRUE(param.isInOut());
}

TEST_F(JSONCTypesParserTests,
ParseOptionalAnnotationCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(_In_opt_ int a);",
					"header": "tx.h",
					"name": "ff",
					"params": [
						{
							"annotations": "_In_opt_",
							"name": "a",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json, {}, retdec::ctypes::CallConvention("stdcall"));
	auto func = mod->getFunctionWithName("ff");
	auto param = func->getParameter(1);

	EXPECT_TRUE(param.isOptional());
}

TEST_F(JSONCTypesParserTests,
GetBitWidthSetsDefaultBitWidthForMyIntTypeNotBitWidthSpecifiedForInt)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "myint ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "26f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"26f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "myint",
					"type": "integral_type"
				}
			}
		}
	)");
	CTypesParser::TypeWidths typeWidths{{"int", 32}};

	auto mod = parser.parse(json, typeWidths);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(0, func->getReturnType()->getBitWidth());
}

TEST_F(JSONCTypesParserTests,
UseCoreTypeFromIntegralTypeNameToSearchItsBitWidthInMapCorrectly)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "long long ff(bool a, signec char b, unsigned short int b, signed int d);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "a",
							"type": "16f8ab7c0cff9df7cd124852e26022a6bf89e315"
						},
						{
							"name": "b",
							"type": "c6f8ab7c0cff9df7cd124852e26022a6bf89e315"
						},
						{
							"name": "c",
							"type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
						},
						{
							"name": "d",
							"type": "26f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "3338ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "unsigned short int",
					"type": "integral_type"
				},
				"3338ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "long long",
					"type": "integral_type"
				},
				"16f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "bool",
					"type": "integral_type"
				},
				"c6f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "signed char",
					"type": "integral_type"
				},
				"26f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "signed int",
					"type": "integral_type"
				}
			}
		}
	)");
	CTypesParser::TypeWidths typeWidths{
		{"bool", 1},
		{"char", 8},
		{"short", 16},
		{"int", 32},
		{"long long", 64},
	};

	auto mod = parser.parse(json, typeWidths);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(64, func->getReturnType()->getBitWidth());
	EXPECT_EQ(1, func->getParameterType(1)->getBitWidth());
	EXPECT_EQ(8, func->getParameterType(2)->getBitWidth());
	EXPECT_EQ(16, func->getParameterType(3)->getBitWidth());
	EXPECT_EQ(32, func->getParameterType(4)->getBitWidth());
}

TEST_F(JSONCTypesParserTests,
ParserSetsIntBitWidthForSignedAndUnsignedType)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "signed ff(signed a, unsigned b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [
						{
							"name": "a",
							"type": "16f8ab7c0cff9df7cd124852e26022a6bf89e315"
						},
						{
							"name": "b",
							"type": "26f8ab7c0cff9df7cd124852e26022a6bf89e315"
						}
					],
					"ret_type": "16f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"16f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "signed",
					"type": "integral_type"
				},
				"26f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "unsigned",
					"type": "integral_type"
				}
			}
		}
	)");
	CTypesParser::TypeWidths typeWidths{{"int", 33}};

	auto mod = parser.parse(json, typeWidths);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(33, func->getParameterType(1)->getBitWidth());
	EXPECT_EQ(33, func->getParameterType(2)->getBitWidth());
}

TEST_F(JSONCTypesParserTests,
ParsingTwoFunctionsWithSameNameKeepsFirstOne)
{
	std::stringstream json1(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");
	std::stringstream json2(R"(
		{
			"functions": {
				"ff": {
					"decl": "char ff(char b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "56f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"56f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "char",
					"type": "integral_type"
				}
			}
		}
	)");
	auto mod = parser.parse(json1);
	parser.parseInto(json2, mod);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ("int", func->getReturnType()->getName());
}

TEST_F(JSONCTypesParserTests,
ParsingTwoFunctionsUsingNewParserForNewInputWithSameNameKeepsFirstOne)
{
	std::stringstream json1(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");
	std::stringstream json2(R"(
		{
			"functions": {
				"ff": {
					"decl": "char ff(char b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "56f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"56f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "char",
					"type": "integral_type"
				}
			}
		}
	)");
	JSONCTypesParser parser2;

	auto mod = parser.parse(json1);
	parser2.parseInto(json2, mod);
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ("int", func->getReturnType()->getName());
}

TEST_F(JSONCTypesParserTests,
ParseIntoUsesContextFromModule)
{
	std::stringstream json1(R"(
		{
			"functions": {
				"ff": {
					"decl": "int ff(int b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "int",
					"type": "integral_type"
				}
			}
		}
	)");
	std::stringstream json2(R"(
		{
			"functions": {
				"ff": {
					"decl": "char ff(char b);",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "56f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"56f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "char",
					"type": "integral_type"
				}
			}
		}
	)");
	auto mod = parser.parse(json1);
	parser.parseInto(json2, mod);

	auto func = mod->getContext()->getFunctionWithName("ff");

	EXPECT_EQ("int", func->getReturnType()->getName());
}

TEST_F(JSONCTypesParserTests,
ParserSetsCorrectBitWidthFromTypeWidthsMapToPointerType)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "char * ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "26f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"26f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"pointed_type": "56f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"type": "pointer"
				},
				"56f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"name": "char",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json, {{"*", 33}});
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(33, func->getReturnType()->getBitWidth());
}

TEST_F(JSONCTypesParserTests,
ParserPrefersBitWidthFromJsonIfExists)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "int32_t * ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "26f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"26f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"bit_width": 32,
					"name": "int32_t",
					"type": "integral_type"
				}
			}
		}
	)");

	auto mod = parser.parse(json, {{"uint32_t", 64}});
	auto func = mod->getFunctionWithName("ff");

	EXPECT_EQ(32, func->getReturnType()->getBitWidth());
}

TEST_F(JSONCTypesParserTests,
ParsingCircularTypedefsBreaksLoopAndSetsTypedefToUnknownType)
{
	std::stringstream json(R"(
		{
			"functions": {
				"ff": {
					"decl": "MY_TYPE ff();",
					"header": "CHeader.h",
					"name": "ff",
					"params": [],
					"ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
				}
			},
			"types": {
				"46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"type": "typedef",
					"typedefed_type": "56f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"name": "MY_TYPE1"
				},
				"56f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"type": "typedef",
					"typedefed_type": "66f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"name": "MY_TYPE2"
				},
				"66f8ab7c0cff9df7cd124852e26022a6bf89e315": {
					"type": "typedef",
					"typedefed_type": "56f8ab7c0cff9df7cd124852e26022a6bf89e315",
					"name": "MY_TYPE3"
				}
			}
		}
	)");

	auto mod = parser.parse(json);
	std::shared_ptr<retdec::ctypes::TypedefedType> retType =
		std::static_pointer_cast<retdec::ctypes::TypedefedType>(
			mod->getFunctionWithName("ff")->getReturnType()
		);
	std::shared_ptr<retdec::ctypes::TypedefedType> type2 =
		std::static_pointer_cast<retdec::ctypes::TypedefedType>(retType->getAliasedType());
	std::shared_ptr<retdec::ctypes::TypedefedType> type3 =
		std::static_pointer_cast<retdec::ctypes::TypedefedType>(type2->getAliasedType());

	EXPECT_EQ(retdec::ctypes::UnknownType::create(), retType->getRealType());
	EXPECT_EQ("MY_TYPE2", type2->getName());
	EXPECT_EQ("MY_TYPE3", type3->getName());
	EXPECT_EQ(retdec::ctypes::UnknownType::create(), type3->getAliasedType());
}

} // namespace tests
} // namespace ctypesparser
} // namespace retdec
