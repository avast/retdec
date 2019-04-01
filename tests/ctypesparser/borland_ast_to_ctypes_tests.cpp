/**
 * @file tests/demangler/borland_demangler_tests.cpp
 * @brief Tests for the borland demangler.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>
#include <retdec/ctypes/floating_point_type.h>

#include "retdec/demangler/demangler.h"
#include "retdec/demangler/context.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/named_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/parameter.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/reference_type.h"
#include "retdec/ctypes/unknown_type.h"

using namespace ::testing;

namespace retdec {
namespace ctypesparser {
namespace tests {

class BorlandCtypesTests : public Test
{
public:
	using status = retdec::demangler::Demangler::Status;

	BorlandCtypesTests() :
		demangler(std::make_unique<retdec::demangler::BorlandDemangler>()),
		module(std::make_unique<ctypes::Module>(std::make_shared<retdec::ctypes::Context>())) {}
protected:
	std::shared_ptr<ctypes::Function> mangledToCtypes(
		const std::string &mangled)
	{
		return demangler->demangleFunctionToCtypes(mangled, module);
	}

	std::unique_ptr<retdec::demangler::Demangler> demangler;
	std::unique_ptr<retdec::ctypes::Module> module;
};

TEST_F(BorlandCtypesTests, basic)
{
	mangledToCtypes("@myFunc_int_$qi");

	EXPECT_TRUE(module->hasFunctionWithName("@myFunc_int_$qi"));

	auto func = module->getFunctionWithName("@myFunc_int_$qi");
	EXPECT_EQ(static_cast<std::string>(func->getDeclaration()), "myFunc_int_(int)");
	EXPECT_TRUE(func->getReturnType()->isUnknown());

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_FALSE(func->isVarArg());
	EXPECT_TRUE(func->getParameter(1).getType()->isIntegral());
}

TEST_F(BorlandCtypesTests, TypeParsingTest)
{
	mangledToCtypes("@foo$qsusiuiluljujzcuccfdgoCsCib");

	EXPECT_TRUE(module->hasFunctionWithName("@foo$qsusiuiluljujzcuccfdgoCsCib"));

	auto func = module->getFunctionWithName("@foo$qsusiuiluljujzcuccfdgoCsCib");

	EXPECT_EQ(func->getParameterCount(), 18);
	std::shared_ptr<ctypes::Type> param;

	param = func->getParameter(1).getType();
	EXPECT_EQ(param->getName(), "short");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(2).getType();
	EXPECT_EQ(param->getName(), "unsigned short");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(3).getType();
	EXPECT_EQ(param->getName(), "int");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(4).getType();
	EXPECT_EQ(param->getName(), "unsigned int");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(5).getType();
	EXPECT_EQ(param->getName(), "long");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(6).getType();
	EXPECT_EQ(param->getName(), "unsigned long");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(7).getType();
	EXPECT_EQ(param->getName(), "long long");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(8).getType();
	EXPECT_EQ(param->getName(), "unsigned long long");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(9).getType();
	EXPECT_EQ(param->getName(), "signed char");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(10).getType();
	EXPECT_EQ(param->getName(), "unsigned char");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(11).getType();
	EXPECT_EQ(param->getName(), "char");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(12).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "float");

	param = func->getParameter(13).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "double");

	param = func->getParameter(14).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "long double");

	param = func->getParameter(15).getType();
	EXPECT_EQ(param->getName(), "bool");

	param = func->getParameter(16).getType();
	EXPECT_EQ(param->getName(), "char16_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(17).getType();
	EXPECT_EQ(param->getName(), "char32_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(18).getType();
	EXPECT_EQ(param->getName(), "wchar_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());
}

TEST_F(BorlandCtypesTests, templateTypes)
{
	mangledToCtypes(
		"@%foo$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%%$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%$v");

	EXPECT_TRUE(module->hasFunctionWithName(
		"@%foo$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%%$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%$v"));

	auto func =	module->getFunctionWithName(
		"@%foo$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%%$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%$v");
	EXPECT_TRUE(func->getReturnType()->isVoid());

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_FALSE(func->isVarArg());
	EXPECT_TRUE(func->getParameter(1).getType()->isNamed());

	auto param = std::static_pointer_cast<ctypes::NamedType>(func->getParameter(1).getType());
	EXPECT_EQ(param->getName(), "std::basic_string<char, std::char_traits<char>, std::allocator<char>>");
}

TEST_F(BorlandCtypesTests, callConventionTest)
{
	std::shared_ptr<ctypes::Function> func;

	mangledToCtypes("@foo1$qqrv");
	EXPECT_TRUE(module->hasFunctionWithName("@foo1$qqrv"));
	func = module->getFunctionWithName("@foo1$qqrv");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "fastcall");

	mangledToCtypes("@foo2$qqsv");
	EXPECT_TRUE(module->hasFunctionWithName("@foo2$qqsv"));
	func = module->getFunctionWithName("@foo2$qqsv");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "stdcall");

	mangledToCtypes("@foo3$qv");
	EXPECT_TRUE(module->hasFunctionWithName("@foo3$qv"));
	func = module->getFunctionWithName("@foo3$qv");
	EXPECT_EQ(static_cast<std::string>(func->getCallConvention()), "unknown");
}

TEST_F(BorlandCtypesTests, PointerAndReferenceTest)
{
	mangledToCtypes("@foo$qpv");
	EXPECT_TRUE(module->hasFunctionWithName("@foo$qpv"));
	auto func = module->getFunctionWithName("@foo$qpv");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isPointer());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::PointerType>(param)->getPointedType()->isVoid());
}

TEST_F(BorlandCtypesTests, VarArgness)
{
	mangledToCtypes("@foo$qri");
	EXPECT_TRUE(module->hasFunctionWithName("@foo$qri"));
	auto func = module->getFunctionWithName("@foo$qri");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isReference());
	EXPECT_TRUE(std::static_pointer_cast<ctypes::ReferenceType>(param)->getReferencedType()->isIntegral());
}

TEST_F(BorlandCtypesTests, ArrayTypeTests)
{
	mangledToCtypes("@foo$qpa3$a6$i");
	EXPECT_TRUE(module->hasFunctionWithName("@foo$qpa3$a6$i"));
	auto func = module->getFunctionWithName("@foo$qpa3$a6$i");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isPointer());

	auto pointee = std::static_pointer_cast<ctypes::PointerType>(param)->getPointedType();

	EXPECT_TRUE(pointee->isArray());

	auto elemType = std::static_pointer_cast<ctypes::ArrayType>(pointee)->getElementType();
	EXPECT_TRUE(elemType->isIntegral());

	EXPECT_EQ(std::static_pointer_cast<ctypes::ArrayType>(pointee)->getDimensionCount(), 2);

	ctypes::ArrayType::Dimensions expectedDimensions{3,6};
	EXPECT_EQ(std::static_pointer_cast<ctypes::ArrayType>(pointee)->getDimensions(), expectedDimensions);
}

TEST_F(BorlandCtypesTests, FunctionPointerTests)
{
	mangledToCtypes("@foo$qpqv$i");
	EXPECT_TRUE(module->hasFunctionWithName("@foo$qpqv$i"));
	auto func = module->getFunctionWithName("@foo$qpqv$i");
	auto param = func->getParameter(1).getType();
	EXPECT_TRUE(param->isPointer());

	auto pointee = std::static_pointer_cast<ctypes::PointerType>(param)->getPointedType();

	EXPECT_TRUE(pointee->isFunction());

	auto funcType = std::static_pointer_cast<ctypes::FunctionType>(pointee);

	EXPECT_EQ(funcType->getParameterCount(), 1);
	EXPECT_TRUE(funcType->getParameter(1)->isVoid());
	EXPECT_EQ(static_cast<std::string>(funcType->getCallConvention()), "unknown");
	EXPECT_TRUE(funcType->getReturnType()->isIntegral());
}

TEST_F(BorlandCtypesTests, All)
{
	mangledToCtypes("@myFunc_s_$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%t1t1");
	mangledToCtypes("@myFunc_empty_$qv");
	mangledToCtypes("@myFunc_short_int_$qs");
	mangledToCtypes("@myFunc_unsigned_short_int_$qus");
	mangledToCtypes("@myFunc_int_$qi");
	mangledToCtypes("@myFunc_unsigned_$qui");
	mangledToCtypes("@myFunc_long_int_$ql");
	mangledToCtypes("@myFunc_unsigned_long_int_$qul");
	mangledToCtypes("@myFunc_long_long_int_$qj");
	mangledToCtypes("@myFunc_unsigned_long_long_$quj");
	mangledToCtypes("@myFunc_signed_char_$qzc");
	mangledToCtypes("@myFunc_unsigned_char_$quc");
	mangledToCtypes("@myFunc_char_$qc");
	mangledToCtypes("@myFunc_float_$qf");
	mangledToCtypes("@myFunc_double_$qd");
	mangledToCtypes("@myFunc_long_double_$qg");
	mangledToCtypes("@myFunc_bool_$qo");
	mangledToCtypes("@foo3$qb");
	mangledToCtypes("@myFunc_all_$qsusiuiluljujzcuccfdgoCsCib");
	mangledToCtypes("@foo$qie");
	mangledToCtypes("@myFunc_std__string_$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%");
	mangledToCtypes("@foo1$qpxi");
	mangledToCtypes("@foo2$qxpi");
	mangledToCtypes("@foo3$qxpxi");
	mangledToCtypes("@foo4$qpwi");
	mangledToCtypes("@foo5$qwpi");
	mangledToCtypes("@foo6$qwpwi");
	mangledToCtypes("@Bar@foo7$xqv");
	mangledToCtypes("@Bar@foo8$wqv");
	mangledToCtypes("@Bar@foo9$wxqv");
	mangledToCtypes("@foo10$qpwxi");
	mangledToCtypes("@foo11$qpwxi");
	mangledToCtypes("@foonew$qrwxpi");
	mangledToCtypes("@Bar@foo$wxqqrv");
	mangledToCtypes("@foo$qrri");
	mangledToCtypes("@myFunc_void1_$qpv");
	mangledToCtypes("@myFunc_void2_$qppv");
	mangledToCtypes("@myFunc_void123_$qpvppvpppv");
	mangledToCtypes("@myFunc_ref1_$qr3Tmp");
	mangledToCtypes("@myFunc_ref2_$qh3Tmp");
	mangledToCtypes("@foo$qri");
	mangledToCtypes("@Themes@TThemeServices@GetElementDetails$qqr25Themes@TThemedExplorerBar");
	mangledToCtypes("@Webscriptas@TActiveScriptObjectFactory@CreateProducerObject$qqr32Webscript@TGlobalScriptVariables52System@%DelphiInterface$t24Httpprod@IScriptProducer%");
	mangledToCtypes("@Webservexp@TWebServExp@GenerateNestedArraySchema$qqr51System@%DelphiInterface$t23Xmlschema@IXMLSchemaDef%56System@%DelphiInterface$t28Xmlschema@IXMLComplexTypeDef%px17Typinfo@TTypeInfori17System@WideString");
	mangledToCtypes("@Dateutils@TryRecodeDateTime$qqrx16System@TDateTimexusxusxusxusxusxusxusr16System@TDateTime");
	mangledToCtypes("@Dbxtablestorage@TDBXDelegateTableStorage@SetColumns$qqrx62System@%DynamicArray$tp36Dbxtablestorage@TDBXColumnDescriptor%");
	mangledToCtypes("@Dbxmysqlmetadatareader@TDBXMySqlCustomMetaDataReader@TDBXMySql4IndexesCursor@FindStringSize$qqrxix62System@%DynamicArray$tp36Dbxtablestorage@TDBXColumnDescriptor%");
	mangledToCtypes("@Idimap4@TIdImapSubSection@$bleq$qqrv");
	mangledToCtypes("@Idimap4@TIdImapSubSection@bagr$qqriipa15$a89$a2$ipa10$a666$25System@%DynamicArray$tuc%");
	mangledToCtypes("@Idimap4@TIdImapSubSection@$brrsh$qqrv");
	mangledToCtypes("@Sqlexpr@TSQLConnection@SQLError$qqrus25Sqlexpr@TSQLExceptionTypex48System@%DelphiInterface$t20Dbxpress@ISQLCommand%");
	mangledToCtypes("@foo$qpa3$i");
	mangledToCtypes("@foo1$qpa3$a5$c");
	mangledToCtypes("@foo3$qpxa3$i");
	mangledToCtypes("@foo4$qpa3500$a6$i");
	mangledToCtypes("@foo5$qra5$a5$i");
	mangledToCtypes("@foo6$qrxa5$a5$i");
	mangledToCtypes("@foo7$qha5$a5$i");
	mangledToCtypes("@foo8$qxpxa5$i");
	mangledToCtypes("@foo10$qpa3$d");
	mangledToCtypes("@bar@foo$qi");
	mangledToCtypes("@Baz@foo$qd");
	mangledToCtypes("@bar@%f$i%$qii$d");
	mangledToCtypes("@%myFunc_template_$i%$qi$d");
	mangledToCtypes("@ns1@ns2@ns3@%foo3$c%$qv$v");
	mangledToCtypes("@ns@ns1@ns2@%myFunc_template_$i%$qi$d");
	mangledToCtypes("@ns@%myFunc_template_$i%$qi$d");
	mangledToCtypes("@%foo2$20std@%basic_string$c%i%$qv$v");
	mangledToCtypes("@%foo2$32std@%basic_string$c10%my_tmp$c%%i%$qv$v");
	mangledToCtypes("@%foo2$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%i%$qv$v");
	mangledToCtypes("@%foo$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%%$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%$v");
	mangledToCtypes("@%adder$iVii%$qiii$i");
	mangledToCtypes("@foo$q10ns@Bar@Baz");
	mangledToCtypes("@foo$qpx10ns@Bar@Baz");
	mangledToCtypes("@%foo$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%t1%$qv$v");
	mangledToCtypes("@Foo@$badd$q3Foo");
	mangledToCtypes("@$badd$q3Bart1");
	mangledToCtypes("@%$badd$3Bar%$q3Bart1$3Bar");
	mangledToCtypes("@Foo@$bsub$q3Foo");
	mangledToCtypes("@Foo@$basg$q3Foo");
	mangledToCtypes("@Foo@$bmul$q3Foo");
	mangledToCtypes("@Foo@$bdiv$q3Foo");
	mangledToCtypes("@Foo@$bmod$q3Foo");
	mangledToCtypes("@Foo@$binc$qi");
	mangledToCtypes("@Foo@$bdec$qi");
	mangledToCtypes("@Foo@$beql$q3Foo");
	mangledToCtypes("@Foo@$bneq$q3Foo");
	mangledToCtypes("@Foo@$bgtr$q3Foo");
	mangledToCtypes("@Foo@$blss$q3Foo");
	mangledToCtypes("@Foo@$bgeq$q3Foo");
	mangledToCtypes("@Foo@$bleq$q3Foo");
	mangledToCtypes("@Foo@$bnot$qv");
	mangledToCtypes("@Foo@$bland$q3Foo");
	mangledToCtypes("@Foo@$blor$q3Foo");
	mangledToCtypes("@Foo@$bcmp$qv");
	mangledToCtypes("@Foo@$band$q3Foo");
	mangledToCtypes("@Foo@$bor$q3Foo");
	mangledToCtypes("@Foo@$bxor$q3Foo");
	mangledToCtypes("@Foo@$blsh$q3Foo");
	mangledToCtypes("@Foo@$brsh$q3Foo");
	mangledToCtypes("@Foo@$brplu$q3Foo");
	mangledToCtypes("@Foo@$brmin$q3Foo");
	mangledToCtypes("@Foo@$brmul$q3Foo");
	mangledToCtypes("@Foo@$brdiv$q3Foo");
	mangledToCtypes("@Foo@$brmod$q3Foo");
	mangledToCtypes("@Foo@$brand$q3Foo");
	mangledToCtypes("@Foo@$bror$q3Foo");
	mangledToCtypes("@Foo@$brxor$q3Foo");
	mangledToCtypes("@Foo@$brlsh$q3Foo");
	mangledToCtypes("@Foo@$brrsh$q3Foo");
	mangledToCtypes("@Foo@$bsubs$q3Foo");
	mangledToCtypes("@Foo@$bind$qv");
	mangledToCtypes("@Foo@$badr$qv");
	mangledToCtypes("@Foo@$barow$qv");
	mangledToCtypes("@Foo@$barwm$q3Foo");
	mangledToCtypes("@Foo@$bcall$qi");
	mangledToCtypes("@Foo@$bcoma$q3Foo");
	mangledToCtypes("@Foo@$bnew$qui");
	mangledToCtypes("@Foo@$bnwa$qui");
	mangledToCtypes("@Foo@$bdele$qpv");
	mangledToCtypes("@Foo@$bdla$qpv");
	mangledToCtypes("@Foo@$o3Bar$qv");
	mangledToCtypes("@Foo@$oi$qv");
	mangledToCtypes("@foo1$qpqv$i");
	mangledToCtypes("@foo2$qr$qv$i");
	mangledToCtypes("@foo3$qh$qv$i");
	mangledToCtypes("@foo4$qpqv$pqpi$v");
	mangledToCtypes("@foo5$qpxpqv$vpxpqv$v");
	mangledToCtypes("@foo6$qpqv$pqpi$pqpd$v");
	mangledToCtypes("Lllvm$workaround$fake$stub$@%$badd$3Bar%$q3Bart1$3Bar");

}


}	// namespace tests
}	// namespace ctypesparser
}	// namespace retdec