/**
 * @file tests/demangler/borland_demangler_tests.cpp
 * @brief Tests for the borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "llvm/Demangle/demangler.h"
#include "dem_test.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace tests {

class BorlandDemanglerTests : public Test
{
public:
	using status = retdec::demangler::Demangler::Status;

	BorlandDemanglerTests() :
		demangler(retdec::demangler::DemanglerFactory::getDemangler("borland")) {}

protected:
	std::unique_ptr<retdec::demangler::Demangler> demangler;
};

TEST_F(BorlandDemanglerTests, BasicTest)
{
	DEM_EQ("@myFunc_int_$qi", "myFunc_int_(int)");
}

TEST_F(BorlandDemanglerTests, CallConhventionsTests)
{
	/* cdecl and pascal cant be differenciated from mangled name */
	DEM_EQ("@myFunc_cdecl_$qv", "myFunc_cdecl_(void)");
	DEM_EQ("@myFunc_pascal_$qv", "myFunc_pascal_(void)");

	DEM_EQ("@myFunc_fastcall_$qqrv", "__fastcall myFunc_fastcall_(void)");
	DEM_EQ("@myFunc_stdcall_$qqsv", "__stdcall myFunc_stdcall_(void)");
}

TEST_F(BorlandDemanglerTests, RepeatingParameters)
{
	DEM_EQ("@myFunc_i_$qiii", "myFunc_i_(int, int, int)");
	DEM_EQ("@myFunc_s_$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%t1t1",
		   "myFunc_s_(std::basic_string<char, std::char_traits<char>, std::allocator<char>>, std::basic_string<char, std::char_traits<char>, std::allocator<char>>, std::basic_string<char, std::char_traits<char>, std::allocator<char>>)");
}

TEST_F(BorlandDemanglerTests, BasicParametersTests)
{
	DEM_EQ("@myFunc_empty_$qv", "myFunc_empty_(void)");
	DEM_EQ("@myFunc_short_int_$qs", "myFunc_short_int_(short)");
	DEM_EQ("@myFunc_unsigned_short_int_$qus", "myFunc_unsigned_short_int_(unsigned short)");
	DEM_EQ("@myFunc_int_$qi", "myFunc_int_(int)");
	DEM_EQ("@myFunc_unsigned_$qui", "myFunc_unsigned_(unsigned int)");
	DEM_EQ("@myFunc_long_int_$ql", "myFunc_long_int_(long)");
	DEM_EQ("@myFunc_unsigned_long_int_$qul", "myFunc_unsigned_long_int_(unsigned long)");
	DEM_EQ("@myFunc_long_long_int_$qj", "myFunc_long_long_int_(long long)");
	DEM_EQ("@myFunc_unsigned_long_long_$quj", "myFunc_unsigned_long_long_(unsigned long long)");
	DEM_EQ("@myFunc_signed_char_$qzc", "myFunc_signed_char_(signed char)");
	DEM_EQ("@myFunc_unsigned_char_$quc", "myFunc_unsigned_char_(unsigned char)");
	DEM_EQ("@myFunc_char_$qc", "myFunc_char_(char)");
	DEM_EQ("@myFunc_float_$qf", "myFunc_float_(float)");
	DEM_EQ("@myFunc_double_$qd", "myFunc_double_(double)");
	DEM_EQ("@myFunc_long_double_$qg", "myFunc_long_double_(long double)");
	DEM_EQ("@myFunc_bool_$qo", "myFunc_bool_(bool)");
	DEM_EQ("@foo3$qb", "foo3(wchar_t)");
	DEM_EQ("@myFunc_all_$qsusiuiluljujzcuccfdgo",
		   "myFunc_all_(short, unsigned short, int, unsigned int, long, unsigned long, long long, unsigned long long, signed char, unsigned char, char, float, double, long double, bool)");
}

TEST_F(BorlandDemanglerTests, MoreComplicatedParameters)
{
	DEM_EQ("@myFunc_std__string_$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%",
		   "myFunc_std__string_(std::basic_string<char, std::char_traits<char>, std::allocator<char>>)");
}

TEST_F(BorlandDemanglerTests, QualifiersTests)
{
	DEM_EQ("@foo1$qpxi", "foo1(const int *)");
	DEM_EQ("@foo2$qxpi", "foo2(int * const)");
	DEM_EQ("@foo3$qxpxi", "foo3(const int * const)");
	DEM_EQ("@foo4$qpwi", "foo4(volatile int *)");
	DEM_EQ("@foo5$qwpi", "foo5(int * volatile)");
	DEM_EQ("@foo6$qwpwi", "foo6(volatile int * volatile)");
	DEM_EQ("@Bar@foo7$xqv", "Bar::foo7(void) const");
	DEM_EQ("@Bar@foo8$wqv", "Bar::foo8(void) volatile");
	DEM_EQ("@Bar@foo9$wxqv", "Bar::foo9(void) volatile const");
	DEM_EQ("@foo10$qpwxi", "foo10(volatile const int *)");
	DEM_EQ("@foo11$qpwxi", "foo11(volatile const int *)");
	DEM_EQ("@foonew$qrwxpi", "foonew(int * volatile const &)");
//	DEM_EQ("@foonew$qrwxpi", "foonew(int *__restrict volatile const)");	// TODO when possible demangle as reference
	DEM_EQ("@Bar@foo$wxqqrv", "__fastcall Bar::foo(void) volatile const");
//	DEM_EQ("@foo$qrri", "foo(int & _restrict)");
}

TEST_F(BorlandDemanglerTests, PointersTests)
{
	DEM_EQ("@myFunc_void1_$qpv", "myFunc_void1_(void *)");
	DEM_EQ("@myFunc_void2_$qppv", "myFunc_void2_(void * *)");
	DEM_EQ("@myFunc_void123_$qpvppvpppv", "myFunc_void123_(void *, void * *, void * * *)");
}

TEST_F(BorlandDemanglerTests, ReferecenceTests)
{
	DEM_EQ("@myFunc_ref1_$qr3Tmp", "myFunc_ref1_(Tmp &)");
	DEM_EQ("@myFunc_ref2_$qh3Tmp", "myFunc_ref2_(Tmp &&)");
	DEM_EQ("@foo$qri", "foo(int &)");
}

TEST_F(BorlandDemanglerTests, RandomTests)
{
//	DEM_EQ("@HTTPParse@_16402",
//		   "HTTPParse::_16402");	// probably bad test

	DEM_EQ("@Themes@TThemeServices@GetElementDetails$qqr25Themes@TThemedExplorerBar",
		   "__fastcall Themes::TThemeServices::GetElementDetails(Themes::TThemedExplorerBar)");

	DEM_EQ(
		"@Webscriptas@TActiveScriptObjectFactory@CreateProducerObject$qqr32Webscript@TGlobalScriptVariables52System@%DelphiInterface$t24Httpprod@IScriptProducer%",
		"__fastcall Webscriptas::TActiveScriptObjectFactory::CreateProducerObject(Webscript::TGlobalScriptVariables, System::DelphiInterface<Httpprod::IScriptProducer>)");

	DEM_EQ(
		"@Webservexp@TWebServExp@GenerateNestedArraySchema$qqr51System@%DelphiInterface$t23Xmlschema@IXMLSchemaDef%56System@%DelphiInterface$t28Xmlschema@IXMLComplexTypeDef%px17Typinfo@TTypeInfori17System@WideString",
		"__fastcall Webservexp::TWebServExp::GenerateNestedArraySchema(System::DelphiInterface<Xmlschema::IXMLSchemaDef>, System::DelphiInterface<Xmlschema::IXMLComplexTypeDef>, const Typinfo::TTypeInfo *, int &, System::WideString)");

	DEM_EQ("@Dateutils@TryRecodeDateTime$qqrx16System@TDateTimexusxusxusxusxusxusxusr16System@TDateTime",
		   "__fastcall Dateutils::TryRecodeDateTime(const System::TDateTime, const unsigned short, const unsigned short, const unsigned short, const unsigned short, const unsigned short, const unsigned short, const unsigned short, System::TDateTime &)");

	DEM_EQ(
		"@Dbxtablestorage@TDBXDelegateTableStorage@SetColumns$qqrx62System@%DynamicArray$tp36Dbxtablestorage@TDBXColumnDescriptor%",
		"__fastcall Dbxtablestorage::TDBXDelegateTableStorage::SetColumns(const System::DynamicArray<Dbxtablestorage::TDBXColumnDescriptor *>)");

	DEM_EQ(
		"@Dbxmysqlmetadatareader@TDBXMySqlCustomMetaDataReader@TDBXMySql4IndexesCursor@FindStringSize$qqrxix62System@%DynamicArray$tp36Dbxtablestorage@TDBXColumnDescriptor%",
		"__fastcall Dbxmysqlmetadatareader::TDBXMySqlCustomMetaDataReader::TDBXMySql4IndexesCursor::FindStringSize(const int, const System::DynamicArray<Dbxtablestorage::TDBXColumnDescriptor *>)");

//	DEM_EQ("@Idimap4@TIdImapSubSection@$bleq$qqrv",
//		   "__fastcall Idimap4::TIdImapSubSection::operator<=(void)");

	DEM_EQ("@Idimap4@TIdImapSubSection@bagr$qqriipa15$a89$a2$ipa10$a666$25System@%DynamicArray$tuc%",
		   "__fastcall Idimap4::TIdImapSubSection::bagr(int, int, int(*)[15][89][2], System::DynamicArray<unsigned char>(*)[10][666])");

//	DEM_EQ("@Idimap4@TIdImapSubSection@$brrsh$qqrv",
//		   "__fastcall Idimap4::TIdImapSubSection::operator>>=(void)");

	DEM_EQ(
		"@Sqlexpr@TSQLConnection@SQLError$qqrus25Sqlexpr@TSQLExceptionTypex48System@%DelphiInterface$t20Dbxpress@ISQLCommand%",
		"__fastcall Sqlexpr::TSQLConnection::SQLError(unsigned short, Sqlexpr::TSQLExceptionType, const System::DelphiInterface<Dbxpress::ISQLCommand>)");
}

TEST_F(BorlandDemanglerTests, ArrayTests)
{
	DEM_EQ("@foo$qpa3$i", "foo(int(*)[3])");
	DEM_EQ("@foo1$qpa3$a5$c", "foo1(char(*)[3][5])");
	DEM_EQ("@foo3$qpxa3$i", "foo3(int const(*)[3])");
	DEM_EQ("@foo4$qpa3500$a6$i", "foo4(int(*)[3500][6])");
	DEM_EQ("@foo5$qra5$a5$i", "foo5(int(&)[5][5])");
	DEM_EQ("@foo6$qrxa5$a5$i", "foo6(int const(&)[5][5])");
	DEM_EQ("@foo7$qha5$a5$i", "foo7(int(&&)[5][5])");
	DEM_EQ("@foo8$qxpxa5$i", "foo8(int const(* const)[5])");
	DEM_EQ("@foo10$qpa3$d", "foo10(double(*)[3])");
}

TEST_F(BorlandDemanglerTests, NamespaceTests)
{
	DEM_EQ("@bar@foo$qi", "bar::foo(int)");
	DEM_EQ("@Baz@foo$qd", "Baz::foo(double)");
	DEM_EQ("@bar@%f$i%$qii$d", "double bar::f<int>(int, int)");
}

TEST_F(BorlandDemanglerTests, TemplateTests)
{
	DEM_EQ("@%myFunc_template_$i%$qi$d", "double myFunc_template_<int>(int)");
	DEM_EQ("@ns1@ns2@ns3@%foo3$c%$qv$v", "void ns1::ns2::ns3::foo3<char>(void)");
	DEM_EQ("@ns@ns1@ns2@%myFunc_template_$i%$qi$d", "double ns::ns1::ns2::myFunc_template_<int>(int)");
	DEM_EQ("@ns@%myFunc_template_$i%$qi$d", "double ns::myFunc_template_<int>(int)");
	DEM_EQ("@%foo2$20std@%basic_string$c%i%$qv$v",
		   "void foo2<std::basic_string<char>, int>(void)");
	DEM_EQ("@%foo2$32std@%basic_string$c10%my_tmp$c%%i%$qv$v",
		   "void foo2<std::basic_string<char, my_tmp<char>>, int>(void)");
	DEM_EQ("@%foo2$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%i%$qv$v",
		   "void foo2<std::basic_string<char, std::char_traits<char>, std::allocator<char>>, int>(void)");
	DEM_EQ(
		"@%foo$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%%$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%$v",
		"void foo<std::basic_string<char, std::char_traits<char>, std::allocator<char>>>(std::basic_string<char, std::char_traits<char>, std::allocator<char>>)");
}

TEST_F(BorlandDemanglerTests, NamedTypes)
{
	DEM_EQ("@foo$q10ns@Bar@Baz", "foo(ns::Bar::Baz)");
	DEM_EQ("@foo$qpx10ns@Bar@Baz", "foo(const ns::Bar::Baz *)");
}

TEST_F(BorlandDemanglerTests, Backrefs)
{
	DEM_EQ("@%foo$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%t1%$qv$v",
		   "void foo<std::basic_string<char, std::char_traits<char>, std::allocator<char>>, std::basic_string<char, std::char_traits<char>, std::allocator<char>>>(void)");
}

TEST_F(BorlandDemanglerTests, Operators)
{
//	DEM_EQ("@Foo@$badd$q3Foo", "Foo::operator+(Foo)");
//	DEM_EQ("@$badd$q3Bart1", "operator+(Bar, Bar)");
//	DEM_EQ("@%$badd$3Bar%$q3Bart1$3Bar", "Bar operator+<Bar>(Bar, Bar)");
}

TEST_F(BorlandDemanglerTests, FunctionPointers)
{
	DEM_EQ("@foo1$qpqv$i", "foo1(int (*)(void))");
	DEM_EQ("@foo2$qr$qv$i", "foo2(int (&)(void))");
	DEM_EQ("@foo3$qh$qv$i", "foo3(int (&&)(void))");
	DEM_EQ("@foo4$qpqv$pqpi$v", "foo4(void (*(*)(void))(int *))");
	DEM_EQ("@foo5$qpxpqv$vpxpqv$v", "foo5(void (* const(*))(void), void (* const(*))(void))");
	DEM_EQ("@foo6$qpqv$pqpi$pqpd$v", "foo6(void (*(*(*)(void))(int *))(double *))");
}

TEST_F(BorlandDemanglerTests, FailTests)
{
	DEM_FAIL("@%foo2$20std@%basic_string$c10%my_tmp$c%%i%$qv$v", status::invalid_mangled_name);
}

// TODO operator tests, named params tests, fail tests, extra long names, backref tests, conversion operators, functions as params

} // namespace tests
} // namespace demangler
} // namespace retdec

