/**
 * @file tests/demangler/borland_demangler_tests.cpp
 * @brief Tests for the borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/demangler/demangler.h"
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
		demangler(std::make_unique<retdec::demangler::BorlandDemangler>()) {}

protected:
	std::unique_ptr<retdec::demangler::Demangler> demangler;
};

TEST_F(BorlandDemanglerTests, BasicTest)
{
	DEM_EQ("@myFunc_int_$qi", "myFunc_int_(int)");
}

TEST_F(BorlandDemanglerTests, EmptyTest)
{
	DEM_FAIL("", status::invalid_mangled_name);
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
	DEM_EQ("@myFunc_all_$qsusiuiluljujzcuccfdgoCsCib",
		   "myFunc_all_(short, unsigned short, int, unsigned int, long, unsigned long, long long, unsigned long long, signed char, unsigned char, char, float, double, long double, bool, char16_t, char32_t, wchar_t)");
	DEM_EQ("@foo$qie", "foo(int, ...)");
	DEM_EQ("@foo$qN", "foo(nullptr_t)");
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
	DEM_EQ("@Bar@foo$wxqqrv", "__fastcall Bar::foo(void) volatile const");
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
	DEM_EQ("@Themes@TThemeServices@GetElementDetails$qqr25Themes@TThemedExplorerBar",
		   "__fastcall Themes::TThemeServices::GetElementDetails(Themes::TThemedExplorerBar)");

	DEM_EQ(
		"@Webscriptas@TActiveScriptObjectFactory@CreateProducerObject$qqr32Webscript@TGlobalScriptVariables51System@%DelphiInterface$24Httpprod@IScriptProducer%",
		"__fastcall Webscriptas::TActiveScriptObjectFactory::CreateProducerObject(Webscript::TGlobalScriptVariables, System::DelphiInterface<Httpprod::IScriptProducer>)");

	DEM_EQ(
		"@Webservexp@TWebServExp@GenerateNestedArraySchema$qqr50System@%DelphiInterface$23Xmlschema@IXMLSchemaDef%55System@%DelphiInterface$28Xmlschema@IXMLComplexTypeDef%px17Typinfo@TTypeInfori17System@WideString",
		"__fastcall Webservexp::TWebServExp::GenerateNestedArraySchema(System::DelphiInterface<Xmlschema::IXMLSchemaDef>, System::DelphiInterface<Xmlschema::IXMLComplexTypeDef>, const Typinfo::TTypeInfo *, int &, System::WideString)");

	DEM_EQ("@Dateutils@TryRecodeDateTime$qqrx16System@TDateTimexusxusxusxusxusxusxusr16System@TDateTime",
		   "__fastcall Dateutils::TryRecodeDateTime(const System::TDateTime, const unsigned short, const unsigned short, const unsigned short, const unsigned short, const unsigned short, const unsigned short, const unsigned short, System::TDateTime &)");

	DEM_EQ(
		"@Dbxtablestorage@TDBXDelegateTableStorage@SetColumns$qqrx61System@%DynamicArray$p36Dbxtablestorage@TDBXColumnDescriptor%",
		"__fastcall Dbxtablestorage::TDBXDelegateTableStorage::SetColumns(const System::DynamicArray<Dbxtablestorage::TDBXColumnDescriptor *>)");

	DEM_EQ(
		"@Dbxmysqlmetadatareader@TDBXMySqlCustomMetaDataReader@TDBXMySql4IndexesCursor@FindStringSize$qqrxix61System@%DynamicArray$p36Dbxtablestorage@TDBXColumnDescriptor%",
		"__fastcall Dbxmysqlmetadatareader::TDBXMySqlCustomMetaDataReader::TDBXMySql4IndexesCursor::FindStringSize(const int, const System::DynamicArray<Dbxtablestorage::TDBXColumnDescriptor *>)");

	DEM_EQ("@Idimap4@TIdImapSubSection@$bleq$qqrv",
		   "__fastcall Idimap4::TIdImapSubSection::operator<=(void)");

	DEM_EQ("@Idimap4@TIdImapSubSection@bagr$qqriipa15$a89$a2$ipa10$a666$24System@%DynamicArray$uc%",
		   "__fastcall Idimap4::TIdImapSubSection::bagr(int, int, int(*)[15][89][2], System::DynamicArray<unsigned char>(*)[10][666])");

	DEM_EQ("@Idimap4@TIdImapSubSection@$brrsh$qqrv",
		   "__fastcall Idimap4::TIdImapSubSection::operator>>=(void)");

	DEM_EQ(
		"@Sqlexpr@TSQLConnection@SQLError$qqrus25Sqlexpr@TSQLExceptionTypex47System@%DelphiInterface$20Dbxpress@ISQLCommand%",
		"__fastcall Sqlexpr::TSQLConnection::SQLError(unsigned short, Sqlexpr::TSQLExceptionType, const System::DelphiInterface<Dbxpress::ISQLCommand>)");

	DEM_EQ(
		"@std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%@_Xlen$xqv",
		"std::basic_string<char, std::char_traits<char>, std::allocator<char>>::_Xlen(void) const");
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
	DEM_EQ("@%adder$iVii%$qiii$i", "int adder<int, int, int>(int, int, int)");	// variadic templates demangle as non variadic
	DEM_EQ("@std@%basic_ios$c19std@%char_traits$c%%@fill$xqv", "std::basic_ios<char, std::char_traits<char>>::fill(void) const");
	DEM_EQ("@std@$bror$qr22std@%_Iosb$i%@_Iostate22std@%_Iosb$i%@_Iostate", "std::operator|=(std::_Iosb<int>::_Iostate &, std::_Iosb<int>::_Iostate)");
}

TEST_F(BorlandDemanglerTests, NamedTypes)
{
	DEM_EQ("@foo$q10ns@Bar@Baz", "foo(ns::Bar::Baz)");
	DEM_EQ("@foo$qpx10ns@Bar@Baz", "foo(const ns::Bar::Baz *)");
	DEM_FAIL("@foo$q010ns@Bar@Baz", status::invalid_mangled_name);
}

TEST_F(BorlandDemanglerTests, Backrefs)
{
	DEM_EQ("@%foo$60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%t1%$qv$v",
		   "void foo<std::basic_string<char, std::char_traits<char>, std::allocator<char>>, std::basic_string<char, std::char_traits<char>, std::allocator<char>>>(void)");
	DEM_EQ("@bar$q4Foo14Foo24Foo34Foo44Foo54Foo64Foo74Foo84Foo95Foo105Foo115Foo125Foo135Foo145Foo155Foo165Foo175Foo185Foo19tftgtht1tjta",
		"bar(Foo1, Foo2, Foo3, Foo4, Foo5, Foo6, Foo7, Foo8, Foo9, Foo10, Foo11, Foo12, Foo13, Foo14, Foo15, Foo16, Foo17, Foo18, Foo19, Foo15, Foo16, Foo17, Foo1, Foo19, Foo10)");
}

TEST_F(BorlandDemanglerTests, Operators)
{
	DEM_EQ("@Foo@$badd$q3Foo", "Foo::operator+(Foo)");
	DEM_EQ("@$badd$q3Bart1", "operator+(Bar, Bar)");
	DEM_EQ("@%$badd$3Bar%$q3Bart1$3Bar", "Bar operator+<Bar>(Bar, Bar)");
	DEM_EQ("@Foo@$bsub$q3Foo", "Foo::operator-(Foo)");
	DEM_EQ("@Foo@$basg$q3Foo", "Foo::operator=(Foo)");
	DEM_EQ("@Foo@$bmul$q3Foo", "Foo::operator*(Foo)");
	DEM_EQ("@Foo@$bdiv$q3Foo", "Foo::operator/(Foo)");
	DEM_EQ("@Foo@$bmod$q3Foo", "Foo::operator%(Foo)");
	DEM_EQ("@Foo@$binc$qi", "Foo::operator++(int)");
	DEM_EQ("@Foo@$bdec$qi", "Foo::operator--(int)");
	DEM_EQ("@Foo@$beql$q3Foo", "Foo::operator==(Foo)");
	DEM_EQ("@Foo@$bneq$q3Foo", "Foo::operator!=(Foo)");
	DEM_EQ("@Foo@$bgtr$q3Foo", "Foo::operator>(Foo)");
	DEM_EQ("@Foo@$blss$q3Foo", "Foo::operator<(Foo)");
	DEM_EQ("@Foo@$bgeq$q3Foo", "Foo::operator>=(Foo)");
	DEM_EQ("@Foo@$bleq$q3Foo", "Foo::operator<=(Foo)");
	DEM_EQ("@Foo@$bnot$qv", "Foo::operator!(void)");
	DEM_EQ("@Foo@$bland$q3Foo", "Foo::operator&&(Foo)");
	DEM_EQ("@Foo@$blor$q3Foo", "Foo::operator||(Foo)");
	DEM_EQ("@Foo@$bcmp$qv", "Foo::operator~(void)");
	DEM_EQ("@Foo@$band$q3Foo", "Foo::operator&(Foo)");
	DEM_EQ("@Foo@$bor$q3Foo", "Foo::operator|(Foo)");
	DEM_EQ("@Foo@$bxor$q3Foo", "Foo::operator^(Foo)");
	DEM_EQ("@Foo@$blsh$q3Foo", "Foo::operator<<(Foo)");
	DEM_EQ("@Foo@$brsh$q3Foo", "Foo::operator>>(Foo)");
	DEM_EQ("@Foo@$brplu$q3Foo", "Foo::operator+=(Foo)");
	DEM_EQ("@Foo@$brmin$q3Foo", "Foo::operator-=(Foo)");
	DEM_EQ("@Foo@$brmul$q3Foo", "Foo::operator*=(Foo)");
	DEM_EQ("@Foo@$brdiv$q3Foo", "Foo::operator/=(Foo)");
	DEM_EQ("@Foo@$brmod$q3Foo", "Foo::operator%=(Foo)");
	DEM_EQ("@Foo@$brand$q3Foo", "Foo::operator&=(Foo)");
	DEM_EQ("@Foo@$bror$q3Foo", "Foo::operator|=(Foo)");
	DEM_EQ("@Foo@$brxor$q3Foo", "Foo::operator^=(Foo)");
	DEM_EQ("@Foo@$brlsh$q3Foo", "Foo::operator<<=(Foo)");
	DEM_EQ("@Foo@$brrsh$q3Foo", "Foo::operator>>=(Foo)");
	DEM_EQ("@Foo@$bsubs$q3Foo", "Foo::operator[](Foo)");
	DEM_EQ("@Foo@$bind$qv", "Foo::operator*(void)");
	DEM_EQ("@Foo@$badr$qv", "Foo::operator&(void)");
	DEM_EQ("@Foo@$barow$qv", "Foo::operator->(void)");
	DEM_EQ("@Foo@$barwm$q3Foo", "Foo::operator->*(Foo)");
	DEM_EQ("@Foo@$bcall$qi", "Foo::operator()(int)");
	DEM_EQ("@Foo@$bcoma$q3Foo", "Foo::operator,(Foo)");
	DEM_EQ("@Foo@$bnew$qui", "Foo::operator new(unsigned int)");
	DEM_EQ("@Foo@$bnwa$qui", "Foo::operator new[](unsigned int)");
	DEM_EQ("@Foo@$bdele$qpv", "Foo::operator delete(void *)");
	DEM_EQ("@Foo@$bdla$qpv", "Foo::operator delete[](void *)");
	DEM_EQ("@Foo@$o3Bar$qv", "Foo::operator Bar(void)");
	DEM_EQ("@Foo@$oi$qv", "Foo::operator int(void)");
	DEM_EQ("@Foo@$bctr$qv", "Foo::Foo(void)");
	DEM_EQ("@Foo@$bctr2$qv", "Foo::Foo(void)");
	DEM_EQ("@Foo@$bdtr1$qv", "Foo::~Foo(void)");
	DEM_EQ("@Foo@$bdtr2$qv", "Foo::~Foo(void)");
	DEM_EQ("@std@error_category@$beql$xqrx18std@error_category", "std::error_category::operator==(const std::error_category &) const");
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
	DEM_FAIL("@foo$q14std@%tmp$c%iii", status::invalid_mangled_name);
	DEM_FAIL("@foo$q14std@%tmp$c%", status::invalid_mangled_name);
	DEM_FAIL("@foo$q14std@%tmp$c11std@%tmp$c%", status::invalid_mangled_name);
	DEM_FAIL("@foo$q23std@%tmp$c11std@%tmp$c%", status::invalid_mangled_name);
	DEM_FAIL("@foo$q14std@%tmp$c11std@%tmp$c%%", status::invalid_mangled_name);
	DEM_FAIL("@Foo@$baddi$q3Foo", status::invalid_mangled_name);
}

TEST_F(BorlandDemanglerTests, FakeStubTest)
{
	DEM_EQ("Lllvm$workaround$fake$stub$@%$badd$3Bar%$q3Bart1$3Bar", "Bar Lllvm::workaround::fake::stub::operator+<Bar>(Bar, Bar)");
	DEM_EQ("Lllvm$workaround$fake$stub$@Bar@$bctr$qv", "Lllvm::workaround::fake::stub::Bar::Bar(void)");
}

TEST_F(BorlandDemanglerTests, Exceptions)
{
	DEM_EQ("@std@_Xlength_error$qpxc", "std::_Xlength_error(const char *)");	// Exceptions could colide with functions, so name is not modified
}

TEST_F(BorlandDemanglerTests, NonClassTemplates)
{
	DEM_EQ("@%foo_int$i$i1$%$qv$v",
		"void foo_int<1>(void)");
	DEM_EQ("@%foo_int$i$i-1$%$qv$v",
		   "void foo_int<-1>(void)");
	DEM_EQ("@%foo_enum$6MyEnum$i1$%$qv$v",
		"void foo_enum<(MyEnum)1>(void)");
	DEM_EQ("@%foo$N%$qN$v",
		"void foo<nullptr_t>(nullptr_t)");
	DEM_EQ("@Unit1@foo_Comp_$qqr11System@Comp", "__fastcall Unit1::foo_Comp_(System::Comp)");
	DEM_EQ("@Unit1@foo_Currency_$qqr15System@Currency", "__fastcall Unit1::foo_Currency_(System::Currency)");
	DEM_EQ("@Unit1@foo_ShortString_$qqrr29System@%SmallString$uc$i255$%", "__fastcall Unit1::foo_ShortString_(System::SmallString<255> &)");
	DEM_EQ("@Unit1@foo_AnsiString_$qqr27System@%AnsiStringT$us$i0$%","__fastcall Unit1::foo_AnsiString_(System::AnsiStringT<0>)");
	DEM_EQ("@Unit1@foo_UnicodeString_$qqr20System@UnicodeString","__fastcall Unit1::foo_UnicodeString_(System::UnicodeString)");
	DEM_EQ("@Unit1@foo_WideString_$qqr17System@WideString", "__fastcall Unit1::foo_WideString_(System::WideString)");
	DEM_EQ("@Unit1@foo_RawByteString_$qqr31System@%AnsiStringT$us$i65535$%", "__fastcall Unit1::foo_RawByteString_(System::AnsiStringT<65535>)");
	DEM_EQ("@Unit1@foo_UTF8String_$qqr31System@%AnsiStringT$us$i65001$%", "__fastcall Unit1::foo_UTF8String_(System::AnsiStringT<65001>)");
//	DEM_EQ("@%foo_obj_ptr$X$badrp3Bar$g@bar$E%$qv$v",
//		"void foo_obj_ptr<&bar>(void)");
//	DEM_EQ("@%foo_func_ptr$X$badrpqv$v$g@fakefunc$qv$E%$qv$v",
//		"void foo_func_ptr<&(fakefunc(void))>(void)");
//	// TODO ci tam da argument funkcie
//	DEM_EQ("@%foo_ref$r3Bar$gbar$%$qv$v",
//		"void foo_ref<bar>(void)");
//	DEM_EQ("@%foo_func_ref$r$qv$v$gfakefunc$qv$%$qv$v",
//		"void foo_func_ref<fakefunc()>(void)");
//	DEM_EQ("@%Strange$X$badrM3Baz3Bar$g@Baz@bar$E%@foo$qv",
//		"void Strange::<&(Baz::bar)>::foo(void)");
//	DEM_EQ("@%foo$i$i1$%$qv$v", "void foo<1>(void)");
//	DEM_EQ("@%foo$X$badrp60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%$g@mystring$E%$qv$v", "void foo<&mystring>");
//	DEM_EQ("@%Strange$X$badrM6Person3Dog$g@Person@dog$E%@foo$qv", "Strange<&Person::dog>::foo(void)");
}

// NOT SUPPORTING __restrict keyword and User defined literal (operator "")

} // namespace tests
} // namespace demangler
} // namespace retdec
