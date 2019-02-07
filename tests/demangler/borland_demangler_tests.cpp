/**
 * @file tests/demangler/borland_demangler_tests.cpp
 * @brief Tests for the borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "llvm/Demangle/demangler_retdec.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace tests {

#define DEM_EQ(mangled, demangled) \
			do {	\
				EXPECT_EQ(demangler->demangleToString(mangled), demangled); \
                EXPECT_EQ(demangler->status(), status::success); \
			} while(0)

class BorlandDemanglerTests : public Test
{
	public:
		using status = retdec::demangler::Demangler::Status;

		BorlandDemanglerTests():
			demangler(retdec::demangler::DemanglerFactory::getDemangler("borland")) {}

	protected:
		std::unique_ptr<retdec::demangler::Demangler> demangler;
};

TEST_F(BorlandDemanglerTests, BasicTest)
{
	DEM_EQ("@myFunc_int_$qi", "myFunc_int_(int)");
}

TEST_F(BorlandDemanglerTests, CallConventionsTests)
{
	/* cdecl and pascal cant be differenciated from mangled name */
	DEM_EQ("@myFunc_cdecl_$qv", "myFunc_cdecl_()");
	DEM_EQ("@myFunc_pascal_$qv", "myFunc_pascal_()");

	DEM_EQ("@myFunc_fastcall_$qqrv", "__fastcall myFunc_fastcall_()");
	DEM_EQ("@myFunc_stdcall_$qqsv", "__stdcall myFunc_stdcall_()");
}

TEST_F(BorlandDemanglerTests, RepeatingParameters) {
	DEM_EQ("@myFunc_i_$qiii", "myFunc_i_(int, int, int)");
	DEM_EQ("@myFunc_s_$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%t1t1", "myFunc_s_(std::string, std::string, std::string)");
}

TEST_F(BorlandDemanglerTests, BasicParametersTests) {
	DEM_EQ("@myFunc_empty_$qv", "myFunc_empty_()");
	DEM_EQ("@myFunc_short_int_$qs", "myFunc_short_int_(short int)");
	DEM_EQ("@myFunc_unsigned_short_int_$qus", "myFunc_unsigned_short_int_(unsigned short int)");
	DEM_EQ("@myFunc_int_$qi", "myFunc_int_(int)");
	DEM_EQ("@myFunc_unsigned_$qui", "myFunc_unsigned_(unsigned)");
	DEM_EQ("@myFunc_long_int_$ql", "myFunc_long_int_(long int)");
	DEM_EQ("@myFunc_unsigned_long_int_$qul", "myFunc_unsigned_long_int_(unsigned long int)");
	DEM_EQ("@myFunc_long_long_int_$qj", "myFunc_long_long_int_(long long int)");
	DEM_EQ("@myFunc_unsigned_long_long_$quj", "myFunc_unsigned_long_long_(unsigned long long)");
	DEM_EQ("@myFunc_signed_char_$qzc", "myFunc_signed_char_(signed char)");
	DEM_EQ("@myFunc_unsigned_char_$quc", "myFunc_unsigned_char_(unsigned char)");
	DEM_EQ("@myFunc_char_$qc", "myFunc_char_(char)");
	DEM_EQ("@myFunc_float_$qf", "myFunc_float_(float)");
	DEM_EQ("@myFunc_double_$qd", "myFunc_double_(double)");
	DEM_EQ("@myFunc_long_double_$qg", "myFunc_long_double_(long double)");
	DEM_EQ("@myFunc_bool_$qo", "myFunc_bool_(bool)");
	DEM_EQ("@myFunc_all_$qsusiuiluljujzcuccfdgo", "myFunc_all_(short int, unsigned short int, int, unsigned, long int, unsigned long int, long long int, unsigned long long, signed char, unsigned char, char, float, double, long double, bool)");
}

TEST_F(BorlandDemanglerTests, MoreComplicatedParameters) {
	DEM_EQ("@myFunc_std__string_$q60std@%basic_string$c19std@%char_traits$c%17std@%allocator$c%%", "myFunc_std__string_(std::basic_string<char,std::char_traits<char>, std::allocator<char>>)");
}

TEST_F(BorlandDemanglerTests, QualifiersTests) {
	DEM_EQ("@foo1$qpxi", "foo1(const int *)");
	DEM_EQ("@foo2$qxpi", "foo2(int * const)");
	DEM_EQ("@foo3$qxpxi", "foo3(const int * const)");
	DEM_EQ("@foo4$qpwi", "foo4(volatile int *)");
	DEM_EQ("@foo5$qwpi", "foo5(int * volatile)");
	DEM_EQ("@foo6$qwpwi", "foo6(volatile int * volatile)");
	DEM_EQ("@Bar@foo7$xqv", "Bar::foo7() const");
	DEM_EQ("@Bar@foo8$wqv", "Bar::foo7() volatile");
	DEM_EQ("@Bar@foo9$wxqv", "BAR::foo9() const volatile");
	DEM_EQ("@foo10$qpwxi", "foo10(const volatile int *)");
	DEM_EQ("@foo11$qpwxi", "foo11(volatile const int *)");
}

TEST_F(BorlandDemanglerTests, PointersTests) {
	DEM_EQ("@myFunc_void1_$qpv", "myFunc_void1_(void *)");
	DEM_EQ("@myFunc_void2_$qppv", "myFunc_void2_(void **)");
	DEM_EQ("@myFunc_void123_$qpvppvpppv", "myFunc_void123_(void *, void **, void ***)");
}

TEST_F(BorlandDemanglerTests, RandomTests)
{
	DEM_EQ("@HTTPParse@_16402",
		   "HTTPParse::_16402");

	DEM_EQ("@Themes@TThemeServices@GetElementDetails$qqr25Themes@TThemedExplorerBar",
		   "__fastcall Themes::TThemeServices::GetElementDetails(Themes::TThemedExplorerBar)");

	DEM_EQ("@Webscriptas@TActiveScriptObjectFactory@CreateProducerObject$qqr32Webscript@TGlobalScriptVariables52System@%DelphiInterface$t24Httpprod@IScriptProducer%",
		   "__fastcall Webscriptas::TActiveScriptObjectFactory::CreateProducerObject(Webscript::TGlobalScriptVariables, System::DelphiInterface<Httpprod::IScriptProducer>)");

	DEM_EQ("@Webservexp@TWebServExp@GenerateNestedArraySchema$qqr51System@%DelphiInterface$t23Xmlschema@IXMLSchemaDef%56System@%DelphiInterface$t28Xmlschema@IXMLComplexTypeDef%px17Typinfo@TTypeInfori17System@WideString",
		   "__fastcall Webservexp::TWebServExp::GenerateNestedArraySchema(System::DelphiInterface<Xmlschema::IXMLSchemaDef>, System::DelphiInterface<Xmlschema::IXMLComplexTypeDef>, const Typinfo::TTypeInfo *, int&, System::WideString)");

	DEM_EQ("@Dateutils@TryRecodeDateTime$qqrx16System@TDateTimexusxusxusxusxusxusxusr16System@TDateTime",
		   "__fastcall Dateutils::TryRecodeDateTime(const System::TDateTime, const unsigned short, const unsigned short, const unsigned short, const unsigned short, const unsigned short, const unsigned short, const unsigned short, System::TDateTime&)");

	DEM_EQ("@Dbxtablestorage@TDBXDelegateTableStorage@SetColumns$qqrx62System@%DynamicArray$tp36Dbxtablestorage@TDBXColumnDescriptor%",
		   "__fastcall Dbxtablestorage::TDBXDelegateTableStorage::SetColumns(const System::DynamicArray<Dbxtablestorage::TDBXColumnDescriptor *>)");

	DEM_EQ("@Dbxmysqlmetadatareader@TDBXMySqlCustomMetaDataReader@TDBXMySql4IndexesCursor@FindStringSize$qqrxix62System@%DynamicArray$tp36Dbxtablestorage@TDBXColumnDescriptor%",
		   "__fastcall Dbxmysqlmetadatareader::TDBXMySqlCustomMetaDataReader::TDBXMySql4IndexesCursor::FindStringSize(const int, const System::DynamicArray<Dbxtablestorage::TDBXColumnDescriptor *>)");

	DEM_EQ("@Idimap4@TIdImapSubSection@$bleq$qqrv",
		   "__fastcall Idimap4::TIdImapSubSection::operator<=()");

	DEM_EQ("@Idimap4@TIdImapSubSection@bagr$qqriipa15$a89$a2$ipa10$a666$25System@%DynamicArray$tuc%",
		   "__fastcall Idimap4::TIdImapSubSection::bagr(int, int, int [15][89][2] *, System::DynamicArray<unsigned char> [10][666] *)");

	DEM_EQ("@Idimap4@TIdImapSubSection@$brrsh$qqrv",
		   "__fastcall Idimap4::TIdImapSubSection::operator>>=()");

	DEM_EQ("@Sqlexpr@TSQLConnection@SQLError$qqrus25Sqlexpr@TSQLExceptionTypex48System@%DelphiInterface$t20Dbxpress@ISQLCommand%",
		   "__fastcall Sqlexpr::TSQLConnection::SQLError(unsigned short, Sqlexpr::TSQLExceptionType, const System::DelphiInterface<Dbxpress::ISQLCommand>)");
}

} // namespace tests
} // namespace demangler
} // namespace retdec

