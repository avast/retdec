/**
 * @file tests/demangler/borland_tests.cpp
 * @brief Tests for the borland demangler.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "demangler/demangler.h"

using namespace ::testing;

#define DEM_EQ(mangled, demangled) EXPECT_EQ(demangled, borland.demangleToString(mangled))

namespace demangler {
namespace tests {

class BorlandDemanglerTests : public Test
{
	public:
		BorlandDemanglerTests() :
			borland("borland")
		{

		}

	protected:
		demangler::CDemangler borland;
};

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
