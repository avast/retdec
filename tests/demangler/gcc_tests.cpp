/**
 * @file tests/demangler/gcc_tests.cpp
 * @brief Tests for the gcc demangler.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "demangler/demangler.h"

using namespace ::testing;

#define DEM_EQ(mangled, demangled) EXPECT_EQ(demangled, gcc.demangleToString(mangled))

namespace demangler {
namespace tests {

class GccDemanglerTests : public Test
{
	public:
		GccDemanglerTests() :
			gcc("gcc")
		{

		}

	protected:
		demangler::CDemangler gcc;
};

TEST_F(GccDemanglerTests, DemangleFunctionsStartingWithExtraUnderscore_bug1434)
{
	DEM_EQ("__ZN1A1B6myFuncEii", "A::B::myFunc(int, int)");
}

TEST_F(GccDemanglerTests, DemangleCppClassNamesWhenCharacterCountIsOk)
{
	DEM_EQ("7Polygon", "Polygon");
	DEM_EQ("14PolygonPolygon", "PolygonPolygon");
	DEM_EQ("19Polygon_1_Polygon_2", "Polygon_1_Polygon_2");
}

TEST_F(GccDemanglerTests, DoNotDemangleCppClassNamesWhenCharacterCountIsBad)
{
	DEM_EQ("0Polygon", "");
	DEM_EQ("6Polygon", "");
	DEM_EQ("8Polygon", "");
}

TEST_F(GccDemanglerTests, DoNotDemangleCppClassNamesWhenTheyDoNotMatchRegex)
{
	DEM_EQ("enc_vad_21363218732487324784rufdekdfbnerwquie2r6732", ""); // #1495
	DEM_EQ(" 7Polygon", ""); // std::regex_match
	DEM_EQ("7Polygon ", ""); // std::regex_match
	DEM_EQ(" 7Polygon ", ""); // std::regex_match
}

TEST_F(GccDemanglerTests, RandomTests)
{
	DEM_EQ("_ZN5cGram11bagrneplaveEPKN5cName6type_tES3_",
			"cGram::bagrneplave(cName::type_t const *, cName::type_t const *)");

	DEM_EQ("_ZN5cGram11bagrneplaveERKPKPKN5cName6type_tESt6vectorIS1_SaIS1_EES8_IPS1_SaISB_EES8_IS3_SaIS3_EES8_IPKSB_SaISH_EES3_",
			"cGram::bagrneplave(cName::type_t const * const * const &, std::vector<cName::type_t, std::allocator<cName::type_t> >, std::vector<cName::type_t *, std::allocator<cName::type_t *> >, std::vector<cName::type_t const *, std::allocator<cName::type_t const *> >, std::vector<cName::type_t * const *, std::allocator<cName::type_t * const *> >, cName::type_t const *)");

	DEM_EQ("_ZN5cGram3eofEv",
			"cGram::eof()");

	DEM_EQ("_ZN9__gnu_cxx13new_allocatorIN5cGram7gelem_tEEC2ERKS3_",
			"__gnu_cxx::new_allocator<cGram::gelem_t>::new_allocator(__gnu_cxx::new_allocator<cGram::gelem_t> const &)");

	DEM_EQ("_ZN9__gnu_cxx13new_allocatorISt13_Rb_tree_nodeISt4pairIKSsSt3mapIcS2_IjN5cGram6semactEESt4lessIcESaIS2_IKcS7_EEEEEED2Ev",
			"__gnu_cxx::new_allocator<std::_Rb_tree_node<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > > >::~new_allocator()");

	DEM_EQ("_ZN9__gnu_cxxmiIPN5cGram6rule_tESt6vectorIS2_SaIS2_EEEENS_17__normal_iteratorIT_T0_E15difference_typeERKSA_SD_",
			"__gnu_cxx::__normal_iterator<cGram::rule_t *, std::vector<cGram::rule_t, std::allocator<cGram::rule_t> > >::difference_type __gnu_cxx::operator-<cGram::rule_t *, std::vector<cGram::rule_t, std::allocator<cGram::rule_t> > >(__gnu_cxx::__normal_iterator<cGram::rule_t *, std::vector<cGram::rule_t, std::allocator<cGram::rule_t> > > const &, __gnu_cxx::__normal_iterator<cGram::rule_t *, std::vector<cGram::rule_t, std::allocator<cGram::rule_t> > > const &)");

	DEM_EQ("_ZNKSs5c_strEv",
			"std::string::c_str() const");

	DEM_EQ("_ZNKSt17_Rb_tree_iteratorISt4pairIKSsSt3mapIcS0_IjN5cGram6semactEESt4lessIcESaIS0_IKcS5_EEEEEneERKSD_",
			"std::_Rb_tree_iterator<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > >::operator!=(std::_Rb_tree_iterator<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > > const &) const");

	DEM_EQ("_ZNKSt5dequeIN5cGram7gelem_tESaIS1_EE5beginEv",
			"std::deque<cGram::gelem_t, std::allocator<cGram::gelem_t> >::begin() const");

	DEM_EQ("_ZNKSt8_Rb_treeISsSt4pairIKSsSt3mapIcS0_IjN5cGram6semactEESt4lessIcESaIS0_IKcS5_EEEESt10_Select1stISC_ES6_ISsESaISC_EE8key_compEv",
			"std::_Rb_tree<std::string, std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > >, std::_Select1st<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > >, std::less<std::string>, std::allocator<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > > >::key_comp() const");

	DEM_EQ("_ZNSspLERKSs",
			"std::string::operator+=(std::string const &)");

	DEM_EQ("_ZNSt11_Deque_baseISt6vectorISsSaISsEESaIS2_EE15_M_allocate_mapEj",
			"std::_Deque_base<std::vector<std::string, std::allocator<std::string> >, std::allocator<std::vector<std::string, std::allocator<std::string> > > >::_M_allocate_map(unsigned int)");

	DEM_EQ("_ZNSt12__miter_baseIPN5cName6type_tELb0EE3__bES2_",
			"std::__miter_base<cName::type_t *, false>::__b(cName::type_t *)");

	DEM_EQ("_ZNSt3mapISsS_IcSt4pairIjN5cGram6semactEESt4lessIcESaIS0_IKcS3_EEES4_ISsESaIS0_IKSsS9_EEE5clearEv",
			"std::map<std::string, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > >, std::less<std::string>, std::allocator<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > > >::clear()");

	DEM_EQ("_ZNSt5stackISsSt5dequeISsSaISsEEEC1ERKS2_",
			"std::stack<std::string, std::deque<std::string, std::allocator<std::string> > >::stack(std::deque<std::string, std::allocator<std::string> > const &)");

	DEM_EQ("_ZNSt8_Rb_treeISsSt4pairIKSsSt3setIN5cGram7gelem_tENS3_14comparegelem_cESaIS4_EEESt10_Select1stIS8_ESt4lessISsESaIS8_EE6_S_keyEPKSt18_Rb_tree_node_base",
			"std::_Rb_tree<std::string, std::pair<std::string const, std::set<cGram::gelem_t, cGram::comparegelem_c, std::allocator<cGram::gelem_t> > >, std::_Select1st<std::pair<std::string const, std::set<cGram::gelem_t, cGram::comparegelem_c, std::allocator<cGram::gelem_t> > > >, std::less<std::string>, std::allocator<std::pair<std::string const, std::set<cGram::gelem_t, cGram::comparegelem_c, std::allocator<cGram::gelem_t> > > > >::_S_key(std::_Rb_tree_node_base const *)");

	DEM_EQ("_ZSt14__copy_move_a2ILb0EN9__gnu_cxx17__normal_iteratorIPKN5cName6name_tESt6vectorIS3_SaIS3_EEEENS1_IPS3_S8_EEET1_T0_SD_SC_",
			"__gnu_cxx::__normal_iterator<cName::name_t *, std::vector<cName::name_t, std::allocator<cName::name_t> > > std::__copy_move_a2<false, __gnu_cxx::__normal_iterator<cName::name_t const *, std::vector<cName::name_t, std::allocator<cName::name_t> > >, __gnu_cxx::__normal_iterator<cName::name_t *, std::vector<cName::name_t, std::allocator<cName::name_t> > > >(__gnu_cxx::__normal_iterator<cName::name_t const *, std::vector<cName::name_t, std::allocator<cName::name_t> > >, __gnu_cxx::__normal_iterator<cName::name_t const *, std::vector<cName::name_t, std::allocator<cName::name_t> > >, __gnu_cxx::__normal_iterator<cName::name_t *, std::vector<cName::name_t, std::allocator<cName::name_t> > >)");

	DEM_EQ("_ZSt8_DestroyIN5cGram7gelem_tEEvPT_",
			"void std::_Destroy<cGram::gelem_t>(cGram::gelem_t *)");
}

} // namespace tests
} // namespace demangler
