/**
 * @file tests/demangler/msvc_tests.cpp
 * @brief Tests for the MSVC demangler.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/demangler/demangler.h"

using namespace ::testing;

#define DEM_EQ(mangled, demangled) EXPECT_EQ(demangled, msvc.demangleToString(mangled))

namespace retdec {
namespace demangler {
namespace tests {

class MsvcDemanglerTests : public Test
{
	public:
		MsvcDemanglerTests() :
			msvc("ms")
		{

		}

	protected:
		retdec::demangler::CDemangler msvc;
};

TEST_F(MsvcDemanglerTests, DemangleCppClassNames)
{
	DEM_EQ(".?AVPolygon@@", "Polygon");
	DEM_EQ(".?AVRectangle@@", "Rectangle");
	DEM_EQ(".?AVPolygon125@@", "Polygon125");
	DEM_EQ(".?AV_Polygon_125@@", "_Polygon_125");
	DEM_EQ(".?AVtype_info@@", "type_info");
}

TEST_F(MsvcDemanglerTests, DoNotDemangleCppClassNamesWhenTheyDoNotMatchRegex)
{
	DEM_EQ(" .?AVPolygon@@", ""); // std::regex_match
	DEM_EQ(".?AVPolygon@@ ", ""); // std::regex_match
	DEM_EQ(" .?AVPolygon@@ ", ""); // std::regex_match
}

TEST_F(MsvcDemanglerTests, RandomTests)
{
	DEM_EQ("??D@YAPAXI@Z",
			"void * __cdecl operator*(unsigned int)");

	DEM_EQ("??1?$map@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_NU?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_N@std@@@2@@std@@QAE@XZ",
			"public: __thiscall std::map<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, bool, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > >, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, bool> > >::~map<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, bool, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > >, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, bool> > >()");

	DEM_EQ("??_DcGram@@UAEPAXI@Z",
			"public: virtual void * __thiscall cGram::`vbase destructor'(unsigned int)");

	DEM_EQ("??_7type_info@@6B@",
			"const type_info::`vftable'");

	DEM_EQ("??_R1A@?0A@EA@?$basic_iostream@DU?$char_traits@D@std@@@std@@8",
			"std::basic_iostream<char, struct std::char_traits<char> >::`RTTI Base Class Descriptor at (0, -1, 0, 64)'");

	DEM_EQ("??1?$_Vector_iterator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@QAE@XZ",
			"public: __thiscall std::_Vector_iterator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, class std::allocator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > > >::~_Vector_iterator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, class std::allocator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > > >()");

	DEM_EQ("?begin@?$vector@Urule_t@cGram@@V?$allocator@Urule_t@cGram@@@std@@@std@@QAE?AV?$_Vector_iterator@Urule_t@cGram@@V?$allocator@Urule_t@cGram@@@std@@@2@XZ",
			"public: class std::_Vector_iterator<struct cGram::rule_t, class std::allocator<struct cGram::rule_t> > __thiscall std::vector<struct cGram::rule_t, class std::allocator<struct cGram::rule_t> >::begin()");

	DEM_EQ("?end@?$_Tree@V?$_Tmap_traits@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$map@DU?$pair@IW4semact@cGram@@@std@@U?$less@D@2@V?$allocator@U?$pair@$$CBDU?$pair@IW4semact@cGram@@@std@@@std@@@2@@2@U?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$map@DU?$pair@IW4semact@cGram@@@std@@U?$less@D@2@V?$allocator@U?$pair@$$CBDU?$pair@IW4semact@cGram@@@std@@@std@@@2@@2@@std@@@2@$0A@@std@@@std@@QAE?AViterator@12@XZ",
			"public: class std::_Tree<class std::_Tmap_traits<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, class std::map<char, struct std::pair<unsigned int, enum cGram::semact>, struct std::less<char>, class std::allocator<struct std::pair<char const, struct std::pair<unsigned int, enum cGram::semact> > > >, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > >, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > const, class std::map<char, struct std::pair<unsigned int, enum cGram::semact>, struct std::less<char>, class std::allocator<struct std::pair<char const, struct std::pair<unsigned int, enum cGram::semact> > > > > >, 0> >::iterator __thiscall std::_Tree<class std::_Tmap_traits<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, class std::map<char, struct std::pair<unsigned int, enum cGram::semact>, struct std::less<char>, class std::allocator<struct std::pair<char const, struct std::pair<unsigned int, enum cGram::semact> > > >, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > >, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > const, class std::map<char, struct std::pair<unsigned int, enum cGram::semact>, struct std::less<char>, class std::allocator<struct std::pair<char const, struct std::pair<unsigned int, enum cGram::semact> > > > > >, 0> >::end()");

	DEM_EQ("?erase@?$vector@IV?$allocator@I@std@@@std@@QAE?AV?$_Vector_iterator@IV?$allocator@I@std@@@2@V32@0@Z",
			"public: class std::_Vector_iterator<unsigned int, class std::allocator<unsigned int> > __thiscall std::vector<unsigned int, class std::allocator<unsigned int> >::erase(class std::_Vector_iterator<unsigned int, class std::allocator<unsigned int> >, class std::_Vector_iterator<unsigned int, class std::allocator<unsigned int> >)");

	DEM_EQ("??0?$deque@Ugelem_t@cGram@@V?$allocator@Ugelem_t@cGram@@@std@@@std@@QAE@XZ",
			"public: __thiscall std::deque<struct cGram::gelem_t, class std::allocator<struct cGram::gelem_t> >::deque<struct cGram::gelem_t, class std::allocator<struct cGram::gelem_t> >()");

	DEM_EQ("??0iterator@?$_Tree@V?$_Tmap_traits@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@U?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@@std@@@2@$0A@@std@@@std@@QAE@PAU_Node@?$_Tree_nod@V?$_Tmap_traits@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@U?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@@std@@@2@$0A@@std@@@2@PBV12@@Z",
			"public: __thiscall std::_Tree<class std::_Tmap_traits<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t> >, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > >, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > const, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t> > > >, 0> >::iterator::iterator(struct std::_Tree_nod<class std::_Tmap_traits<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t> >, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > >, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > const, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t> > > >, 0> >::_Node *, class std::_Tree<class std::_Tmap_traits<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> >, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t> >, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > >, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char> > const, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t> > > >, 0> > const *)");

	DEM_EQ("??G?$_Vector_const_iterator@Utype_t@cName@@V?$allocator@Utype_t@cName@@@std@@@std@@QBEHABV01@@Z",
			"public: int __thiscall std::_Vector_const_iterator<struct cName::type_t, class std::allocator<struct cName::type_t> >::operator-(class std::_Vector_const_iterator<struct cName::type_t, class std::allocator<struct cName::type_t> > const &) const");

	DEM_EQ("??_R3bad_alloc@std@@8",
			"std::bad_alloc::`RTTI Class Hierarchy Descriptor'");
}

} // namespace tests
} // namespace demangler
} // namespace retdec
