/**
 * @file tests/demangler/llvm_microsoft_demangler_tests.cpp
 * @brief Tests for the llvm microsoft demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/demangler/demangler.h"
#include "dem_test.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace tests {

class MicrosoftDemanglerTests : public Test {
	public:
		using status = retdec::demangler::Demangler::Status;

		MicrosoftDemanglerTests() :
			demangler(std::make_unique<retdec::demangler::MicrosoftDemangler>()) {}

	protected:
		std::unique_ptr<retdec::demangler::Demangler> demangler;
};

TEST_F(MicrosoftDemanglerTests, DoNotDemangleCppClassNamesWhenTheyDoNotMatchRegex) {
	DEM_FAIL(" .?AVPolygon@@", status::invalid_mangled_name);
	DEM_FAIL(".?AVPolygon@@ ", status::invalid_mangled_name);
	DEM_FAIL(" .?AVPolygon@@ ", status::invalid_mangled_name);
}

TEST_F(MicrosoftDemanglerTests, RandomTests) {
	DEM_EQ("??D@YAPAXI@Z",
		   "void * __cdecl operator*(unsigned int)");

	DEM_EQ(
		"??1?$map@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_NU?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_N@std@@@2@@std@@QAE@XZ",
		"public: __thiscall std::map<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, bool, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, bool>>>::~map<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, bool, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, bool>>>(void)");

	DEM_EQ("??_DcGram@@UAEPAXI@Z",
		   "public: virtual void * __thiscall cGram::`vbase dtor'(unsigned int)");

	DEM_EQ("??_7type_info@@6B@",
		   "const type_info::`vftable'");

	DEM_EQ("??_R1A@?0A@EA@?$basic_iostream@DU?$char_traits@D@std@@@std@@8",
		   "std::basic_iostream<char, struct std::char_traits<char>>::`RTTI Base Class Descriptor at (0, -1, 0, 64)'");

	DEM_EQ(
		"??1?$_Vector_iterator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@QAE@XZ",
		"public: __thiscall std::_Vector_iterator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, class std::allocator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>>::~_Vector_iterator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, class std::allocator<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>>(void)");

	DEM_EQ(
		"?begin@?$vector@Urule_t@cGram@@V?$allocator@Urule_t@cGram@@@std@@@std@@QAE?AV?$_Vector_iterator@Urule_t@cGram@@V?$allocator@Urule_t@cGram@@@std@@@2@XZ",
		"public: class std::_Vector_iterator<struct cGram::rule_t, class std::allocator<struct cGram::rule_t>> __thiscall std::vector<struct cGram::rule_t, class std::allocator<struct cGram::rule_t>>::begin(void)");

	DEM_EQ(
		"?end@?$_Tree@V?$_Tmap_traits@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$map@DU?$pair@IW4semact@cGram@@@std@@U?$less@D@2@V?$allocator@U?$pair@$$CBDU?$pair@IW4semact@cGram@@@std@@@std@@@2@@2@U?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$map@DU?$pair@IW4semact@cGram@@@std@@U?$less@D@2@V?$allocator@U?$pair@$$CBDU?$pair@IW4semact@cGram@@@std@@@std@@@2@@2@@std@@@2@$0A@@std@@@std@@QAE?AViterator@12@XZ",
		"public: class std::_Tree<class std::_Tmap_traits<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, class std::map<char, struct std::pair<unsigned int, enum cGram::semact>, struct std::less<char>, class std::allocator<struct std::pair<char const, struct std::pair<unsigned int, enum cGram::semact>>>>, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const, class std::map<char, struct std::pair<unsigned int, enum cGram::semact>, struct std::less<char>, class std::allocator<struct std::pair<char const, struct std::pair<unsigned int, enum cGram::semact>>>>>>, 0>>::iterator __thiscall std::_Tree<class std::_Tmap_traits<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, class std::map<char, struct std::pair<unsigned int, enum cGram::semact>, struct std::less<char>, class std::allocator<struct std::pair<char const, struct std::pair<unsigned int, enum cGram::semact>>>>, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const, class std::map<char, struct std::pair<unsigned int, enum cGram::semact>, struct std::less<char>, class std::allocator<struct std::pair<char const, struct std::pair<unsigned int, enum cGram::semact>>>>>>, 0>>::end(void)");

	DEM_EQ(
		"?erase@?$vector@IV?$allocator@I@std@@@std@@QAE?AV?$_Vector_iterator@IV?$allocator@I@std@@@2@V32@0@Z",
		"public: class std::_Vector_iterator<unsigned int, class std::allocator<unsigned int>> __thiscall std::vector<unsigned int, class std::allocator<unsigned int>>::erase(class std::_Vector_iterator<unsigned int, class std::allocator<unsigned int>>, class std::_Vector_iterator<unsigned int, class std::allocator<unsigned int>>)");

	DEM_EQ("??0?$deque@Ugelem_t@cGram@@V?$allocator@Ugelem_t@cGram@@@std@@@std@@QAE@XZ",
		   "public: __thiscall std::deque<struct cGram::gelem_t, class std::allocator<struct cGram::gelem_t>>::deque<struct cGram::gelem_t, class std::allocator<struct cGram::gelem_t>>(void)");

	DEM_EQ(
		"??0iterator@?$_Tree@V?$_Tmap_traits@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@U?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@@std@@@2@$0A@@std@@@std@@QAE@PAU_Node@?$_Tree_nod@V?$_Tmap_traits@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@U?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@@std@@@2@$0A@@std@@@2@PBV12@@Z",
		"public: __thiscall std::_Tree<class std::_Tmap_traits<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t>>, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t>>>>, 0>>::iterator::iterator(struct std::_Tree_nod<class std::_Tmap_traits<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t>>, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t>>>>, 0>>::_Node *, class std::_Tree<class std::_Tmap_traits<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t>>, struct std::less<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>>, class std::allocator<struct std::pair<class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>> const, class std::set<struct cGram::gelem_t, class cGram::comparegelem_c, class std::allocator<struct cGram::gelem_t>>>>, 0>> const *)");

	DEM_EQ(
		"??G?$_Vector_const_iterator@Utype_t@cName@@V?$allocator@Utype_t@cName@@@std@@@std@@QBEHABV01@@Z",
		"public: int __thiscall std::_Vector_const_iterator<struct cName::type_t, class std::allocator<struct cName::type_t>>::operator-(class std::_Vector_const_iterator<struct cName::type_t, class std::allocator<struct cName::type_t>> const &) const");

	DEM_EQ("??_R3bad_alloc@std@@8",
		   "std::bad_alloc::`RTTI Class Hierarchy Descriptor'");
}

TEST_F(MicrosoftDemanglerTests, Basic) {
	DEM_EQ("??D@YAPAXI@Z", "void * __cdecl operator*(unsigned int)");
	DEM_EQ("?x@@3HA", "int x");
	DEM_EQ("?x@@3PEAHEA", "int *x");
	DEM_EQ("?x@@3PEAPEAHEA", "int **x");
	DEM_EQ("?x@@3PEAY02HEA", "int (*x)[3]");
	DEM_EQ("?x@@3PEAY124HEA", "int (*x)[3][5]");
	DEM_EQ("?x@@3PEAY02$$CBHEA", "int const (*x)[3]");
	DEM_EQ("?x@@3PEAEEA", "unsigned char *x");
	DEM_EQ("?x@@3PEAY1NKM@5HEA", "int (*x)[3500][6]");
	DEM_EQ("?x@@YAXMH@Z", "void __cdecl x(float, int)");
	DEM_EQ("?x@@3P6AHMNH@ZEA", "int (__cdecl *x)(float, double, int)");
	DEM_EQ("?x@@3P6AHP6AHM@ZN@ZEA", "int (__cdecl *x)(int (__cdecl *)(float), double)");
	DEM_EQ("?x@@3P6AHP6AHM@Z0@ZEA",
		   "int (__cdecl *x)(int (__cdecl *)(float), int (__cdecl *)(float))");
	DEM_EQ("?x@ns@@3HA", "int ns::x");
	DEM_EQ("?x@@3PEAHEA", "int *x");
	DEM_EQ("?x@@3PEBHEB", "int const *x");
	DEM_EQ("?x@@3QEAHEA", "int *const x");
	DEM_EQ("?x@@3QEBHEB", "int const *const x");
	DEM_EQ("?x@@3AEBHEB", "int const &x");
	DEM_EQ("?x@@3PEAUty@@EA", "struct ty *x");
	DEM_EQ("?x@@3PEATty@@EA", "union ty *x");
	DEM_EQ("?x@@3PEAVty@@EA", "class ty *x");
	DEM_EQ("?x@@3PEAW4ty@@EA", "enum ty *x");
	DEM_EQ("?x@@3PEAV?$tmpl@H@@EA", "class tmpl<int> *x");
	DEM_EQ("?x@@3PEAU?$tmpl@H@@EA", "struct tmpl<int> *x");
	DEM_EQ("?x@@3PEAT?$tmpl@H@@EA", "union tmpl<int> *x");
	DEM_EQ("?instance@@3Vklass@@A", "class klass instance");
	DEM_EQ("?instance$initializer$@@3P6AXXZEA", "void (__cdecl *instance$initializer$)(void)");
	DEM_EQ("??0klass@@QEAA@XZ", "public: __cdecl klass::klass(void)");
	DEM_EQ("??1klass@@QEAA@XZ", "public: __cdecl klass::~klass(void)");
	DEM_EQ("?x@@YAHPEAVklass@@AEAV1@@Z", "int __cdecl x(class klass *, class klass &)");
	DEM_EQ("?x@ns@@3PEAV?$klass@HH@1@EA", "class ns::klass<int, int> *ns::x");
	DEM_EQ("?fn@?$klass@H@ns@@QEBAIXZ", "public: unsigned int __cdecl ns::klass<int>::fn(void) const");
	DEM_EQ("??4klass@@QEAAAEBV0@AEBV0@@Z",
		   "public: class klass const & __cdecl klass::operator=(class klass const &)");
	DEM_EQ("??7klass@@QEAA_NXZ", "public: bool __cdecl klass::operator!(void)");
	DEM_EQ("??8klass@@QEAA_NAEBV0@@Z", "public: bool __cdecl klass::operator==(class klass const &)");
	DEM_EQ("??9klass@@QEAA_NAEBV0@@Z", "public: bool __cdecl klass::operator!=(class klass const &)");
	DEM_EQ("??Aklass@@QEAAH_K@Z", "public: int __cdecl klass::operator[](unsigned __int64)");
	DEM_EQ("??Cklass@@QEAAHXZ", "public: int __cdecl klass::operator->(void)");
	DEM_EQ("??Dklass@@QEAAHXZ", "public: int __cdecl klass::operator*(void)");
	DEM_EQ("??Eklass@@QEAAHXZ", "public: int __cdecl klass::operator++(void)");
	DEM_EQ("??Eklass@@QEAAHH@Z", "public: int __cdecl klass::operator++(int)");
	DEM_EQ("??Fklass@@QEAAHXZ", "public: int __cdecl klass::operator--(void)");
	DEM_EQ("??Fklass@@QEAAHH@Z", "public: int __cdecl klass::operator--(int)");
	DEM_EQ("??Hklass@@QEAAHH@Z", "public: int __cdecl klass::operator+(int)");
	DEM_EQ("??Gklass@@QEAAHH@Z", "public: int __cdecl klass::operator-(int)");
	DEM_EQ("??Iklass@@QEAAHH@Z", "public: int __cdecl klass::operator&(int)");
	DEM_EQ("??Jklass@@QEAAHH@Z", "public: int __cdecl klass::operator->*(int)");
	DEM_EQ("??Kklass@@QEAAHH@Z", "public: int __cdecl klass::operator/(int)");
	DEM_EQ("??Mklass@@QEAAHH@Z", "public: int __cdecl klass::operator<(int)");
	DEM_EQ("??Nklass@@QEAAHH@Z", "public: int __cdecl klass::operator<=(int)");
	DEM_EQ("??Oklass@@QEAAHH@Z", "public: int __cdecl klass::operator>(int)");
	DEM_EQ("??Pklass@@QEAAHH@Z", "public: int __cdecl klass::operator>=(int)");
	DEM_EQ("??Qklass@@QEAAHH@Z", "public: int __cdecl klass::operator,(int)");
	DEM_EQ("??Rklass@@QEAAHH@Z", "public: int __cdecl klass::operator()(int)");
	DEM_EQ("??Sklass@@QEAAHXZ", "public: int __cdecl klass::operator~(void)");
	DEM_EQ("??Tklass@@QEAAHH@Z", "public: int __cdecl klass::operator^(int)");
	DEM_EQ("??Uklass@@QEAAHH@Z", "public: int __cdecl klass::operator|(int)");
	DEM_EQ("??Vklass@@QEAAHH@Z", "public: int __cdecl klass::operator&&(int)");
	DEM_EQ("??Wklass@@QEAAHH@Z", "public: int __cdecl klass::operator||(int)");
	DEM_EQ("??Xklass@@QEAAHH@Z", "public: int __cdecl klass::operator*=(int)");
	DEM_EQ("??Yklass@@QEAAHH@Z", "public: int __cdecl klass::operator+=(int)");
	DEM_EQ("??Zklass@@QEAAHH@Z", "public: int __cdecl klass::operator-=(int)");
	DEM_EQ("??_0klass@@QEAAHH@Z", "public: int __cdecl klass::operator/=(int)");
	DEM_EQ("??_1klass@@QEAAHH@Z", "public: int __cdecl klass::operator%=(int)");
	DEM_EQ("??_2klass@@QEAAHH@Z", "public: int __cdecl klass::operator>>=(int)");
	DEM_EQ("??_3klass@@QEAAHH@Z", "public: int __cdecl klass::operator<<=(int)");
	DEM_EQ("??_6klass@@QEAAHH@Z", "public: int __cdecl klass::operator^=(int)");
	DEM_EQ("??6@YAAEBVklass@@AEBV0@H@Z",
		   "class klass const & __cdecl operator<<(class klass const &, int)");
	DEM_EQ("??5@YAAEBVklass@@AEBV0@_K@Z",
		   "class klass const & __cdecl operator>>(class klass const &, unsigned __int64)");
	DEM_EQ("??2@YAPEAX_KAEAVklass@@@Z",
		   "void * __cdecl operator new(unsigned __int64, class klass &)");
	DEM_EQ("??_U@YAPEAX_KAEAVklass@@@Z",
		   "void * __cdecl operator new[](unsigned __int64, class klass &)");
	DEM_EQ("??3@YAXPEAXAEAVklass@@@Z", "void __cdecl operator delete(void *, class klass &)");
	DEM_EQ("??_V@YAXPEAXAEAVklass@@@Z", "void __cdecl operator delete[](void *, class klass &)");
}

TEST_F(MicrosoftDemanglerTests, ArgQualifiers) {
	DEM_EQ("?foo@@YAXI@Z", "void __cdecl foo(unsigned int)");
	DEM_EQ("?foo@@YAXN@Z  ", "void __cdecl foo(double)");
	DEM_EQ("?foo_pad@@YAXPAD@Z", "void __cdecl foo_pad(char *)");
	DEM_EQ("?foo_pad@@YAXPEAD@Z", "void __cdecl foo_pad(char *)");
	DEM_EQ("?foo_pbd@@YAXPBD@Z", "void __cdecl foo_pbd(char const *)");
	DEM_EQ("?foo_pbd@@YAXPEBD@Z", "void __cdecl foo_pbd(char const *)");
	DEM_EQ("?foo_pcd@@YAXPCD@Z", "void __cdecl foo_pcd(char volatile *)");
	DEM_EQ("?foo_pcd@@YAXPECD@Z", "void __cdecl foo_pcd(char volatile *)");
	DEM_EQ("?foo_qad@@YAXQAD@Z", "void __cdecl foo_qad(char *const)");
	DEM_EQ("?foo_qad@@YAXQEAD@Z", "void __cdecl foo_qad(char *const)");
	DEM_EQ("?foo_rad@@YAXRAD@Z", "void __cdecl foo_rad(char *volatile)");
	DEM_EQ("?foo_rad@@YAXREAD@Z", "void __cdecl foo_rad(char *volatile)");
	DEM_EQ("?foo_sad@@YAXSAD@Z", "void __cdecl foo_sad(char *const volatile)");
	DEM_EQ("?foo_sad@@YAXSEAD@Z", "void __cdecl foo_sad(char *const volatile)");
	DEM_EQ("?foo_piad@@YAXPIAD@Z", "void __cdecl foo_piad(char *__restrict)");
	DEM_EQ("?foo_piad@@YAXPEIAD@Z", "void __cdecl foo_piad(char *__restrict)");
	DEM_EQ("?foo_qiad@@YAXQIAD@Z", "void __cdecl foo_qiad(char *const __restrict)");
	DEM_EQ("?foo_qiad@@YAXQEIAD@Z", "void __cdecl foo_qiad(char *const __restrict)");
	DEM_EQ("?foo_riad@@YAXRIAD@Z", "void __cdecl foo_riad(char *volatile __restrict)");
	DEM_EQ("?foo_riad@@YAXREIAD@Z", "void __cdecl foo_riad(char *volatile __restrict)");
	DEM_EQ("?foo_siad@@YAXSIAD@Z", "void __cdecl foo_siad(char *const volatile __restrict)");
	DEM_EQ("?foo_siad@@YAXSEIAD@Z", "void __cdecl foo_siad(char *const volatile __restrict)");
	DEM_EQ("?foo_papad@@YAXPAPAD@Z", "void __cdecl foo_papad(char **)");
	DEM_EQ("?foo_papad@@YAXPEAPEAD@Z", "void __cdecl foo_papad(char **)");
	DEM_EQ("?foo_papbd@@YAXPAPBD@Z", "void __cdecl foo_papbd(char const **)");
	DEM_EQ("?foo_papbd@@YAXPEAPEBD@Z", "void __cdecl foo_papbd(char const **)");
	DEM_EQ("?foo_papcd@@YAXPAPCD@Z", "void __cdecl foo_papcd(char volatile **)");
	DEM_EQ("?foo_papcd@@YAXPEAPECD@Z", "void __cdecl foo_papcd(char volatile **)");
	DEM_EQ("?foo_pbqad@@YAXPBQAD@Z", "void __cdecl foo_pbqad(char *const *)");
	DEM_EQ("?foo_pbqad@@YAXPEBQEAD@Z", "void __cdecl foo_pbqad(char *const *)");
	DEM_EQ("?foo_pcrad@@YAXPCRAD@Z", "void __cdecl foo_pcrad(char *volatile *)");
	DEM_EQ("?foo_pcrad@@YAXPECREAD@Z", "void __cdecl foo_pcrad(char *volatile *)");
	DEM_EQ("?foo_qapad@@YAXQAPAD@Z", "void __cdecl foo_qapad(char **const)");
	DEM_EQ("?foo_qapad@@YAXQEAPEAD@Z", "void __cdecl foo_qapad(char **const)");
	DEM_EQ("?foo_rapad@@YAXRAPAD@Z", "void __cdecl foo_rapad(char **volatile)");
	DEM_EQ("?foo_rapad@@YAXREAPEAD@Z", "void __cdecl foo_rapad(char **volatile)");
	DEM_EQ("?foo_pbqbd@@YAXPBQBD@Z", "void __cdecl foo_pbqbd(char const *const *)");
	DEM_EQ("?foo_pbqbd@@YAXPEBQEBD@Z", "void __cdecl foo_pbqbd(char const *const *)");
	DEM_EQ("?foo_pbqcd@@YAXPBQCD@Z", "void __cdecl foo_pbqcd(char volatile *const *)");
	DEM_EQ("?foo_pbqcd@@YAXPEBQECD@Z", "void __cdecl foo_pbqcd(char volatile *const *)");
	DEM_EQ("?foo_pcrbd@@YAXPCRBD@Z", "void __cdecl foo_pcrbd(char const *volatile *)");
	DEM_EQ("?foo_pcrbd@@YAXPECREBD@Z", "void __cdecl foo_pcrbd(char const *volatile *)");
	DEM_EQ("?foo_pcrcd@@YAXPCRCD@Z", "void __cdecl foo_pcrcd(char volatile *volatile *)");
	DEM_EQ("?foo_pcrcd@@YAXPECRECD@Z", "void __cdecl foo_pcrcd(char volatile *volatile *)");
	DEM_EQ("?foo_abd@@YAXABD@Z", "void __cdecl foo_abd(char const &)");
	DEM_EQ("?foo_abd@@YAXAEBD@Z", "void __cdecl foo_abd(char const &)");
	DEM_EQ("?foo_aapad@@YAXAAPAD@Z", "void __cdecl foo_aapad(char *&)");
	DEM_EQ("?foo_aapad@@YAXAEAPEAD@Z", "void __cdecl foo_aapad(char *&)");
	DEM_EQ("?foo_aapbd@@YAXAAPBD@Z", "void __cdecl foo_aapbd(char const *&)");
	DEM_EQ("?foo_aapbd@@YAXAEAPEBD@Z", "void __cdecl foo_aapbd(char const *&)");
	DEM_EQ("?foo_abqad@@YAXABQAD@Z", "void __cdecl foo_abqad(char *const &)");
	DEM_EQ("?foo_abqad@@YAXAEBQEAD@Z", "void __cdecl foo_abqad(char *const &)");
	DEM_EQ("?foo_abqbd@@YAXABQBD@Z", "void __cdecl foo_abqbd(char const *const &)");
	DEM_EQ("?foo_abqbd@@YAXAEBQEBD@Z", "void __cdecl foo_abqbd(char const *const &)");
	DEM_EQ("?foo_aay144h@@YAXAAY144H@Z", "void __cdecl foo_aay144h(int (&)[5][5])");
	DEM_EQ("?foo_aay144h@@YAXAEAY144H@Z", "void __cdecl foo_aay144h(int (&)[5][5])");
	DEM_EQ("?foo_aay144cbh@@YAXAAY144$$CBH@Z", "void __cdecl foo_aay144cbh(int const (&)[5][5])");
	DEM_EQ("?foo_aay144cbh@@YAXAEAY144$$CBH@Z", "void __cdecl foo_aay144cbh(int const (&)[5][5])");
	DEM_EQ("?foo_qay144h@@YAX$$QAY144H@Z", "void __cdecl foo_qay144h(int (&&)[5][5])");
	DEM_EQ("?foo_qay144h@@YAX$$QEAY144H@Z", "void __cdecl foo_qay144h(int (&&)[5][5])");
	DEM_EQ("?foo_qay144cbh@@YAX$$QAY144$$CBH@Z",
		   "void __cdecl foo_qay144cbh(int const (&&)[5][5])");
	DEM_EQ("?foo_qay144cbh@@YAX$$QEAY144$$CBH@Z",
		   "void __cdecl foo_qay144cbh(int const (&&)[5][5])");
	DEM_EQ("?foo_p6ahxz@@YAXP6AHXZ@Z", "void __cdecl foo_p6ahxz(int (__cdecl *)(void))");
	DEM_EQ("?foo_p6ahxz@@YAXP6AHXZ@Z", "void __cdecl foo_p6ahxz(int (__cdecl *)(void))");
	DEM_EQ("?foo_a6ahxz@@YAXA6AHXZ@Z", "void __cdecl foo_a6ahxz(int (__cdecl &)(void))");
	DEM_EQ("?foo_a6ahxz@@YAXA6AHXZ@Z", "void __cdecl foo_a6ahxz(int (__cdecl &)(void))");
	DEM_EQ("?foo_q6ahxz@@YAX$$Q6AHXZ@Z", "void __cdecl foo_q6ahxz(int (__cdecl &&)(void))");
	DEM_EQ("?foo_q6ahxz@@YAX$$Q6AHXZ@Z", "void __cdecl foo_q6ahxz(int (__cdecl &&)(void))");
	DEM_EQ("?foo_qay04cbh@@YAXQAY04$$CBH@Z", "void __cdecl foo_qay04cbh(int const (*const)[5])");
	DEM_EQ("?foo_qay04cbh@@YAXQEAY04$$CBH@Z", "void __cdecl foo_qay04cbh(int const (*const)[5])");
	DEM_EQ("?foo@@YAXPAY02N@Z", "void __cdecl foo(double (*)[3])");
	DEM_EQ("?foo@@YAXPEAY02N@Z", "void __cdecl foo(double (*)[3])");
	DEM_EQ("?foo@@YAXQAN@Z", "void __cdecl foo(double *const)");
	DEM_EQ("?foo@@YAXQEAN@Z", "void __cdecl foo(double *const)");
	DEM_EQ("?foo_const@@YAXQBN@Z", "void __cdecl foo_const(double const *const)");
	DEM_EQ("?foo_const@@YAXQEBN@Z", "void __cdecl foo_const(double const *const)");
	DEM_EQ("?foo_volatile@@YAXQCN@Z", "void __cdecl foo_volatile(double volatile *const)");
	DEM_EQ("?foo_volatile@@YAXQECN@Z", "void __cdecl foo_volatile(double volatile *const)");
	DEM_EQ("?foo@@YAXPAY02NQBNN@Z", "void __cdecl foo(double (*)[3], double const *const, double)");
	DEM_EQ("?foo@@YAXPEAY02NQEBNN@Z",
		   "void __cdecl foo(double (*)[3], double const *const, double)");
	DEM_EQ("?foo_fnptrconst@@YAXP6AXQAH@Z@Z",
		   "void __cdecl foo_fnptrconst(void (__cdecl *)(int *const))");
	DEM_EQ("?foo_fnptrconst@@YAXP6AXQEAH@Z@Z",
		   "void __cdecl foo_fnptrconst(void (__cdecl *)(int *const))");
	DEM_EQ("?foo_fnptrarray@@YAXP6AXQAH@Z@Z",
		   "void __cdecl foo_fnptrarray(void (__cdecl *)(int *const))");
	DEM_EQ("?foo_fnptrarray@@YAXP6AXQEAH@Z@Z",
		   "void __cdecl foo_fnptrarray(void (__cdecl *)(int *const))");
	DEM_EQ("?foo_fnptrbackref1@@YAXP6AXQAH@Z1@Z",
		   "void __cdecl foo_fnptrbackref1(void (__cdecl *)(int *const), void (__cdecl *)(int *const))");
	DEM_EQ("?foo_fnptrbackref1@@YAXP6AXQEAH@Z1@Z",
		   "void __cdecl foo_fnptrbackref1(void (__cdecl *)(int *const), void (__cdecl *)(int *const))");
	DEM_EQ("?foo_fnptrbackref2@@YAXP6AXQAH@Z1@Z",
		   "void __cdecl foo_fnptrbackref2(void (__cdecl *)(int *const), void (__cdecl *)(int *const))");
	DEM_EQ("?foo_fnptrbackref2@@YAXP6AXQEAH@Z1@Z",
		   "void __cdecl foo_fnptrbackref2(void (__cdecl *)(int *const), void (__cdecl *)(int *const))");
	DEM_EQ("?foo_fnptrbackref3@@YAXP6AXQAH@Z1@Z",
		   "void __cdecl foo_fnptrbackref3(void (__cdecl *)(int *const), void (__cdecl *)(int *const))");
	DEM_EQ("?foo_fnptrbackref3@@YAXP6AXQEAH@Z1@Z",
		   "void __cdecl foo_fnptrbackref3(void (__cdecl *)(int *const), void (__cdecl *)(int *const))");
	DEM_EQ("?foo_fnptrbackref4@@YAXP6AXPAH@Z1@Z",
		   "void __cdecl foo_fnptrbackref4(void (__cdecl *)(int *), void (__cdecl *)(int *))");
	DEM_EQ("?foo_fnptrbackref4@@YAXP6AXPEAH@Z1@Z",
		   "void __cdecl foo_fnptrbackref4(void (__cdecl *)(int *), void (__cdecl *)(int *))");
	DEM_EQ("?ret_fnptrarray@@YAP6AXQAH@ZXZ",
		   "void (__cdecl * __cdecl ret_fnptrarray(void))(int *const)");
	DEM_EQ("?ret_fnptrarray@@YAP6AXQEAH@ZXZ",
		   "void (__cdecl * __cdecl ret_fnptrarray(void))(int *const)");
	DEM_EQ("?mangle_no_backref0@@YAXQAHPAH@Z",
		   "void __cdecl mangle_no_backref0(int *const, int *)");
	DEM_EQ("?mangle_no_backref0@@YAXQEAHPEAH@Z",
		   "void __cdecl mangle_no_backref0(int *const, int *)");
	DEM_EQ("?mangle_no_backref1@@YAXQAHQAH@Z",
		   "void __cdecl mangle_no_backref1(int *const, int *const)");
	DEM_EQ("?mangle_no_backref1@@YAXQEAHQEAH@Z",
		   "void __cdecl mangle_no_backref1(int *const, int *const)");
	DEM_EQ("?mangle_no_backref2@@YAXP6AXXZP6AXXZ@Z",
		   "void __cdecl mangle_no_backref2(void (__cdecl *)(void), void (__cdecl *)(void))");
	DEM_EQ("?mangle_no_backref2@@YAXP6AXXZP6AXXZ@Z",
		   "void __cdecl mangle_no_backref2(void (__cdecl *)(void), void (__cdecl *)(void))");
	DEM_EQ("?mangle_yes_backref0@@YAXQAH0@Z",
		   "void __cdecl mangle_yes_backref0(int *const, int *const)");
	DEM_EQ("?mangle_yes_backref0@@YAXQEAH0@Z",
		   "void __cdecl mangle_yes_backref0(int *const, int *const)");
	DEM_EQ("?mangle_yes_backref1@@YAXQAH0@Z",
		   "void __cdecl mangle_yes_backref1(int *const, int *const)");
	DEM_EQ("?mangle_yes_backref1@@YAXQEAH0@Z",
		   "void __cdecl mangle_yes_backref1(int *const, int *const)");
	DEM_EQ("?mangle_yes_backref2@@YAXQBQ6AXXZ0@Z",
		   "void __cdecl mangle_yes_backref2(void (__cdecl *const *const)(void), void (__cdecl *const *const)(void))");
	DEM_EQ("?mangle_yes_backref2@@YAXQEBQ6AXXZ0@Z",
		   "void __cdecl mangle_yes_backref2(void (__cdecl *const *const)(void), void (__cdecl *const *const)(void))");
	DEM_EQ("?mangle_yes_backref3@@YAXQAP6AXXZ0@Z",
		   "void __cdecl mangle_yes_backref3(void (__cdecl **const)(void), void (__cdecl **const)(void))");
	DEM_EQ("?mangle_yes_backref3@@YAXQEAP6AXXZ0@Z",
		   "void __cdecl mangle_yes_backref3(void (__cdecl **const)(void), void (__cdecl **const)(void))");
	DEM_EQ("?mangle_yes_backref4@@YAXQIAH0@Z",
		   "void __cdecl mangle_yes_backref4(int *const __restrict, int *const __restrict)");
	DEM_EQ("?mangle_yes_backref4@@YAXQEIAH0@Z",
		   "void __cdecl mangle_yes_backref4(int *const __restrict, int *const __restrict)");
	DEM_EQ("?pr23325@@YAXQBUS@@0@Z",
		   "void __cdecl pr23325(struct S const *const, struct S const *const)");
	DEM_EQ("?pr23325@@YAXQEBUS@@0@Z",
		   "void __cdecl pr23325(struct S const *const, struct S const *const)");
}

TEST_F(MicrosoftDemanglerTests, BackReferences) {
	DEM_EQ("?f1@@YAXPBD0@Z", "void __cdecl f1(char const *, char const *)");
	DEM_EQ("?f2@@YAXPBDPAD@Z", "void __cdecl f2(char const *, char *)");
	DEM_EQ("?f3@@YAXHPBD0@Z", "void __cdecl f3(int, char const *, char const *)");
	DEM_EQ("?f4@@YAPBDPBD0@Z", "char const * __cdecl f4(char const *, char const *)");
	DEM_EQ("?f5@@YAXPBDIDPBX0I@Z",
		   "void __cdecl f5(char const *, unsigned int, char, void const *, char const *, unsigned int)");
	DEM_EQ("?f6@@YAX_N0@Z", "void __cdecl f6(bool, bool)");
	DEM_EQ("?f7@@YAXHPAHH0_N1PA_N@Z",
		   "void __cdecl f7(int, int *, int, int *, bool, bool, bool *)");
	DEM_EQ("?g1@@YAXUS@@@Z", "void __cdecl g1(struct S)");
	DEM_EQ("?g2@@YAXUS@@0@Z", "void __cdecl g2(struct S, struct S)");
	DEM_EQ("?g3@@YAXUS@@0PAU1@1@Z", "void __cdecl g3(struct S, struct S, struct S *, struct S *)");
	DEM_EQ("?g4@@YAXPBDPAUS@@01@Z",
		   "void __cdecl g4(char const *, struct S *, char const *, struct S *)");
	DEM_EQ("?mbb@S@@QAEX_N0@Z", "public: void __thiscall S::mbb(bool, bool)");
	DEM_EQ("?h1@@YAXPBD0P6AXXZ1@Z",
		   "void __cdecl h1(char const *, char const *, void (__cdecl *)(void), void (__cdecl *)(void))");
	DEM_EQ("?h2@@YAXP6AXPAX@Z0@Z", "void __cdecl h2(void (__cdecl *)(void *), void *)");
	DEM_EQ("?h3@@YAP6APAHPAH0@ZP6APAH00@Z10@Z",
		   "int * (__cdecl * __cdecl h3(int * (__cdecl *)(int *, int *), int * (__cdecl *)(int *, int *), int *))(int *, int *)");
	DEM_EQ("?foo@0@YAXXZ", "void __cdecl foo::foo(void)");
	DEM_EQ("??$?HH@S@@QEAAAEAU0@H@Z", "public: struct S & __cdecl S::operator+<int>(int)");
	DEM_EQ("?foo_abbb@@YAXV?$A@V?$B@D@@V1@V1@@@@Z",
		   "void __cdecl foo_abbb(class A<class B<char>, class B<char>, class B<char>>)");
	DEM_EQ("?foo_abb@@YAXV?$A@DV?$B@D@@V1@@@@Z",
		   "void __cdecl foo_abb(class A<char, class B<char>, class B<char>>)");
	DEM_EQ("?foo_abc@@YAXV?$A@DV?$B@D@@V?$C@D@@@@@Z",
		   "void __cdecl foo_abc(class A<char, class B<char>, class C<char>>)");
	DEM_EQ("?foo_bt@@YAX_NV?$B@$$A6A_N_N@Z@@@Z",
		   "void __cdecl foo_bt(bool, class B<bool __cdecl(bool)>)");
	DEM_EQ("?foo_abbb@@YAXV?$A@V?$B@D@N@@V12@V12@@N@@@Z",
		   "void __cdecl foo_abbb(class N::A<class N::B<char>, class N::B<char>, class N::B<char>>)");
	DEM_EQ("?foo_abb@@YAXV?$A@DV?$B@D@N@@V12@@N@@@Z",
		   "void __cdecl foo_abb(class N::A<char, class N::B<char>, class N::B<char>>)");
	DEM_EQ("?foo_abc@@YAXV?$A@DV?$B@D@N@@V?$C@D@2@@N@@@Z",
		   "void __cdecl foo_abc(class N::A<char, class N::B<char>, class N::C<char>>)");
	DEM_EQ("?abc_foo@@YA?AV?$A@DV?$B@D@N@@V?$C@D@2@@N@@XZ",
		   "class N::A<char, class N::B<char>, class N::C<char>> __cdecl abc_foo(void)");
	DEM_EQ("?z_foo@@YA?AVZ@N@@V12@@Z", "class N::Z __cdecl z_foo(class N::Z)");
	DEM_EQ("?b_foo@@YA?AV?$B@D@N@@V12@@Z", "class N::B<char> __cdecl b_foo(class N::B<char>)");
	DEM_EQ("?d_foo@@YA?AV?$D@DD@N@@V12@@Z",
		   "class N::D<char, char> __cdecl d_foo(class N::D<char, char>)");
	DEM_EQ("?abc_foo_abc@@YA?AV?$A@DV?$B@D@N@@V?$C@D@2@@N@@V12@@Z",
		   "class N::A<char, class N::B<char>, class N::C<char>> __cdecl abc_foo_abc(class N::A<char, class N::B<char>, class N::C<char>>)");
	DEM_EQ("?foo5@@YAXV?$Y@V?$Y@V?$Y@V?$Y@VX@NA@@@NB@@@NA@@@NB@@@NA@@@Z",
		   "void __cdecl foo5(class NA::Y<class NB::Y<class NA::Y<class NB::Y<class NA::X>>>>)");
	DEM_EQ("?foo11@@YAXV?$Y@VX@NA@@@NA@@V1NB@@@Z",
		   "void __cdecl foo11(class NA::Y<class NA::X>, class NB::Y<class NA::X>)");
	DEM_EQ("?foo112@@YAXV?$Y@VX@NA@@@NA@@V?$Y@VX@NB@@@NB@@@Z",
		   "void __cdecl foo112(class NA::Y<class NA::X>, class NB::Y<class NB::X>)");
	DEM_EQ("?foo22@@YAXV?$Y@V?$Y@VX@NA@@@NB@@@NA@@V?$Y@V?$Y@VX@NA@@@NA@@@NB@@@Z",
		   "void __cdecl foo22(class NA::Y<class NB::Y<class NA::X>>, class NB::Y<class NA::Y<class NA::X>>)");
	DEM_EQ("?foo@L@PR13207@@QAEXV?$I@VA@PR13207@@@2@@Z",
		   "public: void __thiscall PR13207::L::foo(class PR13207::I<class PR13207::A>)");
	DEM_EQ("?foo@PR13207@@YAXV?$I@VA@PR13207@@@1@@Z",
		   "void __cdecl PR13207::foo(class PR13207::I<class PR13207::A>)");
	DEM_EQ("?foo2@PR13207@@YAXV?$I@VA@PR13207@@@1@0@Z",
		   "void __cdecl PR13207::foo2(class PR13207::I<class PR13207::A>, class PR13207::I<class PR13207::A>)");
	DEM_EQ("?bar@PR13207@@YAXV?$J@VA@PR13207@@VB@2@@1@@Z",
		   "void __cdecl PR13207::bar(class PR13207::J<class PR13207::A, class PR13207::B>)");
	DEM_EQ("?spam@PR13207@@YAXV?$K@VA@PR13207@@VB@2@VC@2@@1@@Z",
		   "void __cdecl PR13207::spam(class PR13207::K<class PR13207::A, class PR13207::B, class PR13207::C>)");
	DEM_EQ("?baz@PR13207@@YAXV?$K@DV?$F@D@PR13207@@V?$I@D@2@@1@@Z",
		   "void __cdecl PR13207::baz(class PR13207::K<char, class PR13207::F<char>, class PR13207::I<char>>)");
	DEM_EQ("?qux@PR13207@@YAXV?$K@DV?$I@D@PR13207@@V12@@1@@Z",
		   "void __cdecl PR13207::qux(class PR13207::K<char, class PR13207::I<char>, class PR13207::I<char>>)");
	DEM_EQ("?foo@NA@PR13207@@YAXV?$Y@VX@NA@PR13207@@@12@@Z",
		   "void __cdecl PR13207::NA::foo(class PR13207::NA::Y<class PR13207::NA::X>)");
	DEM_EQ("?foofoo@NA@PR13207@@YAXV?$Y@V?$Y@VX@NA@PR13207@@@NA@PR13207@@@12@@Z",
		   "void __cdecl PR13207::NA::foofoo(class PR13207::NA::Y<class PR13207::NA::Y<class PR13207::NA::X>>)");
	DEM_EQ("?foo@NB@PR13207@@YAXV?$Y@VX@NA@PR13207@@@12@@Z",
		   "void __cdecl PR13207::NB::foo(class PR13207::NB::Y<class PR13207::NA::X>)");
	DEM_EQ("?bar@NB@PR13207@@YAXV?$Y@VX@NB@PR13207@@@NA@2@@Z",
		   "void __cdecl PR13207::NB::bar(class PR13207::NA::Y<class PR13207::NB::X>)");
	DEM_EQ("?spam@NB@PR13207@@YAXV?$Y@VX@NA@PR13207@@@NA@2@@Z",
		   "void __cdecl PR13207::NB::spam(class PR13207::NA::Y<class PR13207::NA::X>)");
	DEM_EQ("?foobar@NB@PR13207@@YAXV?$Y@V?$Y@VX@NB@PR13207@@@NB@PR13207@@@NA@2@V312@@Z",
		   "void __cdecl PR13207::NB::foobar(class PR13207::NA::Y<class PR13207::NB::Y<class PR13207::NB::X>>, class PR13207::NB::Y<class PR13207::NB::Y<class PR13207::NB::X>>)");
	DEM_EQ(
		"?foobarspam@NB@PR13207@@YAXV?$Y@VX@NB@PR13207@@@12@V?$Y@V?$Y@VX@NB@PR13207@@@NB@PR13207@@@NA@2@V412@@Z",
		"void __cdecl PR13207::NB::foobarspam(class PR13207::NB::Y<class PR13207::NB::X>, class PR13207::NA::Y<class PR13207::NB::Y<class PR13207::NB::X>>, class PR13207::NB::Y<class PR13207::NB::Y<class PR13207::NB::X>>)");
	DEM_EQ(
		"?foobarbaz@NB@PR13207@@YAXV?$Y@VX@NB@PR13207@@@12@V?$Y@V?$Y@VX@NB@PR13207@@@NB@PR13207@@@NA@2@V412@2@Z",
		"void __cdecl PR13207::NB::foobarbaz(class PR13207::NB::Y<class PR13207::NB::X>, class PR13207::NA::Y<class PR13207::NB::Y<class PR13207::NB::X>>, class PR13207::NB::Y<class PR13207::NB::Y<class PR13207::NB::X>>, class PR13207::NB::Y<class PR13207::NB::Y<class PR13207::NB::X>>)");
	DEM_EQ(
		"?foobarbazqux@NB@PR13207@@YAXV?$Y@VX@NB@PR13207@@@12@V?$Y@V?$Y@VX@NB@PR13207@@@NB@PR13207@@@NA@2@V412@2V?$Y@V?$Y@V?$Y@VX@NB@PR13207@@@NB@PR13207@@@NB@PR13207@@@52@@Z",
		"void __cdecl PR13207::NB::foobarbazqux(class PR13207::NB::Y<class PR13207::NB::X>, class PR13207::NA::Y<class PR13207::NB::Y<class PR13207::NB::X>>, class PR13207::NB::Y<class PR13207::NB::Y<class PR13207::NB::X>>, class PR13207::NB::Y<class PR13207::NB::Y<class PR13207::NB::X>>, class PR13207::NA::Y<class PR13207::NB::Y<class PR13207::NB::Y<class PR13207::NB::X>>>)");
	DEM_EQ("?foo@NC@PR13207@@YAXV?$Y@VX@NB@PR13207@@@12@@Z",
		   "void __cdecl PR13207::NC::foo(class PR13207::NC::Y<class PR13207::NB::X>)");
	DEM_EQ("?foobar@NC@PR13207@@YAXV?$Y@V?$Y@V?$Y@VX@NA@PR13207@@@NA@PR13207@@@NB@PR13207@@@12@@Z",
		   "void __cdecl PR13207::NC::foobar(class PR13207::NC::Y<class PR13207::NB::Y<class PR13207::NA::Y<class PR13207::NA::X>>>)");
	DEM_EQ("?fun_normal@fn_space@@YA?AURetVal@1@H@Z",
		   "struct fn_space::RetVal __cdecl fn_space::fun_normal(int)");
	DEM_EQ("??$fun_tmpl@H@fn_space@@YA?AURetVal@0@ABH@Z",
		   "struct fn_space::RetVal __cdecl fn_space::fun_tmpl<int>(int const &)");
	DEM_EQ(
		"??$fun_tmpl_recurse@H$1??$fun_tmpl_recurse@H$1?ident@fn_space@@YA?AURetVal@2@H@Z@fn_space@@YA?AURetVal@1@H@Z@fn_space@@YA?AURetVal@0@H@Z",
		"struct fn_space::RetVal __cdecl fn_space::fun_tmpl_recurse<int, &struct fn_space::RetVal __cdecl fn_space::fun_tmpl_recurse<int, &struct fn_space::RetVal __cdecl fn_space::ident(int)>(int)>(int)");
	DEM_EQ("??$fun_tmpl_recurse@H$1?ident@fn_space@@YA?AURetVal@2@H@Z@fn_space@@YA?AURetVal@0@H@Z",
		   "struct fn_space::RetVal __cdecl fn_space::fun_tmpl_recurse<int, &struct fn_space::RetVal __cdecl fn_space::ident(int)>(int)");
	DEM_EQ(
		"?AddEmitPasses@EmitAssemblyHelper@?A0x43583946@@AEAA_NAEAVPassManager@legacy@llvm@@W4BackendAction@clang@@AEAVraw_pwrite_stream@5@PEAV85@@Z",
		"private: bool __cdecl `anonymous namespace'::EmitAssemblyHelper::AddEmitPasses(class llvm::legacy::PassManager &, enum clang::BackendAction, class llvm::raw_pwrite_stream &, class llvm::raw_pwrite_stream *)");
	DEM_EQ(
		"??$forward@P8?$DecoderStream@$01@media@@AEXXZ@std@@YA$$QAP8?$DecoderStream@$01@media@@AEXXZAAP812@AEXXZ@Z",
		"void (__thiscall media::DecoderStream<2>::*&& __cdecl std::forward<void (__thiscall media::DecoderStream<2>::*)(void)>(void (__thiscall media::DecoderStream<2>::*&)(void)))(void)");
}

TEST_F(MicrosoftDemanglerTests, ConversionOperators) {
	DEM_EQ("??$?BH@TemplateOps@@QAEHXZ", "public: int __thiscall TemplateOps::operator<int> int(void)");
	DEM_EQ("??BOps@@QAEHXZ", "public: int __thiscall Ops::operator int(void)");
	DEM_EQ("??BConstOps@@QAE?BHXZ", "public: int const __thiscall ConstOps::operator int const(void)");
	DEM_EQ("??BVolatileOps@@QAE?CHXZ",
		   "public: int volatile __thiscall VolatileOps::operator int volatile(void)");
	DEM_EQ("??BConstVolatileOps@@QAE?DHXZ",
		   "public: int const volatile __thiscall ConstVolatileOps::operator int const volatile(void)");
	DEM_EQ("??$?BN@TemplateOps@@QAENXZ",
		   "public: double __thiscall TemplateOps::operator<double> double(void)");
	DEM_EQ("??BOps@@QAENXZ", "public: double __thiscall Ops::operator double(void)");
	DEM_EQ("??BConstOps@@QAE?BNXZ",
		   "public: double const __thiscall ConstOps::operator double const(void)");
	DEM_EQ("??BVolatileOps@@QAE?CNXZ",
		   "public: double volatile __thiscall VolatileOps::operator double volatile(void)");
	DEM_EQ("??BConstVolatileOps@@QAE?DNXZ",
		   "public: double const volatile __thiscall ConstVolatileOps::operator double const volatile(void)");
	DEM_EQ("??BCompoundTypeOps@@QAEPAHXZ", "public: int * __thiscall CompoundTypeOps::operator int *(void)");
	DEM_EQ("??BCompoundTypeOps@@QAEPBHXZ",
		   "public: int const * __thiscall CompoundTypeOps::operator int const *(void)");
	DEM_EQ("??BCompoundTypeOps@@QAE$$QAHXZ",
		   "public: int && __thiscall CompoundTypeOps::operator int &&(void)");
	DEM_EQ("??BCompoundTypeOps@@QAE?AU?$Foo@H@@XZ",
		   "public: struct Foo<int> __thiscall CompoundTypeOps::operator struct Foo<int>(void)");
	DEM_EQ("??$?BH@CompoundTypeOps@@QAE?AU?$Bar@U?$Foo@H@@@@XZ",
		   "public: struct Bar<struct Foo<int>> __thiscall CompoundTypeOps::operator<int> struct Bar<struct Foo<int>>(void)");
	DEM_EQ("??$?BPAH@TemplateOps@@QAEPAHXZ",
		   "public: int * __thiscall TemplateOps::operator<int *> int *(void)");
}

TEST_F(MicrosoftDemanglerTests, cxx11) {
	DEM_EQ("?a@FTypeWithQuals@@3U?$S@$$A8@@BAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) const> FTypeWithQuals::a");
	DEM_EQ("?b@FTypeWithQuals@@3U?$S@$$A8@@CAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) volatile> FTypeWithQuals::b");
	DEM_EQ("?c@FTypeWithQuals@@3U?$S@$$A8@@IAAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) __restrict> FTypeWithQuals::c");
	DEM_EQ("?d@FTypeWithQuals@@3U?$S@$$A8@@GBAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) const &> FTypeWithQuals::d");
	DEM_EQ("?e@FTypeWithQuals@@3U?$S@$$A8@@GCAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) volatile &> FTypeWithQuals::e");
	DEM_EQ("?f@FTypeWithQuals@@3U?$S@$$A8@@IGAAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) __restrict &> FTypeWithQuals::f");
	DEM_EQ("?g@FTypeWithQuals@@3U?$S@$$A8@@HBAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) const &&> FTypeWithQuals::g");
	DEM_EQ("?h@FTypeWithQuals@@3U?$S@$$A8@@HCAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) volatile &&> FTypeWithQuals::h");
	DEM_EQ("?i@FTypeWithQuals@@3U?$S@$$A8@@IHAAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) __restrict &&> FTypeWithQuals::i");
	DEM_EQ("?j@FTypeWithQuals@@3U?$S@$$A6AHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void)> FTypeWithQuals::j");
	DEM_EQ("?k@FTypeWithQuals@@3U?$S@$$A8@@GAAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) &> FTypeWithQuals::k");
	DEM_EQ("?l@FTypeWithQuals@@3U?$S@$$A8@@HAAHXZ@1@A",
		   "struct FTypeWithQuals::S<int __cdecl(void) &&> FTypeWithQuals::l");
	DEM_EQ("?Char16Var@@3_SA", "char16_t Char16Var");
	DEM_EQ("?Char32Var@@3_UA", "char32_t Char32Var");
	DEM_EQ("?LRef@@YAXAAH@Z", "void __cdecl LRef(int &)");
	DEM_EQ("?RRef@@YAH$$QAH@Z", "int __cdecl RRef(int &&)");
	DEM_EQ("?Null@@YAX$$T@Z", "void __cdecl Null(std::nullptr_t)");
	DEM_EQ("?fun@PR18022@@YA?AU<unnamed-type-a>@1@U21@0@Z",
		   "struct PR18022::<unnamed-type-a> __cdecl PR18022::fun(struct PR18022::<unnamed-type-a>, struct PR18022::<unnamed-type-a>)");
	DEM_EQ("?lambda@?1??define_lambda@@YAHXZ@4V<lambda_1>@?0??1@YAHXZ@A",
		   "class `int __cdecl define_lambda(void)'::`1'::<lambda_1> `int __cdecl define_lambda(void)'::`2'::lambda");
	DEM_EQ("??R<lambda_1>@?0??define_lambda@@YAHXZ@QBE@XZ",
		   "public: __thiscall `int __cdecl define_lambda(void)'::`1'::<lambda_1>::operator()(void) const");
	DEM_EQ("?local@?2???R<lambda_1>@?0??define_lambda@@YAHXZ@QBE@XZ@4HA",
		   "int `public: __thiscall `int __cdecl define_lambda(void)'::`1'::<lambda_1>::operator()(void) const'::`3'::local");
	DEM_EQ(
		"??$use_lambda_arg@V<lambda_1>@?0??call_with_lambda_arg1@@YAXXZ@@@YAXV<lambda_1>@?0??call_with_lambda_arg1@@YAXXZ@@Z",
		"void __cdecl use_lambda_arg<class `void __cdecl call_with_lambda_arg1(void)'::`1'::<lambda_1>>(class `void __cdecl call_with_lambda_arg1(void)'::`1'::<lambda_1>)");
	DEM_EQ("?foo@A@PR19361@@QIGAEXXZ", "public: void __thiscall PR19361::A::foo(void) __restrict &");
	DEM_EQ("?foo@A@PR19361@@QIHAEXXZ", "public: void __thiscall PR19361::A::foo(void) __restrict &&");
	DEM_EQ("??__K_deg@@YAHO@Z", "int __cdecl operator \"\"_deg(long double)");
	DEM_EQ("??$templ_fun_with_pack@$S@@YAXXZ", "void __cdecl templ_fun_with_pack<>(void)");
	DEM_EQ("??$func@H$$ZH@@YAHAEBU?$Foo@H@@0@Z",
		   "int __cdecl func<int, int>(struct Foo<int> const &, struct Foo<int> const &)");
	DEM_EQ("??$templ_fun_with_ty_pack@$$$V@@YAXXZ", "void __cdecl templ_fun_with_ty_pack<>(void)");
	DEM_EQ("??$templ_fun_with_ty_pack@$$V@@YAXXZ", "void __cdecl templ_fun_with_ty_pack<>(void)");
	DEM_EQ("??$f@$$YAliasA@PR20047@@@PR20047@@YAXXZ",
		   "void __cdecl PR20047::f<PR20047::AliasA>(void)");
	DEM_EQ("?f@UnnamedType@@YAXAAU<unnamed-type-TD>@A@1@@Z",
		   "void __cdecl UnnamedType::f(struct UnnamedType::A::<unnamed-type-TD> &)");
	DEM_EQ("?f@UnnamedType@@YAXPAW4<unnamed-type-e>@?$B@H@1@@Z",
		   "void __cdecl UnnamedType::f(enum UnnamedType::B<int>::<unnamed-type-e> *)");
	DEM_EQ(
		"??$f@W4<unnamed-type-E>@?1??g@PR24651@@YAXXZ@@PR24651@@YAXW4<unnamed-type-E>@?1??g@0@YAXXZ@@Z",
		"void __cdecl PR24651::f<enum `void __cdecl PR24651::g(void)'::`2'::<unnamed-type-E>>(enum `void __cdecl PR24651::g(void)'::`2'::<unnamed-type-E>)");
	DEM_EQ("??$f@T<unnamed-type-$S1>@PR18204@@@PR18204@@YAHPAT<unnamed-type-$S1>@0@@Z",
		   "int __cdecl PR18204::f<union PR18204::<unnamed-type-$S1>>(union PR18204::<unnamed-type-$S1> *)");
	DEM_EQ("??R<lambda_0>@?0??PR26105@@YAHXZ@QBE@H@Z",
		   "public: __thiscall `int __cdecl PR26105(void)'::`1'::<lambda_0>::operator()(int) const");
	DEM_EQ("??R<lambda_1>@?0???R<lambda_0>@?0??PR26105@@YAHXZ@QBE@H@Z@QBE@H@Z",
		   "public: __thiscall `public: __thiscall `int __cdecl PR26105(void)'::`1'::<lambda_0>::operator()(int) const'::`1'::<lambda_1>::operator()(int) const");
	DEM_EQ("?unaligned_foo1@@YAPFAHXZ", "int __unaligned * __cdecl unaligned_foo1(void)");
	DEM_EQ("?unaligned_foo2@@YAPFAPFAHXZ",
		   "int __unaligned *__unaligned * __cdecl unaligned_foo2(void)");
	DEM_EQ("?unaligned_foo3@@YAHXZ", "int __cdecl unaligned_foo3(void)");
	DEM_EQ("?unaligned_foo4@@YAXPFAH@Z", "void __cdecl unaligned_foo4(int __unaligned *)");
	DEM_EQ("?unaligned_foo5@@YAXPIFAH@Z",
		   "void __cdecl unaligned_foo5(int __unaligned *__restrict)");
	DEM_EQ("??$unaligned_foo6@PAH@@YAPAHPAH@Z", "int * __cdecl unaligned_foo6<int *>(int *)");
	DEM_EQ("??$unaligned_foo6@PFAH@@YAPFAHPFAH@Z",
		   "int __unaligned * __cdecl unaligned_foo6<int __unaligned *>(int __unaligned *)");
	DEM_EQ("?unaligned_foo8@unaligned_foo8_S@@QFCEXXZ",
		   "public: void __thiscall unaligned_foo8_S::unaligned_foo8(void) volatile __unaligned");
	DEM_EQ("??R<lambda_1>@x@A@PR31197@@QBE@XZ",
		   "public: __thiscall PR31197::A::x::<lambda_1>::operator()(void) const");
	DEM_EQ("?white@?1???R<lambda_1>@x@A@PR31197@@QBE@XZ@4HA",
		   "int `public: __thiscall PR31197::A::x::<lambda_1>::operator()(void) const'::`2'::white");
	DEM_EQ("?f@@YAXW4<unnamed-enum-enumerator>@@@Z",
		   "void __cdecl f(enum <unnamed-enum-enumerator>)");
}

TEST_F(MicrosoftDemanglerTests, Cxx14) {
	DEM_EQ("??$x@X@@3HA", "int x<void>");
	DEM_EQ("?FunctionWithLocalType@@YA?A?<auto>@@XZ", "<auto> __cdecl FunctionWithLocalType(void)");
	DEM_EQ(
		"?ValueFromFunctionWithLocalType@@3ULocalType@?1??FunctionWithLocalType@@YA?A?<auto>@@XZ@A",
		"struct `<auto> __cdecl FunctionWithLocalType(void)'::`2'::LocalType ValueFromFunctionWithLocalType");
	DEM_EQ("??R<lambda_0>@@QBE?A?<auto>@@XZ",
		   "public: <auto> __thiscall <lambda_0>::operator()(void) const");
	DEM_EQ("?ValueFromLambdaWithLocalType@@3ULocalType@?1???R<lambda_0>@@QBE?A?<auto>@@XZ@A",
		   "struct `public: <auto> __thiscall <lambda_0>::operator()(void) const'::`2'::LocalType ValueFromLambdaWithLocalType");
	DEM_EQ(
		"?ValueFromTemplateFuncionWithLocalLambda@@3ULocalType@?2???R<lambda_1>@?0???$TemplateFuncionWithLocalLambda@H@@YA?A?<auto>@@H@Z@QBE?A?3@XZ@A",
		"struct `public: <auto> __thiscall `<auto> __cdecl TemplateFuncionWithLocalLambda<int>(int)'::`1'::<lambda_1>::operator()(void) const'::`3'::LocalType ValueFromTemplateFuncionWithLocalLambda");
	DEM_EQ("??$TemplateFuncionWithLocalLambda@H@@YA?A?<auto>@@H@Z",
		   "<auto> __cdecl TemplateFuncionWithLocalLambda<int>(int)");
	DEM_EQ("??R<lambda_1>@?0???$TemplateFuncionWithLocalLambda@H@@YA?A?<auto>@@H@Z@QBE?A?1@XZ",
		   "public: <auto> __thiscall `<auto> __cdecl TemplateFuncionWithLocalLambda<int>(int)'::`1'::<lambda_1>::operator()(void) const");
	DEM_EQ("??$WithPMD@$GA@A@?0@@3HA", "int WithPMD<{0, 0, -1}>");
	DEM_EQ("?Zoo@@3U?$Foo@$1??$x@H@@3HA$1?1@3HA@@A", "struct Foo<&int x<int>, &int x<int>> Zoo");
	DEM_EQ("??$unaligned_x@PFAH@@3PFAHA", "int __unaligned *unaligned_x<int __unaligned *>");
}

TEST_F(MicrosoftDemanglerTests, Cxx17NoExcept) {
	DEM_EQ("?nochange@@YAXXZ", "void __cdecl nochange(void)");
	DEM_EQ("?a@@YAXP6AHXZ@Z", "void __cdecl a(int (__cdecl *)(void))");
	DEM_EQ("?a@@YAXP6AHX_E@Z", "void __cdecl a(int (__cdecl *)(void) noexcept)");
	DEM_EQ("?b@@YAXP6AHXZ@Z", "void __cdecl b(int (__cdecl *)(void))");
	DEM_EQ("?c@@YAXP6AHXZ@Z", "void __cdecl c(int (__cdecl *)(void))");
	DEM_EQ("?c@@YAXP6AHX_E@Z", "void __cdecl c(int (__cdecl *)(void) noexcept)");
	DEM_EQ("?ee@?$e@$$A6AXXZ@@EEAAXXZ",
		   "private: virtual void __cdecl e<void __cdecl(void)>::ee(void)");
	DEM_EQ("?ee@?$e@$$A6AXX_E@@EEAAXXZ",
		   "private: virtual void __cdecl e<void __cdecl(void) noexcept>::ee(void)");
}

TEST_F(MicrosoftDemanglerTests, msmangle) {
	DEM_EQ("?a@@3HA", "int a");
	DEM_EQ("?b@N@@3HA", "int N::b");
	DEM_EQ("?anonymous@?A@N@@3HA", "int N::`anonymous namespace'::anonymous");
	DEM_EQ("?$RT1@NeedsReferenceTemporary@@3ABHB", "int const &NeedsReferenceTemporary::$RT1");
	DEM_EQ("?$RT1@NeedsReferenceTemporary@@3AEBHEB", "int const &NeedsReferenceTemporary::$RT1");
	DEM_EQ("?_c@@YAHXZ", "int __cdecl _c(void)");
	DEM_EQ("?d@foo@@0FB", "private: static short const foo::d");
	DEM_EQ("?e@foo@@1JC", "protected: static long volatile foo::e");
	DEM_EQ("?f@foo@@2DD", "public: static char const volatile foo::f");
	DEM_EQ("??0foo@@QAE@XZ", "public: __thiscall foo::foo(void)");
	DEM_EQ("??0foo@@QEAA@XZ", "public: __cdecl foo::foo(void)");
	DEM_EQ("??1foo@@QAE@XZ", "public: __thiscall foo::~foo(void)");
	DEM_EQ("??1foo@@QEAA@XZ", "public: __cdecl foo::~foo(void)");
	DEM_EQ("??0foo@@QAE@H@Z", "public: __thiscall foo::foo(int)");
	DEM_EQ("??0foo@@QEAA@H@Z", "public: __cdecl foo::foo(int)");
	DEM_EQ("??0foo@@QAE@PAD@Z", "public: __thiscall foo::foo(char *)");
	DEM_EQ("??0foo@@QEAA@PEAD@Z", "public: __cdecl foo::foo(char *)");
	DEM_EQ("?bar@@YA?AVfoo@@XZ", "class foo __cdecl bar(void)");
	DEM_EQ("?bar@@YA?AVfoo@@XZ", "class foo __cdecl bar(void)");
	DEM_EQ("??Hfoo@@QAEHH@Z", "public: int __thiscall foo::operator+(int)");
	DEM_EQ("??Hfoo@@QEAAHH@Z", "public: int __cdecl foo::operator+(int)");
	DEM_EQ("??$?HH@S@@QEAAAEANH@Z", "public: double & __cdecl S::operator+<int>(int)");
	DEM_EQ("?static_method@foo@@SAPAV1@XZ", "public: static class foo * __cdecl foo::static_method(void)");
	DEM_EQ("?static_method@foo@@SAPEAV1@XZ", "public: static class foo * __cdecl foo::static_method(void)");
	DEM_EQ("?g@bar@@2HA", "public: static int bar::g");
	DEM_EQ("?h1@@3QAHA", "int *const h1");
	DEM_EQ("?h2@@3QBHB", "int const *const h2");
	DEM_EQ("?h3@@3QIAHIA", "int *const __restrict h3");
	DEM_EQ("?h3@@3QEIAHEIA", "int *const __restrict h3");
	DEM_EQ("?i@@3PAY0BE@HA", "int (*i)[20]");
	DEM_EQ("?FunArr@@3PAY0BE@P6AHHH@ZA", "int (__cdecl *(*FunArr)[20])(int, int)");
	DEM_EQ("?j@@3P6GHCE@ZA", "int (__stdcall *j)(signed char, unsigned char)");
	DEM_EQ("?funptr@@YAP6AHXZXZ", "int (__cdecl * __cdecl funptr(void))(void)");
	DEM_EQ("?k@@3PTfoo@@DT1@", "char const volatile foo::*k");
	DEM_EQ("?k@@3PETfoo@@DET1@", "char const volatile foo::*k");
	DEM_EQ("?l@@3P8foo@@AEHH@ZQ1@", "int (__thiscall foo::*l)(int)");
	DEM_EQ("?g_cInt@@3HB", "int const g_cInt");
	DEM_EQ("?g_vInt@@3HC", "int volatile g_vInt");
	DEM_EQ("?g_cvInt@@3HD", "int const volatile g_cvInt");
	DEM_EQ("?beta@@YI_N_J_W@Z", "bool __fastcall beta(__int64, wchar_t)");
	DEM_EQ("?beta@@YA_N_J_W@Z", "bool __cdecl beta(__int64, wchar_t)");
	DEM_EQ("?alpha@@YGXMN@Z", "void __stdcall alpha(float, double)");
	DEM_EQ("?alpha@@YAXMN@Z", "void __cdecl alpha(float, double)");
	DEM_EQ("?gamma@@YAXVfoo@@Ubar@@Tbaz@@W4quux@@@Z",
		   "void __cdecl gamma(class foo, struct bar, union baz, enum quux)");
	DEM_EQ("?gamma@@YAXVfoo@@Ubar@@Tbaz@@W4quux@@@Z",
		   "void __cdecl gamma(class foo, struct bar, union baz, enum quux)");
	DEM_EQ("?delta@@YAXQAHABJ@Z", "void __cdecl delta(int *const, long const &)");
	DEM_EQ("?delta@@YAXQEAHAEBJ@Z", "void __cdecl delta(int *const, long const &)");
	DEM_EQ("?epsilon@@YAXQAY19BE@H@Z", "void __cdecl epsilon(int (*const)[10][20])");
	DEM_EQ("?epsilon@@YAXQEAY19BE@H@Z", "void __cdecl epsilon(int (*const)[10][20])");
	DEM_EQ("?zeta@@YAXP6AHHH@Z@Z", "void __cdecl zeta(int (__cdecl *)(int, int))");
	DEM_EQ("?zeta@@YAXP6AHHH@Z@Z", "void __cdecl zeta(int (__cdecl *)(int, int))");
	DEM_EQ("??2@YAPAXI@Z", "void * __cdecl operator new(unsigned int)");
	DEM_EQ("??3@YAXPAX@Z", "void __cdecl operator delete(void *)");
	DEM_EQ("??_U@YAPAXI@Z", "void * __cdecl operator new[](unsigned int)");
	DEM_EQ("??_V@YAXPAX@Z", "void __cdecl operator delete[](void *)");
	DEM_EQ("?color1@@3PANA", "double *color1");
	DEM_EQ("?color2@@3QBNB", "double const *const color2");
	DEM_EQ("?color3@@3QAY02$$CBNA", "double const (*const color3)[3]");
	DEM_EQ("?color4@@3QAY02$$CBNA", "double const (*const color4)[3]");
	DEM_EQ("?memptr1@@3RESB@@HES1@", "int volatile B::*volatile memptr1");
	DEM_EQ("?memptr2@@3PESB@@HES1@", "int volatile B::*memptr2");
	DEM_EQ("?memptr3@@3REQB@@HEQ1@", "int B::*volatile memptr3");
	DEM_EQ("?funmemptr1@@3RESB@@R6AHXZES1@",
		   "int (__cdecl *volatile B::*volatile funmemptr1)(void)");
	DEM_EQ("?funmemptr2@@3PESB@@R6AHXZES1@", "int (__cdecl *volatile B::*funmemptr2)(void)");
	DEM_EQ("?funmemptr3@@3REQB@@P6AHXZEQ1@", "int (__cdecl *B::*volatile funmemptr3)(void)");
	DEM_EQ("?memptrtofun1@@3R8B@@EAAXXZEQ1@", "void (__cdecl B::*volatile memptrtofun1)(void)");
	DEM_EQ("?memptrtofun2@@3P8B@@EAAXXZEQ1@", "void (__cdecl B::*memptrtofun2)(void)");
	DEM_EQ("?memptrtofun3@@3P8B@@EAAXXZEQ1@", "void (__cdecl B::*memptrtofun3)(void)");
	DEM_EQ("?memptrtofun4@@3R8B@@EAAHXZEQ1@", "int (__cdecl B::*volatile memptrtofun4)(void)");
	DEM_EQ("?memptrtofun5@@3P8B@@EAA?CHXZEQ1@", "int volatile (__cdecl B::*memptrtofun5)(void)");
	DEM_EQ("?memptrtofun6@@3P8B@@EAA?BHXZEQ1@", "int const (__cdecl B::*memptrtofun6)(void)");
	DEM_EQ("?memptrtofun7@@3R8B@@EAAP6AHXZXZEQ1@",
		   "int (__cdecl * (__cdecl B::*volatile memptrtofun7)(void))(void)");
	DEM_EQ("?memptrtofun8@@3P8B@@EAAR6AHXZXZEQ1@",
		   "int (__cdecl *volatile (__cdecl B::*memptrtofun8)(void))(void)");
	DEM_EQ("?memptrtofun9@@3P8B@@EAAQ6AHXZXZEQ1@",
		   "int (__cdecl *const (__cdecl B::*memptrtofun9)(void))(void)");
	DEM_EQ("?fooE@@YA?AW4E@@XZ", "enum E __cdecl fooE(void)");
	DEM_EQ("?fooE@@YA?AW4E@@XZ", "enum E __cdecl fooE(void)");
	DEM_EQ("?fooX@@YA?AVX@@XZ", "class X __cdecl fooX(void)");
	DEM_EQ("?fooX@@YA?AVX@@XZ", "class X __cdecl fooX(void)");
	DEM_EQ("?s0@PR13182@@3PADA", "char *PR13182::s0");
	DEM_EQ("?s1@PR13182@@3PADA", "char *PR13182::s1");
	DEM_EQ("?s2@PR13182@@3QBDB", "char const *const PR13182::s2");
	DEM_EQ("?s3@PR13182@@3QBDB", "char const *const PR13182::s3");
	DEM_EQ("?s4@PR13182@@3RCDC", "char volatile *volatile PR13182::s4");
	DEM_EQ("?s5@PR13182@@3SDDD", "char const volatile *const volatile PR13182::s5");
	DEM_EQ("?s6@PR13182@@3PBQBDB", "char const *const *PR13182::s6");
	DEM_EQ("?local@?1??extern_c_func@@9@4HA", "int `extern \"C\" extern_c_func'::`2'::local");
	DEM_EQ("?local@?1??extern_c_func@@9@4HA", "int `extern \"C\" extern_c_func'::`2'::local");
	DEM_EQ("?v@?1??f@@YAHXZ@4U<unnamed-type-v>@?1??1@YAHXZ@A",
		   "struct `int __cdecl f(void)'::`2'::<unnamed-type-v> `int __cdecl f(void)'::`2'::v");
	DEM_EQ("?v@?1???$f@H@@YAHXZ@4U<unnamed-type-v>@?1???$f@H@@YAHXZ@A",
		   "struct `int __cdecl f<int>(void)'::`2'::<unnamed-type-v> `int __cdecl f<int>(void)'::`2'::v");
	DEM_EQ("??2OverloadedNewDelete@@SAPAXI@Z",
		   "public: static void * __cdecl OverloadedNewDelete::operator new(unsigned int)");
	DEM_EQ("??_UOverloadedNewDelete@@SAPAXI@Z",
		   "public: static void * __cdecl OverloadedNewDelete::operator new[](unsigned int)");
	DEM_EQ("??3OverloadedNewDelete@@SAXPAX@Z",
		   "public: static void __cdecl OverloadedNewDelete::operator delete(void *)");
	DEM_EQ("??_VOverloadedNewDelete@@SAXPAX@Z",
		   "public: static void __cdecl OverloadedNewDelete::operator delete[](void *)");
	DEM_EQ("??HOverloadedNewDelete@@QAEHH@Z", "public: int __thiscall OverloadedNewDelete::operator+(int)");
	DEM_EQ("??2OverloadedNewDelete@@SAPEAX_K@Z",
		   "public: static void * __cdecl OverloadedNewDelete::operator new(unsigned __int64)");
	DEM_EQ("??_UOverloadedNewDelete@@SAPEAX_K@Z",
		   "public: static void * __cdecl OverloadedNewDelete::operator new[](unsigned __int64)");
	DEM_EQ("??3OverloadedNewDelete@@SAXPEAX@Z",
		   "public: static void __cdecl OverloadedNewDelete::operator delete(void *)");
	DEM_EQ("??_VOverloadedNewDelete@@SAXPEAX@Z",
		   "public: static void __cdecl OverloadedNewDelete::operator delete[](void *)");
	DEM_EQ("??HOverloadedNewDelete@@QEAAHH@Z", "public: int __cdecl OverloadedNewDelete::operator+(int)");
	DEM_EQ("??2TypedefNewDelete@@SAPAXI@Z",
		   "public: static void * __cdecl TypedefNewDelete::operator new(unsigned int)");
	DEM_EQ("??_UTypedefNewDelete@@SAPAXI@Z",
		   "public: static void * __cdecl TypedefNewDelete::operator new[](unsigned int)");
	DEM_EQ("??3TypedefNewDelete@@SAXPAX@Z",
		   "public: static void __cdecl TypedefNewDelete::operator delete(void *)");
	DEM_EQ("??_VTypedefNewDelete@@SAXPAX@Z",
		   "public: static void __cdecl TypedefNewDelete::operator delete[](void *)");
	DEM_EQ("?vector_func@@YQXXZ", "void __vectorcall vector_func(void)");
	DEM_EQ("??$fn_tmpl@$1?extern_c_func@@YAXXZ@@YAXXZ",
		   "void __cdecl fn_tmpl<&void __cdecl extern_c_func(void)>(void)");
	DEM_EQ("?overloaded_fn@@$$J0YAXXZ", "extern \"C\" void __cdecl overloaded_fn(void)");
	DEM_EQ("?f@UnnamedType@@YAXQAPAU<unnamed-type-T1>@S@1@@Z",
		   "void __cdecl UnnamedType::f(struct UnnamedType::S::<unnamed-type-T1> **const)");
	DEM_EQ("?f@UnnamedType@@YAXUT2@S@1@@Z",
		   "void __cdecl UnnamedType::f(struct UnnamedType::S::T2)");
	DEM_EQ("?f@UnnamedType@@YAXPAUT4@S@1@@Z",
		   "void __cdecl UnnamedType::f(struct UnnamedType::S::T4 *)");
	DEM_EQ("?f@UnnamedType@@YAXUT4@S@1@@Z",
		   "void __cdecl UnnamedType::f(struct UnnamedType::S::T4)");
	DEM_EQ("?f@UnnamedType@@YAXUT5@S@1@@Z",
		   "void __cdecl UnnamedType::f(struct UnnamedType::S::T5)");
	DEM_EQ("?f@UnnamedType@@YAXUT2@S@1@@Z",
		   "void __cdecl UnnamedType::f(struct UnnamedType::S::T2)");
	DEM_EQ("?f@UnnamedType@@YAXUT4@S@1@@Z",
		   "void __cdecl UnnamedType::f(struct UnnamedType::S::T4)");
	DEM_EQ("?f@UnnamedType@@YAXUT5@S@1@@Z",
		   "void __cdecl UnnamedType::f(struct UnnamedType::S::T5)");
	DEM_EQ("?f@Atomic@@YAXU?$_Atomic@H@__clang@@@Z",
		   "void __cdecl Atomic::f(struct __clang::_Atomic<int>)");
	DEM_EQ("?f@Complex@@YAXU?$_Complex@H@__clang@@@Z",
		   "void __cdecl Complex::f(struct __clang::_Complex<int>)");
	DEM_EQ("?f@Float16@@YAXU_Float16@__clang@@@Z",
		   "void __cdecl Float16::f(struct __clang::_Float16)");
	DEM_EQ("??0?$L@H@NS@@QEAA@XZ", "public: __cdecl NS::L<int>::L<int>(void)");
	DEM_EQ("??0Bar@Foo@@QEAA@XZ", "public: __cdecl Foo::Bar::Bar(void)");
	DEM_EQ("??0?$L@V?$H@PAH@PR26029@@@PR26029@@QAE@XZ",
		   "public: __thiscall PR26029::L<class PR26029::H<int *>>::L<class PR26029::H<int *>>(void)");
}

TEST_F(MicrosoftDemanglerTests, msnestedscopes) {
	DEM_EQ("?M@?@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`0'::M");
	DEM_EQ("?M@?0??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`1'::M");
	DEM_EQ("?M@?1??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`2'::M");
	DEM_EQ("?M@?2??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`3'::M");
	DEM_EQ("?M@?3??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`4'::M");
	DEM_EQ("?M@?4??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`5'::M");
	DEM_EQ("?M@?5??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`6'::M");
	DEM_EQ("?M@?6??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`7'::M");
	DEM_EQ("?M@?7??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`8'::M");
	DEM_EQ("?M@?8??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`9'::M");
	DEM_EQ("?M@?9??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`10'::M");
	DEM_EQ("?M@?L@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`11'::M");
	DEM_EQ("?M@?M@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`12'::M");
	DEM_EQ("?M@?N@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`13'::M");
	DEM_EQ("?M@?O@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`14'::M");
	DEM_EQ("?M@?P@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`15'::M");
	DEM_EQ("?M@?BA@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`16'::M");
	DEM_EQ("?M@?BB@??L@@YAHXZ@4HA", "int `int __cdecl L(void)'::`17'::M");
	DEM_EQ("?j@?1??L@@YAHXZ@4UJ@@A", "struct J `int __cdecl L(void)'::`2'::j");
	DEM_EQ("?NN@0XX@@3HA", "int XX::NN::NN");
	DEM_EQ("?MM@0NN@XX@@3HA", "int XX::NN::MM::MM");
	DEM_EQ("?NN@MM@0XX@@3HA", "int XX::NN::MM::NN");
	DEM_EQ("?OO@0NN@01XX@@3HA", "int XX::NN::OO::NN::OO::OO");
	DEM_EQ("?NN@OO@010XX@@3HA", "int XX::NN::OO::NN::OO::NN");
	DEM_EQ("?M@?1??0@YAHXZ@4HA", "int `int __cdecl M(void)'::`2'::M");
	DEM_EQ("?L@?2??M@0?2??0@YAHXZ@QEAAHXZ@4HA",
		   "int `public: int __cdecl `int __cdecl L(void)'::`3'::L::M(void)'::`3'::L");
	DEM_EQ("?M@?2??0L@?2??1@YAHXZ@QEAAHXZ@4HA",
		   "int `public: int __cdecl `int __cdecl L(void)'::`3'::L::M(void)'::`3'::M");
	DEM_EQ("?M@?1???$L@H@@YAHXZ@4HA", "int `int __cdecl L<int>(void)'::`2'::M");
	DEM_EQ("?SN@?$NS@H@NS@@QEAAHXZ", "public: int __cdecl NS::NS<int>::SN(void)");
	DEM_EQ("?NS@?1??SN@?$NS@H@0@QEAAHXZ@4HA",
		   "int `public: int __cdecl NS::NS<int>::SN(void)'::`2'::NS");
	DEM_EQ("?SN@?1??0?$NS@H@NS@@QEAAHXZ@4HA",
		   "int `public: int __cdecl NS::NS<int>::SN(void)'::`2'::SN");
	DEM_EQ("?NS@?1??SN@?$NS@H@10@QEAAHXZ@4HA",
		   "int `public: int __cdecl NS::SN::NS<int>::SN(void)'::`2'::NS");
	DEM_EQ("?SN@?1??0?$NS@H@0NS@@QEAAHXZ@4HA",
		   "int `public: int __cdecl NS::SN::NS<int>::SN(void)'::`2'::SN");
	DEM_EQ("?X@?$C@H@C@0@2HB", "public: static int const X::C::C<int>::X");
	DEM_EQ("?X@?$C@H@C@1@2HB", "public: static int const C<int>::C::C<int>::X");
	DEM_EQ("?X@?$C@H@C@2@2HB", "public: static int const C::C::C<int>::X");
	DEM_EQ("?C@?1??B@?$C@H@0101A@@QEAAHXZ@4U201013@A",
		   "struct A::B::C::B::C::C<int> `public: int __cdecl A::B::C::B::C::C<int>::B(void)'::`2'::C");
	DEM_EQ("?B@?1??0?$C@H@C@020A@@QEAAHXZ@4HA",
		   "int `public: int __cdecl A::B::C::B::C::C<int>::B(void)'::`2'::B");
	DEM_EQ("?A@?1??B@?$C@H@C@1310@QEAAHXZ@4HA",
		   "int `public: int __cdecl A::B::C::B::C::C<int>::B(void)'::`2'::A");
}

TEST_F(MicrosoftDemanglerTests, msoperators) {
	DEM_EQ("??0Base@@QEAA@XZ", "public: __cdecl Base::Base(void)");
	DEM_EQ("??1Base@@UEAA@XZ", "public: virtual __cdecl Base::~Base(void)");
	DEM_EQ("??2@YAPEAX_K@Z", "void * __cdecl operator new(unsigned __int64)");
	DEM_EQ("??3@YAXPEAX_K@Z", "void __cdecl operator delete(void *, unsigned __int64)");
	DEM_EQ("??4Base@@QEAAHH@Z", "public: int __cdecl Base::operator=(int)");
	DEM_EQ("??6Base@@QEAAHH@Z", "public: int __cdecl Base::operator<<(int)");
	DEM_EQ("??5Base@@QEAAHH@Z", "public: int __cdecl Base::operator>>(int)");
	DEM_EQ("??7Base@@QEAAHXZ", "public: int __cdecl Base::operator!(void)");
	DEM_EQ("??8Base@@QEAAHH@Z", "public: int __cdecl Base::operator==(int)");
	DEM_EQ("??9Base@@QEAAHH@Z", "public: int __cdecl Base::operator!=(int)");
	DEM_EQ("??ABase@@QEAAHH@Z", "public: int __cdecl Base::operator[](int)");
	DEM_EQ("??BBase@@QEAAHXZ", "public: int __cdecl Base::operator int(void)");
	DEM_EQ("??CBase@@QEAAHXZ", "public: int __cdecl Base::operator->(void)");
	DEM_EQ("??DBase@@QEAAHXZ", "public: int __cdecl Base::operator*(void)");
	DEM_EQ("??EBase@@QEAAHXZ", "public: int __cdecl Base::operator++(void)");
	DEM_EQ("??EBase@@QEAAHH@Z", "public: int __cdecl Base::operator++(int)");
	DEM_EQ("??FBase@@QEAAHXZ", "public: int __cdecl Base::operator--(void)");
	DEM_EQ("??FBase@@QEAAHH@Z", "public: int __cdecl Base::operator--(int)");
	DEM_EQ("??GBase@@QEAAHH@Z", "public: int __cdecl Base::operator-(int)");
	DEM_EQ("??HBase@@QEAAHH@Z", "public: int __cdecl Base::operator+(int)");
	DEM_EQ("??IBase@@QEAAHH@Z", "public: int __cdecl Base::operator&(int)");
	DEM_EQ("??JBase@@QEAAHH@Z", "public: int __cdecl Base::operator->*(int)");
	DEM_EQ("??KBase@@QEAAHH@Z", "public: int __cdecl Base::operator/(int)");
	DEM_EQ("??LBase@@QEAAHH@Z", "public: int __cdecl Base::operator%(int)");
	DEM_EQ("??MBase@@QEAAHH@Z", "public: int __cdecl Base::operator<(int)");
	DEM_EQ("??NBase@@QEAAHH@Z", "public: int __cdecl Base::operator<=(int)");
	DEM_EQ("??OBase@@QEAAHH@Z", "public: int __cdecl Base::operator>(int)");
	DEM_EQ("??PBase@@QEAAHH@Z", "public: int __cdecl Base::operator>=(int)");
	DEM_EQ("??QBase@@QEAAHH@Z", "public: int __cdecl Base::operator,(int)");
	DEM_EQ("??RBase@@QEAAHXZ", "public: int __cdecl Base::operator()(void)");
	DEM_EQ("??SBase@@QEAAHXZ", "public: int __cdecl Base::operator~(void)");
	DEM_EQ("??TBase@@QEAAHH@Z", "public: int __cdecl Base::operator^(int)");
	DEM_EQ("??UBase@@QEAAHH@Z", "public: int __cdecl Base::operator|(int)");
	DEM_EQ("??VBase@@QEAAHH@Z", "public: int __cdecl Base::operator&&(int)");
	DEM_EQ("??WBase@@QEAAHH@Z", "public: int __cdecl Base::operator||(int)");
	DEM_EQ("??XBase@@QEAAHH@Z", "public: int __cdecl Base::operator*=(int)");
	DEM_EQ("??YBase@@QEAAHH@Z", "public: int __cdecl Base::operator+=(int)");
	DEM_EQ("??ZBase@@QEAAHH@Z", "public: int __cdecl Base::operator-=(int)");
	DEM_EQ("??_0Base@@QEAAHH@Z", "public: int __cdecl Base::operator/=(int)");
	DEM_EQ("??_1Base@@QEAAHH@Z", "public: int __cdecl Base::operator%=(int)");
	DEM_EQ("??_2Base@@QEAAHH@Z", "public: int __cdecl Base::operator>>=(int)");
	DEM_EQ("??_3Base@@QEAAHH@Z", "public: int __cdecl Base::operator<<=(int)");
	DEM_EQ("??_4Base@@QEAAHH@Z", "public: int __cdecl Base::operator&=(int)");
	DEM_EQ("??_5Base@@QEAAHH@Z", "public: int __cdecl Base::operator|=(int)");
	DEM_EQ("??_6Base@@QEAAHH@Z", "public: int __cdecl Base::operator^=(int)");
	DEM_EQ("??_7Base@@6B@", "const Base::`vftable'");
	DEM_EQ("??_7A@B@@6BC@D@@@", "const B::A::`vftable'{for `D::C'}");
	DEM_EQ("??_8Middle2@@7B@", "const Middle2::`vbtable'");
	DEM_EQ("??_9Base@@$B7AA", "[thunk]: __cdecl Base::`vcall'{8, {flat}}");
	DEM_EQ("??_B?1??getS@@YAAAUS@@XZ@51",
		   "`struct S & __cdecl getS(void)'::`2'::`local static guard'{2}");
	DEM_EQ("??_C@_02PCEFGMJL@hi?$AA@", "\"hi\"");
	DEM_EQ("??_DDiamond@@QEAAXXZ", "public: void __cdecl Diamond::`vbase dtor'(void)");
	DEM_EQ("??_EBase@@UEAAPEAXI@Z",
		   "public: virtual void * __cdecl Base::`vector deleting dtor'(unsigned int)");
	DEM_EQ("??_EBase@@G3AEPAXI@Z",
		   "[thunk]: private: void * __thiscall Base::`vector deleting dtor'`adjustor{4}'(unsigned int)");
	DEM_EQ("??_F?$SomeTemplate@H@@QAEXXZ",
		   "public: void __thiscall SomeTemplate<int>::`default ctor closure'(void)");
	DEM_EQ("??_GBase@@UEAAPEAXI@Z",
		   "public: virtual void * __cdecl Base::`scalar deleting dtor'(unsigned int)");
	DEM_EQ("??_H@YAXPEAX_K1P6APEAX0@Z@Z",
		   "void __cdecl `vector ctor iterator'(void *, unsigned __int64, unsigned __int64, void * (__cdecl *)(void *))");
	DEM_EQ("??_I@YAXPEAX_K1P6AX0@Z@Z",
		   "void __cdecl `vector dtor iterator'(void *, unsigned __int64, unsigned __int64, void (__cdecl *)(void *))");
	DEM_EQ("??_JBase@@UEAAPEAXI@Z",
		   "public: virtual void * __cdecl Base::`vector vbase ctor iterator'(unsigned int)");
	DEM_EQ("??_KBase@@UEAAPEAXI@Z",
		   "public: virtual void * __cdecl Base::`virtual displacement map'(unsigned int)");
	DEM_EQ("??_LBase@@UEAAPEAXI@Z",
		   "public: virtual void * __cdecl Base::`eh vector ctor iterator'(unsigned int)");
	DEM_EQ("??_MBase@@UEAAPEAXI@Z",
		   "public: virtual void * __cdecl Base::`eh vector dtor iterator'(unsigned int)");
	DEM_EQ("??_NBase@@UEAAPEAXI@Z",
		   "public: virtual void * __cdecl Base::`eh vector vbase ctor iterator'(unsigned int)");
	DEM_EQ("??_O?$SomeTemplate@H@@QAEXXZ",
		   "public: void __thiscall SomeTemplate<int>::`copy ctor closure'(void)");
	DEM_EQ("??_SBase@@6B@", "const Base::`local vftable'");
	DEM_EQ("??_TDerived@@QEAAXXZ", "public: void __cdecl Derived::`local vftable ctor closure'(void)");
	DEM_EQ("??_U@YAPEAX_KAEAVklass@@@Z",
		   "void * __cdecl operator new[](unsigned __int64, class klass &)");
	DEM_EQ("??_V@YAXPEAXAEAVklass@@@Z", "void __cdecl operator delete[](void *, class klass &)");
	DEM_EQ("??_R0?AUBase@@@8", "struct Base `RTTI Type Descriptor'");
	DEM_EQ("??_R1A@?0A@EA@Base@@8", "Base::`RTTI Base Class Descriptor at (0, -1, 0, 64)'");
	DEM_EQ("??_R2Base@@8", "Base::`RTTI Base Class Array'");
	DEM_EQ("??_R3Base@@8", "Base::`RTTI Class Hierarchy Descriptor'");
	DEM_EQ("??_R4Base@@6B@", "const Base::`RTTI Complete Object Locator'");
	DEM_EQ("??__EFoo@@YAXXZ", "void __cdecl `dynamic initializer for 'Foo''(void)");
	DEM_EQ("??__FFoo@@YAXXZ", "void __cdecl `dynamic atexit destructor for 'Foo''(void)");
	DEM_EQ(
		"??__F_decisionToDFA@XPathLexer@@0V?$vector@VDFA@dfa@antlr4@@V?$allocator@VDFA@dfa@antlr4@@@std@@@std@@A@YAXXZ",
		"void __cdecl `dynamic atexit destructor for `private: static class std::vector<class antlr4::dfa::DFA, class std::allocator<class antlr4::dfa::DFA>> XPathLexer::_decisionToDFA''(void)");
	DEM_EQ("??__K_deg@@YAHO@Z", "int __cdecl operator \"\"_deg(long double)");
}

TEST_F(MicrosoftDemanglerTests, msreturnqualifiers) {
	DEM_EQ("?a1@@YAXXZ", "void __cdecl a1(void)");
	DEM_EQ("?a2@@YAHXZ", "int __cdecl a2(void)");
	DEM_EQ("?a3@@YA?BHXZ", "int const __cdecl a3(void)");
	DEM_EQ("?a4@@YA?CHXZ", "int volatile __cdecl a4(void)");
	DEM_EQ("?a5@@YA?DHXZ", "int const volatile __cdecl a5(void)");
	DEM_EQ("?a6@@YAMXZ", "float __cdecl a6(void)");
	DEM_EQ("?b1@@YAPAHXZ", "int * __cdecl b1(void)");
	DEM_EQ("?b2@@YAPBDXZ", "char const * __cdecl b2(void)");
	DEM_EQ("?b3@@YAPAMXZ", "float * __cdecl b3(void)");
	DEM_EQ("?b4@@YAPBMXZ", "float const * __cdecl b4(void)");
	DEM_EQ("?b5@@YAPCMXZ", "float volatile * __cdecl b5(void)");
	DEM_EQ("?b6@@YAPDMXZ", "float const volatile * __cdecl b6(void)");
	DEM_EQ("?b7@@YAAAMXZ", "float & __cdecl b7(void)");
	DEM_EQ("?b8@@YAABMXZ", "float const & __cdecl b8(void)");
	DEM_EQ("?b9@@YAACMXZ", "float volatile & __cdecl b9(void)");
	DEM_EQ("?b10@@YAADMXZ", "float const volatile & __cdecl b10(void)");
	DEM_EQ("?b11@@YAPAPBDXZ", "char const ** __cdecl b11(void)");
	DEM_EQ("?c1@@YA?AVA@@XZ", "class A __cdecl c1(void)");
	DEM_EQ("?c2@@YA?BVA@@XZ", "class A const __cdecl c2(void)");
	DEM_EQ("?c3@@YA?CVA@@XZ", "class A volatile __cdecl c3(void)");
	DEM_EQ("?c4@@YA?DVA@@XZ", "class A const volatile __cdecl c4(void)");
	DEM_EQ("?c5@@YAPBVA@@XZ", "class A const * __cdecl c5(void)");
	DEM_EQ("?c6@@YAPCVA@@XZ", "class A volatile * __cdecl c6(void)");
	DEM_EQ("?c7@@YAPDVA@@XZ", "class A const volatile * __cdecl c7(void)");
	DEM_EQ("?c8@@YAAAVA@@XZ", "class A & __cdecl c8(void)");
	DEM_EQ("?c9@@YAABVA@@XZ", "class A const & __cdecl c9(void)");
	DEM_EQ("?c10@@YAACVA@@XZ", "class A volatile & __cdecl c10(void)");
	DEM_EQ("?c11@@YAADVA@@XZ", "class A const volatile & __cdecl c11(void)");
	DEM_EQ("?d1@@YA?AV?$B@H@@XZ", "class B<int> __cdecl d1(void)");
	DEM_EQ("?d2@@YA?AV?$B@PBD@@XZ", "class B<char const *> __cdecl d2(void)");
	DEM_EQ("?d3@@YA?AV?$B@VA@@@@XZ", "class B<class A> __cdecl d3(void)");
	DEM_EQ("?d4@@YAPAV?$B@VA@@@@XZ", "class B<class A> * __cdecl d4(void)");
	DEM_EQ("?d5@@YAPBV?$B@VA@@@@XZ", "class B<class A> const * __cdecl d5(void)");
	DEM_EQ("?d6@@YAPCV?$B@VA@@@@XZ", "class B<class A> volatile * __cdecl d6(void)");
	DEM_EQ("?d7@@YAPDV?$B@VA@@@@XZ", "class B<class A> const volatile * __cdecl d7(void)");
	DEM_EQ("?d8@@YAAAV?$B@VA@@@@XZ", "class B<class A> & __cdecl d8(void)");
	DEM_EQ("?d9@@YAABV?$B@VA@@@@XZ", "class B<class A> const & __cdecl d9(void)");
	DEM_EQ("?d10@@YAACV?$B@VA@@@@XZ", "class B<class A> volatile & __cdecl d10(void)");
	DEM_EQ("?d11@@YAADV?$B@VA@@@@XZ", "class B<class A> const volatile & __cdecl d11(void)");
	DEM_EQ("?e1@@YA?AW4Enum@@XZ", "enum Enum __cdecl e1(void)");
	DEM_EQ("?e2@@YA?BW4Enum@@XZ", "enum Enum const __cdecl e2(void)");
	DEM_EQ("?e3@@YAPAW4Enum@@XZ", "enum Enum * __cdecl e3(void)");
	DEM_EQ("?e4@@YAAAW4Enum@@XZ", "enum Enum & __cdecl e4(void)");
	DEM_EQ("?f1@@YA?AUS@@XZ", "struct S __cdecl f1(void)");
	DEM_EQ("?f2@@YA?BUS@@XZ", "struct S const __cdecl f2(void)");
	DEM_EQ("?f3@@YAPAUS@@XZ", "struct S * __cdecl f3(void)");
	DEM_EQ("?f4@@YAPBUS@@XZ", "struct S const * __cdecl f4(void)");
	DEM_EQ("?f5@@YAPDUS@@XZ", "struct S const volatile * __cdecl f5(void)");
	DEM_EQ("?f6@@YAAAUS@@XZ", "struct S & __cdecl f6(void)");
	DEM_EQ("?f7@@YAQAUS@@XZ", "struct S *const __cdecl f7(void)");
	DEM_EQ("?f8@@YAPQS@@HXZ", "int S::* __cdecl f8(void)");
	DEM_EQ("?f9@@YAQQS@@HXZ", "int S::*const __cdecl f9(void)");
	DEM_EQ("?f10@@YAPIQS@@HXZ", "int S::*__restrict __cdecl f10(void)");
	DEM_EQ("?f11@@YAQIQS@@HXZ", "int S::*const __restrict __cdecl f11(void)");
	DEM_EQ("?g1@@YAP6AHH@ZXZ", "int (__cdecl * __cdecl g1(void))(int)");
	DEM_EQ("?g2@@YAQ6AHH@ZXZ", "int (__cdecl *const __cdecl g2(void))(int)");
	DEM_EQ("?g3@@YAPAP6AHH@ZXZ", "int (__cdecl ** __cdecl g3(void))(int)");
	DEM_EQ("?g4@@YAPBQ6AHH@ZXZ", "int (__cdecl *const * __cdecl g4(void))(int)");
	DEM_EQ("?h1@@YAAIAHXZ", "int &__restrict __cdecl h1(void)");
}

TEST_F(MicrosoftDemanglerTests, msstringliterals) {
	DEM_EQ("??_C@_0CF@LABBIIMO@012345678901234567890123456789AB@",
		   "\"012345678901234567890123456789AB\"...");
	DEM_EQ(
		"??_C@_1EK@KFPEBLPK@?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AAA?$AAB@",
		"L\"012345678901234567890123456789AB\"...");
	DEM_EQ("??_C@_13IIHIAFKH@?W?$PP?$AA?$AA@", "L\"\\xD7\\xFF\"");
	DEM_EQ("??_C@_02PCEFGMJL@hi?$AA@", "\"hi\"");
	DEM_EQ("??_C@_05OMLEGLOC@h?$AAi?$AA?$AA?$AA@", "u\"hi\"");
	DEM_EQ(
		"??_C@_0EK@FEAOBHPP@o?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA@",
		"u\"o123456789012345\"...");
	DEM_EQ("??_C@_0M@GFNAJIPG@h?$AA?$AA?$AAi?$AA?$AA?$AA?$AA?$AA?$AA?$AA@", "U\"hi\"");
	DEM_EQ(
		"??_C@_0JE@IMHFEDAA@0?$AA?$AA?$AA1?$AA?$AA?$AA2?$AA?$AA?$AA3?$AA?$AA?$AA4?$AA?$AA?$AA5?$AA?$AA?$AA6?$AA?$AA?$AA7?$AA?$AA?$AA@",
		"U\"01234567\"...");
	DEM_EQ("??_C@_0CA@NMANGEKF@012345678901234567890123456789A?$AA@",
		   "\"012345678901234567890123456789A\"");
	DEM_EQ(
		"??_C@_1EA@LJAFPILO@?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AAA?$AA?$AA@",
		"L\"012345678901234567890123456789A\"");
	DEM_EQ("??_C@_0CA@NMANGEKF@012345678901234567890123456789A?$AA@",
		   "\"012345678901234567890123456789A\"");
	DEM_EQ(
		"??_C@_0CA@NFEFHIFO@0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA?$AA?$AA@",
		"u\"012345678901234\"");
	DEM_EQ(
		"??_C@_0CA@KFPHPCC@0?$AA?$AA?$AA1?$AA?$AA?$AA2?$AA?$AA?$AA3?$AA?$AA?$AA4?$AA?$AA?$AA5?$AA?$AA?$AA6?$AA?$AA?$AA?$AA?$AA?$AA?$AA@",
		"U\"0123456\"");
	DEM_EQ(
		"??_C@_0CG@HJGBPLNO@l?$AAo?$AAo?$AAk?$AAA?$AAh?$AAe?$AAa?$AAd?$AAH?$AAa?$AAr?$AAd?$AAB?$AAr?$AAe?$AAa?$AAk?$AA?$AA?$AA@",
		"u\"lookAheadHardBreak\"");
	DEM_EQ(
		"??_C@_0CG@HJGBPLNO@l?$AAo?$AAo?$AAk?$AAA?$AAh?$AAe?$AAa?$AAd?$AAH?$AAa?$AAr?$AAd?$AAB?$AAr?$AAe?$AA@",
		"u\"lookAheadHardBre\"...");
}

TEST_F(MicrosoftDemanglerTests, mstemplatecallback) {
	DEM_EQ("?callback_void@@3V?$C@$$A6AXXZ@@A", "class C<void __cdecl(void)> callback_void");
	DEM_EQ("?callback_void_volatile@@3V?$C@$$A6AXXZ@@C",
		   "class C<void __cdecl(void)> volatile callback_void_volatile");
	DEM_EQ("?callback_int@@3V?$C@$$A6AHXZ@@A", "class C<int __cdecl(void)> callback_int");
	DEM_EQ("?callback_Type@@3V?$C@$$A6A?AVType@@XZ@@A",
		   "class C<class Type __cdecl(void)> callback_Type");
	DEM_EQ("?callback_void_int@@3V?$C@$$A6AXH@Z@@A", "class C<void __cdecl(int)> callback_void_int");
	DEM_EQ("?callback_int_int@@3V?$C@$$A6AHH@Z@@A", "class C<int __cdecl(int)> callback_int_int");
	DEM_EQ("?callback_void_Type@@3V?$C@$$A6AXVType@@@Z@@A",
		   "class C<void __cdecl(class Type)> callback_void_Type");
	DEM_EQ("?foo@@YAXV?$C@$$A6AXXZ@@@Z", "void __cdecl foo(class C<void __cdecl(void)>)");
	DEM_EQ("?function@@YAXV?$C@$$A6AXXZ@@@Z", "void __cdecl function(class C<void __cdecl(void)>)");
	DEM_EQ("?function_pointer@@YAXV?$C@P6AXXZ@@@Z",
		   "void __cdecl function_pointer(class C<void (__cdecl *)(void)>)");
	DEM_EQ("?member_pointer@@YAXV?$C@P8Z@@AEXXZ@@@Z",
		   "void __cdecl member_pointer(class C<void (__thiscall Z::*)(void)>)");
	DEM_EQ("??$bar@P6AHH@Z@@YAXP6AHH@Z@Z",
		   "void __cdecl bar<int (__cdecl *)(int)>(int (__cdecl *)(int))");
	DEM_EQ("??$WrapFnPtr@$1?VoidFn@@YAXXZ@@YAXXZ",
		   "void __cdecl WrapFnPtr<&void __cdecl VoidFn(void)>(void)");
	DEM_EQ("??$WrapFnRef@$1?VoidFn@@YAXXZ@@YAXXZ",
		   "void __cdecl WrapFnRef<&void __cdecl VoidFn(void)>(void)");
	DEM_EQ("??$WrapFnPtr@$1?VoidStaticMethod@Thing@@SAXXZ@@YAXXZ",
		   "void __cdecl WrapFnPtr<&public: static void __cdecl Thing::VoidStaticMethod(void)>(void)");
	DEM_EQ("??$WrapFnRef@$1?VoidStaticMethod@Thing@@SAXXZ@@YAXXZ",
		   "void __cdecl WrapFnRef<&public: static void __cdecl Thing::VoidStaticMethod(void)>(void)");
}

TEST_F(MicrosoftDemanglerTests, mstemplates) {
	DEM_EQ("??0?$Class@VTypename@@@@QAE@XZ",
		   "public: __thiscall Class<class Typename>::Class<class Typename>(void)");
	DEM_EQ("??0?$Class@VTypename@@@@QEAA@XZ",
		   "public: __cdecl Class<class Typename>::Class<class Typename>(void)");
	DEM_EQ("??0?$Class@$$CBVTypename@@@@QAE@XZ",
		   "public: __thiscall Class<class Typename const>::Class<class Typename const>(void)");
	DEM_EQ("??0?$Class@$$CBVTypename@@@@QEAA@XZ",
		   "public: __cdecl Class<class Typename const>::Class<class Typename const>(void)");
	DEM_EQ("??0?$Class@$$CCVTypename@@@@QAE@XZ",
		   "public: __thiscall Class<class Typename volatile>::Class<class Typename volatile>(void)");
	DEM_EQ("??0?$Class@$$CCVTypename@@@@QEAA@XZ",
		   "public: __cdecl Class<class Typename volatile>::Class<class Typename volatile>(void)");
	DEM_EQ("??0?$Class@$$CDVTypename@@@@QAE@XZ",
		   "public: __thiscall Class<class Typename const volatile>::Class<class Typename const volatile>(void)");
	DEM_EQ("??0?$Class@$$CDVTypename@@@@QEAA@XZ",
		   "public: __cdecl Class<class Typename const volatile>::Class<class Typename const volatile>(void)");
	DEM_EQ("??0?$Class@V?$Nested@VTypename@@@@@@QAE@XZ",
		   "public: __thiscall Class<class Nested<class Typename>>::Class<class Nested<class Typename>>(void)");
	DEM_EQ("??0?$Class@V?$Nested@VTypename@@@@@@QEAA@XZ",
		   "public: __cdecl Class<class Nested<class Typename>>::Class<class Nested<class Typename>>(void)");
	DEM_EQ("??0?$Class@QAH@@QAE@XZ", "public: __thiscall Class<int *const>::Class<int *const>(void)");
	DEM_EQ("??0?$Class@QEAH@@QEAA@XZ", "public: __cdecl Class<int *const>::Class<int *const>(void)");
	DEM_EQ("??0?$Class@$$A6AHXZ@@QAE@XZ",
		   "public: __thiscall Class<int __cdecl(void)>::Class<int __cdecl(void)>(void)");
	DEM_EQ("??0?$Class@$$A6AHXZ@@QEAA@XZ",
		   "public: __cdecl Class<int __cdecl(void)>::Class<int __cdecl(void)>(void)");
	DEM_EQ("??0?$Class@$$BY0A@H@@QAE@XZ", "public: __thiscall Class<int[]>::Class<int[]>(void)");
	DEM_EQ("??0?$Class@$$BY0A@H@@QEAA@XZ", "public: __cdecl Class<int[]>::Class<int[]>(void)");
	DEM_EQ("??0?$Class@$$BY04H@@QAE@XZ", "public: __thiscall Class<int[5]>::Class<int[5]>(void)");
	DEM_EQ("??0?$Class@$$BY04H@@QEAA@XZ", "public: __cdecl Class<int[5]>::Class<int[5]>(void)");
	DEM_EQ("??0?$Class@$$BY04$$CBH@@QAE@XZ",
		   "public: __thiscall Class<int const[5]>::Class<int const[5]>(void)");
	DEM_EQ("??0?$Class@$$BY04$$CBH@@QEAA@XZ",
		   "public: __cdecl Class<int const[5]>::Class<int const[5]>(void)");
	DEM_EQ("??0?$Class@$$BY04QAH@@QAE@XZ",
		   "public: __thiscall Class<int *const[5]>::Class<int *const[5]>(void)");
	DEM_EQ("??0?$Class@$$BY04QEAH@@QEAA@XZ",
		   "public: __cdecl Class<int *const[5]>::Class<int *const[5]>(void)");
	DEM_EQ("??0?$BoolTemplate@$0A@@@QAE@XZ", "public: __thiscall BoolTemplate<0>::BoolTemplate<0>(void)");
	DEM_EQ("??0?$BoolTemplate@$0A@@@QEAA@XZ", "public: __cdecl BoolTemplate<0>::BoolTemplate<0>(void)");
	DEM_EQ("??0?$BoolTemplate@$00@@QAE@XZ", "public: __thiscall BoolTemplate<1>::BoolTemplate<1>(void)");
	DEM_EQ("??0?$BoolTemplate@$00@@QEAA@XZ", "public: __cdecl BoolTemplate<1>::BoolTemplate<1>(void)");
	DEM_EQ("??$Foo@H@?$BoolTemplate@$00@@QAEXH@Z",
		   "public: void __thiscall BoolTemplate<1>::Foo<int>(int)");
	DEM_EQ("??$Foo@H@?$BoolTemplate@$00@@QEAAXH@Z", "public: void __cdecl BoolTemplate<1>::Foo<int>(int)");
	DEM_EQ("??0?$IntTemplate@$0A@@@QAE@XZ", "public: __thiscall IntTemplate<0>::IntTemplate<0>(void)");
	DEM_EQ("??0?$IntTemplate@$0A@@@QEAA@XZ", "public: __cdecl IntTemplate<0>::IntTemplate<0>(void)");
	DEM_EQ("??0?$IntTemplate@$04@@QAE@XZ", "public: __thiscall IntTemplate<5>::IntTemplate<5>(void)");
	DEM_EQ("??0?$IntTemplate@$04@@QEAA@XZ", "public: __cdecl IntTemplate<5>::IntTemplate<5>(void)");
	DEM_EQ("??0?$IntTemplate@$0L@@@QAE@XZ", "public: __thiscall IntTemplate<11>::IntTemplate<11>(void)");
	DEM_EQ("??0?$IntTemplate@$0L@@@QEAA@XZ", "public: __cdecl IntTemplate<11>::IntTemplate<11>(void)");
	DEM_EQ("??0?$IntTemplate@$0BAA@@@QAE@XZ",
		   "public: __thiscall IntTemplate<256>::IntTemplate<256>(void)");
	DEM_EQ("??0?$IntTemplate@$0BAA@@@QEAA@XZ", "public: __cdecl IntTemplate<256>::IntTemplate<256>(void)");
	DEM_EQ("??0?$IntTemplate@$0CAB@@@QAE@XZ",
		   "public: __thiscall IntTemplate<513>::IntTemplate<513>(void)");
	DEM_EQ("??0?$IntTemplate@$0CAB@@@QEAA@XZ", "public: __cdecl IntTemplate<513>::IntTemplate<513>(void)");
	DEM_EQ("??0?$IntTemplate@$0EAC@@@QAE@XZ",
		   "public: __thiscall IntTemplate<1026>::IntTemplate<1026>(void)");
	DEM_EQ("??0?$IntTemplate@$0EAC@@@QEAA@XZ",
		   "public: __cdecl IntTemplate<1026>::IntTemplate<1026>(void)");
	DEM_EQ("??0?$IntTemplate@$0PPPP@@@QAE@XZ",
		   "public: __thiscall IntTemplate<65535>::IntTemplate<65535>(void)");
	DEM_EQ("??0?$IntTemplate@$0PPPP@@@QEAA@XZ",
		   "public: __cdecl IntTemplate<65535>::IntTemplate<65535>(void)");
	DEM_EQ("??0?$IntTemplate@$0?0@@QAE@XZ", "public: __thiscall IntTemplate<-1>::IntTemplate<-1>(void)");
	DEM_EQ("??0?$IntTemplate@$0?0@@QEAA@XZ", "public: __cdecl IntTemplate<-1>::IntTemplate<-1>(void)");
	DEM_EQ("??0?$IntTemplate@$0?8@@QAE@XZ", "public: __thiscall IntTemplate<-9>::IntTemplate<-9>(void)");
	DEM_EQ("??0?$IntTemplate@$0?8@@QEAA@XZ", "public: __cdecl IntTemplate<-9>::IntTemplate<-9>(void)");
	DEM_EQ("??0?$IntTemplate@$0?9@@QAE@XZ", "public: __thiscall IntTemplate<-10>::IntTemplate<-10>(void)");
	DEM_EQ("??0?$IntTemplate@$0?9@@QEAA@XZ", "public: __cdecl IntTemplate<-10>::IntTemplate<-10>(void)");
	DEM_EQ("??0?$IntTemplate@$0?L@@@QAE@XZ", "public: __thiscall IntTemplate<-11>::IntTemplate<-11>(void)");
	DEM_EQ("??0?$IntTemplate@$0?L@@@QEAA@XZ", "public: __cdecl IntTemplate<-11>::IntTemplate<-11>(void)");
	DEM_EQ("??0?$UnsignedIntTemplate@$0PPPPPPPP@@@QAE@XZ",
		   "public: __thiscall UnsignedIntTemplate<4294967295>::UnsignedIntTemplate<4294967295>(void)");
	DEM_EQ("??0?$UnsignedIntTemplate@$0PPPPPPPP@@@QEAA@XZ",
		   "public: __cdecl UnsignedIntTemplate<4294967295>::UnsignedIntTemplate<4294967295>(void)");
	DEM_EQ("??0?$LongLongTemplate@$0?IAAAAAAAAAAAAAAA@@@QAE@XZ",
		   "public: __thiscall LongLongTemplate<-9223372036854775808>::LongLongTemplate<-9223372036854775808>(void)");
	DEM_EQ("??0?$LongLongTemplate@$0?IAAAAAAAAAAAAAAA@@@QEAA@XZ",
		   "public: __cdecl LongLongTemplate<-9223372036854775808>::LongLongTemplate<-9223372036854775808>(void)");
	DEM_EQ("??0?$LongLongTemplate@$0HPPPPPPPPPPPPPPP@@@QAE@XZ",
		   "public: __thiscall LongLongTemplate<9223372036854775807>::LongLongTemplate<9223372036854775807>(void)");
	DEM_EQ("??0?$LongLongTemplate@$0HPPPPPPPPPPPPPPP@@@QEAA@XZ",
		   "public: __cdecl LongLongTemplate<9223372036854775807>::LongLongTemplate<9223372036854775807>(void)");
	DEM_EQ("??0?$UnsignedLongLongTemplate@$0?0@@QAE@XZ",
		   "public: __thiscall UnsignedLongLongTemplate<-1>::UnsignedLongLongTemplate<-1>(void)");
	DEM_EQ("??0?$UnsignedLongLongTemplate@$0?0@@QEAA@XZ",
		   "public: __cdecl UnsignedLongLongTemplate<-1>::UnsignedLongLongTemplate<-1>(void)");
	DEM_EQ("??$foo@H@space@@YAABHABH@Z", "int const & __cdecl space::foo<int>(int const &)");
	DEM_EQ("??$foo@H@space@@YAAEBHAEBH@Z", "int const & __cdecl space::foo<int>(int const &)");
	DEM_EQ("??$FunctionPointerTemplate@$1?spam@@YAXXZ@@YAXXZ",
		   "void __cdecl FunctionPointerTemplate<&void __cdecl spam(void)>(void)");
	DEM_EQ("??$variadic_fn_template@HHHH@@YAXABH000@Z",
		   "void __cdecl variadic_fn_template<int, int, int, int>(int const &, int const &, int const &, int const &)");
	DEM_EQ("??$variadic_fn_template@HHD$$BY01D@@YAXABH0ABDAAY01$$CBD@Z",
		   "void __cdecl variadic_fn_template<int, int, char, char[2]>(int const &, int const &, char const &, char const (&)[2])");
	DEM_EQ("??0?$VariadicClass@HD_N@@QAE@XZ",
		   "public: __thiscall VariadicClass<int, char, bool>::VariadicClass<int, char, bool>(void)");
	DEM_EQ("??0?$VariadicClass@_NDH@@QAE@XZ",
		   "public: __thiscall VariadicClass<bool, char, int>::VariadicClass<bool, char, int>(void)");
	DEM_EQ("?template_template_fun@@YAXU?$Type@U?$Thing@USecond@@$00@@USecond@@@@@Z",
		   "void __cdecl template_template_fun(struct Type<struct Thing<struct Second, 1>, struct Second>)");
	DEM_EQ(
		"??$template_template_specialization@$$A6AXU?$Type@U?$Thing@USecond@@$00@@USecond@@@@@Z@@YAXXZ",
		"void __cdecl template_template_specialization<void __cdecl(struct Type<struct Thing<struct Second, 1>, struct Second>)>(void)");
	DEM_EQ("?f@@YAXU?$S1@$0A@@@@Z", "void __cdecl f(struct S1<0>)");
	DEM_EQ("?recref@@YAXU?$type1@$E?inst@@3Urecord@@B@@@Z",
		   "void __cdecl recref(struct type1<struct record const inst>)");
	DEM_EQ(
		"?fun@@YAXU?$UUIDType1@Uuuid@@$1?_GUID_12345678_1234_1234_1234_1234567890ab@@3U__s_GUID@@B@@@Z",
		"void __cdecl fun(struct UUIDType1<struct uuid, &struct __s_GUID const _GUID_12345678_1234_1234_1234_1234567890ab>)");
	DEM_EQ(
		"?fun@@YAXU?$UUIDType2@Uuuid@@$E?_GUID_12345678_1234_1234_1234_1234567890ab@@3U__s_GUID@@B@@@Z",
		"void __cdecl fun(struct UUIDType2<struct uuid, struct __s_GUID const _GUID_12345678_1234_1234_1234_1234567890ab>)");
	DEM_EQ("?FunctionDefinedWithInjectedName@@YAXU?$TypeWithFriendDefinition@H@@@Z",
		   "void __cdecl FunctionDefinedWithInjectedName(struct TypeWithFriendDefinition<int>)");
	DEM_EQ("?bar@?$UUIDType4@$1?_GUID_12345678_1234_1234_1234_1234567890ab@@3U__s_GUID@@B@@QAEXXZ",
		   "public: void __thiscall UUIDType4<&struct __s_GUID const _GUID_12345678_1234_1234_1234_1234567890ab>::bar(void)");
	DEM_EQ("??$f@US@@$1?g@1@QEAAXXZ@@YAXXZ",
		   "void __cdecl f<struct S, &public: void __cdecl S::g(void)>(void)");
	DEM_EQ("??$?0N@?$Foo@H@@QEAA@N@Z", "public: __cdecl Foo<int>::Foo<int><double>(double)");
}

TEST_F(MicrosoftDemanglerTests, mstemplatesmemptrs) {
	DEM_EQ(
		"??$CallMethod@UC@NegativeNVOffset@@$I??_912@$BA@AEPPPPPPPM@A@@@YAXAAUC@NegativeNVOffset@@@Z",
		"void __cdecl CallMethod<struct NegativeNVOffset::C, {[thunk]: __thiscall NegativeNVOffset::C::`vcall'{0, {flat}}, 4294967292, 0}>(struct NegativeNVOffset::C &)");
	DEM_EQ("??$CallMethod@UM@@$0A@@@YAXAAUM@@@Z",
		   "void __cdecl CallMethod<struct M, 0>(struct M &)");
	DEM_EQ("??$CallMethod@UM@@$H??_91@$BA@AEA@@@YAXAAUM@@@Z",
		   "void __cdecl CallMethod<struct M, {[thunk]: __thiscall M::`vcall'{0, {flat}}, 0}>(struct M &)");
	DEM_EQ("??$CallMethod@UM@@$H?f@1@QAEXXZA@@@YAXAAUM@@@Z",
		   "void __cdecl CallMethod<struct M, {public: void __thiscall M::f(void), 0}>(struct M &)");
	DEM_EQ("??$CallMethod@UO@@$H??_91@$BA@AE3@@YAXAAUO@@@Z",
		   "void __cdecl CallMethod<struct O, {[thunk]: __thiscall O::`vcall'{0, {flat}}, 4}>(struct O &)");
	DEM_EQ("??$CallMethod@US@@$0A@@@YAXAAUS@@@Z",
		   "void __cdecl CallMethod<struct S, 0>(struct S &)");
	DEM_EQ("??$CallMethod@US@@$1??_91@$BA@AE@@YAXAAUS@@@Z",
		   "void __cdecl CallMethod<struct S, &[thunk]: __thiscall S::`vcall'{0, {flat}}>(struct S &)");
	DEM_EQ("??$CallMethod@US@@$1?f@1@QAEXXZ@@YAXAAUS@@@Z",
		   "void __cdecl CallMethod<struct S, &public: void __thiscall S::f(void)>(struct S &)");
	DEM_EQ("??$CallMethod@UU@@$0A@@@YAXAAUU@@@Z",
		   "void __cdecl CallMethod<struct U, 0>(struct U &)");
	DEM_EQ("??$CallMethod@UU@@$J??_91@$BA@AEA@A@A@@@YAXAAUU@@@Z",
		   "void __cdecl CallMethod<struct U, {[thunk]: __thiscall U::`vcall'{0, {flat}}, 0, 0, 0}>(struct U &)");
	DEM_EQ("??$CallMethod@UU@@$J?f@1@QAEXXZA@A@A@@@YAXAAUU@@@Z",
		   "void __cdecl CallMethod<struct U, {public: void __thiscall U::f(void), 0, 0, 0}>(struct U &)");
	DEM_EQ("??$CallMethod@UV@@$0A@@@YAXAAUV@@@Z",
		   "void __cdecl CallMethod<struct V, 0>(struct V &)");
	DEM_EQ("??$CallMethod@UV@@$I??_91@$BA@AEA@A@@@YAXAAUV@@@Z",
		   "void __cdecl CallMethod<struct V, {[thunk]: __thiscall V::`vcall'{0, {flat}}, 0, 0}>(struct V &)");
	DEM_EQ("??$CallMethod@UV@@$I?f@1@QAEXXZA@A@@@YAXAAUV@@@Z",
		   "void __cdecl CallMethod<struct V, {public: void __thiscall V::f(void), 0, 0}>(struct V &)");
	DEM_EQ("??$ReadField@UA@@$0?0@@YAHAAUA@@@Z", "int __cdecl ReadField<struct A, -1>(struct A &)");
	DEM_EQ("??$ReadField@UA@@$0A@@@YAHAAUA@@@Z", "int __cdecl ReadField<struct A, 0>(struct A &)");
	DEM_EQ("??$ReadField@UI@@$03@@YAHAAUI@@@Z", "int __cdecl ReadField<struct I, 4>(struct I &)");
	DEM_EQ("??$ReadField@UI@@$0A@@@YAHAAUI@@@Z", "int __cdecl ReadField<struct I, 0>(struct I &)");
	DEM_EQ("??$ReadField@UM@@$0A@@@YAHAAUM@@@Z", "int __cdecl ReadField<struct M, 0>(struct M &)");
	DEM_EQ("??$ReadField@UM@@$0BA@@@YAHAAUM@@@Z",
		   "int __cdecl ReadField<struct M, 16>(struct M &)");
	DEM_EQ("??$ReadField@UM@@$0M@@@YAHAAUM@@@Z", "int __cdecl ReadField<struct M, 12>(struct M &)");
	DEM_EQ("??$ReadField@US@@$03@@YAHAAUS@@@Z", "int __cdecl ReadField<struct S, 4>(struct S &)");
	DEM_EQ("??$ReadField@US@@$07@@YAHAAUS@@@Z", "int __cdecl ReadField<struct S, 8>(struct S &)");
	DEM_EQ("??$ReadField@US@@$0A@@@YAHAAUS@@@Z", "int __cdecl ReadField<struct S, 0>(struct S &)");
	DEM_EQ("??$ReadField@UU@@$0A@@@YAHAAUU@@@Z", "int __cdecl ReadField<struct U, 0>(struct U &)");
	DEM_EQ("??$ReadField@UU@@$G3A@A@@@YAHAAUU@@@Z",
		   "int __cdecl ReadField<struct U, {4, 0, 0}>(struct U &)");
	DEM_EQ("??$ReadField@UU@@$G7A@A@@@YAHAAUU@@@Z",
		   "int __cdecl ReadField<struct U, {8, 0, 0}>(struct U &)");
	DEM_EQ("??$ReadField@UV@@$0A@@@YAHAAUV@@@Z", "int __cdecl ReadField<struct V, 0>(struct V &)");
	DEM_EQ("??$ReadField@UV@@$F7A@@@YAHAAUV@@@Z",
		   "int __cdecl ReadField<struct V, {8, 0}>(struct V &)");
	DEM_EQ("??$ReadField@UV@@$FM@A@@@YAHAAUV@@@Z",
		   "int __cdecl ReadField<struct V, {12, 0}>(struct V &)");
	DEM_EQ("?Q@@3$$QEAP8Foo@@EAAXXZEA", "void (__cdecl Foo::*&&Q)(void)");
}

TEST_F(MicrosoftDemanglerTests, mstemplatesmemptrs2) {
	DEM_EQ("?m@@3U?$J@UM@@$0A@@@A", "struct J<struct M, 0> m");
	DEM_EQ("?m2@@3U?$K@UM@@$0?0@@A", "struct K<struct M, -1> m2");
	DEM_EQ("?n@@3U?$J@UN@@$HA@@@A", "struct J<struct N, {0}> n");
	DEM_EQ("?n2@@3U?$K@UN@@$0?0@@A", "struct K<struct N, -1> n2");
	DEM_EQ("?o@@3U?$J@UO@@$IA@A@@@A", "struct J<struct O, {0, 0}> o");
	DEM_EQ("?o2@@3U?$K@UO@@$FA@?0@@A", "struct K<struct O, {0, -1}> o2");
	DEM_EQ("?p@@3U?$J@UP@@$JA@A@?0@@A", "struct J<struct P, {0, 0, -1}> p");
	DEM_EQ("?p2@@3U?$K@UP@@$GA@A@?0@@A", "struct K<struct P, {0, 0, -1}> p2");
	DEM_EQ("??0?$ClassTemplate@$J??_9MostGeneral@@$BA@AEA@M@3@@QAE@XZ",
		   "public: __thiscall ClassTemplate<{[thunk]: __thiscall MostGeneral::`vcall'{0, {flat}}, 0, 12, 4}>::ClassTemplate<{[thunk]: __thiscall MostGeneral::`vcall'{0, {flat}}, 0, 12, 4}>(void)");
}

TEST_F(MicrosoftDemanglerTests, msthunks) {
	DEM_EQ("?f@C@@WBA@EAAHXZ", "[thunk]: public: virtual int __cdecl C::f`adjustor{16}'(void)");
	DEM_EQ("??_EDerived@@$4PPPPPPPM@A@EAAPEAXI@Z",
		   "[thunk]: public: virtual void * __cdecl Derived::`vector deleting dtor'`vtordisp{-4, 0}'(unsigned int)");
	DEM_EQ("?f@A@simple@@$R477PPPPPPPM@7AEXXZ",
		   "[thunk]: public: virtual void __thiscall simple::A::f`vtordispex{8, 8, -4, 8}'(void)");
	DEM_EQ("??_9Base@@$B7AA", "[thunk]: __cdecl Base::`vcall'{8, {flat}}");
}

TEST_F(MicrosoftDemanglerTests, mswindows) {
	DEM_EQ("?bar@Foo@@SGXXZ", "public: static void __stdcall Foo::bar(void)");
	DEM_EQ("?bar@Foo@@QAGXXZ", "public: void __stdcall Foo::bar(void)");
	DEM_EQ("?f2@@YIXXZ", "void __fastcall f2(void)");
	DEM_EQ("?f1@@YGXXZ", "void __stdcall f1(void)");
}

TEST_F(MicrosoftDemanglerTests, variadic) {
//	DEM_EQ("?foo@@YAHHZ", "int __cdecl foo(int, ...)"); // TODO: temporarily disabled
}

TEST_F(MicrosoftDemanglerTests, InvalidManglings) {
	DEM_FAIL("?ff@@$$J0YAXAU?$AS_@$0A@PEAU?$AS_@$0A@H@__clang@@@__clang@@@Z", status::invalid_mangled_name);
	DEM_FAIL("?f0@@YAXPEU?$AS_@$00$$CAD@__clang@@@Z", status::invalid_mangled_name);
	DEM_FAIL("??0?$basic_ostream@DU?$char_traits@D@std@@@std@@QAE@PAV?$basic_streambuf@DU?$char_traits@D@std@@", status::invalid_mangled_name);
}

} // namespace tests
} // namespace demangler
} // namespace retdec
