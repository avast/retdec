/**
 * @file tests/demangler/llvm_itanium_demangler_tests.cpp
 * @brief Tests for the llvm itanium demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/demangler/demangler.h"
#include "dem_test.h"

using namespace ::testing;

namespace retdec {
namespace demangler {
namespace tests {

class LlvmItaniumDemanglerTests : public Test
{
	public:
		using status = retdec::demangler::Demangler::Status;

		LlvmItaniumDemanglerTests():
			demangler(std::make_unique<retdec::demangler::ItaniumDemangler>()) {}

	protected:
		std::unique_ptr<retdec::demangler::Demangler> demangler;
};

TEST_F(LlvmItaniumDemanglerTests,
BasicTest)
{
	DEM_EQ("_ZN3fooILi1EEC5Ev", "foo<1>::foo()");
}

TEST_F(LlvmItaniumDemanglerTests, DemangleFunctionsStartingWithExtraUnderscore_bug1434)
{
	DEM_EQ("__ZN1A1B6myFuncEii", "A::B::myFunc(int, int)");
}

TEST_F(LlvmItaniumDemanglerTests, DemangleCppClassNamesWhenCharacterCountIsOk)
{
	DEM_EQ("7Polygon", "Polygon");
	DEM_EQ("14PolygonPolygon", "PolygonPolygon");
	DEM_EQ("19Polygon_1_Polygon_2", "Polygon_1_Polygon_2");
}

TEST_F(LlvmItaniumDemanglerTests, DoNotDemangleCppClassNamesWhenCharacterCountIsBad)
{
	DEM_FAIL("0Polygon", status::invalid_mangled_name);
	DEM_FAIL("6Polygon", status::invalid_mangled_name);
	DEM_FAIL("8Polygon", status::invalid_mangled_name);
}

TEST_F(LlvmItaniumDemanglerTests, DoNotDemangleCppClassNamesWhenTheyDoNotMatchRegex)
{
	DEM_FAIL("enc_vad_21363218732487324784rufdekdfbnerwquie2r6732", status::invalid_mangled_name);
	DEM_FAIL(" 7Polygon", status::invalid_mangled_name); // std::regex_match
	DEM_FAIL("7Polygon ", status::invalid_mangled_name); // std::regex_match
	DEM_FAIL(" 7Polygon ", status::invalid_mangled_name); // std::regex_match
}

TEST_F(LlvmItaniumDemanglerTests, RandomTests)
{
	DEM_EQ("_ZN5cGram11bagrneplaveEPKN5cName6type_tES3_",
		   "cGram::bagrneplave(cName::type_t const*, cName::type_t const*)");

	DEM_EQ("_ZN5cGram11bagrneplaveERKPKPKN5cName6type_tESt6vectorIS1_SaIS1_EES8_IPS1_SaISB_EES8_IS3_SaIS3_EES8_IPKSB_SaISH_EES3_",
		   "cGram::bagrneplave(cName::type_t const* const* const&, std::vector<cName::type_t, std::allocator<cName::type_t> >, std::vector<cName::type_t*, std::allocator<cName::type_t*> >, std::vector<cName::type_t const*, std::allocator<cName::type_t const*> >, std::vector<cName::type_t* const*, std::allocator<cName::type_t* const*> >, cName::type_t const*)");

	DEM_EQ("_ZN5cGram3eofEv",
		   "cGram::eof()");

	DEM_EQ("_ZN9__gnu_cxx13new_allocatorIN5cGram7gelem_tEEC2ERKS3_",
		   "__gnu_cxx::new_allocator<cGram::gelem_t>::new_allocator(__gnu_cxx::new_allocator<cGram::gelem_t> const&)");

	DEM_EQ("_ZN9__gnu_cxx13new_allocatorISt13_Rb_tree_nodeISt4pairIKSsSt3mapIcS2_IjN5cGram6semactEESt4lessIcESaIS2_IKcS7_EEEEEED2Ev",
		   "__gnu_cxx::new_allocator<std::_Rb_tree_node<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > > >::~new_allocator()");

	DEM_EQ("_ZN9__gnu_cxxmiIPN5cGram6rule_tESt6vectorIS2_SaIS2_EEEENS_17__normal_iteratorIT_T0_E15difference_typeERKSA_SD_",
		   "__gnu_cxx::__normal_iterator<cGram::rule_t*, std::vector<cGram::rule_t, std::allocator<cGram::rule_t> > >::difference_type __gnu_cxx::operator-<cGram::rule_t*, std::vector<cGram::rule_t, std::allocator<cGram::rule_t> > >(__gnu_cxx::__normal_iterator<cGram::rule_t*, std::vector<cGram::rule_t, std::allocator<cGram::rule_t> > > const&, __gnu_cxx::__normal_iterator<cGram::rule_t*, std::vector<cGram::rule_t, std::allocator<cGram::rule_t> > > const&)");

	DEM_EQ("_ZNKSs5c_strEv",
		   "std::string::c_str() const");

	DEM_EQ("_ZNKSt17_Rb_tree_iteratorISt4pairIKSsSt3mapIcS0_IjN5cGram6semactEESt4lessIcESaIS0_IKcS5_EEEEEneERKSD_",
		   "std::_Rb_tree_iterator<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > >::operator!=(std::_Rb_tree_iterator<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > > const&) const");

	DEM_EQ("_ZNKSt5dequeIN5cGram7gelem_tESaIS1_EE5beginEv",
		   "std::deque<cGram::gelem_t, std::allocator<cGram::gelem_t> >::begin() const");

	DEM_EQ("_ZNKSt8_Rb_treeISsSt4pairIKSsSt3mapIcS0_IjN5cGram6semactEESt4lessIcESaIS0_IKcS5_EEEESt10_Select1stISC_ES6_ISsESaISC_EE8key_compEv",
		   "std::_Rb_tree<std::string, std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > >, std::_Select1st<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > >, std::less<std::string>, std::allocator<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > > >::key_comp() const");

	DEM_EQ("_ZNSspLERKSs",
		   "std::string::operator+=(std::string const&)");

	DEM_EQ("_ZNSt11_Deque_baseISt6vectorISsSaISsEESaIS2_EE15_M_allocate_mapEj",
		   "std::_Deque_base<std::vector<std::string, std::allocator<std::string> >, std::allocator<std::vector<std::string, std::allocator<std::string> > > >::_M_allocate_map(unsigned int)");

	DEM_EQ("_ZNSt12__miter_baseIPN5cName6type_tELb0EE3__bES2_",
		   "std::__miter_base<cName::type_t*, false>::__b(cName::type_t*)");

	DEM_EQ("_ZNSt3mapISsS_IcSt4pairIjN5cGram6semactEESt4lessIcESaIS0_IKcS3_EEES4_ISsESaIS0_IKSsS9_EEE5clearEv",
		   "std::map<std::string, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > >, std::less<std::string>, std::allocator<std::pair<std::string const, std::map<char, std::pair<unsigned int, cGram::semact>, std::less<char>, std::allocator<std::pair<char const, std::pair<unsigned int, cGram::semact> > > > > > >::clear()");

	DEM_EQ("_ZNSt5stackISsSt5dequeISsSaISsEEEC1ERKS2_",
		   "std::stack<std::string, std::deque<std::string, std::allocator<std::string> > >::stack(std::deque<std::string, std::allocator<std::string> > const&)");

	DEM_EQ("_ZNSt8_Rb_treeISsSt4pairIKSsSt3setIN5cGram7gelem_tENS3_14comparegelem_cESaIS4_EEESt10_Select1stIS8_ESt4lessISsESaIS8_EE6_S_keyEPKSt18_Rb_tree_node_base",
		   "std::_Rb_tree<std::string, std::pair<std::string const, std::set<cGram::gelem_t, cGram::comparegelem_c, std::allocator<cGram::gelem_t> > >, std::_Select1st<std::pair<std::string const, std::set<cGram::gelem_t, cGram::comparegelem_c, std::allocator<cGram::gelem_t> > > >, std::less<std::string>, std::allocator<std::pair<std::string const, std::set<cGram::gelem_t, cGram::comparegelem_c, std::allocator<cGram::gelem_t> > > > >::_S_key(std::_Rb_tree_node_base const*)");

	DEM_EQ("_ZSt14__copy_move_a2ILb0EN9__gnu_cxx17__normal_iteratorIPKN5cName6name_tESt6vectorIS3_SaIS3_EEEENS1_IPS3_S8_EEET1_T0_SD_SC_",
		   "__gnu_cxx::__normal_iterator<cName::name_t*, std::vector<cName::name_t, std::allocator<cName::name_t> > > std::__copy_move_a2<false, __gnu_cxx::__normal_iterator<cName::name_t const*, std::vector<cName::name_t, std::allocator<cName::name_t> > >, __gnu_cxx::__normal_iterator<cName::name_t*, std::vector<cName::name_t, std::allocator<cName::name_t> > > >(__gnu_cxx::__normal_iterator<cName::name_t const*, std::vector<cName::name_t, std::allocator<cName::name_t> > >, __gnu_cxx::__normal_iterator<cName::name_t const*, std::vector<cName::name_t, std::allocator<cName::name_t> > >, __gnu_cxx::__normal_iterator<cName::name_t*, std::vector<cName::name_t, std::allocator<cName::name_t> > >)");

	DEM_EQ("_ZSt8_DestroyIN5cGram7gelem_tEEvPT_",
		   "void std::_Destroy<cGram::gelem_t>(cGram::gelem_t*)");
}

TEST_F(LlvmItaniumDemanglerTests, GCCTestSuite){
	DEM_EQ("_Z3fo5n", "fo5(__int128)");
	DEM_EQ("_Z3fo5o", "fo5(unsigned __int128)");
	DEM_EQ("St9bad_alloc", "std::bad_alloc");
	DEM_EQ("_ZN1f1fE", "f::f");
	DEM_EQ("_Z1fv", "f()");
	DEM_EQ("_Z1fi", "f(int)");
	DEM_EQ("_Z3foo3bar", "foo(bar)");
	DEM_EQ("_Zrm1XS_", "operator%(X, X)");
	DEM_EQ("_ZplR1XS0_", "operator+(X&, X&)");
	DEM_EQ("_ZlsRK1XS1_", "operator<<(X const&, X const&)");
	DEM_EQ("_ZN3FooIA4_iE3barE", "Foo<int [4]>::bar");
	DEM_EQ("_Z1fIiEvi", "void f<int>(int)");
	DEM_EQ("_Z5firstI3DuoEvS0_", "void first<Duo>(Duo)");
	DEM_EQ("_Z5firstI3DuoEvT_", "void first<Duo>(Duo)");
	DEM_EQ("_Z3fooIiFvdEiEvv", "void foo<int, void (double), int>()");
	DEM_EQ("_Z1fIFvvEEvv", "void f<void ()>()");
	DEM_EQ("_ZN1N1fE", "N::f");
	DEM_EQ("_ZN6System5Sound4beepEv", "System::Sound::beep()");
	DEM_EQ("_ZN5Arena5levelE", "Arena::level");
	DEM_EQ("_ZN5StackIiiE5levelE", "Stack<int, int>::level");
	DEM_EQ("_Z1fI1XEvPVN1AIT_E1TE", "void f<X>(A<X>::T volatile*)");
	DEM_EQ("_ZngILi42EEvN1AIXplT_Li2EEE1TE", "void operator-<42>(A<(42) + (2)>::T)");
	DEM_EQ("_Z4makeI7FactoryiET_IT0_Ev", "Factory<int> make<Factory, int>()");
	DEM_EQ("_Z4makeI7FactoryiET_IT0_Ev", "Factory<int> make<Factory, int>()");
	DEM_EQ("_Z3foo5Hello5WorldS0_S_", "foo(Hello, World, World, Hello)");
	DEM_EQ("_Z3fooPM2ABi", "foo(int AB::**)");
	DEM_EQ("_ZlsRSoRKSs", "operator<<(std::ostream&, std::string const&)");
	DEM_EQ("_ZTI7a_class", "typeinfo for a_class");
	DEM_EQ("U4_farrVKPi", "int* const volatile restrict _far");
	DEM_EQ("_Z3fooILi2EEvRAplT_Li1E_i", "void foo<2>(int (&) [(2) + (1)])");
	DEM_EQ("_Z3fooILi2EEvOAplT_Li1E_i", "void foo<2>(int (&&) [(2) + (1)])");
	DEM_EQ("_Z1fM1AKFvvE", "f(void (A::*)() const)");
	DEM_EQ("_Z3fooc", "foo(char)");
	DEM_EQ("_Z2f0u8char16_t", "f0(char16_t)");
	DEM_EQ("_Z2f0Pu8char16_t", "f0(char16_t*)");
	DEM_EQ("_Z2f0u8char32_t", "f0(char32_t)");
	DEM_EQ("_Z2f0Pu8char32_t", "f0(char32_t*)");
	DEM_EQ("2CBIL_Z3foocEE", "CB<foo(char)>");
	DEM_EQ("2CBIL_Z7IsEmptyEE", "CB<IsEmpty>");
	DEM_EQ("_ZZN1N1fEiE1p", "N::f(int)::p");
	DEM_EQ("_ZZN1N1fEiEs", "N::f(int)::string literal");
	DEM_EQ("_Z1fPFvvEM1SFvvE", "f(void (*)(), void (S::*)())");
	DEM_EQ("_ZN1N1TIiiE2mfES0_IddE", "N::T<int, int>::mf(N::T<double, double>)");
	DEM_EQ("_ZSt5state", "std::state");
	DEM_EQ("_ZNSt3_In4wardE", "std::_In::ward");
	DEM_EQ("_Z1fKPFiiE", "f(int (* const)(int))");
	DEM_EQ("_Z1fAszL_ZZNK1N1A1fEvE3foo_0E_i", "f(int [sizeof (N::A::f() const::foo)])");
	DEM_EQ("_Z1fA37_iPS_", "f(int [37], int (*) [37])");
	DEM_EQ("_Z1fM1AFivEPS0_", "f(int (A::*)(), int (*)())");
	DEM_EQ("_Z1fPFPA1_ivE", "f(int (* (*)()) [1])");
	DEM_EQ("_Z1fPKM1AFivE", "f(int (A::* const*)())");
	DEM_EQ("_Z1jM1AFivEPS1_", "j(int (A::*)(), int (A::**)())");
	DEM_EQ("_Z1sPA37_iPS0_", "s(int (*) [37], int (**) [37])");
	DEM_EQ("_Z3fooA30_A_i", "foo(int [30][])");
	DEM_EQ("_Z3kooPA28_A30_i", "koo(int (*) [28][30])");
	DEM_EQ("_Z1fM1AKFivE", "f(int (A::*)() const)");
	DEM_EQ("_Z3absILi11EEvv", "void abs<11>()");
	DEM_EQ("_ZN1AIfEcvT_IiEEv", "A<float>::operator int<int>()");
	DEM_EQ("_ZN12libcw_app_ct10add_optionIS_EEvMT_FvPKcES3_cS3_S3_", "void libcw_app_ct::add_option<libcw_app_ct>(void (libcw_app_ct::*)(char const*), char const*, char, char const*, char const*)");
	DEM_EQ("_ZGVN5libcw24_GLOBAL__N_cbll.cc0ZhUKa23compiler_bug_workaroundISt6vectorINS_13omanip_id_tctINS_5debug32memblk_types_manipulator_data_ctEEESaIS6_EEE3idsE", "guard variable for libcw::(anonymous namespace)::compiler_bug_workaround<std::vector<libcw::omanip_id_tct<libcw::debug::memblk_types_manipulator_data_ct>, std::allocator<libcw::omanip_id_tct<libcw::debug::memblk_types_manipulator_data_ct> > > >::ids");
	DEM_EQ("_ZN5libcw5debug13cwprint_usingINS_9_private_12GlobalObjectEEENS0_17cwprint_using_tctIT_EERKS5_MS5_KFvRSt7ostreamE", "libcw::debug::cwprint_using_tct<libcw::_private_::GlobalObject> libcw::debug::cwprint_using<libcw::_private_::GlobalObject>(libcw::_private_::GlobalObject const&, void (libcw::_private_::GlobalObject::*)(std::ostream&) const)");
	DEM_EQ("_ZNKSt14priority_queueIP27timer_event_request_base_ctSt5dequeIS1_SaIS1_EE13timer_greaterE3topEv", "std::priority_queue<timer_event_request_base_ct*, std::deque<timer_event_request_base_ct*, std::allocator<timer_event_request_base_ct*> >, timer_greater>::top() const");
	DEM_EQ("_ZNKSt15_Deque_iteratorIP15memory_block_stRKS1_PS2_EeqERKS5_", "std::_Deque_iterator<memory_block_st*, memory_block_st* const&, memory_block_st* const*>::operator==(std::_Deque_iterator<memory_block_st*, memory_block_st* const&, memory_block_st* const*> const&) const");
	DEM_EQ("_ZNKSt17__normal_iteratorIPK6optionSt6vectorIS0_SaIS0_EEEmiERKS6_", "std::__normal_iterator<option const*, std::vector<option, std::allocator<option> > >::operator-(std::__normal_iterator<option const*, std::vector<option, std::allocator<option> > > const&) const");
	DEM_EQ("_ZNSbIcSt11char_traitsIcEN5libcw5debug27no_alloc_checking_allocatorEE12_S_constructIPcEES6_T_S7_RKS3_", "char* std::basic_string<char, std::char_traits<char>, libcw::debug::no_alloc_checking_allocator>::_S_construct<char*>(char*, char*, libcw::debug::no_alloc_checking_allocator const&)");
	DEM_EQ("_Z1fI1APS0_PKS0_EvT_T0_T1_PA4_S3_M1CS8_", "void f<A, A*, A const*>(A, A*, A const*, A const* (*) [4], A const* (* C::*) [4])");
	DEM_EQ("_Z3fooiPiPS_PS0_PS1_PS2_PS3_PS4_PS5_PS6_PS7_PS8_PS9_PSA_PSB_PSC_", "foo(int, int*, int**, int***, int****, int*****, int******, int*******, int********, int*********, int**********, int***********, int************, int*************, int**************, int***************)");
	DEM_EQ("_ZSt1BISt1DIP1ARKS2_PS3_ES0_IS2_RS2_PS2_ES2_ET0_T_SB_SA_PT1_", "std::D<A*, A*&, A**> std::B<std::D<A*, A* const&, A* const*>, std::D<A*, A*&, A**>, A*>(std::D<A*, A* const&, A* const*>, std::D<A*, A* const&, A* const*>, std::D<A*, A*&, A**>, A**)");
	DEM_EQ("_ZNSt13_Alloc_traitsISbIcSt18string_char_traitsIcEN5libcw5debug9_private_17allocator_adaptorIcSt24__default_alloc_templateILb0ELi327664EELb1EEEENS5_IS9_S7_Lb1EEEE15_S_instancelessE", "std::_Alloc_traits<std::basic_string<char, std::string_char_traits<char>, libcw::debug::_private_::allocator_adaptor<char, std::__default_alloc_template<false, 327664>, true> >, libcw::debug::_private_::allocator_adaptor<std::basic_string<char, std::string_char_traits<char>, libcw::debug::_private_::allocator_adaptor<char, std::__default_alloc_template<false, 327664>, true> >, std::__default_alloc_template<false, 327664>, true> >::_S_instanceless");
	DEM_EQ("_Z1rM1GFivEMS_KFivES_M1HFivES1_4whatIKS_E5what2IS8_ES3_", "r(int (G::*)(), int (G::*)() const, G, int (H::*)(), int (G::*)(), what<G const>, what2<G const>, int (G::*)() const)");
	DEM_EQ("_Z10hairyfunc5PFPFilEPcE", "hairyfunc5(int (* (*)(char*))(long))");
	DEM_EQ("_ZNK11__gnu_debug16_Error_formatter14_M_format_wordImEEvPciPKcT_", "void __gnu_debug::_Error_formatter::_M_format_word<unsigned long>(char*, int, char const*, unsigned long) const");
	DEM_EQ("_ZSt18uninitialized_copyIN9__gnu_cxx17__normal_iteratorIPSt4pairISsPFbP6sqlitePPcEESt6vectorIS9_SaIS9_EEEESE_ET0_T_SG_SF_", "__gnu_cxx::__normal_iterator<std::pair<std::string, bool (*)(sqlite*, char**)>*, std::vector<std::pair<std::string, bool (*)(sqlite*, char**)>, std::allocator<std::pair<std::string, bool (*)(sqlite*, char**)> > > > std::uninitialized_copy<__gnu_cxx::__normal_iterator<std::pair<std::string, bool (*)(sqlite*, char**)>*, std::vector<std::pair<std::string, bool (*)(sqlite*, char**)>, std::allocator<std::pair<std::string, bool (*)(sqlite*, char**)> > > >, __gnu_cxx::__normal_iterator<std::pair<std::string, bool (*)(sqlite*, char**)>*, std::vector<std::pair<std::string, bool (*)(sqlite*, char**)>, std::allocator<std::pair<std::string, bool (*)(sqlite*, char**)> > > > >(__gnu_cxx::__normal_iterator<std::pair<std::string, bool (*)(sqlite*, char**)>*, std::vector<std::pair<std::string, bool (*)(sqlite*, char**)>, std::allocator<std::pair<std::string, bool (*)(sqlite*, char**)> > > >, __gnu_cxx::__normal_iterator<std::pair<std::string, bool (*)(sqlite*, char**)>*, std::vector<std::pair<std::string, bool (*)(sqlite*, char**)>, std::allocator<std::pair<std::string, bool (*)(sqlite*, char**)> > > >, __gnu_cxx::__normal_iterator<std::pair<std::string, bool (*)(sqlite*, char**)>*, std::vector<std::pair<std::string, bool (*)(sqlite*, char**)>, std::allocator<std::pair<std::string, bool (*)(sqlite*, char**)> > > >)");
	DEM_EQ("_Z1fP1cIPFiiEE", "f(c<int (*)(int)>*)");
	DEM_EQ("_Z4dep9ILi3EEvP3fooIXgtT_Li2EEE", "void dep9<3>(foo<((3) > (2))>*)");
	DEM_EQ("_ZStltI9file_pathSsEbRKSt4pairIT_T0_ES6_", "bool std::operator<<file_path, std::string>(std::pair<file_path, std::string> const&, std::pair<file_path, std::string> const&)");
	DEM_EQ("_Z1fILin1EEvv", "void f<-1>()");
	DEM_EQ("_ZNSdD0Ev", "std::basic_iostream<char, std::char_traits<char> >::~basic_iostream()");
	DEM_EQ("_ZNK15nsBaseHashtableI15nsUint32HashKey8nsCOMPtrI4IFooEPS2_E13EnumerateReadEPF15PLDHashOperatorRKjS4_PvES9_", "nsBaseHashtable<nsUint32HashKey, nsCOMPtr<IFoo>, IFoo*>::EnumerateRead(PLDHashOperator (*)(unsigned int const&, IFoo*, void*), void*) const");
	DEM_EQ("_ZZZ3BBdI3FooEvvENK3Fob3FabEvENK3Gob3GabEv", "void BBd<Foo>()::Fob::Fab() const::Gob::Gab() const");
	DEM_EQ("_ZNK5boost6spirit5matchI13rcs_deltatextEcvMNS0_4impl5dummyEFvvEEv", "boost::spirit::match<rcs_deltatext>::operator void (boost::spirit::impl::dummy::*)()() const");
	DEM_EQ("_Z3fooIA3_iEvRKT_", "void foo<int [3]>(int const (&) [3])");
	DEM_EQ("_Z3fooIPA3_iEvRKT_", "void foo<int (*) [3]>(int (* const&) [3])");
	DEM_EQ("_ZN13PatternDriver23StringScalarDeleteValueC1ERKNS_25ConflateStringScalarValueERKNS_25AbstractStringScalarValueERKNS_12TemplateEnumINS_12pdcomplementELZNS_16complement_namesEELZNS_14COMPLEMENTENUMEEEE", "PatternDriver::StringScalarDeleteValue::StringScalarDeleteValue(PatternDriver::ConflateStringScalarValue const&, PatternDriver::AbstractStringScalarValue const&, PatternDriver::TemplateEnum<PatternDriver::pdcomplement, PatternDriver::complement_names, PatternDriver::COMPLEMENTENUM> const&)");
	DEM_EQ("_Z3addIidEDTplfp_fp0_ET_T0_", "decltype((fp) + (fp0)) add<int, double>(int, double)");
	DEM_EQ("_Z1fI1SENDtfp_E4typeET_", "decltype(fp)::type f<S>(S)");
	DEM_EQ("_Z4add3IidEDTclL_Z1gEfp_fp0_EET_T0_", "decltype(g(fp, fp0)) add3<int, double>(int, double)");
	DEM_EQ("_Z1hI1AIiEdEDTcldtfp_1gIT0_EEET_S2_", "decltype(fp.g<double>()) h<A<int>, double>(A<int>, double)");
	DEM_EQ("_Z1gIJidEEDTclL_Z1fEspplfp_Li1EEEDpT_", "decltype(f((fp) + (1)...)) g<int, double>(int, double)");
	DEM_EQ("_ZZ1giENKUlvE_clEv", "g(int)::'lambda'()::operator()() const");
	DEM_EQ("_Z4algoIZ1giEUlvE0_EiT_", "int algo<g(int)::'lambda0'()>(g(int)::'lambda0'())");
	DEM_EQ("_ZNK1SIiE1xMUlvE1_clEv", "S<int>::x::'lambda1'()::operator()() const");
	DEM_EQ("_Z1fN1SUt_E", "f(S::'unnamed')");
	DEM_EQ("_Z1fI1AEDTclonplfp_fp_EET_", "decltype(operator+(fp, fp)) f<A>(A)");
	DEM_EQ("_Z1fIRiEvOT_b", "void f<int&>(int&, bool)");
	DEM_EQ("_ZN5aaaaa6bbbbbb5cccccIN23ddddddddddddddddddddddd3eeeENS2_4ffff16ggggggggggggggggENS0_9hhhhhhhhhES6_S6_S6_S6_S6_S6_S6_EE", "aaaaa::bbbbbb::ccccc<ddddddddddddddddddddddd::eee, ddddddddddddddddddddddd::ffff::gggggggggggggggg, aaaaa::bbbbbb::hhhhhhhhh, aaaaa::bbbbbb::hhhhhhhhh, aaaaa::bbbbbb::hhhhhhhhh, aaaaa::bbbbbb::hhhhhhhhh, aaaaa::bbbbbb::hhhhhhhhh, aaaaa::bbbbbb::hhhhhhhhh, aaaaa::bbbbbb::hhhhhhhhh, aaaaa::bbbbbb::hhhhhhhhh>");
	DEM_EQ("_Z5outerIsEcPFilE", "char outer<short>(int (*)(long))");
	DEM_EQ("_Z5outerPFsiEl", "outer(short (*)(int), long)");
	DEM_EQ("_Z6outer2IsEPFilES1_", "int (*outer2<short>(int (*)(long)))(long)");
	DEM_EQ("_Z5outerPFsiEl", "outer(short (*)(int), long)");
	DEM_EQ("_Z5outerIsEcPFilE", "char outer<short>(int (*)(long))");
	DEM_EQ("_Z5outerPFsiEl", "outer(short (*)(int), long)");
	DEM_EQ("_Z1fIJiEiEv1AIJDpT_EET0_S4_", "void f<int, int>(A<int>, int, int)");
	DEM_EQ("_Z1fIiiEDTcvT__EET0_S2_", "decltype((int)()) f<int, int>(int, int)");
	DEM_EQ("_Z2f1Ii1AEDTdsfp_fp0_ET0_MS2_T_", "decltype(fp.*fp0) f1<int, A>(A, int A::*)");
	DEM_EQ("_Z2f2IiEDTquL_Z1bEfp_trET_", "decltype((b) ? (fp) : (throw)) f2<int>(int)");
	DEM_EQ("_Z6check1IiEvP6helperIXsznw_T_EEE", "void check1<int>(helper<sizeof (new int)>*)");
	DEM_EQ("_Z6check3IiEvP6helperIXsznwadL_Z1iE_T_piLi1EEEE", "void check3<int>(helper<sizeof (new (&(i))int(1))>*)");
	DEM_EQ("_Z1fIiEDTcmdafp_psfp_EPT_", "decltype((delete[] fp) , (+(fp))) f<int>(int*)");
	DEM_EQ("_ZN1AdlEPv", "A::operator delete(void*)");
	DEM_EQ("_Z2f1IiEDTppfp_ET_", "decltype((fp)++) f1<int>(int)");
	DEM_EQ("_Z2f1IiEDTpp_fp_ET_", "decltype(++(fp)) f1<int>(int)");
	DEM_EQ("_Z2f1IiEDTcl1gfp_ilEEET_", "decltype(g(fp, {})) f1<int>(int)");
	DEM_EQ("_Zli2_wPKc", "operator\"\" _w(char const*)");
	DEM_EQ("_Z1fIiEDTnw_Dapifp_EET_", "decltype(new auto(fp)) f<int>(int)");
	DEM_EQ("_Z1fIiERDaRKT_S1_", "auto& f<int>(int const&, int)");
	DEM_EQ("_Z1gIiEDcRKT_S0_", "decltype(auto) g<int>(int const&, int)");
	DEM_EQ("_Z1gILi1EEvR1AIXT_EER1BIXscbT_EE", "void g<1>(A<1>&, B<static_cast<bool>(1)>&)");
	DEM_EQ("_ZNKSt7complexIiE4realB5cxx11Ev", "std::complex<int>::real[abi:cxx11]() const");
	DEM_EQ("_Z1fIKFvvES0_Evv", "void f<void () const, void () const>()");
	DEM_EQ("_ZNKR1A1hEv", "A::h() const &");
	DEM_EQ("_Z1lM1AKFvvRE", "l(void (A::*)() const &)");
	DEM_EQ("_Z1mIFvvOEEvM1AT_", "void m<void () &&>(void (A::*)() &&)");
	DEM_EQ("_Z1nIM1AKFvvREEvT_", "void n<void (A::*)() const &>(void (A::*)() const &)");
	DEM_EQ("_ZL1fIiEvv", "void f<int>()");
	DEM_EQ("_ZNK7strings8internal8SplitterINS_9delimiter5AnyOfENS_9SkipEmptyEEcvT_ISt6vectorI12basic_stringIcSt11char_traitsIcESaIcEESaISD_EEvEEv", "strings::internal::Splitter<strings::delimiter::AnyOf, strings::SkipEmpty>::operator std::vector<basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<basic_string<char, std::char_traits<char>, std::allocator<char> > > ><std::vector<basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<basic_string<char, std::char_traits<char>, std::allocator<char> > > >, void>() const");
	DEM_EQ("_ZN1AcvT_I1CEEv", "A::operator C<C>()");
	DEM_EQ("_ZN1AcvPT_I1CEEv", "A::operator C*<C>()");
	DEM_EQ("_ZN1AcvT_IiEI1CEEv", "A::operator C<int><C>()");
	DEM_EQ("_Z1fSsB3fooS_", "f(std::string[abi:foo], std::string[abi:foo])");
	DEM_EQ("_Z13function_tempIiEv1AIXszcvT_Li999EEE", "void function_temp<int>(A<sizeof ((int)(999))>)");
	DEM_EQ("_Z14int_if_addableI1YERiP1AIXszpldecvPT_Li0EdecvS4_Li0EEE", "int& int_if_addable<Y>(A<sizeof ((*((Y*)(0))) + (*((Y*)(0))))>*)");
	DEM_EQ("_Z3fooI1FEN1XIXszdtcl1PclcvT__EEE5arrayEE4TypeEv", "X<sizeof (P((F)()()).array)>::Type foo<F>()");
}

TEST_F(LlvmItaniumDemanglerTests, BasicTests) {
	DEM_EQ("_Z3fooPA3_dPKdd", "foo(double (*) [3], double const*, double)");
	DEM_EQ("_Z3fooPFvPiE", "foo(void (*)(int*))");
	DEM_EQ("_Z3fooPFvPiES1_", "foo(void (*)(int*), void (*)(int*))");
	DEM_EQ("_Z3fooPFPFvPiEvE", "foo(void (* (*)())(int*))");
	DEM_EQ("_Z3fooPiS_", "foo(int*, int*)");
	DEM_EQ("_Z3fooPFvvES0_", "foo(void (*)(), void (*)())");
	DEM_EQ("_Z3fooPKPFvvES2_", "foo(void (* const*)(), void (* const*)())");
	DEM_EQ("_Z3fooPPFvvES1_", "foo(void (**)(), void (**)())");
	DEM_EQ("_Z3fooPK1SS1_", "foo(S const*, S const*)");
}

TEST_F(LlvmItaniumDemanglerTests, issue_96) {
	DEM_EQ("_ZL21size_of_encoded_valueh", "size_of_encoded_value(unsigned char)");
	DEM_EQ("_ZStmiISt6vectorIN5cName6type_tESaIS2_EERS4_PS4_ENSt15_Deque_iteratorIT_T0_T1_E15difference_typeERKSB_SE_", "std::_Deque_iterator<std::vector<cName::type_t, std::allocator<cName::type_t> >, std::vector<cName::type_t, std::allocator<cName::type_t> >&, std::vector<cName::type_t, std::allocator<cName::type_t> >*>::difference_type std::operator-<std::vector<cName::type_t, std::allocator<cName::type_t> >, std::vector<cName::type_t, std::allocator<cName::type_t> >&, std::vector<cName::type_t, std::allocator<cName::type_t> >*>(std::_Deque_iterator<std::vector<cName::type_t, std::allocator<cName::type_t> >, std::vector<cName::type_t, std::allocator<cName::type_t> >&, std::vector<cName::type_t, std::allocator<cName::type_t> >*> const&, std::_Deque_iterator<std::vector<cName::type_t, std::allocator<cName::type_t> >, std::vector<cName::type_t, std::allocator<cName::type_t> >&, std::vector<cName::type_t, std::allocator<cName::type_t> >*> const&)");
	DEM_EQ("_ZTI5cName", "typeinfo for cName");
	DEM_EQ("_ZTS5cName", "typeinfo name for cName");
	DEM_EQ("_ZTVN10__cxxabiv117__class_type_infoE", "vtable for __cxxabiv1::__class_type_info");
	DEM_EQ("_ZdlPvS_", "operator delete(void*, void*)");
}

} // namespace tests
} // namespace demangler
} // namespace retdec
