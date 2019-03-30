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

class MsCtypesTests : public Test
{
public:
	using status = retdec::demangler::Demangler::Status;

	MsCtypesTests() :
		demangler(std::make_unique<retdec::demangler::MicrosoftDemangler>()),
		context(std::make_shared<retdec::ctypes::Context>()),
		module(std::make_shared<ctypes::Module>(context)) {}
protected:
	std::shared_ptr<ctypes::Function> mangledToCtypes(
		const std::string &mangled)
	{
		return demangler->demangleFunctionToCtypes(mangled, module);
	}

	std::unique_ptr<retdec::demangler::Demangler> demangler;
	std::shared_ptr<retdec::ctypes::Context> context;
	std::shared_ptr<retdec::ctypes::Module> module;
};

TEST_F(MsCtypesTests, basic)
{
	mangledToCtypes("?foo@@YAXI@Z");	// void __cdecl foo(unsigned int)

	EXPECT_TRUE(module->hasFunctionWithName("?foo@@YAXI@Z"));

	auto func = module->getFunctionWithName("?foo@@YAXI@Z");

	EXPECT_TRUE(func->getReturnType()->isVoid());

	EXPECT_EQ(func->getParameterCount(), 1);
	EXPECT_FALSE(func->isVarArg());
	EXPECT_TRUE(func->getParameter(1).getType()->isIntegral());
}

TEST_F(MsCtypesTests, Types)
{
	mangledToCtypes("?foo@@YAXFGHIJK_J_KCED_W_S_UMNO_N@Z");

	EXPECT_TRUE(module->hasFunctionWithName("?foo@@YAXFGHIJK_J_KCED_W_S_UMNO_N@Z"));

	auto func = module->getFunctionWithName("?foo@@YAXFGHIJK_J_KCED_W_S_UMNO_N@Z");

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
	EXPECT_EQ(param->getName(), "int64_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isSigned());

	param = func->getParameter(8).getType();
	EXPECT_EQ(param->getName(), "uint64_t");
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
	EXPECT_EQ(param->getName(), "wchar_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(13).getType();
	EXPECT_EQ(param->getName(), "char16_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(14).getType();
	EXPECT_EQ(param->getName(), "char32_t");
	EXPECT_TRUE(std::static_pointer_cast<ctypes::IntegralType>(param)->isUnsigned());

	param = func->getParameter(15).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "float");

	param = func->getParameter(16).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "double");

	param = func->getParameter(17).getType();
	EXPECT_TRUE(param->isFloatingPoint());
	EXPECT_EQ(param->getName(), "long double");

	param = func->getParameter(18).getType();
	EXPECT_EQ(param->getName(), "bool");
}

TEST_F(MsCtypesTests, Operators)
{
	mangledToCtypes("??_UTypedefNewDelete@@SAPAXI@Z");	// public: static void * __cdecl TypedefNewDelete::operator new[](unsigned int)

	EXPECT_TRUE(module->hasFunctionWithName("??_UTypedefNewDelete@@SAPAXI@Z"));
}

TEST_F(MsCtypesTests, NamedTypes)
{
	mangledToCtypes("?function@@YAXV?$C@$$A6AXXZ@@@Z");	// "void __cdecl function(class C<void __cdecl(void)>)"

	EXPECT_TRUE(module->hasFunctionWithName("?function@@YAXV?$C@$$A6AXXZ@@@Z"));
	auto func = module->getFunctionWithName("?function@@YAXV?$C@$$A6AXXZ@@@Z");

	EXPECT_EQ(func->getParameterCount(), 1);
	auto param = func->getParameter(1);
	EXPECT_TRUE(param.getType()->isNamed());
}

TEST_F(MsCtypesTests, TemplateTypes)
{
	mangledToCtypes("?ee@?$e@$$A6AXXZ@@EEAAXXZ");	// private: virtual void __cdecl e<void __cdecl(void)>::ee(void)

	EXPECT_TRUE(module->hasFunctionWithName("?ee@?$e@$$A6AXXZ@@EEAAXXZ"));
	auto func = module->getFunctionWithName("?ee@?$e@$$A6AXXZ@@EEAAXXZ");

	EXPECT_EQ(func->getParameterCount(), 0);
}

TEST_F(MsCtypesTests, All)
{
	mangledToCtypes("??D@YAPAXI@Z");
	mangledToCtypes("??1?$map@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_NU?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_N@std@@@2@@std@@QAE@XZ");
	mangledToCtypes("??_DcGram@@UAEPAXI@Z");
	mangledToCtypes("??_7type_info@@6B@");
	mangledToCtypes("??_R1A@?0A@EA@?$basic_iostream@DU?$char_traits@D@std@@@std@@8");
	mangledToCtypes("??1?$_Vector_iterator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@QAE@XZ");
	mangledToCtypes("?begin@?$vector@Urule_t@cGram@@V?$allocator@Urule_t@cGram@@@std@@@std@@QAE?AV?$_Vector_iterator@Urule_t@cGram@@V?$allocator@Urule_t@cGram@@@std@@@2@XZ");
	mangledToCtypes("?end@?$_Tree@V?$_Tmap_traits@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$map@DU?$pair@IW4semact@cGram@@@std@@U?$less@D@2@V?$allocator@U?$pair@$$CBDU?$pair@IW4semact@cGram@@@std@@@std@@@2@@2@U?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$map@DU?$pair@IW4semact@cGram@@@std@@U?$less@D@2@V?$allocator@U?$pair@$$CBDU?$pair@IW4semact@cGram@@@std@@@std@@@2@@2@@std@@@2@$0A@@std@@@std@@QAE?AViterator@12@XZ");
	mangledToCtypes("?erase@?$vector@IV?$allocator@I@std@@@std@@QAE?AV?$_Vector_iterator@IV?$allocator@I@std@@@2@V32@0@Z");
	mangledToCtypes("??0?$deque@Ugelem_t@cGram@@V?$allocator@Ugelem_t@cGram@@@std@@@std@@QAE@XZ");
	mangledToCtypes("??0iterator@?$_Tree@V?$_Tmap_traits@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@U?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@@std@@@2@$0A@@std@@@std@@QAE@PAU_Node@?$_Tree_nod@V?$_Tmap_traits@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@U?$less@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$set@Ugelem_t@cGram@@Vcomparegelem_c@2@V?$allocator@Ugelem_t@cGram@@@std@@@2@@std@@@2@$0A@@std@@@2@PBV12@@Z");
	mangledToCtypes("??G?$_Vector_const_iterator@Utype_t@cName@@V?$allocator@Utype_t@cName@@@std@@@std@@QBEHABV01@@Z");
	mangledToCtypes("??_R3bad_alloc@std@@8");
	mangledToCtypes("??D@YAPAXI@Z");
	mangledToCtypes("?x@@3HA");
	mangledToCtypes("?x@@3PEAHEA");
	mangledToCtypes("?x@@3PEAPEAHEA");
	mangledToCtypes("?x@@3PEAY02HEA");
	mangledToCtypes("?x@@3PEAY124HEA");
	mangledToCtypes("?x@@3PEAY02$$CBHEA");
	mangledToCtypes("?x@@3PEAEEA");
	mangledToCtypes("?x@@3PEAY1NKM@5HEA");
	mangledToCtypes("?x@@YAXMH@Z");
	mangledToCtypes("?x@@3P6AHMNH@ZEA");
	mangledToCtypes("?x@@3P6AHP6AHM@ZN@ZEA");
	mangledToCtypes("?x@@3P6AHP6AHM@Z0@ZEA");
	mangledToCtypes("?x@ns@@3HA");
	mangledToCtypes("?x@@3PEAHEA");
	mangledToCtypes("?x@@3PEBHEB");
	mangledToCtypes("?x@@3QEAHEA");
	mangledToCtypes("?x@@3QEBHEB");
	mangledToCtypes("?x@@3AEBHEB");
	mangledToCtypes("?x@@3PEAUty@@EA");
	mangledToCtypes("?x@@3PEATty@@EA");
	mangledToCtypes("?x@@3PEAVty@@EA");
	mangledToCtypes("?x@@3PEAW4ty@@EA");
	mangledToCtypes("?x@@3PEAV?$tmpl@H@@EA");
	mangledToCtypes("?x@@3PEAU?$tmpl@H@@EA");
	mangledToCtypes("?x@@3PEAT?$tmpl@H@@EA");
	mangledToCtypes("?instance@@3Vklass@@A");
	mangledToCtypes("?instance$initializer$@@3P6AXXZEA");
	mangledToCtypes("??0klass@@QEAA@XZ");
	mangledToCtypes("??1klass@@QEAA@XZ");
	mangledToCtypes("?x@@YAHPEAVklass@@AEAV1@@Z");
	mangledToCtypes("?x@ns@@3PEAV?$klass@HH@1@EA");
	mangledToCtypes("?fn@?$klass@H@ns@@QEBAIXZ");
	mangledToCtypes("??4klass@@QEAAAEBV0@AEBV0@@Z");
	mangledToCtypes("??7klass@@QEAA_NXZ");
	mangledToCtypes("??8klass@@QEAA_NAEBV0@@Z");
	mangledToCtypes("??9klass@@QEAA_NAEBV0@@Z");
	mangledToCtypes("??Aklass@@QEAAH_K@Z");
	mangledToCtypes("??Cklass@@QEAAHXZ");
	mangledToCtypes("??Dklass@@QEAAHXZ");
	mangledToCtypes("??Eklass@@QEAAHXZ");
	mangledToCtypes("??Eklass@@QEAAHH@Z");
	mangledToCtypes("??Fklass@@QEAAHXZ");
	mangledToCtypes("??Fklass@@QEAAHH@Z");
	mangledToCtypes("??Hklass@@QEAAHH@Z");
	mangledToCtypes("??Gklass@@QEAAHH@Z");
	mangledToCtypes("??Iklass@@QEAAHH@Z");
	mangledToCtypes("??Jklass@@QEAAHH@Z");
	mangledToCtypes("??Kklass@@QEAAHH@Z");
	mangledToCtypes("??Mklass@@QEAAHH@Z");
	mangledToCtypes("??Nklass@@QEAAHH@Z");
	mangledToCtypes("??Oklass@@QEAAHH@Z");
	mangledToCtypes("??Pklass@@QEAAHH@Z");
	mangledToCtypes("??Qklass@@QEAAHH@Z");
	mangledToCtypes("??Rklass@@QEAAHH@Z");
	mangledToCtypes("??Sklass@@QEAAHXZ");
	mangledToCtypes("??Tklass@@QEAAHH@Z");
	mangledToCtypes("??Uklass@@QEAAHH@Z");
	mangledToCtypes("??Vklass@@QEAAHH@Z");
	mangledToCtypes("??Wklass@@QEAAHH@Z");
	mangledToCtypes("??Xklass@@QEAAHH@Z");
	mangledToCtypes("??Yklass@@QEAAHH@Z");
	mangledToCtypes("??Zklass@@QEAAHH@Z");
	mangledToCtypes("??_0klass@@QEAAHH@Z");
	mangledToCtypes("??_1klass@@QEAAHH@Z");
	mangledToCtypes("??_2klass@@QEAAHH@Z");
	mangledToCtypes("??_3klass@@QEAAHH@Z");
	mangledToCtypes("??_6klass@@QEAAHH@Z");
	mangledToCtypes("??6@YAAEBVklass@@AEBV0@H@Z");
	mangledToCtypes("??5@YAAEBVklass@@AEBV0@_K@Z");
	mangledToCtypes("??2@YAPEAX_KAEAVklass@@@Z");
	mangledToCtypes("??_U@YAPEAX_KAEAVklass@@@Z");
	mangledToCtypes("??3@YAXPEAXAEAVklass@@@Z");
	mangledToCtypes("??_V@YAXPEAXAEAVklass@@@Z");
	mangledToCtypes("?foo@@YAXI@Z");
	mangledToCtypes("?foo@@YAXN@Z  ");
	mangledToCtypes("?foo_pad@@YAXPAD@Z");
	mangledToCtypes("?foo_pad@@YAXPEAD@Z");
	mangledToCtypes("?foo_pbd@@YAXPBD@Z");
	mangledToCtypes("?foo_pbd@@YAXPEBD@Z");
	mangledToCtypes("?foo_pcd@@YAXPCD@Z");
	mangledToCtypes("?foo_pcd@@YAXPECD@Z");
	mangledToCtypes("?foo_qad@@YAXQAD@Z");
	mangledToCtypes("?foo_qad@@YAXQEAD@Z");
	mangledToCtypes("?foo_rad@@YAXRAD@Z");
	mangledToCtypes("?foo_rad@@YAXREAD@Z");
	mangledToCtypes("?foo_sad@@YAXSAD@Z");
	mangledToCtypes("?foo_sad@@YAXSEAD@Z");
	mangledToCtypes("?foo_piad@@YAXPIAD@Z");
	mangledToCtypes("?foo_piad@@YAXPEIAD@Z");
	mangledToCtypes("?foo_qiad@@YAXQIAD@Z");
	mangledToCtypes("?foo_qiad@@YAXQEIAD@Z");
	mangledToCtypes("?foo_riad@@YAXRIAD@Z");
	mangledToCtypes("?foo_riad@@YAXREIAD@Z");
	mangledToCtypes("?foo_siad@@YAXSIAD@Z");
	mangledToCtypes("?foo_siad@@YAXSEIAD@Z");
	mangledToCtypes("?foo_papad@@YAXPAPAD@Z");
	mangledToCtypes("?foo_papad@@YAXPEAPEAD@Z");
	mangledToCtypes("?foo_papbd@@YAXPAPBD@Z");
	mangledToCtypes("?foo_papbd@@YAXPEAPEBD@Z");
	mangledToCtypes("?foo_papcd@@YAXPAPCD@Z");
	mangledToCtypes("?foo_papcd@@YAXPEAPECD@Z");
	mangledToCtypes("?foo_pbqad@@YAXPBQAD@Z");
	mangledToCtypes("?foo_pbqad@@YAXPEBQEAD@Z");
	mangledToCtypes("?foo_pcrad@@YAXPCRAD@Z");
	mangledToCtypes("?foo_pcrad@@YAXPECREAD@Z");
	mangledToCtypes("?foo_qapad@@YAXQAPAD@Z");
	mangledToCtypes("?foo_qapad@@YAXQEAPEAD@Z");
	mangledToCtypes("?foo_rapad@@YAXRAPAD@Z");
	mangledToCtypes("?foo_rapad@@YAXREAPEAD@Z");
	mangledToCtypes("?foo_pbqbd@@YAXPBQBD@Z");
	mangledToCtypes("?foo_pbqbd@@YAXPEBQEBD@Z");
	mangledToCtypes("?foo_pbqcd@@YAXPBQCD@Z");
	mangledToCtypes("?foo_pbqcd@@YAXPEBQECD@Z");
	mangledToCtypes("?foo_pcrbd@@YAXPCRBD@Z");
	mangledToCtypes("?foo_pcrbd@@YAXPECREBD@Z");
	mangledToCtypes("?foo_pcrcd@@YAXPCRCD@Z");
	mangledToCtypes("?foo_pcrcd@@YAXPECRECD@Z");
	mangledToCtypes("?foo_abd@@YAXABD@Z");
	mangledToCtypes("?foo_abd@@YAXAEBD@Z");
	mangledToCtypes("?foo_aapad@@YAXAAPAD@Z");
	mangledToCtypes("?foo_aapad@@YAXAEAPEAD@Z");
	mangledToCtypes("?foo_aapbd@@YAXAAPBD@Z");
	mangledToCtypes("?foo_aapbd@@YAXAEAPEBD@Z");
	mangledToCtypes("?foo_abqad@@YAXABQAD@Z");
	mangledToCtypes("?foo_abqad@@YAXAEBQEAD@Z");
	mangledToCtypes("?foo_abqbd@@YAXABQBD@Z");
	mangledToCtypes("?foo_abqbd@@YAXAEBQEBD@Z");
	mangledToCtypes("?foo_aay144h@@YAXAAY144H@Z");
	mangledToCtypes("?foo_aay144h@@YAXAEAY144H@Z");
	mangledToCtypes("?foo_aay144cbh@@YAXAAY144$$CBH@Z");
	mangledToCtypes("?foo_aay144cbh@@YAXAEAY144$$CBH@Z");
	mangledToCtypes("?foo_qay144h@@YAX$$QAY144H@Z");
	mangledToCtypes("?foo_qay144h@@YAX$$QEAY144H@Z");
	mangledToCtypes("?foo_qay144cbh@@YAX$$QAY144$$CBH@Z");
	mangledToCtypes("?foo_qay144cbh@@YAX$$QEAY144$$CBH@Z");
	mangledToCtypes("?foo_p6ahxz@@YAXP6AHXZ@Z");
	mangledToCtypes("?foo_p6ahxz@@YAXP6AHXZ@Z");
	mangledToCtypes("?foo_a6ahxz@@YAXA6AHXZ@Z");
	mangledToCtypes("?foo_a6ahxz@@YAXA6AHXZ@Z");
	mangledToCtypes("?foo_q6ahxz@@YAX$$Q6AHXZ@Z");
	mangledToCtypes("?foo_q6ahxz@@YAX$$Q6AHXZ@Z");
	mangledToCtypes("?foo_qay04cbh@@YAXQAY04$$CBH@Z");
	mangledToCtypes("?foo_qay04cbh@@YAXQEAY04$$CBH@Z");
	mangledToCtypes("?foo@@YAXPAY02N@Z");
	mangledToCtypes("?foo@@YAXPEAY02N@Z");
	mangledToCtypes("?foo@@YAXQAN@Z");
	mangledToCtypes("?foo@@YAXQEAN@Z");
	mangledToCtypes("?foo_const@@YAXQBN@Z");
	mangledToCtypes("?foo_const@@YAXQEBN@Z");
	mangledToCtypes("?foo_volatile@@YAXQCN@Z");
	mangledToCtypes("?foo_volatile@@YAXQECN@Z");
	mangledToCtypes("?foo@@YAXPAY02NQBNN@Z");
	mangledToCtypes("?foo@@YAXPEAY02NQEBNN@Z");
	mangledToCtypes("?foo_fnptrconst@@YAXP6AXQAH@Z@Z");
	mangledToCtypes("?foo_fnptrconst@@YAXP6AXQEAH@Z@Z");
	mangledToCtypes("?foo_fnptrarray@@YAXP6AXQAH@Z@Z");
	mangledToCtypes("?foo_fnptrarray@@YAXP6AXQEAH@Z@Z");
	mangledToCtypes("?foo_fnptrbackref1@@YAXP6AXQAH@Z1@Z");
	mangledToCtypes("?foo_fnptrbackref1@@YAXP6AXQEAH@Z1@Z");
	mangledToCtypes("?foo_fnptrbackref2@@YAXP6AXQAH@Z1@Z");
	mangledToCtypes("?foo_fnptrbackref2@@YAXP6AXQEAH@Z1@Z");
	mangledToCtypes("?foo_fnptrbackref3@@YAXP6AXQAH@Z1@Z");
	mangledToCtypes("?foo_fnptrbackref3@@YAXP6AXQEAH@Z1@Z");
	mangledToCtypes("?foo_fnptrbackref4@@YAXP6AXPAH@Z1@Z");
	mangledToCtypes("?foo_fnptrbackref4@@YAXP6AXPEAH@Z1@Z");
	mangledToCtypes("?ret_fnptrarray@@YAP6AXQAH@ZXZ");
	mangledToCtypes("?ret_fnptrarray@@YAP6AXQEAH@ZXZ");
	mangledToCtypes("?mangle_no_backref0@@YAXQAHPAH@Z");
	mangledToCtypes("?mangle_no_backref0@@YAXQEAHPEAH@Z");
	mangledToCtypes("?mangle_no_backref1@@YAXQAHQAH@Z");
	mangledToCtypes("?mangle_no_backref1@@YAXQEAHQEAH@Z");
	mangledToCtypes("?mangle_no_backref2@@YAXP6AXXZP6AXXZ@Z");
	mangledToCtypes("?mangle_no_backref2@@YAXP6AXXZP6AXXZ@Z");
	mangledToCtypes("?mangle_yes_backref0@@YAXQAH0@Z");
	mangledToCtypes("?mangle_yes_backref0@@YAXQEAH0@Z");
	mangledToCtypes("?mangle_yes_backref1@@YAXQAH0@Z");
	mangledToCtypes("?mangle_yes_backref1@@YAXQEAH0@Z");
	mangledToCtypes("?mangle_yes_backref2@@YAXQBQ6AXXZ0@Z");
	mangledToCtypes("?mangle_yes_backref2@@YAXQEBQ6AXXZ0@Z");
	mangledToCtypes("?mangle_yes_backref3@@YAXQAP6AXXZ0@Z");
	mangledToCtypes("?mangle_yes_backref3@@YAXQEAP6AXXZ0@Z");
	mangledToCtypes("?mangle_yes_backref4@@YAXQIAH0@Z");
	mangledToCtypes("?mangle_yes_backref4@@YAXQEIAH0@Z");
	mangledToCtypes("?pr23325@@YAXQBUS@@0@Z");
	mangledToCtypes("?pr23325@@YAXQEBUS@@0@Z");
	mangledToCtypes("?f1@@YAXPBD0@Z");
	mangledToCtypes("?f2@@YAXPBDPAD@Z");
	mangledToCtypes("?f3@@YAXHPBD0@Z");
	mangledToCtypes("?f4@@YAPBDPBD0@Z");
	mangledToCtypes("?f5@@YAXPBDIDPBX0I@Z");
	mangledToCtypes("?f6@@YAX_N0@Z");
	mangledToCtypes("?f7@@YAXHPAHH0_N1PA_N@Z");
	mangledToCtypes("?g1@@YAXUS@@@Z");
	mangledToCtypes("?g2@@YAXUS@@0@Z");
	mangledToCtypes("?g3@@YAXUS@@0PAU1@1@Z");
	mangledToCtypes("?g4@@YAXPBDPAUS@@01@Z");
	mangledToCtypes("?mbb@S@@QAEX_N0@Z");
	mangledToCtypes("?h1@@YAXPBD0P6AXXZ1@Z");
	mangledToCtypes("?h2@@YAXP6AXPAX@Z0@Z");
	mangledToCtypes("?h3@@YAP6APAHPAH0@ZP6APAH00@Z10@Z");
	mangledToCtypes("?foo@0@YAXXZ");
	mangledToCtypes("??$?HH@S@@QEAAAEAU0@H@Z");
	mangledToCtypes("?foo_abbb@@YAXV?$A@V?$B@D@@V1@V1@@@@Z");
	mangledToCtypes("?foo_abb@@YAXV?$A@DV?$B@D@@V1@@@@Z");
	mangledToCtypes("?foo_abc@@YAXV?$A@DV?$B@D@@V?$C@D@@@@@Z");
	mangledToCtypes("?foo_bt@@YAX_NV?$B@$$A6A_N_N@Z@@@Z");
	mangledToCtypes("?foo_abbb@@YAXV?$A@V?$B@D@N@@V12@V12@@N@@@Z");
	mangledToCtypes("?foo_abb@@YAXV?$A@DV?$B@D@N@@V12@@N@@@Z");
	mangledToCtypes("?foo_abc@@YAXV?$A@DV?$B@D@N@@V?$C@D@2@@N@@@Z");
	mangledToCtypes("?abc_foo@@YA?AV?$A@DV?$B@D@N@@V?$C@D@2@@N@@XZ");
	mangledToCtypes("?z_foo@@YA?AVZ@N@@V12@@Z");
	mangledToCtypes("?b_foo@@YA?AV?$B@D@N@@V12@@Z");
	mangledToCtypes("?d_foo@@YA?AV?$D@DD@N@@V12@@Z");
	mangledToCtypes("?abc_foo_abc@@YA?AV?$A@DV?$B@D@N@@V?$C@D@2@@N@@V12@@Z");
	mangledToCtypes("?foo5@@YAXV?$Y@V?$Y@V?$Y@V?$Y@VX@NA@@@NB@@@NA@@@NB@@@NA@@@Z");
	mangledToCtypes("?foo11@@YAXV?$Y@VX@NA@@@NA@@V1NB@@@Z");
	mangledToCtypes("?foo112@@YAXV?$Y@VX@NA@@@NA@@V?$Y@VX@NB@@@NB@@@Z");
	mangledToCtypes("?foo22@@YAXV?$Y@V?$Y@VX@NA@@@NB@@@NA@@V?$Y@V?$Y@VX@NA@@@NA@@@NB@@@Z");
	mangledToCtypes("?foo@L@PR13207@@QAEXV?$I@VA@PR13207@@@2@@Z");
	mangledToCtypes("?foo@PR13207@@YAXV?$I@VA@PR13207@@@1@@Z");
	mangledToCtypes("?foo2@PR13207@@YAXV?$I@VA@PR13207@@@1@0@Z");
	mangledToCtypes("?bar@PR13207@@YAXV?$J@VA@PR13207@@VB@2@@1@@Z");
	mangledToCtypes("?spam@PR13207@@YAXV?$K@VA@PR13207@@VB@2@VC@2@@1@@Z");
	mangledToCtypes("?baz@PR13207@@YAXV?$K@DV?$F@D@PR13207@@V?$I@D@2@@1@@Z");
	mangledToCtypes("?qux@PR13207@@YAXV?$K@DV?$I@D@PR13207@@V12@@1@@Z");
	mangledToCtypes("?foo@NA@PR13207@@YAXV?$Y@VX@NA@PR13207@@@12@@Z");
	mangledToCtypes("?foofoo@NA@PR13207@@YAXV?$Y@V?$Y@VX@NA@PR13207@@@NA@PR13207@@@12@@Z");
	mangledToCtypes("?foo@NB@PR13207@@YAXV?$Y@VX@NA@PR13207@@@12@@Z");
	mangledToCtypes("?bar@NB@PR13207@@YAXV?$Y@VX@NB@PR13207@@@NA@2@@Z");
	mangledToCtypes("?spam@NB@PR13207@@YAXV?$Y@VX@NA@PR13207@@@NA@2@@Z");
	mangledToCtypes("?foobar@NB@PR13207@@YAXV?$Y@V?$Y@VX@NB@PR13207@@@NB@PR13207@@@NA@2@V312@@Z");
	mangledToCtypes("?foobarspam@NB@PR13207@@YAXV?$Y@VX@NB@PR13207@@@12@V?$Y@V?$Y@VX@NB@PR13207@@@NB@PR13207@@@NA@2@V412@@Z");
	mangledToCtypes("?foobarbaz@NB@PR13207@@YAXV?$Y@VX@NB@PR13207@@@12@V?$Y@V?$Y@VX@NB@PR13207@@@NB@PR13207@@@NA@2@V412@2@Z");
	mangledToCtypes("?foobarbazqux@NB@PR13207@@YAXV?$Y@VX@NB@PR13207@@@12@V?$Y@V?$Y@VX@NB@PR13207@@@NB@PR13207@@@NA@2@V412@2V?$Y@V?$Y@V?$Y@VX@NB@PR13207@@@NB@PR13207@@@NB@PR13207@@@52@@Z");
	mangledToCtypes("?foo@NC@PR13207@@YAXV?$Y@VX@NB@PR13207@@@12@@Z");
	mangledToCtypes("?foobar@NC@PR13207@@YAXV?$Y@V?$Y@V?$Y@VX@NA@PR13207@@@NA@PR13207@@@NB@PR13207@@@12@@Z");
	mangledToCtypes("?fun_normal@fn_space@@YA?AURetVal@1@H@Z");
	mangledToCtypes("??$fun_tmpl@H@fn_space@@YA?AURetVal@0@ABH@Z");
	mangledToCtypes("??$fun_tmpl_recurse@H$1??$fun_tmpl_recurse@H$1?ident@fn_space@@YA?AURetVal@2@H@Z@fn_space@@YA?AURetVal@1@H@Z@fn_space@@YA?AURetVal@0@H@Z");
	mangledToCtypes("??$fun_tmpl_recurse@H$1?ident@fn_space@@YA?AURetVal@2@H@Z@fn_space@@YA?AURetVal@0@H@Z");
	mangledToCtypes("?AddEmitPasses@EmitAssemblyHelper@?A0x43583946@@AEAA_NAEAVPassManager@legacy@llvm@@W4BackendAction@clang@@AEAVraw_pwrite_stream@5@PEAV85@@Z");
	mangledToCtypes("??$forward@P8?$DecoderStream@$01@media@@AEXXZ@std@@YA$$QAP8?$DecoderStream@$01@media@@AEXXZAAP812@AEXXZ@Z");
	mangledToCtypes("??$?BH@TemplateOps@@QAEHXZ");
	mangledToCtypes("??BOps@@QAEHXZ");
	mangledToCtypes("??BConstOps@@QAE?BHXZ");
	mangledToCtypes("??BVolatileOps@@QAE?CHXZ");
	mangledToCtypes("??BConstVolatileOps@@QAE?DHXZ");
	mangledToCtypes("??$?BN@TemplateOps@@QAENXZ");
	mangledToCtypes("??BOps@@QAENXZ");
	mangledToCtypes("??BConstOps@@QAE?BNXZ");
	mangledToCtypes("??BVolatileOps@@QAE?CNXZ");
	mangledToCtypes("??BConstVolatileOps@@QAE?DNXZ");
	mangledToCtypes("??BCompoundTypeOps@@QAEPAHXZ");
	mangledToCtypes("??BCompoundTypeOps@@QAEPBHXZ");
	mangledToCtypes("??BCompoundTypeOps@@QAE$$QAHXZ");
	mangledToCtypes("??BCompoundTypeOps@@QAE?AU?$Foo@H@@XZ");
	mangledToCtypes("??$?BH@CompoundTypeOps@@QAE?AU?$Bar@U?$Foo@H@@@@XZ");
	mangledToCtypes("??$?BPAH@TemplateOps@@QAEPAHXZ");
	mangledToCtypes("?a@FTypeWithQuals@@3U?$S@$$A8@@BAHXZ@1@A");
	mangledToCtypes("?b@FTypeWithQuals@@3U?$S@$$A8@@CAHXZ@1@A");
	mangledToCtypes("?c@FTypeWithQuals@@3U?$S@$$A8@@IAAHXZ@1@A");
	mangledToCtypes("?d@FTypeWithQuals@@3U?$S@$$A8@@GBAHXZ@1@A");
	mangledToCtypes("?e@FTypeWithQuals@@3U?$S@$$A8@@GCAHXZ@1@A");
	mangledToCtypes("?f@FTypeWithQuals@@3U?$S@$$A8@@IGAAHXZ@1@A");
	mangledToCtypes("?g@FTypeWithQuals@@3U?$S@$$A8@@HBAHXZ@1@A");
	mangledToCtypes("?h@FTypeWithQuals@@3U?$S@$$A8@@HCAHXZ@1@A");
	mangledToCtypes("?i@FTypeWithQuals@@3U?$S@$$A8@@IHAAHXZ@1@A");
	mangledToCtypes("?j@FTypeWithQuals@@3U?$S@$$A6AHXZ@1@A");
	mangledToCtypes("?k@FTypeWithQuals@@3U?$S@$$A8@@GAAHXZ@1@A");
	mangledToCtypes("?l@FTypeWithQuals@@3U?$S@$$A8@@HAAHXZ@1@A");
	mangledToCtypes("?Char16Var@@3_SA");
	mangledToCtypes("?Char32Var@@3_UA");
	mangledToCtypes("?LRef@@YAXAAH@Z");
	mangledToCtypes("?RRef@@YAH$$QAH@Z");
	mangledToCtypes("?Null@@YAX$$T@Z");
	mangledToCtypes("?fun@PR18022@@YA?AU<unnamed-type-a>@1@U21@0@Z");
	mangledToCtypes("?lambda@?1??define_lambda@@YAHXZ@4V<lambda_1>@?0??1@YAHXZ@A");
	mangledToCtypes("??R<lambda_1>@?0??define_lambda@@YAHXZ@QBE@XZ");
	mangledToCtypes("?local@?2???R<lambda_1>@?0??define_lambda@@YAHXZ@QBE@XZ@4HA");
	mangledToCtypes("??$use_lambda_arg@V<lambda_1>@?0??call_with_lambda_arg1@@YAXXZ@@@YAXV<lambda_1>@?0??call_with_lambda_arg1@@YAXXZ@@Z");
	mangledToCtypes("?foo@A@PR19361@@QIGAEXXZ");
	mangledToCtypes("?foo@A@PR19361@@QIHAEXXZ");
	mangledToCtypes("??__K_deg@@YAHO@Z");
	mangledToCtypes("??$templ_fun_with_pack@$S@@YAXXZ");
	mangledToCtypes("??$func@H$$ZH@@YAHAEBU?$Foo@H@@0@Z");
	mangledToCtypes("??$templ_fun_with_ty_pack@$$$V@@YAXXZ");
	mangledToCtypes("??$templ_fun_with_ty_pack@$$V@@YAXXZ");
	mangledToCtypes("??$f@$$YAliasA@PR20047@@@PR20047@@YAXXZ");
	mangledToCtypes("?f@UnnamedType@@YAXAAU<unnamed-type-TD>@A@1@@Z");
	mangledToCtypes("?f@UnnamedType@@YAXPAW4<unnamed-type-e>@?$B@H@1@@Z");
	mangledToCtypes("??$f@W4<unnamed-type-E>@?1??g@PR24651@@YAXXZ@@PR24651@@YAXW4<unnamed-type-E>@?1??g@0@YAXXZ@@Z");
	mangledToCtypes("??$f@T<unnamed-type-$S1>@PR18204@@@PR18204@@YAHPAT<unnamed-type-$S1>@0@@Z");
	mangledToCtypes("??R<lambda_0>@?0??PR26105@@YAHXZ@QBE@H@Z");
	mangledToCtypes("??R<lambda_1>@?0???R<lambda_0>@?0??PR26105@@YAHXZ@QBE@H@Z@QBE@H@Z");
	mangledToCtypes("?unaligned_foo1@@YAPFAHXZ");
	mangledToCtypes("?unaligned_foo2@@YAPFAPFAHXZ");
	mangledToCtypes("?unaligned_foo3@@YAHXZ");
	mangledToCtypes("?unaligned_foo4@@YAXPFAH@Z");
	mangledToCtypes("?unaligned_foo5@@YAXPIFAH@Z");
	mangledToCtypes("??$unaligned_foo6@PAH@@YAPAHPAH@Z");
	mangledToCtypes("??$unaligned_foo6@PFAH@@YAPFAHPFAH@Z");
	mangledToCtypes("?unaligned_foo8@unaligned_foo8_S@@QFCEXXZ");
	mangledToCtypes("??R<lambda_1>@x@A@PR31197@@QBE@XZ");
	mangledToCtypes("?white@?1???R<lambda_1>@x@A@PR31197@@QBE@XZ@4HA");
	mangledToCtypes("?f@@YAXW4<unnamed-enum-enumerator>@@@Z");
	mangledToCtypes("??$x@X@@3HA");
	mangledToCtypes("?FunctionWithLocalType@@YA?A?<auto>@@XZ");
	mangledToCtypes("?ValueFromFunctionWithLocalType@@3ULocalType@?1??FunctionWithLocalType@@YA?A?<auto>@@XZ@A");
	mangledToCtypes("??R<lambda_0>@@QBE?A?<auto>@@XZ");
	mangledToCtypes("?ValueFromLambdaWithLocalType@@3ULocalType@?1???R<lambda_0>@@QBE?A?<auto>@@XZ@A");
	mangledToCtypes("?ValueFromTemplateFuncionWithLocalLambda@@3ULocalType@?2???R<lambda_1>@?0???$TemplateFuncionWithLocalLambda@H@@YA?A?<auto>@@H@Z@QBE?A?3@XZ@A");
	mangledToCtypes("??$TemplateFuncionWithLocalLambda@H@@YA?A?<auto>@@H@Z");
	mangledToCtypes("??R<lambda_1>@?0???$TemplateFuncionWithLocalLambda@H@@YA?A?<auto>@@H@Z@QBE?A?1@XZ");
	mangledToCtypes("??$WithPMD@$GA@A@?0@@3HA");
	mangledToCtypes("?Zoo@@3U?$Foo@$1??$x@H@@3HA$1?1@3HA@@A");
	mangledToCtypes("??$unaligned_x@PFAH@@3PFAHA");
	mangledToCtypes("?nochange@@YAXXZ");
	mangledToCtypes("?a@@YAXP6AHXZ@Z");
	mangledToCtypes("?a@@YAXP6AHX_E@Z");
	mangledToCtypes("?b@@YAXP6AHXZ@Z");
	mangledToCtypes("?c@@YAXP6AHXZ@Z");
	mangledToCtypes("?c@@YAXP6AHX_E@Z");
	mangledToCtypes("?ee@?$e@$$A6AXXZ@@EEAAXXZ");
	mangledToCtypes("?ee@?$e@$$A6AXX_E@@EEAAXXZ");
	mangledToCtypes("?a@@3HA");
	mangledToCtypes("?b@N@@3HA");
	mangledToCtypes("?anonymous@?A@N@@3HA");
	mangledToCtypes("?$RT1@NeedsReferenceTemporary@@3ABHB");
	mangledToCtypes("?$RT1@NeedsReferenceTemporary@@3AEBHEB");
	mangledToCtypes("?_c@@YAHXZ");
	mangledToCtypes("?d@foo@@0FB");
	mangledToCtypes("?e@foo@@1JC");
	mangledToCtypes("?f@foo@@2DD");
	mangledToCtypes("??0foo@@QAE@XZ");
	mangledToCtypes("??0foo@@QEAA@XZ");
	mangledToCtypes("??1foo@@QAE@XZ");
	mangledToCtypes("??1foo@@QEAA@XZ");
	mangledToCtypes("??0foo@@QAE@H@Z");
	mangledToCtypes("??0foo@@QEAA@H@Z");
	mangledToCtypes("??0foo@@QAE@PAD@Z");
	mangledToCtypes("??0foo@@QEAA@PEAD@Z");
	mangledToCtypes("?bar@@YA?AVfoo@@XZ");
	mangledToCtypes("?bar@@YA?AVfoo@@XZ");
	mangledToCtypes("??Hfoo@@QAEHH@Z");
	mangledToCtypes("??Hfoo@@QEAAHH@Z");
	mangledToCtypes("??$?HH@S@@QEAAAEANH@Z");
	mangledToCtypes("?static_method@foo@@SAPAV1@XZ");
	mangledToCtypes("?static_method@foo@@SAPEAV1@XZ");
	mangledToCtypes("?g@bar@@2HA");
	mangledToCtypes("?h1@@3QAHA");
	mangledToCtypes("?h2@@3QBHB");
	mangledToCtypes("?h3@@3QIAHIA");
	mangledToCtypes("?h3@@3QEIAHEIA");
	mangledToCtypes("?i@@3PAY0BE@HA");
	mangledToCtypes("?FunArr@@3PAY0BE@P6AHHH@ZA");
	mangledToCtypes("?j@@3P6GHCE@ZA");
	mangledToCtypes("?funptr@@YAP6AHXZXZ");
	mangledToCtypes("?k@@3PTfoo@@DT1@");
	mangledToCtypes("?k@@3PETfoo@@DET1@");
	mangledToCtypes("?l@@3P8foo@@AEHH@ZQ1@");
	mangledToCtypes("?g_cInt@@3HB");
	mangledToCtypes("?g_vInt@@3HC");
	mangledToCtypes("?g_cvInt@@3HD");
	mangledToCtypes("?beta@@YI_N_J_W@Z");
	mangledToCtypes("?beta@@YA_N_J_W@Z");
	mangledToCtypes("?alpha@@YGXMN@Z");
	mangledToCtypes("?alpha@@YAXMN@Z");
	mangledToCtypes("?gamma@@YAXVfoo@@Ubar@@Tbaz@@W4quux@@@Z");
	mangledToCtypes("?gamma@@YAXVfoo@@Ubar@@Tbaz@@W4quux@@@Z");
	mangledToCtypes("?delta@@YAXQAHABJ@Z");
	mangledToCtypes("?delta@@YAXQEAHAEBJ@Z");
	mangledToCtypes("?epsilon@@YAXQAY19BE@H@Z");
	mangledToCtypes("?epsilon@@YAXQEAY19BE@H@Z");
	mangledToCtypes("?zeta@@YAXP6AHHH@Z@Z");
	mangledToCtypes("?zeta@@YAXP6AHHH@Z@Z");
	mangledToCtypes("??2@YAPAXI@Z");
	mangledToCtypes("??3@YAXPAX@Z");
	mangledToCtypes("??_U@YAPAXI@Z");
	mangledToCtypes("??_V@YAXPAX@Z");
	mangledToCtypes("?color1@@3PANA");
	mangledToCtypes("?color2@@3QBNB");
	mangledToCtypes("?color3@@3QAY02$$CBNA");
	mangledToCtypes("?color4@@3QAY02$$CBNA");
	mangledToCtypes("?memptr1@@3RESB@@HES1@");
	mangledToCtypes("?memptr2@@3PESB@@HES1@");
	mangledToCtypes("?memptr3@@3REQB@@HEQ1@");
	mangledToCtypes("?funmemptr1@@3RESB@@R6AHXZES1@");
	mangledToCtypes("?funmemptr2@@3PESB@@R6AHXZES1@");
	mangledToCtypes("?funmemptr3@@3REQB@@P6AHXZEQ1@");
	mangledToCtypes("?memptrtofun1@@3R8B@@EAAXXZEQ1@");
	mangledToCtypes("?memptrtofun2@@3P8B@@EAAXXZEQ1@");
	mangledToCtypes("?memptrtofun3@@3P8B@@EAAXXZEQ1@");
	mangledToCtypes("?memptrtofun4@@3R8B@@EAAHXZEQ1@");
	mangledToCtypes("?memptrtofun5@@3P8B@@EAA?CHXZEQ1@");
	mangledToCtypes("?memptrtofun6@@3P8B@@EAA?BHXZEQ1@");
	mangledToCtypes("?memptrtofun7@@3R8B@@EAAP6AHXZXZEQ1@");
	mangledToCtypes("?memptrtofun8@@3P8B@@EAAR6AHXZXZEQ1@");
	mangledToCtypes("?memptrtofun9@@3P8B@@EAAQ6AHXZXZEQ1@");
	mangledToCtypes("?fooE@@YA?AW4E@@XZ");
	mangledToCtypes("?fooE@@YA?AW4E@@XZ");
	mangledToCtypes("?fooX@@YA?AVX@@XZ");
	mangledToCtypes("?fooX@@YA?AVX@@XZ");
	mangledToCtypes("?s0@PR13182@@3PADA");
	mangledToCtypes("?s1@PR13182@@3PADA");
	mangledToCtypes("?s2@PR13182@@3QBDB");
	mangledToCtypes("?s3@PR13182@@3QBDB");
	mangledToCtypes("?s4@PR13182@@3RCDC");
	mangledToCtypes("?s5@PR13182@@3SDDD");
	mangledToCtypes("?s6@PR13182@@3PBQBDB");
	mangledToCtypes("?local@?1??extern_c_func@@9@4HA");
	mangledToCtypes("?local@?1??extern_c_func@@9@4HA");
	mangledToCtypes("?v@?1??f@@YAHXZ@4U<unnamed-type-v>@?1??1@YAHXZ@A");
	mangledToCtypes("?v@?1???$f@H@@YAHXZ@4U<unnamed-type-v>@?1???$f@H@@YAHXZ@A");
	mangledToCtypes("??2OverloadedNewDelete@@SAPAXI@Z");
	mangledToCtypes("??_UOverloadedNewDelete@@SAPAXI@Z");
	mangledToCtypes("??3OverloadedNewDelete@@SAXPAX@Z");
	mangledToCtypes("??_VOverloadedNewDelete@@SAXPAX@Z");
	mangledToCtypes("??HOverloadedNewDelete@@QAEHH@Z");
	mangledToCtypes("??2OverloadedNewDelete@@SAPEAX_K@Z");
	mangledToCtypes("??_UOverloadedNewDelete@@SAPEAX_K@Z");
	mangledToCtypes("??3OverloadedNewDelete@@SAXPEAX@Z");
	mangledToCtypes("??_VOverloadedNewDelete@@SAXPEAX@Z");
	mangledToCtypes("??HOverloadedNewDelete@@QEAAHH@Z");
	mangledToCtypes("??2TypedefNewDelete@@SAPAXI@Z");
	mangledToCtypes("??_UTypedefNewDelete@@SAPAXI@Z");
	mangledToCtypes("??3TypedefNewDelete@@SAXPAX@Z");
	mangledToCtypes("??_VTypedefNewDelete@@SAXPAX@Z");
	mangledToCtypes("?vector_func@@YQXXZ");
	mangledToCtypes("??$fn_tmpl@$1?extern_c_func@@YAXXZ@@YAXXZ");
	mangledToCtypes("?overloaded_fn@@$$J0YAXXZ");
	mangledToCtypes("?f@UnnamedType@@YAXQAPAU<unnamed-type-T1>@S@1@@Z");
	mangledToCtypes("?f@UnnamedType@@YAXUT2@S@1@@Z");
	mangledToCtypes("?f@UnnamedType@@YAXPAUT4@S@1@@Z");
	mangledToCtypes("?f@UnnamedType@@YAXUT4@S@1@@Z");
	mangledToCtypes("?f@UnnamedType@@YAXUT5@S@1@@Z");
	mangledToCtypes("?f@UnnamedType@@YAXUT2@S@1@@Z");
	mangledToCtypes("?f@UnnamedType@@YAXUT4@S@1@@Z");
	mangledToCtypes("?f@UnnamedType@@YAXUT5@S@1@@Z");
	mangledToCtypes("?f@Atomic@@YAXU?$_Atomic@H@__clang@@@Z");
	mangledToCtypes("?f@Complex@@YAXU?$_Complex@H@__clang@@@Z");
	mangledToCtypes("?f@Float16@@YAXU_Float16@__clang@@@Z");
	mangledToCtypes("??0?$L@H@NS@@QEAA@XZ");
	mangledToCtypes("??0Bar@Foo@@QEAA@XZ");
	mangledToCtypes("??0?$L@V?$H@PAH@PR26029@@@PR26029@@QAE@XZ");
	mangledToCtypes("?M@?@??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?0??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?1??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?2??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?3??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?4??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?5??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?6??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?7??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?8??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?9??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?L@??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?M@??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?N@??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?O@??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?P@??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?BA@??L@@YAHXZ@4HA");
	mangledToCtypes("?M@?BB@??L@@YAHXZ@4HA");
	mangledToCtypes("?j@?1??L@@YAHXZ@4UJ@@A");
	mangledToCtypes("?NN@0XX@@3HA");
	mangledToCtypes("?MM@0NN@XX@@3HA");
	mangledToCtypes("?NN@MM@0XX@@3HA");
	mangledToCtypes("?OO@0NN@01XX@@3HA");
	mangledToCtypes("?NN@OO@010XX@@3HA");
	mangledToCtypes("?M@?1??0@YAHXZ@4HA");
	mangledToCtypes("?L@?2??M@0?2??0@YAHXZ@QEAAHXZ@4HA");
	mangledToCtypes("?M@?2??0L@?2??1@YAHXZ@QEAAHXZ@4HA");
	mangledToCtypes("?M@?1???$L@H@@YAHXZ@4HA");
	mangledToCtypes("?SN@?$NS@H@NS@@QEAAHXZ");
	mangledToCtypes("?NS@?1??SN@?$NS@H@0@QEAAHXZ@4HA");
	mangledToCtypes("?SN@?1??0?$NS@H@NS@@QEAAHXZ@4HA");
	mangledToCtypes("?NS@?1??SN@?$NS@H@10@QEAAHXZ@4HA");
	mangledToCtypes("?SN@?1??0?$NS@H@0NS@@QEAAHXZ@4HA");
	mangledToCtypes("?X@?$C@H@C@0@2HB");
	mangledToCtypes("?X@?$C@H@C@1@2HB");
	mangledToCtypes("?X@?$C@H@C@2@2HB");
	mangledToCtypes("?C@?1??B@?$C@H@0101A@@QEAAHXZ@4U201013@A");
	mangledToCtypes("?B@?1??0?$C@H@C@020A@@QEAAHXZ@4HA");
	mangledToCtypes("?A@?1??B@?$C@H@C@1310@QEAAHXZ@4HA");
	mangledToCtypes("??0Base@@QEAA@XZ");
	mangledToCtypes("??1Base@@UEAA@XZ");
	mangledToCtypes("??2@YAPEAX_K@Z");
	mangledToCtypes("??3@YAXPEAX_K@Z");
	mangledToCtypes("??4Base@@QEAAHH@Z");
	mangledToCtypes("??6Base@@QEAAHH@Z");
	mangledToCtypes("??5Base@@QEAAHH@Z");
	mangledToCtypes("??7Base@@QEAAHXZ");
	mangledToCtypes("??8Base@@QEAAHH@Z");
	mangledToCtypes("??9Base@@QEAAHH@Z");
	mangledToCtypes("??ABase@@QEAAHH@Z");
	mangledToCtypes("??BBase@@QEAAHXZ");
	mangledToCtypes("??CBase@@QEAAHXZ");
	mangledToCtypes("??DBase@@QEAAHXZ");
	mangledToCtypes("??EBase@@QEAAHXZ");
	mangledToCtypes("??EBase@@QEAAHH@Z");
	mangledToCtypes("??FBase@@QEAAHXZ");
	mangledToCtypes("??FBase@@QEAAHH@Z");
	mangledToCtypes("??GBase@@QEAAHH@Z");
	mangledToCtypes("??HBase@@QEAAHH@Z");
	mangledToCtypes("??IBase@@QEAAHH@Z");
	mangledToCtypes("??JBase@@QEAAHH@Z");
	mangledToCtypes("??KBase@@QEAAHH@Z");
	mangledToCtypes("??LBase@@QEAAHH@Z");
	mangledToCtypes("??MBase@@QEAAHH@Z");
	mangledToCtypes("??NBase@@QEAAHH@Z");
	mangledToCtypes("??OBase@@QEAAHH@Z");
	mangledToCtypes("??PBase@@QEAAHH@Z");
	mangledToCtypes("??QBase@@QEAAHH@Z");
	mangledToCtypes("??RBase@@QEAAHXZ");
	mangledToCtypes("??SBase@@QEAAHXZ");
	mangledToCtypes("??TBase@@QEAAHH@Z");
	mangledToCtypes("??UBase@@QEAAHH@Z");
	mangledToCtypes("??VBase@@QEAAHH@Z");
	mangledToCtypes("??WBase@@QEAAHH@Z");
	mangledToCtypes("??XBase@@QEAAHH@Z");
	mangledToCtypes("??YBase@@QEAAHH@Z");
	mangledToCtypes("??ZBase@@QEAAHH@Z");
	mangledToCtypes("??_0Base@@QEAAHH@Z");
	mangledToCtypes("??_1Base@@QEAAHH@Z");
	mangledToCtypes("??_2Base@@QEAAHH@Z");
	mangledToCtypes("??_3Base@@QEAAHH@Z");
	mangledToCtypes("??_4Base@@QEAAHH@Z");
	mangledToCtypes("??_5Base@@QEAAHH@Z");
	mangledToCtypes("??_6Base@@QEAAHH@Z");
	mangledToCtypes("??_7Base@@6B@");
	mangledToCtypes("??_7A@B@@6BC@D@@@");
	mangledToCtypes("??_8Middle2@@7B@");
	mangledToCtypes("??_9Base@@$B7AA");
	mangledToCtypes("??_B?1??getS@@YAAAUS@@XZ@51");
	mangledToCtypes("??_C@_02PCEFGMJL@hi?$AA@");
	mangledToCtypes("??_DDiamond@@QEAAXXZ");
	mangledToCtypes("??_EBase@@UEAAPEAXI@Z");
	mangledToCtypes("??_EBase@@G3AEPAXI@Z");
	mangledToCtypes("??_F?$SomeTemplate@H@@QAEXXZ");
	mangledToCtypes("??_GBase@@UEAAPEAXI@Z");
	mangledToCtypes("??_H@YAXPEAX_K1P6APEAX0@Z@Z");
	mangledToCtypes("??_I@YAXPEAX_K1P6AX0@Z@Z");
	mangledToCtypes("??_JBase@@UEAAPEAXI@Z");
	mangledToCtypes("??_KBase@@UEAAPEAXI@Z");
	mangledToCtypes("??_LBase@@UEAAPEAXI@Z");
	mangledToCtypes("??_MBase@@UEAAPEAXI@Z");
	mangledToCtypes("??_NBase@@UEAAPEAXI@Z");
	mangledToCtypes("??_O?$SomeTemplate@H@@QAEXXZ");
	mangledToCtypes("??_SBase@@6B@");
	mangledToCtypes("??_TDerived@@QEAAXXZ");
	mangledToCtypes("??_U@YAPEAX_KAEAVklass@@@Z");
	mangledToCtypes("??_V@YAXPEAXAEAVklass@@@Z");
	mangledToCtypes("??_R0?AUBase@@@8");
	mangledToCtypes("??_R1A@?0A@EA@Base@@8");
	mangledToCtypes("??_R2Base@@8");
	mangledToCtypes("??_R3Base@@8");
	mangledToCtypes("??_R4Base@@6B@");
	mangledToCtypes("??__EFoo@@YAXXZ");
	mangledToCtypes("??__FFoo@@YAXXZ");
	mangledToCtypes("??__F_decisionToDFA@XPathLexer@@0V?$vector@VDFA@dfa@antlr4@@V?$allocator@VDFA@dfa@antlr4@@@std@@@std@@A@YAXXZ");
	mangledToCtypes("??__K_deg@@YAHO@Z");
	mangledToCtypes("?a1@@YAXXZ");
	mangledToCtypes("?a2@@YAHXZ");
	mangledToCtypes("?a3@@YA?BHXZ");
	mangledToCtypes("?a4@@YA?CHXZ");
	mangledToCtypes("?a5@@YA?DHXZ");
	mangledToCtypes("?a6@@YAMXZ");
	mangledToCtypes("?b1@@YAPAHXZ");
	mangledToCtypes("?b2@@YAPBDXZ");
	mangledToCtypes("?b3@@YAPAMXZ");
	mangledToCtypes("?b4@@YAPBMXZ");
	mangledToCtypes("?b5@@YAPCMXZ");
	mangledToCtypes("?b6@@YAPDMXZ");
	mangledToCtypes("?b7@@YAAAMXZ");
	mangledToCtypes("?b8@@YAABMXZ");
	mangledToCtypes("?b9@@YAACMXZ");
	mangledToCtypes("?b10@@YAADMXZ");
	mangledToCtypes("?b11@@YAPAPBDXZ");
	mangledToCtypes("?c1@@YA?AVA@@XZ");
	mangledToCtypes("?c2@@YA?BVA@@XZ");
	mangledToCtypes("?c3@@YA?CVA@@XZ");
	mangledToCtypes("?c4@@YA?DVA@@XZ");
	mangledToCtypes("?c5@@YAPBVA@@XZ");
	mangledToCtypes("?c6@@YAPCVA@@XZ");
	mangledToCtypes("?c7@@YAPDVA@@XZ");
	mangledToCtypes("?c8@@YAAAVA@@XZ");
	mangledToCtypes("?c9@@YAABVA@@XZ");
	mangledToCtypes("?c10@@YAACVA@@XZ");
	mangledToCtypes("?c11@@YAADVA@@XZ");
	mangledToCtypes("?d1@@YA?AV?$B@H@@XZ");
	mangledToCtypes("?d2@@YA?AV?$B@PBD@@XZ");
	mangledToCtypes("?d3@@YA?AV?$B@VA@@@@XZ");
	mangledToCtypes("?d4@@YAPAV?$B@VA@@@@XZ");
	mangledToCtypes("?d5@@YAPBV?$B@VA@@@@XZ");
	mangledToCtypes("?d6@@YAPCV?$B@VA@@@@XZ");
	mangledToCtypes("?d7@@YAPDV?$B@VA@@@@XZ");
	mangledToCtypes("?d8@@YAAAV?$B@VA@@@@XZ");
	mangledToCtypes("?d9@@YAABV?$B@VA@@@@XZ");
	mangledToCtypes("?d10@@YAACV?$B@VA@@@@XZ");
	mangledToCtypes("?d11@@YAADV?$B@VA@@@@XZ");
	mangledToCtypes("?e1@@YA?AW4Enum@@XZ");
	mangledToCtypes("?e2@@YA?BW4Enum@@XZ");
	mangledToCtypes("?e3@@YAPAW4Enum@@XZ");
	mangledToCtypes("?e4@@YAAAW4Enum@@XZ");
	mangledToCtypes("?f1@@YA?AUS@@XZ");
	mangledToCtypes("?f2@@YA?BUS@@XZ");
	mangledToCtypes("?f3@@YAPAUS@@XZ");
	mangledToCtypes("?f4@@YAPBUS@@XZ");
	mangledToCtypes("?f5@@YAPDUS@@XZ");
	mangledToCtypes("?f6@@YAAAUS@@XZ");
	mangledToCtypes("?f7@@YAQAUS@@XZ");
	mangledToCtypes("?f8@@YAPQS@@HXZ");
	mangledToCtypes("?f9@@YAQQS@@HXZ");
	mangledToCtypes("?f10@@YAPIQS@@HXZ");
	mangledToCtypes("?f11@@YAQIQS@@HXZ");
	mangledToCtypes("?g1@@YAP6AHH@ZXZ");
	mangledToCtypes("?g2@@YAQ6AHH@ZXZ");
	mangledToCtypes("?g3@@YAPAP6AHH@ZXZ");
	mangledToCtypes("?g4@@YAPBQ6AHH@ZXZ");
	mangledToCtypes("?h1@@YAAIAHXZ");
	mangledToCtypes("??_C@_0CF@LABBIIMO@012345678901234567890123456789AB@");
	mangledToCtypes("??_C@_1EK@KFPEBLPK@?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AAA?$AAB@");
	mangledToCtypes("??_C@_13IIHIAFKH@?W?$PP?$AA?$AA@");
	mangledToCtypes("??_C@_02PCEFGMJL@hi?$AA@");
	mangledToCtypes("??_C@_05OMLEGLOC@h?$AAi?$AA?$AA?$AA@");
	mangledToCtypes("??_C@_0EK@FEAOBHPP@o?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA@");
	mangledToCtypes("??_C@_0M@GFNAJIPG@h?$AA?$AA?$AAi?$AA?$AA?$AA?$AA?$AA?$AA?$AA@");
	mangledToCtypes("??_C@_0JE@IMHFEDAA@0?$AA?$AA?$AA1?$AA?$AA?$AA2?$AA?$AA?$AA3?$AA?$AA?$AA4?$AA?$AA?$AA5?$AA?$AA?$AA6?$AA?$AA?$AA7?$AA?$AA?$AA@");
	mangledToCtypes("??_C@_0CA@NMANGEKF@012345678901234567890123456789A?$AA@");
	mangledToCtypes("??_C@_1EA@LJAFPILO@?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AAA?$AA?$AA@");
	mangledToCtypes("??_C@_0CA@NMANGEKF@012345678901234567890123456789A?$AA@");
	mangledToCtypes("??_C@_0CA@NFEFHIFO@0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA?$AA?$AA@");
	mangledToCtypes("??_C@_0CA@KFPHPCC@0?$AA?$AA?$AA1?$AA?$AA?$AA2?$AA?$AA?$AA3?$AA?$AA?$AA4?$AA?$AA?$AA5?$AA?$AA?$AA6?$AA?$AA?$AA?$AA?$AA?$AA?$AA@");
	mangledToCtypes("??_C@_0CG@HJGBPLNO@l?$AAo?$AAo?$AAk?$AAA?$AAh?$AAe?$AAa?$AAd?$AAH?$AAa?$AAr?$AAd?$AAB?$AAr?$AAe?$AAa?$AAk?$AA?$AA?$AA@");
	mangledToCtypes("??_C@_0CG@HJGBPLNO@l?$AAo?$AAo?$AAk?$AAA?$AAh?$AAe?$AAa?$AAd?$AAH?$AAa?$AAr?$AAd?$AAB?$AAr?$AAe?$AA@");
	mangledToCtypes("?callback_void@@3V?$C@$$A6AXXZ@@A");
	mangledToCtypes("?callback_void_volatile@@3V?$C@$$A6AXXZ@@C");
	mangledToCtypes("?callback_int@@3V?$C@$$A6AHXZ@@A");
	mangledToCtypes("?callback_Type@@3V?$C@$$A6A?AVType@@XZ@@A");
	mangledToCtypes("?callback_void_int@@3V?$C@$$A6AXH@Z@@A");
	mangledToCtypes("?callback_int_int@@3V?$C@$$A6AHH@Z@@A");
	mangledToCtypes("?callback_void_Type@@3V?$C@$$A6AXVType@@@Z@@A");
	mangledToCtypes("?foo@@YAXV?$C@$$A6AXXZ@@@Z");
	mangledToCtypes("?function@@YAXV?$C@$$A6AXXZ@@@Z");
	mangledToCtypes("?function_pointer@@YAXV?$C@P6AXXZ@@@Z");
	mangledToCtypes("?member_pointer@@YAXV?$C@P8Z@@AEXXZ@@@Z");
	mangledToCtypes("??$bar@P6AHH@Z@@YAXP6AHH@Z@Z");
	mangledToCtypes("??$WrapFnPtr@$1?VoidFn@@YAXXZ@@YAXXZ");
	mangledToCtypes("??$WrapFnRef@$1?VoidFn@@YAXXZ@@YAXXZ");
	mangledToCtypes("??$WrapFnPtr@$1?VoidStaticMethod@Thing@@SAXXZ@@YAXXZ");
	mangledToCtypes("??$WrapFnRef@$1?VoidStaticMethod@Thing@@SAXXZ@@YAXXZ");
	mangledToCtypes("??0?$Class@VTypename@@@@QAE@XZ");
	mangledToCtypes("??0?$Class@VTypename@@@@QEAA@XZ");
	mangledToCtypes("??0?$Class@$$CBVTypename@@@@QAE@XZ");
	mangledToCtypes("??0?$Class@$$CBVTypename@@@@QEAA@XZ");
	mangledToCtypes("??0?$Class@$$CCVTypename@@@@QAE@XZ");
	mangledToCtypes("??0?$Class@$$CCVTypename@@@@QEAA@XZ");
	mangledToCtypes("??0?$Class@$$CDVTypename@@@@QAE@XZ");
	mangledToCtypes("??0?$Class@$$CDVTypename@@@@QEAA@XZ");
	mangledToCtypes("??0?$Class@V?$Nested@VTypename@@@@@@QAE@XZ");
	mangledToCtypes("??0?$Class@V?$Nested@VTypename@@@@@@QEAA@XZ");
	mangledToCtypes("??0?$Class@QAH@@QAE@XZ");
	mangledToCtypes("??0?$Class@QEAH@@QEAA@XZ");
	mangledToCtypes("??0?$Class@$$A6AHXZ@@QAE@XZ");
	mangledToCtypes("??0?$Class@$$A6AHXZ@@QEAA@XZ");
	mangledToCtypes("??0?$Class@$$BY0A@H@@QAE@XZ");
	mangledToCtypes("??0?$Class@$$BY0A@H@@QEAA@XZ");
	mangledToCtypes("??0?$Class@$$BY04H@@QAE@XZ");
	mangledToCtypes("??0?$Class@$$BY04H@@QEAA@XZ");
	mangledToCtypes("??0?$Class@$$BY04$$CBH@@QAE@XZ");
	mangledToCtypes("??0?$Class@$$BY04$$CBH@@QEAA@XZ");
	mangledToCtypes("??0?$Class@$$BY04QAH@@QAE@XZ");
	mangledToCtypes("??0?$Class@$$BY04QEAH@@QEAA@XZ");
	mangledToCtypes("??0?$BoolTemplate@$0A@@@QAE@XZ");
	mangledToCtypes("??0?$BoolTemplate@$0A@@@QEAA@XZ");
	mangledToCtypes("??0?$BoolTemplate@$00@@QAE@XZ");
	mangledToCtypes("??0?$BoolTemplate@$00@@QEAA@XZ");
	mangledToCtypes("??$Foo@H@?$BoolTemplate@$00@@QAEXH@Z");
	mangledToCtypes("??$Foo@H@?$BoolTemplate@$00@@QEAAXH@Z");
	mangledToCtypes("??0?$IntTemplate@$0A@@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$0A@@@QEAA@XZ");
	mangledToCtypes("??0?$IntTemplate@$04@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$04@@QEAA@XZ");
	mangledToCtypes("??0?$IntTemplate@$0L@@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$0L@@@QEAA@XZ");
	mangledToCtypes("??0?$IntTemplate@$0BAA@@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$0BAA@@@QEAA@XZ");
	mangledToCtypes("??0?$IntTemplate@$0CAB@@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$0CAB@@@QEAA@XZ");
	mangledToCtypes("??0?$IntTemplate@$0EAC@@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$0EAC@@@QEAA@XZ");
	mangledToCtypes("??0?$IntTemplate@$0PPPP@@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$0PPPP@@@QEAA@XZ");
	mangledToCtypes("??0?$IntTemplate@$0?0@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$0?0@@QEAA@XZ");
	mangledToCtypes("??0?$IntTemplate@$0?8@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$0?8@@QEAA@XZ");
	mangledToCtypes("??0?$IntTemplate@$0?9@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$0?9@@QEAA@XZ");
	mangledToCtypes("??0?$IntTemplate@$0?L@@@QAE@XZ");
	mangledToCtypes("??0?$IntTemplate@$0?L@@@QEAA@XZ");
	mangledToCtypes("??0?$UnsignedIntTemplate@$0PPPPPPPP@@@QAE@XZ");
	mangledToCtypes("??0?$UnsignedIntTemplate@$0PPPPPPPP@@@QEAA@XZ");
	mangledToCtypes("??0?$LongLongTemplate@$0?IAAAAAAAAAAAAAAA@@@QAE@XZ");
	mangledToCtypes("??0?$LongLongTemplate@$0?IAAAAAAAAAAAAAAA@@@QEAA@XZ");
	mangledToCtypes("??0?$LongLongTemplate@$0HPPPPPPPPPPPPPPP@@@QAE@XZ");
	mangledToCtypes("??0?$LongLongTemplate@$0HPPPPPPPPPPPPPPP@@@QEAA@XZ");
	mangledToCtypes("??0?$UnsignedLongLongTemplate@$0?0@@QAE@XZ");
	mangledToCtypes("??0?$UnsignedLongLongTemplate@$0?0@@QEAA@XZ");
	mangledToCtypes("??$foo@H@space@@YAABHABH@Z");
	mangledToCtypes("??$foo@H@space@@YAAEBHAEBH@Z");
	mangledToCtypes("??$FunctionPointerTemplate@$1?spam@@YAXXZ@@YAXXZ");
	mangledToCtypes("??$variadic_fn_template@HHHH@@YAXABH000@Z");
	mangledToCtypes("??$variadic_fn_template@HHD$$BY01D@@YAXABH0ABDAAY01$$CBD@Z");
	mangledToCtypes("??0?$VariadicClass@HD_N@@QAE@XZ");
	mangledToCtypes("??0?$VariadicClass@_NDH@@QAE@XZ");
	mangledToCtypes("?template_template_fun@@YAXU?$Type@U?$Thing@USecond@@$00@@USecond@@@@@Z");
	mangledToCtypes("??$template_template_specialization@$$A6AXU?$Type@U?$Thing@USecond@@$00@@USecond@@@@@Z@@YAXXZ");
	mangledToCtypes("?f@@YAXU?$S1@$0A@@@@Z");
	mangledToCtypes("?recref@@YAXU?$type1@$E?inst@@3Urecord@@B@@@Z");
	mangledToCtypes("?fun@@YAXU?$UUIDType1@Uuuid@@$1?_GUID_12345678_1234_1234_1234_1234567890ab@@3U__s_GUID@@B@@@Z");
	mangledToCtypes("?fun@@YAXU?$UUIDType2@Uuuid@@$E?_GUID_12345678_1234_1234_1234_1234567890ab@@3U__s_GUID@@B@@@Z");
	mangledToCtypes("?FunctionDefinedWithInjectedName@@YAXU?$TypeWithFriendDefinition@H@@@Z");
	mangledToCtypes("?bar@?$UUIDType4@$1?_GUID_12345678_1234_1234_1234_1234567890ab@@3U__s_GUID@@B@@QAEXXZ");
	mangledToCtypes("??$f@US@@$1?g@1@QEAAXXZ@@YAXXZ");
	mangledToCtypes("??$?0N@?$Foo@H@@QEAA@N@Z");
	mangledToCtypes("??$CallMethod@UC@NegativeNVOffset@@$I??_912@$BA@AEPPPPPPPM@A@@@YAXAAUC@NegativeNVOffset@@@Z");
	mangledToCtypes("??$CallMethod@UM@@$0A@@@YAXAAUM@@@Z");
	mangledToCtypes("??$CallMethod@UM@@$H??_91@$BA@AEA@@@YAXAAUM@@@Z");
	mangledToCtypes("??$CallMethod@UM@@$H?f@1@QAEXXZA@@@YAXAAUM@@@Z");
	mangledToCtypes("??$CallMethod@UO@@$H??_91@$BA@AE3@@YAXAAUO@@@Z");
	mangledToCtypes("??$CallMethod@US@@$0A@@@YAXAAUS@@@Z");
	mangledToCtypes("??$CallMethod@US@@$1??_91@$BA@AE@@YAXAAUS@@@Z");
	mangledToCtypes("??$CallMethod@US@@$1?f@1@QAEXXZ@@YAXAAUS@@@Z");
	mangledToCtypes("??$CallMethod@UU@@$0A@@@YAXAAUU@@@Z");
	mangledToCtypes("??$CallMethod@UU@@$J??_91@$BA@AEA@A@A@@@YAXAAUU@@@Z");
	mangledToCtypes("??$CallMethod@UU@@$J?f@1@QAEXXZA@A@A@@@YAXAAUU@@@Z");
	mangledToCtypes("??$CallMethod@UV@@$0A@@@YAXAAUV@@@Z");
	mangledToCtypes("??$CallMethod@UV@@$I??_91@$BA@AEA@A@@@YAXAAUV@@@Z");
	mangledToCtypes("??$CallMethod@UV@@$I?f@1@QAEXXZA@A@@@YAXAAUV@@@Z");
	mangledToCtypes("??$ReadField@UA@@$0?0@@YAHAAUA@@@Z");
	mangledToCtypes("??$ReadField@UA@@$0A@@@YAHAAUA@@@Z");
	mangledToCtypes("??$ReadField@UI@@$03@@YAHAAUI@@@Z");
	mangledToCtypes("??$ReadField@UI@@$0A@@@YAHAAUI@@@Z");
	mangledToCtypes("??$ReadField@UM@@$0A@@@YAHAAUM@@@Z");
	mangledToCtypes("??$ReadField@UM@@$0BA@@@YAHAAUM@@@Z");
	mangledToCtypes("??$ReadField@UM@@$0M@@@YAHAAUM@@@Z");
	mangledToCtypes("??$ReadField@US@@$03@@YAHAAUS@@@Z");
	mangledToCtypes("??$ReadField@US@@$07@@YAHAAUS@@@Z");
	mangledToCtypes("??$ReadField@US@@$0A@@@YAHAAUS@@@Z");
	mangledToCtypes("??$ReadField@UU@@$0A@@@YAHAAUU@@@Z");
	mangledToCtypes("??$ReadField@UU@@$G3A@A@@@YAHAAUU@@@Z");
	mangledToCtypes("??$ReadField@UU@@$G7A@A@@@YAHAAUU@@@Z");
	mangledToCtypes("??$ReadField@UV@@$0A@@@YAHAAUV@@@Z");
	mangledToCtypes("??$ReadField@UV@@$F7A@@@YAHAAUV@@@Z");
	mangledToCtypes("??$ReadField@UV@@$FM@A@@@YAHAAUV@@@Z");
	mangledToCtypes("?Q@@3$$QEAP8Foo@@EAAXXZEA");
	mangledToCtypes("?m@@3U?$J@UM@@$0A@@@A");
	mangledToCtypes("?m2@@3U?$K@UM@@$0?0@@A");
	mangledToCtypes("?n@@3U?$J@UN@@$HA@@@A");
	mangledToCtypes("?n2@@3U?$K@UN@@$0?0@@A");
	mangledToCtypes("?o@@3U?$J@UO@@$IA@A@@@A");
	mangledToCtypes("?o2@@3U?$K@UO@@$FA@?0@@A");
	mangledToCtypes("?p@@3U?$J@UP@@$JA@A@?0@@A");
	mangledToCtypes("?p2@@3U?$K@UP@@$GA@A@?0@@A");
	mangledToCtypes("??0?$ClassTemplate@$J??_9MostGeneral@@$BA@AEA@M@3@@QAE@XZ");
	mangledToCtypes("?f@C@@WBA@EAAHXZ");
	mangledToCtypes("??_EDerived@@$4PPPPPPPM@A@EAAPEAXI@Z");
	mangledToCtypes("?f@A@simple@@$R477PPPPPPPM@7AEXXZ");
	mangledToCtypes("??_9Base@@$B7AA");
	mangledToCtypes("?bar@Foo@@SGXXZ");
	mangledToCtypes("?bar@Foo@@QAGXXZ");
	mangledToCtypes("?f2@@YIXXZ");
	mangledToCtypes("?f1@@YGXXZ");
}

}	// namespace tests
}	// namespace ctypesparser
}	// namespace retdec