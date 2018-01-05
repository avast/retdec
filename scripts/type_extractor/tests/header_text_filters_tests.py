"""Units tests for the type_extractor.header_text_filters module."""

import unittest

from type_extractor.header_text_filters import filter_annotations_with_brackets
from type_extractor.header_text_filters import filter_annotations_without_brackets
from type_extractor.header_text_filters import filter_conditional_preprocessor_statements
from type_extractor.header_text_filters import filter_cplusplus_ifdefs
from type_extractor.header_text_filters import filter_oneline_typedefs
from type_extractor.header_text_filters import filter_out_comments
from type_extractor.header_text_filters import filter_out_macros
from type_extractor.header_text_filters import filter_specific_keywords
from type_extractor.header_text_filters import filter_whitespaces
from type_extractor.header_text_filters import join_lines_ending_with_backslash
from type_extractor.header_text_filters import substitute_specific_keywords
from type_extractor.header_text_filters import unify_ends_of_lines
from type_extractor.header_text_filters import use_filters


class FilterTests(unittest.TestCase):
    def test_unifies_ends_of_lines(self):
        text = 'a\r\nb\rc\nd'
        self.assertEqual(unify_ends_of_lines(text), 'a\nb\nc\nd')

    def test_joins_lines_ending_with_backslash(self):
        text = '#define\\\nA\\\nB'
        self.assertEqual(join_lines_ending_with_backslash(text), '#define A B')

    def test_filter_cplusplus_ifdef(self):
        text = '# ifdef __cplusplus class {xyz} #def STH... # endif'
        self.assertEqual(filter_cplusplus_ifdefs(text), ';')

    def test_filter_cplusplus_ifdef_to_else_branch(self):
        text = '# ifdef __cplusplus class {xyz} #else STH # endif'
        self.assertEqual(filter_cplusplus_ifdefs(text), '; STH # endif')

    def test_filter_cplusplus_ifdef_to_elif_branch(self):
        text = '# ifdef (__cplusplus) class {xyz} #elif not_cpp do sth'
        self.assertEqual(filter_cplusplus_ifdefs(text), '; not_cpp do sth')

    def test_use_all_filters(self):
        text = """//comment
            #ifdef
            __In_read_ __nonull((3)) ;
        """
        self.assertEqual(use_filters(text), ' ; ')

    def scenario_is_not_supported_text(self, text):
        """Verifies that the given text is not supported and should not be
        processed.
        """
        self.assertEqual(use_filters(text), '')

    def test_files_with_cpp_classes_are_unsupported(self):
        text = """//comment
            class A : class B{
                some data };
            __In_read_ __nonull() ;
        """
        self.scenario_is_not_supported_text(text)

    def test_files_with_assembly_code_in_windows_sdk_are_unsupported(self):
        text = ';\n; Copyright (c) Microsoft Corporation.  All rights reserved.\n'
        self.scenario_is_not_supported_text(text)

    def test_filter_out_oneline_comment(self):
        text = """some text//comment
        new line"""
        expected = """some text
        new line"""
        self.assertEqual(filter_out_comments(text), expected)

    def test_filter_out_multiline_comment(self):
        text = """some text/* comment on
        few lines
        http://xyz.com */and last few words"""
        expected = """some text and last few words"""
        self.assertEqual(filter_out_comments(text), expected)

    def test_filter_out_comments_correctly(self):
        text = """//**************
        first
        // xx */ yy
        second
        /*
        //http://xyz.com /*and last few words
        */
        """
        expected = ['first', 'second']
        self.assertEqual(filter_out_comments(text).split(), expected)

    def test_filter_macros(self):
        text = """first line
        #define XYZZ 10
        #define multi \
                line \
                macro"""
        expected = """first line\n\n"""
        self.assertEqual(filter_out_macros(text), expected)

    def test_filter_typedefs(self):
        type1 = 'typedef int_64 MY_NEW_TYPE ;'
        type2 = """typedef struct {
            multiline} no_effect;"""

        self.assertEqual(filter_oneline_typedefs(type1), '')
        self.assertEqual(filter_oneline_typedefs(type2), type2)

    def test_filter_annotations(self):
        self.assertEqual(
            filter_annotations_without_brackets('_Suc_cess_'), '')
        self.assertEqual(
            filter_annotations_without_brackets('_Must_inspect_result_'), '')
        self.assertEqual(
            filter_annotations_without_brackets(
                '_Out_ _Out_Writes_maybe_null_'),
            '_Out_ '
        )
        self.assertEqual(
            filter_annotations_without_brackets(
                '__attribute__ ((format, printf(3)))'),
            ''
        )
        self.assertEqual(
            filter_annotations_with_brackets(
                '_Out_writes_bytes_(lptr* somewhere (where roses are red))'),
            ''
        )

    def test_filter__in__out_annotations_with_brackets(self):
        self.assertEqual(
            filter_annotations_with_brackets(', __in_xx(yy) param'), ', param')
        self.assertEqual(
            filter_annotations_with_brackets('(__out_xx(yy) __int32_t'), '( __int32_t')

    def test_filter_some_keywords(self):
        words = [
            'WINAPI_INLINE',
            'extern',
            'extern "C" {',
            'ExternC',
            '__wur',
            'BEGIN_NAMESPACE_CPP'
            'BEGIN_NAMESPACE'
            'NAMESPACE_CPP'
        ]
        for w in words:
            self.assertEqual(filter_specific_keywords(w), '')

        w1 = '__THROW;'
        self.assertEqual(filter_specific_keywords(w1), ';')

    def test_filter_whitespaces_correctly(self):
        self.assertEqual(
            filter_whitespaces(')   ; int *a; char * *c;'),
            '); int * a; char ** c;'
        )

    def test_filter_annotations_with_incorrect_brackets_count_not_remove_it(self):
        text = '__Throw__(((format, 2);'
        self.assertEqual(filter_annotations_with_brackets(text), text)

    def test_filter_whitespaces_around_one_pointer(self):
        self.assertEqual(filter_whitespaces('  *  '), ' * ')

    def test_filter_whitespaces_around__double_pointer(self):
        self.assertEqual(filter_whitespaces('  * *  '), ' ** ')

    def test_filter_whitespaces_around_many_pointers(self):
        self.assertEqual(filter_whitespaces('  * * *  * * '), ' ***** ')

    def test_filter_whitespaces_around_comma(self):
        self.assertEqual(filter_whitespaces('  ,  '), ', ')

    def test_filter_many_whitespaces_to_one(self):
        self.assertEqual(filter_whitespaces('   \n \t '), ' ')

    def test_filter_whitespaces_around_brackets(self):
        self.assertEqual(filter_whitespaces(' ( )  [  ]  {  } '), '()[]{ }')

    def test_filter_api_keyword(self):
        self.assertEqual(filter_specific_keywords('ACLUIAPI'), '')
        self.assertEqual(filter_specific_keywords('ACMAPI'), '')
        self.assertEqual(filter_specific_keywords('AJ_API'), '')
        self.assertEqual(filter_specific_keywords('AMOVIEAPI'), '')
        self.assertEqual(filter_specific_keywords('APIENTRY'), '')
        self.assertEqual(filter_specific_keywords('AUTHZAPI'), '')
        self.assertEqual(filter_specific_keywords('AVRTAPI'), '')
        self.assertEqual(filter_specific_keywords('BATTERYCLASSAPI'), '')
        self.assertEqual(filter_specific_keywords('BERAPI'), '')
        self.assertEqual(filter_specific_keywords('CERTBCLI_API'), '')
        self.assertEqual(filter_specific_keywords('CERTPOLENGAPI'), '')
        self.assertEqual(filter_specific_keywords('CLFSUSER_API'), '')
        self.assertEqual(filter_specific_keywords('CMAPI'), '')
        self.assertEqual(filter_specific_keywords('CREDUIAPI'), '')
        self.assertEqual(filter_specific_keywords('CRYPTDLGAPI'), '')
        self.assertEqual(filter_specific_keywords('DDAPI'), '')
        self.assertEqual(filter_specific_keywords('DHCP_API_FUNCTION'), '')
        self.assertEqual(filter_specific_keywords('DIAMONDAPI'), '')
        self.assertEqual(filter_specific_keywords('DPAPI_IMP'), '')
        self.assertEqual(filter_specific_keywords('DSGETDCAPI'), '')
        self.assertEqual(filter_specific_keywords('ENGAPI'), '')
        self.assertEqual(filter_specific_keywords('EVNTAPI'), '')
        self.assertEqual(filter_specific_keywords('FLTAPI'), '')
        self.assertEqual(filter_specific_keywords('GPEDITAPI'), '')
        self.assertEqual(filter_specific_keywords('HBA_API'), '')
        self.assertEqual(filter_specific_keywords('HTTPAPI_LINKAGE'), '')
        self.assertEqual(filter_specific_keywords('IMAGEAPI'), '')
        self.assertEqual(filter_specific_keywords('INSTAPI'), '')
        self.assertEqual(filter_specific_keywords('INTSHCUTAPI'), '')
        self.assertEqual(filter_specific_keywords('ISDSC_API'), '')
        self.assertEqual(filter_specific_keywords('JET_API'), '')
        self.assertEqual(filter_specific_keywords('KSDDKAPI'), '')
        self.assertEqual(filter_specific_keywords('LDAPAPI'), '')
        self.assertEqual(filter_specific_keywords('NETIOAPI_API_'), '')
        self.assertEqual(filter_specific_keywords('NET_API_FUNCTION'), '')
        self.assertEqual(filter_specific_keywords('NTKERNELAPI'), '')
        self.assertEqual(filter_specific_keywords('NTAPI'), '')
        self.assertEqual(filter_specific_keywords('NTDSAPI'), '')
        self.assertEqual(filter_specific_keywords('NTHALAPI'), '')
        self.assertEqual(filter_specific_keywords('NTPSHEDAPI'), '')
        self.assertEqual(filter_specific_keywords('NTSYSAPI'), '')
        self.assertEqual(filter_specific_keywords('NTSYSCALLAPI'), '')
        self.assertEqual(filter_specific_keywords('ORAPI'), '')
        self.assertEqual(filter_specific_keywords('PATCHAPI'), '')
        self.assertEqual(filter_specific_keywords('PHP_JSON_API'), '')
        self.assertEqual(filter_specific_keywords('PXEAPI'), '')
        self.assertEqual(filter_specific_keywords('PORTCLASSAPI'), '')
        self.assertEqual(filter_specific_keywords('ROAPI'), '')
        self.assertEqual(filter_specific_keywords('REGAPI'), '')
        self.assertEqual(filter_specific_keywords('RPCNSAPI'), '')
        self.assertEqual(filter_specific_keywords('RPCRTAPI'), '')
        self.assertEqual(filter_specific_keywords('SCSIPORT_API'), '')
        self.assertEqual(filter_specific_keywords('SDBAPI'), '')
        self.assertEqual(filter_specific_keywords('SNAPI'), '')
        self.assertEqual(filter_specific_keywords('SNMPAPI_CALL'), '')
        self.assertEqual(filter_specific_keywords('SNMP_FUNC_TYPE'), '')
        self.assertEqual(filter_specific_keywords('SQL_API'), '')
        self.assertEqual(filter_specific_keywords('SQL_SPI'), '')
        self.assertEqual(filter_specific_keywords('STORPORT_API'), '')
        self.assertEqual(filter_specific_keywords('TSPIAPI'), '')
        self.assertEqual(filter_specific_keywords('UDAPICALL'), '')
        self.assertEqual(filter_specific_keywords('USBRPMAPI'), '')
        self.assertEqual(filter_specific_keywords('USERENVAPI'), '')
        self.assertEqual(filter_specific_keywords('VFWAPI'), '')
        self.assertEqual(filter_specific_keywords('VFWAPIV'), '')
        self.assertEqual(filter_specific_keywords('VIDEOPORT_API'), '')
        self.assertEqual(filter_specific_keywords('W32KAPI'), '')
        self.assertEqual(filter_specific_keywords('WDSBPAPI'), '')
        self.assertEqual(filter_specific_keywords('WDSCLIAPI'), '')
        self.assertEqual(filter_specific_keywords('WDSMCSAPI'), '')
        self.assertEqual(filter_specific_keywords('WDSTCIAPI'), '')
        self.assertEqual(filter_specific_keywords('WDSTRANSPORTPROVIDERAPI'), '')
        self.assertEqual(filter_specific_keywords('WIAMICRO_API'), '')
        self.assertEqual(filter_specific_keywords('WINAPI'), '')
        self.assertEqual(filter_specific_keywords('WINAPI_INLINE'), '')
        self.assertEqual(filter_specific_keywords('WINGDIAPI'), '')
        self.assertEqual(filter_specific_keywords('WINSOCK_API_LINKAGE'), '')
        self.assertEqual(filter_specific_keywords('WMIAPI'), '')
        self.assertEqual(filter_specific_keywords('WSAAPI'), '')
        self.assertEqual(filter_specific_keywords('WSPAPI'), '')

    def test_filter_extern_keyword(self):
        self.assertEqual(filter_specific_keywords('extern'), '')
        self.assertEqual(filter_specific_keywords('extern "C" {'), '')

    def test_filter_throw_keyword(self):
        self.assertEqual(filter_specific_keywords('THROW;'), ';')
        self.assertEqual(filter_specific_keywords('__THROW(x);'), ';')
        self.assertEqual(filter_specific_keywords('__throw(x);'), ';')

    def test_filter_wur_keyword(self):
        self.assertEqual(filter_specific_keywords('__wur'), '')

    def test_filter_namespace_keyword(self):
        self.assertEqual(filter_specific_keywords('_NAMESPACE_'), '')
        self.assertEqual(filter_specific_keywords('BEGIN_NAMESPACE_X'), '')
        self.assertEqual(filter_specific_keywords('END_NAMESPACE_X'), '')

    def test_filter_extern_define_keyword(self):
        self.assertEqual(filter_specific_keywords('EXTERN_C'), '')
        self.assertEqual(filter_specific_keywords('EXTERN_GUID f();'), ' f();')
        self.assertEqual(filter_specific_keywords('EXTERN_GUID(xx) f();'), ' f();')
        self.assertEqual(filter_specific_keywords('DEFINE_ f();'), ' f();')
        self.assertEqual(filter_specific_keywords('DEFINE_XX(yy) f();'), ' f();')

    def test_filter_redirected_declarations(self):
        self.assertEqual(filter_specific_keywords('void __REDIRECT_NTH(f1,(p),f2);'), '')

    def test_filter_CRT_keyword(self):
        self.assertEqual(filter_specific_keywords('__CRT '), ' ')
        self.assertEqual(filter_specific_keywords('_CRT(xx)'), '')
        self.assertEqual(filter_specific_keywords('__crt(xx)'), '')

    def test_do_not_filter_CRT_DOUBLE_macro(self):
        self.assertEqual(filter_specific_keywords('_CRT_DOUBLE'), '_CRT_DOUBLE')

    def test_filter_drv_macro(self):
        self.assertEqual(filter_specific_keywords('__drv_xx'), '')
        self.assertEqual(filter_specific_keywords('__drv_xx(yy)'), '')

    def test_filter_declspec_macro(self):
        self.assertEqual(filter_specific_keywords('__DECLSPEC_ALIGN(x)'), '')
        self.assertEqual(filter_specific_keywords('__declspec(yy)'), '')

    def test_filter_align_macros(self):
        self.assertEqual(filter_specific_keywords('POINTER_ALIGNMENT'), '')
        self.assertEqual(filter_specific_keywords('ALIGN(8)'), '')

    def test_filter_RPC_keyword(self):
        self.assertEqual(filter_specific_keywords('__RPC_sth'), '')
        self.assertEqual(filter_specific_keywords('__RPC_sth(xx)'), '')

    def test_filter_macros_with_numbers_inside_double_brackets(self):
        self.assertEqual(filter_specific_keywords('__nonnull(())'), '')
        self.assertEqual(filter_specific_keywords('GL_ATTRIBUTE((1, 2))'), '')

    def test_filter_noreturn_keyword(self):
        self.assertEqual(filter_specific_keywords('__analysis_noreturn'), '')

    def test_filter_begin_end_decl_keyword(self):
        self.assertEqual(filter_specific_keywords('__BEGIN_DECLS'), '')
        self.assertEqual(filter_specific_keywords('__END_DECLS'), '')

    def test_filter_altdecl_macro(self):
        self.assertEqual(filter_specific_keywords('__ALTDECL'), '')

    def test_filter_dhcp_const_macro(self):
        self.assertEqual(filter_specific_keywords('DHCP_CONST'), '')

    def test_filter_fortify_function_macro(self):
        self.assertEqual(filter_specific_keywords('__fortify_function'), '')

    def test_filter_aligned_macro(self):
        self.assertEqual(filter_specific_keywords('aligned(8)'), '')
        self.assertEqual(filter_specific_keywords('__aligned(x)'), '')

    def test_filter_clrcall_macro(self):
        self.assertEqual(filter_specific_keywords('__clrcall'), '')

    def test_filter_v1_enum_macro(self):
        self.assertEqual(filter_specific_keywords('[v1_enum]'), '')

    def test_filter_inline_keyword(self):
        self.assertEqual(filter_specific_keywords('inline'), '')
        self.assertEqual(filter_specific_keywords('_inline'), '')
        self.assertEqual(filter_specific_keywords('__inline'), '')
        self.assertEqual(filter_specific_keywords('__INLINE'), '')
        self.assertEqual(filter_specific_keywords('__STRING_INLINE'), '')
        self.assertEqual(filter_specific_keywords('__MATH_INLINE'), '')
        self.assertEqual(filter_specific_keywords('__GMP_EXTERN_INLINE'), '')
        self.assertEqual(filter_specific_keywords('__extern_inline'), '')
        self.assertEqual(filter_specific_keywords('__extern_always_inline'), '')
        self.assertEqual(filter_specific_keywords('__forceinline'), '')
        self.assertEqual(filter_specific_keywords('FORCEINLINE'), '')
        self.assertEqual(filter_specific_keywords('CFORCEINLINE'), '')
        self.assertEqual(filter_specific_keywords('D2D1FORCEINLINE'), '')
        self.assertEqual(filter_specific_keywords('INLINE'), '')
        self.assertEqual(filter_specific_keywords('MI_INLINE'), '')
        self.assertEqual(filter_specific_keywords('MI_INLINE_CALL'), '')
        self.assertEqual(filter_specific_keywords('MSTCPIP_INLINE'), '')
        self.assertEqual(filter_specific_keywords('MSWSOCKDEF_INLINE'), '')
        self.assertEqual(filter_specific_keywords('NTAPI_INLINE'), '')
        self.assertEqual(filter_specific_keywords('VFWAPI_INLINE'), '')
        self.assertEqual(filter_specific_keywords('VXDINLINE'), '')
        self.assertEqual(filter_specific_keywords('WS2TCPIP_INLINE'), '')

    def test_return_keyword(self):
        self.assertEqual(filter_specific_keywords('return (x+y);'), ';')

    def test_filter_call_conv_macros(self):
        self.assertEqual(filter_specific_keywords('__callback'), '')
        self.assertEqual(filter_specific_keywords('__kernel_entry'), '')
        self.assertEqual(filter_specific_keywords('AJ_CALL'), '')
        self.assertEqual(filter_specific_keywords('CALLBACK'), '')
        self.assertEqual(filter_specific_keywords('PASCAL'), '')
        self.assertEqual(filter_specific_keywords('RPC_ENTRY'), '')
        self.assertEqual(filter_specific_keywords('STDMETHODCALLTYPE'), '')
        self.assertEqual(filter_specific_keywords('XM_CALLCONV'), '')

    def test_filter_dead_code_correctly(self):
        self.assertEqual(filter_out_macros('#if 0 int f(...); #endif'), '')

    def test_filter_preprocessor_else_branches(self):
        self.assertEqual(
            filter_conditional_preprocessor_statements(
                """#ifdef X
                    int a;
                   #elif Y
                    int b;
                   #else
                    int c;
                  #endif
                """).strip(),
            'int a;'
        )

    def test_filter_zlib_ZEXTERN_macro(self):
        self.assertEqual(filter_specific_keywords('ZEXTERN'), '')

    def test_filter_export_macros(self):
        self.assertEqual(filter_specific_keywords('DRMEXPORT'), '')
        self.assertEqual(filter_specific_keywords('EXPORT'), '')
        self.assertEqual(filter_specific_keywords('ZEXPORT'), '')
        self.assertEqual(filter_specific_keywords('FILEHC_EXPORT'), '')

    def test_filter_static_keyword(self):
        self.assertEqual(filter_specific_keywords('static'), '')

    def test_substitute_restrict_keyword(self):
        self.assertEqual(substitute_specific_keywords('__restrict'), 'restrict')

    def test_substitute_boolapi_without_underscore_with_bool(self):
        self.assertEqual(substitute_specific_keywords('BOOLAPI'), 'BOOL')

    def test_substitute_pfapientry_without_underscore_with_dword(self):
        self.assertEqual(substitute_specific_keywords('PFAPIENTRY'), 'DWORD')

    def test_substitute_snmpapi_without_underscore_with_int(self):
        self.assertEqual(substitute_specific_keywords('SNMPAPI'), 'INT')

    def test_substitute_tdhapi_without_underscore_with_ulong(self):
        self.assertEqual(substitute_specific_keywords('TDHAPI'), 'ULONG')

    def test_substitute_urlcacheapi_without_underscore_with_dword(self):
        self.assertEqual(substitute_specific_keywords('URLCACHEAPI'), 'DWORD')

    def test_substitute_api_without_underscore_with_hresult(self):
        self.assertEqual(substitute_specific_keywords('DWMAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('EXPORTAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('INTERNETAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('LWSTDAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('LWSTDAPIV'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('PSSTDAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('SHDOCAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('STDAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('SHFOLDERAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('SHSTDAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('STDMETHODIMP'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('STRSAFEAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('STRSAFEWORKERAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('STRSAFELOCALEWORKERAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('THEMEAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('WINOLEAPI'), 'HRESULT')
        self.assertEqual(substitute_specific_keywords('WINOLEAUTAPI'), 'HRESULT')

    def test_substitute_api_with_type_in_brackets(self):
        self.assertEqual(substitute_specific_keywords('LWSTDAPI_(BOOL)'), 'BOOL')
        self.assertEqual(substitute_specific_keywords('LWSTDAPIV_(BOOL)'), 'BOOL')
        self.assertEqual(substitute_specific_keywords('PSSTDAPI_(BOOL)'), 'BOOL')
        self.assertEqual(substitute_specific_keywords('SHSTDAPI_(BOOL)'), 'BOOL')
        self.assertEqual(substitute_specific_keywords('STDAPI_(BOOL)'), 'BOOL')
        self.assertEqual(substitute_specific_keywords('STDMETHODIMP_(BOOL)'), 'BOOL')
        self.assertEqual(substitute_specific_keywords('URLCACHEAPI_(BOOL)'), 'BOOL')
        self.assertEqual(substitute_specific_keywords('WINOLEAPI_(BOOL)'), 'BOOL')
        self.assertEqual(substitute_specific_keywords('WINOLEAUTAPI_(VOID)'), 'VOID')

    def test_filter_out_data_source_winapi_macro(self):
        self.assertEqual(filter_specific_keywords('__out_data_source(MacroItem)'), '')
        self.assertEqual(filter_specific_keywords('__in_data_source(MacroItem)'), '')

    def test_substitute_OF_function_wrapper(self):
        self.assertEqual(
            substitute_specific_keywords('int func OF((int a, char b));'),
            'int func (int a, char b);'
        )

    def test_substitute_Z_ARG_function_wrapper(self):
        self.assertEqual(
            substitute_specific_keywords('int func Z_ARG((int a, char b));'),
            'int func (int a, char b);'
        )

    def test_substitute_sec_entry_with_stdcall(self):
        self.assertEqual(substitute_specific_keywords('SEC_ENTRY'), '__stdcall')

    def test_substitute_RPC_VAR_ENTRY_with_cdecl(self):
        self.assertEqual(substitute_specific_keywords('RPC_VAR_ENTRY'), '__cdecl')

    def test_swap_optional_annotation_with_previous_word(self):
        self.assertEqual(
            substitute_specific_keywords('int pname OPTIONAL'),
            'int OPTIONAL pname'
        )

    def test_do_not_remove_annotations_ending_with_type(self):
        self.assertEqual(
            filter_annotations_without_brackets('__SIZE_TYPE__ x'),
            '__SIZE_TYPE__ x'
        )
