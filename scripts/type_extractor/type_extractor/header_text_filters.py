"""Filters useless information from header content."""

import re


def use_filters(text):
    text = unify_ends_of_lines(text)
    text = join_lines_ending_with_backslash(text)
    text = filter_out_comments(text)
    text = filter_cplusplus_ifdefs(text)
    text = filter_out_dead_code(text)
    text = filter_conditional_preprocessor_statements(text)
    text = filter_out_macros(text)
    text = filter_annotations_without_brackets(text)
    text = filter_annotations_with_brackets(text)
    text = substitute_specific_keywords(text)
    text = filter_specific_keywords(text)
    text = inline_func_to_decl(text)
    text = filter_whitespaces(text)
    return text if is_supported(text) else ''


def unify_ends_of_lines(text):
    """Converts CRLF (DOS) and CR (MacOS) to LF (UNIX).

    This is needed to simplify other filtering functions (they can assume that
    lines end with LF).
    """
    return re.sub('\r\n|\r', '\n', text)


def join_lines_ending_with_backslash(text):
    """Joins lines ending with '\\' (a single backslash).

    It removes the backslash and inserts a single space between the lines, just
    like the C pre-processor does.
    """
    # This prevents the extractor from considering e.g. 'defined
    # __USE_XOPEN2K8' as part of the return type of strdup():
    #
    #    #if defined __USE_SVID || defined __USE_BSD \
    #            || defined __USE_XOPEN2K8
    #        extern char *strdup(const char *__s);
    #    #endif
    #
    return text.replace('\\\n', ' ')


def filter_cplusplus_ifdefs(text):
    """Removes code for C++."""
    text = re.sub(
        r'#\s*if(def)?\s*\(?__cplusplus\)?.*?#\s*(else|elif|endif)', ';', text, flags=re.S)
    return text


def filter_conditional_preprocessor_statements(text):
    """Removes 'else' branches of #if[def] statement."""
    return re.sub(
        r'^\s*#\s*if(?:def)?.*?[\r\n]{1,2}(.*?(?=#\s*(?:else|elif|endif))).*?#\s*endif',
        r'\1', text, flags=re.S | re.M
    )


def is_supported(text):
    """Is the given text supported and should be processed?"""
    # Files with C++ classes are not supported.
    if re.search(r'\bclass\b[\w\s]+(:[^{]+)?\{', text):
        return False

    # Files with assembly code in Windows SDK are not supported. They start
    # with the following comment:
    if re.search(r'; *Copyright *\(c\) *Microsoft *Corporation\.', text):
        return False

    return True


def inline_func_to_decl(text):
    return re.sub(r'\)\s*\{.*?\}', '); ', text, flags=re.S)


def filter_out_comments(text):
    """Removes one-line and multi-line comments."""
    text = re.sub(r'//(?:(?!\*/).)*$', '', text, flags=re.M)
    text = re.sub(r'(?<!/)/\*.*?\*/', ' ', text, flags=re.S)
    text = re.sub(r'//.*?$', '', text, flags=re.M)
    return text


def filter_out_dead_code(text):
    """Removes '#if 0' code."""
    return re.sub(
        r'^\s*#\s*if\s*0\s*(?!\|\|).*?#\s*(else|elif|endif)', '', text, flags=re.S | re.M)


def filter_out_macros(text):
    """Removes one-line and multi-line preprocessor instructions."""
    text = re.sub(r'^\s*#.*[^\\]$', '', text, flags=re.M)
    start = r'^\s*#[^\\]+'
    cont = r'(?:.*\\[\n\r]{1,2})+'
    last = r'.*$'
    text = re.sub(start + cont + last, ' ', text, flags=re.M)
    return text


def filter_oneline_typedefs(text):
    """Removes definitions of typedefed types."""
    text = re.sub(r'typedef[^{}]*?;', '', text, flags=re.S)
    return text


def filter_annotations_without_brackets(text):
    """Removes useless annotations.

    Leaves only In|Out|Inout(opt). We expect annotations as '_sth_[sth2_]'.
    """
    text = re.sub(r'_Must_inspect_result_', '', text)
    text = re.sub(
        r"""
            __attribute__\s*
            \(\(
            [^()]+
            (\([^()]+\))?
            \)\)
        """,
        '',
        text,
        flags=re.VERBOSE
    )
    text = re.sub(
        r'\b(?!(_In_|_Out_|_Inout_)(opt_|z_)?\b|\w+_TYPE__\b)(_{1,2}\w+?_\b)(?!\s*\()', '', text)
    return text


def filter_annotations_with_brackets(text):
    """Removes annotations with some brackets.

    Even nested e.g. _When_(sth(nested bracket(nested in nested))).
    """
    text = re.sub(r'(?<=,|\()\s*\b__(in|out)\w+\s*\([^)]*\)', '', text)

    x = 0
    found = re.search(r'\b_{1,2}[A-Z]\w*_{1,2}\b\s*\(.*?\)(.*?\)){%d}' % x, text, flags=re.S)
    if found is None:
        return text
    annot = re.escape(found.group(0))
    while annot:
        while annot.count('(') != annot.count(')'):
            x = x + 1
            found = re.search(r'\b_{1,2}[A-Z]\w*_\b\s*\(.*?\)(.*?\)){%d}' % x, text, flags=re.S)
            if found is None:
                return text
            annot = re.escape(found.group(0))
        text = re.sub(annot, '', text, count=1)
        x = 0
        found = re.search(r'\b_{1,2}[A-Z]\w*_\b\s*\(.*?\)(.*?\)){%d}' % x, text, flags=re.S)
        if found is None:
            return text
        annot = re.escape(found.group(0))


def filter_specific_keywords(text):
    """Filters some keywords we don't need."""
    text = re.sub(
        r"""\b(
                ACLUIAPI
            |
                ACMAPI
            |
                AJ_API
            |
                AMOVIEAPI
            |
                APIENTRY
            |
                AUTHZAPI
            |
                AVRTAPI
            |
                BATTERYCLASSAPI
            |
                BERAPI
            |
                CERTBCLI_API
            |
                CERTPOLENGAPI
            |
                CLFSUSER_API
            |
                CMAPI
            |
                CREDUIAPI
            |
                CRYPTDLGAPI
            |
                DDAPI
            |
                DHCP_API_FUNCTION
            |
                DIAMONDAPI
            |
                DPAPI_IMP
            |
                DSGETDCAPI
            |
                ENGAPI
            |
                EVNTAPI
            |
                FLTAPI
            |
                GPEDITAPI
            |
                HBA_API
            |
                HTTPAPI_LINKAGE
            |
                IMAGEAPI
            |
                INSTAPI
            |
                INTSHCUTAPI
            |
                ISDSC_API
            |
                JET_API
            |
                KSDDKAPI
            |
                LDAPAPI
            |
                NETIOAPI_API_
            |
                NET_API_FUNCTION
            |
                NTAPI
            |
                NTDSAPI
            |
                NTHALAPI
            |
                NTKERNELAPI
            |
                NTPSHEDAPI
            |
                NTSYSAPI
            |
                NTSYSCALLAPI
            |
                ORAPI
            |
                PATCHAPI
            |
                PHP_JSON_API
            |
                PORTCLASSAPI
            |
                PXEAPI
            |
                REGAPI
            |
                ROAPI
            |
                RPCNSAPI
            |
                RPCRTAPI
            |
                SCSIPORT_API
            |
                SDBAPI
            |
                SNAPI
            |
                SNMPAPI_CALL
            |
                SNMP_FUNC_TYPE
            |
                SQL_(A|S)PI
            |
                STORPORT_API
            |
                TSPIAPI
            |
                UDAPICALL
            |
                USBRPMAPI
            |
                USERENVAPI
            |
                VFWAPIV?
            |
                VIDEOPORT_API
            |
                W32KAPI
            |
                WDSBPAPI
            |
                WDSCLIAPI
            |
                WDSMCSAPI
            |
                WDSTCIAPI
            |
                WDSTRANSPORTPROVIDERAPI
            |
                WIAMICRO_API
            |
                WIN[A-Z0-9_]*API[A-Z0-9_]*
            |
                WMIAPI
            |
                WSAAPI
            |
                WSPAPI
            )\b
        """,
        '',
        text,
        flags=re.VERBOSE
    )
    text = re.sub(r'\bextern(\s*"C"\s*\{)?', '', text)  # extern "C" {
    text = re.sub(r'\bExternC\b', '', text)
    text = re.sub(r'\s*(__)?(THROW|throw\s*\().*?;', ';', text)
    text = re.sub(r'__wur', '', text)
    text = re.sub(r'\b(\w*_)?NAMESPACE(_\w*)?\b', '', text)
    text = re.sub(
        r'(\bEXTERN_GUID|\bDEFINE_)\w*\b(\s*\([^()]*(\(\))?[^()]*\))?', '', text)
    text = re.sub(r'^[\w\s\*]*?__REDIRECT.*?;', '', text, flags=re.M | re.S)
    text = re.sub(r'\b_{1,2}(RPC|CRT(?!_DOUBLE)|crt)\w*\b(\s*\([^()]*\))?', '', text)
    text = re.sub(r'__(BEGIN|END)_DECLS', '', text)
    text = re.sub(r'\b\w*ALIGN\w*\b(\([^()]*\))?', '', text)
    text = re.sub(
        r"""\b(
                DRMEXPORT
            |
                EXPORT
            |
                ZEXPORT
            |
                FILEHC_EXPORT
            )\b
        """,
        '',
        text,
        flags=re.VERBOSE
    )
    text = re.sub(
        r"""\b(
                EXTERN_C
            |
                ZEXTERN
            )\b
        """,
        '',
        text,
        flags=re.VERBOSE
    )
    text = re.sub(
        r"""\b(
                inline
            |
                _inline
            |
                __inline
            |
                __INLINE
            |
                __STRING_INLINE
            |
                __MATH_INLINE
            |
                __GMP_EXTERN_INLINE
            |
                __extern_inline
            |
                __extern_always_inline
            |
                __forceinline
            |
                C?FORCEINLINE
            |
                D2D1FORCEINLINE
            |
                INLINE
            |
                MI_INLINE(_CALL)?
            |
                MSTCPIP_INLINE
            |
                MSWSOCKDEF_INLINE
            |
                NTAPI_INLINE
            |
                VFWAPI_INLINE
            |
                VXDINLINE
            |
                WS2TCPIP_INLINE
            )\b
        """,
        '',
        text,
        flags=re.VERBOSE
    )
    text = re.sub(
        r"""\b(
                __callback
            |
                __kernel_entry
            |
                AJ_CALL
            |
                CALLBACK
            |
                PASCAL
            |
                RPC_ENTRY
            |
                STDMETHODCALLTYPE
            |
                XM_CALLCONV
            |
                __clrcall
            )\b
        """,
        '',
        text,
        flags=re.VERBOSE
    )
    text = re.sub(r'__drv_\w+\b(\s*\([^()]*(\([^()]*\))?[^()]*\))?', '', text)
    text = re.sub(r'\breturn\b.*?;', ';', text)  # in inline blocks
    text = re.sub(r'\b__analysis_noreturn\b', '', text)
    text = re.sub(r'\b_.?CRTIMP\b', '', text)
    text = re.sub(r'\b\w*(DECLSPEC|declspec)\w*\b(\([^()]*\))?', '', text)
    text = re.sub(r'\b\__ALTDECL\b', '', text)
    text = re.sub(r'__(in|out)_data_source\([\s\w\*]+\)', '', text)
    text = re.sub(r'\b(FAR|far)\b', '', text)
    text = re.sub(r'\bstatic\b', '', text)
    text = re.sub(r'\b__fortify_function\b', '', text)
    text = re.sub(r'\w+\s*\(\([\d\s,]*\)\)', '', text)
    text = re.sub(r'(__|\b)aligned\(\w+\)', '', text)
    text = re.sub(r'\[v1_enum\]', '', text)
    text = re.sub(r'\bDHCP_CONST\b', '', text)
    return text


def substitute_specific_keywords(text):
    text = substitute_api_macors(text)
    text = re.sub(r'\bSEC_ENTRY\b', '__stdcall', text)
    text = re.sub(r'\bRPC_VAR_ENTRY\b', '__cdecl', text)
    text = re.sub(r'\bCONST\b', 'const', text)
    text = re.sub(r'\b__restrict\b', 'restrict', text)
    text = re.sub(r'\b(?:OF|Z_ARG)\s*\(\(([^;]*)\)\)\s*;', r'(\1);', text)  # zlib.h
    text = re.sub(r'\b(\w+)\s+(OPTIONAL)\b', r'\2 \1', text)
    return text


def substitute_api_macors(text):
    text = re.sub(r'\bBOOLAPI\b', 'BOOL', text)
    text = re.sub(r'\bPFAPIENTRY\b', 'DWORD', text)
    text = re.sub(r'\bSNMPAPI\b', 'INT', text)
    text = re.sub(r'\bTDHAPI\b', 'ULONG', text)
    text = re.sub(r'\bURLCACHEAPI\b', 'DWORD', text)

    text = re.sub(
        r"""\b(
                DWMAPI
            |
                EXPORTAPI
            |
                INTERNETAPI
            |
                LWSTDAPIV?
            |
                SHDOCAPI
            |
                (?:PS|SH)?STDAPI
            |
                SHFOLDERAPI
            |
                STDMETHODIMP
            |
                STRSAFE(LOCALEWORKER|WORKER)?API
            |
                THEMEAPI
            |
                WINOLE(?:AUT)?API
            )\b
        """,
        'HRESULT',
        text,
        flags=re.VERBOSE
    )
    text = re.sub(
        r"""\b(?:
                LWSTDAPIV?_
            |
                (?:PS|SH)?STDAPI_
            |
                STDMETHODIMP_
            |
                URLCACHEAPI_
            |
                WINOLE(?:AUT)?API_
            )
                \(([^()]+(?:\([^()]*\))?[^()]*)\)
        """,
        r'\1',
        text,
        flags=re.VERBOSE
    )
    return text


def filter_whitespaces(text):
    """Filters redundant whitespaces.

    Adds spaces around pointers, behind commas.
    """
    text = re.sub(r'\s*\*\s*', ' * ', text)
    text = re.sub(r'\*\s+\*', '**', text)
    text = re.sub(r'\*\s+\*', '**', text)  # need for 3+ pointers
    text = re.sub(r'\s*,\s*', ', ', text)
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'\s*\)\s*', ')', text)
    text = re.sub(r'\s*\(\s*', '(', text)
    text = re.sub(r'\s*\{\s*', '{ ', text)
    text = re.sub(r'\s*\}\s*', ' }', text)
    text = re.sub(r'\s*\[\s*', '[', text)
    text = re.sub(r'\s*\]\s*', ']', text)
    return text
