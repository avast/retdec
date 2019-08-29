/**
* @file src/llvmir2hll/hll/output_manager/json_manager.cpp
* @brief Implementation of JsonOutputManager.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/output_managers/json_manager.h"
#include "retdec/utils/string.h"

namespace retdec {
namespace llvmir2hll {

namespace {

const std::string JSON_KEY_LANGUAGE        = "language";
const std::string JSON_KEY_ADDRESS         = "addr";
const std::string JSON_KEY_TOKENS          = "tokens";
const std::string JSON_KEY_KIND            = "kind";
const std::string JSON_KEY_VALUE           = "val";

const std::string JSON_TOKEN_NEWLINE       = "nl";
const std::string JSON_TOKEN_SPACE         = "ws";
const std::string JSON_TOKEN_PUNCTUATION   = "punc";
const std::string JSON_TOKEN_OPERATOR      = "op";
const std::string JSON_TOKEN_ID_VAR        = "i_var";
const std::string JSON_TOKEN_ID_MEMBER     = "i_mem";
const std::string JSON_TOKEN_ID_LABEL      = "i_lab";
const std::string JSON_TOKEN_ID_FUNCTION   = "i_fnc";
const std::string JSON_TOKEN_ID_PARAMETER  = "i_arg";
const std::string JSON_TOKEN_KEYWORD       = "keyw";
const std::string JSON_TOKEN_DATA_TYPE     = "type";
const std::string JSON_TOKEN_PREPROCESSOR  = "preproc";
const std::string JSON_TOKEN_INCLUDE       = "inc";
const std::string JSON_TOKEN_CONST_BOOL    = "c_bool";
const std::string JSON_TOKEN_CONST_INT     = "c_int";
const std::string JSON_TOKEN_CONST_FLOAT   = "c_fp";
const std::string JSON_TOKEN_CONST_STRING  = "c_str";
const std::string JSON_TOKEN_CONST_SYMBOL  = "c_sym";
const std::string JSON_TOKEN_CONST_POINTER = "c_ptr";
const std::string JSON_TOKEN_COMMENT       = "cmnt";

/**
 * We don't like macros, but we potentially need to return from methods calling
 * this helper routine, so we use it here anyway.
 * \val Anything that can be concatenated (+) to a std::string.
 */
#define HANDLE_COMMENT_MODIFIER(val)                 \
{                                                    \
    if (_commentModifierOn)                          \
    {                                                \
        _runningComment += val;                      \
        return;                                      \
    }                                                \
}

} // anonymous namespace

JsonOutputManager::JsonOutputManager(llvm::raw_ostream& out, bool humanReadable) :
        _out(out),
        _humanReadable(humanReadable),
        _tokens(Json::arrayValue)
{

}

JsonOutputManager::~JsonOutputManager()
{
    Json::StreamWriterBuilder builder;

    if (!isHumanReadable())
    {
        builder["commentStyle"] = "None";
        builder["indentation"] = "";
    }

    Json::Value root;
    root[JSON_KEY_LANGUAGE] = getOutputLanguage();
    root[JSON_KEY_TOKENS] = _tokens;
    _out << writeString(builder, root);
}

void JsonOutputManager::setHumanReadable(bool b)
{
    _humanReadable = b;
}

bool JsonOutputManager::isHumanReadable() const
{
    return _humanReadable;
}

void JsonOutputManager::newLine(Address a)
{
    if (_commentModifierOn)
    {
        if (!_runningComment.empty())
        {
            comment(_runningComment, _commentModifierAddr);
            _runningComment.clear();
        }
        _commentModifierOn = false;
        _commentModifierAddr = Address::Undefined;
    }

    _tokens.append(jsonToken(JSON_TOKEN_NEWLINE, "\n", a));
}

void JsonOutputManager::space(const std::string& space, Address a)
{
    HANDLE_COMMENT_MODIFIER(space);
    _tokens.append(jsonToken(JSON_TOKEN_SPACE, space, a));
}

void JsonOutputManager::punctuation(char p, Address a)
{
    HANDLE_COMMENT_MODIFIER(p);
    _tokens.append(jsonToken(JSON_TOKEN_PUNCTUATION, std::string(1, p), a));
}

void JsonOutputManager::operatorX(const std::string& op, Address a)
{
    HANDLE_COMMENT_MODIFIER(op);
    _tokens.append(jsonToken(JSON_TOKEN_OPERATOR, op, a));
}

void JsonOutputManager::variableId(const std::string& id, Address a)
{
    HANDLE_COMMENT_MODIFIER(id);
    _tokens.append(jsonToken(JSON_TOKEN_ID_VAR, id, a));
}

void JsonOutputManager::memberId(const std::string& id, Address a)
{
    HANDLE_COMMENT_MODIFIER(id);
    _tokens.append(jsonToken(JSON_TOKEN_ID_MEMBER, id, a));
}

void JsonOutputManager::labelId(const std::string& id, Address a)
{
    HANDLE_COMMENT_MODIFIER(id);
    _tokens.append(jsonToken(JSON_TOKEN_ID_LABEL, id, a));
}

void JsonOutputManager::functionId(const std::string& id, Address a)
{
    HANDLE_COMMENT_MODIFIER(id);
    _tokens.append(jsonToken(JSON_TOKEN_ID_FUNCTION, id, a));
}

void JsonOutputManager::parameterId(const std::string& id, Address a)
{
    HANDLE_COMMENT_MODIFIER(id);
    _tokens.append(jsonToken(JSON_TOKEN_ID_PARAMETER, id, a));
}

void JsonOutputManager::keyword(const std::string& k, Address a)
{
    HANDLE_COMMENT_MODIFIER(k);
    _tokens.append(jsonToken(JSON_TOKEN_KEYWORD, k, a));
}

void JsonOutputManager::dataType(const std::string& t, Address a)
{
    HANDLE_COMMENT_MODIFIER(t);
    _tokens.append(jsonToken(JSON_TOKEN_DATA_TYPE, t, a));
}

void JsonOutputManager::preprocessor(const std::string& p, Address a)
{
    HANDLE_COMMENT_MODIFIER(p);
    _tokens.append(jsonToken(JSON_TOKEN_PREPROCESSOR, p, a));
}

void JsonOutputManager::include(const std::string& i, Address a)
{
    HANDLE_COMMENT_MODIFIER(i);
    _tokens.append(jsonToken(JSON_TOKEN_INCLUDE, "<" + i + ">", a));
}

void JsonOutputManager::constantBool(const std::string& c, Address a)
{
    HANDLE_COMMENT_MODIFIER(c);
    _tokens.append(jsonToken(JSON_TOKEN_CONST_BOOL, c, a));
}

void JsonOutputManager::constantInt(const std::string& c, Address a)
{
    HANDLE_COMMENT_MODIFIER(c);
    _tokens.append(jsonToken(JSON_TOKEN_CONST_INT, c, a));
}

void JsonOutputManager::constantFloat(const std::string& c, Address a)
{
    HANDLE_COMMENT_MODIFIER(c);
    _tokens.append(jsonToken(JSON_TOKEN_CONST_FLOAT, c, a));
}

void JsonOutputManager::constantString(const std::string& c, Address a)
{
    HANDLE_COMMENT_MODIFIER(c);
    _tokens.append(jsonToken(JSON_TOKEN_CONST_STRING, c, a));
}

void JsonOutputManager::constantSymbol(const std::string& c, Address a)
{
    HANDLE_COMMENT_MODIFIER(c);
    _tokens.append(jsonToken(JSON_TOKEN_CONST_SYMBOL, c, a));
}

void JsonOutputManager::constantPointer(const std::string& c, Address a)
{
    HANDLE_COMMENT_MODIFIER(c);
    _tokens.append(jsonToken(JSON_TOKEN_CONST_POINTER, c, a));
}

void JsonOutputManager::comment(const std::string& c, Address a)
{
    HANDLE_COMMENT_MODIFIER(" " + c);
    std::string str = getCommentPrefix();
    if (!c.empty())
    {
        str += " " + utils::replaceCharsWithStrings(c, '\n', " ");
    }
    _tokens.append(jsonToken(JSON_TOKEN_COMMENT, str, a));
}

void JsonOutputManager::commentModifier(Address a)
{
    _commentModifierOn = true;
    _commentModifierAddr = a;
}

Json::Value JsonOutputManager::jsonToken(
        const std::string& k,
        const std::string& v,
        Address a) const
{
	Json::Value r;
	r[JSON_KEY_KIND] = k;
    r[JSON_KEY_VALUE] = v;
    if (a.isDefined())
    {
        r[JSON_KEY_ADDRESS] = a.toHexPrefixString();
    }
	return r;
}

} // namespace llvmir2hll
} // namespace retdec
