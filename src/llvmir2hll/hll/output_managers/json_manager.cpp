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

using JsonKeyPair = const JsonOutputManager::JsonKeyPair;

JsonKeyPair JSON_KEY_LANGUAGE        = {"l", "language"};
JsonKeyPair JSON_KEY_LINES           = {"ls", "lines"};
JsonKeyPair JSON_KEY_ADDRESS         = {"a", "addr"};
JsonKeyPair JSON_KEY_TOKENS          = {"ts", "tokens"};
JsonKeyPair JSON_KEY_KIND            = {"k", "kind"};
JsonKeyPair JSON_KEY_VALUE           = {"v", "value"};

JsonKeyPair JSON_TOKEN_SPACE         = {"s", "space"};
JsonKeyPair JSON_TOKEN_PUNCTUATION   = {"p", "punctuation"};
JsonKeyPair JSON_TOKEN_OPERATOR      = {"o", "operator"};
JsonKeyPair JSON_TOKEN_ID_VAR        = {"iv", "id_var"};
JsonKeyPair JSON_TOKEN_ID_MEMBER     = {"im", "id_member"};
JsonKeyPair JSON_TOKEN_ID_LABEL      = {"il", "id_label"};
JsonKeyPair JSON_TOKEN_ID_FUNCTION   = {"if", "id_function"};
JsonKeyPair JSON_TOKEN_ID_PARAMETER  = {"ip", "id_param"};
JsonKeyPair JSON_TOKEN_KEYWORD       = {"k", "keyword"};
JsonKeyPair JSON_TOKEN_DATA_TYPE     = {"dt", "data_type"};
JsonKeyPair JSON_TOKEN_PREPROCESSOR  = {"r", "preprocessor"};
JsonKeyPair JSON_TOKEN_INCLUDE       = {"i", "include"};
JsonKeyPair JSON_TOKEN_CONST_BOOL    = {"cb", "const_bool"};
JsonKeyPair JSON_TOKEN_CONST_INT     = {"ci", "const_int"};
JsonKeyPair JSON_TOKEN_CONST_FLOAT   = {"cf", "const_f"};
JsonKeyPair JSON_TOKEN_CONST_STRING  = {"cs", "const_string"};
JsonKeyPair JSON_TOKEN_CONST_SYMBOL  = {"cy", "const_symbol"};
JsonKeyPair JSON_TOKEN_CONST_POINTER = {"cp", "const_pointer"};
JsonKeyPair JSON_TOKEN_COMMENT       = {"c", "comment"};

} // anonymous namespace

JsonOutputManager::JsonOutputManager(llvm::raw_ostream& out) :
        _out(out),
        _lines(Json::arrayValue),
        _line(Json::arrayValue)
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
    root[getJsonKey(JSON_KEY_LANGUAGE)] = getOutputLanguage();
    root[getJsonKey(JSON_KEY_LINES)] = _lines;
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

void JsonOutputManager::space(const std::string& space)
{
    _line.append(jsonToken(JSON_TOKEN_SPACE, space));
}

void JsonOutputManager::punctuation(char p)
{
    _line.append(jsonToken(JSON_TOKEN_PUNCTUATION, std::string(1, p)));
}

void JsonOutputManager::operatorX(
    const std::string& op,
    bool spaceBefore,
    bool spaceAfter)
{
    if (spaceBefore)
    {
        space();
    }
    _line.append(jsonToken(JSON_TOKEN_OPERATOR, op));
    if (spaceAfter)
    {
        space();
    }
}

void JsonOutputManager::variableId(const std::string& id)
{
    _line.append(jsonToken(JSON_TOKEN_ID_VAR, id));
}

void JsonOutputManager::memberId(const std::string& id)
{
    _line.append(jsonToken(JSON_TOKEN_ID_MEMBER, id));
}

void JsonOutputManager::labelId(const std::string& id)
{
    _line.append(jsonToken(JSON_TOKEN_ID_LABEL, id));
}

void JsonOutputManager::functionId(const std::string& id)
{
    _line.append(jsonToken(JSON_TOKEN_ID_FUNCTION, id));
}

void JsonOutputManager::parameterId(const std::string& id)
{
    _line.append(jsonToken(JSON_TOKEN_ID_PARAMETER, id));
}

void JsonOutputManager::keyword(const std::string& k)

{
    _line.append(jsonToken(JSON_TOKEN_KEYWORD, k));
}

void JsonOutputManager::dataType(const std::string& t)
{
    _line.append(jsonToken(JSON_TOKEN_DATA_TYPE, t));
}

void JsonOutputManager::preprocessor(const std::string& p)
{
    _line.append(jsonToken(JSON_TOKEN_PREPROCESSOR, p));
}

void JsonOutputManager::include(const std::string& i)
{
    _line.append(jsonToken(JSON_TOKEN_INCLUDE, "<" + i + ">"));
}

void JsonOutputManager::constantBool(const std::string& c)
{
    _line.append(jsonToken(JSON_TOKEN_CONST_BOOL, c));
}

void JsonOutputManager::constantInt(const std::string& c)
{
    _line.append(jsonToken(JSON_TOKEN_CONST_INT, c));
}

void JsonOutputManager::constantFloat(const std::string& c)
{
    _line.append(jsonToken(JSON_TOKEN_CONST_FLOAT, c));
}

void JsonOutputManager::constantString(const std::string& c)
{
    _line.append(jsonToken(JSON_TOKEN_CONST_STRING, c));
}

void JsonOutputManager::constantSymbol(const std::string& c)
{
    _line.append(jsonToken(JSON_TOKEN_CONST_SYMBOL, c));
}

void JsonOutputManager::constantPointer(const std::string& c)
{
    _line.append(jsonToken(JSON_TOKEN_CONST_POINTER, c));
}

void JsonOutputManager::comment(
    const std::string& c,
    const std::string& indent)
{
    std::stringstream ss;
    ss << indent << getCommentPrefix();
    if (!c.empty())
    {
        ss << " " << utils::replaceCharsWithStrings(c, '\n', " ");
    }
    _line.append(jsonToken(JSON_TOKEN_COMMENT, ss.str()));
}

void JsonOutputManager::newLine(Address addr)
{
    Json::Value l;
    l[getJsonKey(JSON_KEY_ADDRESS)] = utils::toHexString(addr);
    l[getJsonKey(JSON_KEY_TOKENS)] = _line;
    _lines.append(l);
    _line = Json::Value(Json::arrayValue);
}

void JsonOutputManager::commentModifier(const std::string& indent)
{
    // TODO
}

const std::string& JsonOutputManager::getJsonKey(
        const JsonOutputManager::JsonKeyPair& k) const
{
    return isHumanReadable() ? k.humanKey : k.defaultKey;
}

Json::Value JsonOutputManager::jsonToken(
        const JsonOutputManager::JsonKeyPair& k,
        const std::string& v) const
{
	Json::Value r;
	r[getJsonKey(JSON_KEY_KIND)] = getJsonKey(k);
	r[getJsonKey(JSON_KEY_VALUE)] = v;
	return r;
}

} // namespace llvmir2hll
} // namespace retdec
