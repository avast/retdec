/**
* @file src/llvmir2hll/hll/output_managers/json_manager.cpp
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
const std::string JSON_TOKEN_ID_GVAR       = "i_gvar";
const std::string JSON_TOKEN_ID_LVAR       = "i_lvar";
const std::string JSON_TOKEN_ID_MEMBER     = "i_mem";
const std::string JSON_TOKEN_ID_LABEL      = "i_lab";
const std::string JSON_TOKEN_ID_FUNCTION   = "i_fnc";
const std::string JSON_TOKEN_ID_PARAMETER  = "i_arg";
const std::string JSON_TOKEN_KEYWORD       = "keyw";
const std::string JSON_TOKEN_DATA_TYPE     = "type";
const std::string JSON_TOKEN_PREPROCESSOR  = "preproc";
const std::string JSON_TOKEN_INCLUDE       = "inc";
const std::string JSON_TOKEN_CONST_BOOL    = "l_bool";
const std::string JSON_TOKEN_CONST_INT     = "l_int";
const std::string JSON_TOKEN_CONST_FLOAT   = "l_fp";
const std::string JSON_TOKEN_CONST_STRING  = "l_str";
const std::string JSON_TOKEN_CONST_SYMBOL  = "l_sym";
const std::string JSON_TOKEN_CONST_POINTER = "l_ptr";
const std::string JSON_TOKEN_COMMENT       = "cmnt";

/**
 * We don't like macros, but we potentially need to return from methods calling
 * this helper routine, so we use it here anyway.
 * \param val Anything that can be concatenated (+) to a std::string.
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

template <typename Writer>
JsonOutputManager<Writer>::JsonOutputManager(llvm::raw_ostream& out) :
		_out(out),
		writer(sb)
{
	writer.StartObject();

	writer.String(JSON_KEY_TOKENS);
	writer.StartArray();

	addressPush(Address::Undefined);
}

template <typename Writer>
void JsonOutputManager<Writer>::finalize()
{
	writer.EndArray();

	writer.String(JSON_KEY_LANGUAGE);
	writer.String(getOutputLanguage());

	writer.EndObject();

	_out << sb.GetString();
}

template <typename Writer>
void JsonOutputManager<Writer>::newLine()
{
	if (_commentModifierOn)
	{
		// Clear it righ away because comment() is used to generate token
		// and it checks for it.
		_commentModifierOn = false;
		if (!_runningComment.empty())
		{
			comment(_runningComment);
			_runningComment.clear();
		}
	}

	jsonToken(JSON_TOKEN_NEWLINE, "\n");
}

template <typename Writer>
void JsonOutputManager<Writer>::space(const std::string& space)
{
	HANDLE_COMMENT_MODIFIER(space);
	jsonToken(JSON_TOKEN_SPACE, space);
}

template <typename Writer>
void JsonOutputManager<Writer>::punctuation(char p)
{
	HANDLE_COMMENT_MODIFIER(p);
	jsonToken(JSON_TOKEN_PUNCTUATION, std::string(1, p));
}

template <typename Writer>
void JsonOutputManager<Writer>::operatorX(const std::string& op)
{
	HANDLE_COMMENT_MODIFIER(op);
	jsonToken(JSON_TOKEN_OPERATOR, op);
}

template <typename Writer>
void JsonOutputManager<Writer>::globalVariableId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	jsonToken(JSON_TOKEN_ID_GVAR, id);
}

template <typename Writer>
void JsonOutputManager<Writer>::localVariableId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	jsonToken(JSON_TOKEN_ID_LVAR, id);
}

template <typename Writer>
void JsonOutputManager<Writer>::memberId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	jsonToken(JSON_TOKEN_ID_MEMBER, id);
}

template <typename Writer>
void JsonOutputManager<Writer>::labelId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	jsonToken(JSON_TOKEN_ID_LABEL, id);
}

template <typename Writer>
void JsonOutputManager<Writer>::functionId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	jsonToken(JSON_TOKEN_ID_FUNCTION, id);
}

template <typename Writer>
void JsonOutputManager<Writer>::parameterId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	jsonToken(JSON_TOKEN_ID_PARAMETER, id);
}

template <typename Writer>
void JsonOutputManager<Writer>::keyword(const std::string& k)
{
	HANDLE_COMMENT_MODIFIER(k);
	jsonToken(JSON_TOKEN_KEYWORD, k);
}

template <typename Writer>
void JsonOutputManager<Writer>::dataType(const std::string& t)
{
	HANDLE_COMMENT_MODIFIER(t);
	jsonToken(JSON_TOKEN_DATA_TYPE, t);
}

template <typename Writer>
void JsonOutputManager<Writer>::preprocessor(const std::string& p)
{
	HANDLE_COMMENT_MODIFIER(p);
	jsonToken(JSON_TOKEN_PREPROCESSOR, p);
}

template <typename Writer>
void JsonOutputManager<Writer>::include(const std::string& i)
{
	HANDLE_COMMENT_MODIFIER(i);
	jsonToken(JSON_TOKEN_INCLUDE, "<" + i + ">");
}

template <typename Writer>
void JsonOutputManager<Writer>::constantBool(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	jsonToken(JSON_TOKEN_CONST_BOOL, c);
}

template <typename Writer>
void JsonOutputManager<Writer>::constantInt(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	jsonToken(JSON_TOKEN_CONST_INT, c);
}

template <typename Writer>
void JsonOutputManager<Writer>::constantFloat(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	jsonToken(JSON_TOKEN_CONST_FLOAT, c);
}

template <typename Writer>
void JsonOutputManager<Writer>::constantString(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	jsonToken(JSON_TOKEN_CONST_STRING, c);
}

template <typename Writer>
void JsonOutputManager<Writer>::constantSymbol(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	jsonToken(JSON_TOKEN_CONST_SYMBOL, c);
}

template <typename Writer>
void JsonOutputManager<Writer>::constantPointer(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	jsonToken(JSON_TOKEN_CONST_POINTER, c);
}

template <typename Writer>
void JsonOutputManager<Writer>::comment(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(" " + c);
	std::string str = getCommentPrefix();
	if (!c.empty())
	{
		str += " " + utils::replaceCharsWithStrings(c, '\n', " ");
	}
	jsonToken(JSON_TOKEN_COMMENT, str);
}

template <typename Writer>
void JsonOutputManager<Writer>::commentModifier()
{
	_commentModifierOn = true;
}

template <typename Writer>
void JsonOutputManager<Writer>::addressPush(Address a)
{
	bool generate = true;

	// Always generate the first pushed address so that first tokens are
	// associated with something.
	if (_addrs.empty())
	{
		generate = true;
	}
	// Do not generate address changes while in comment modifier mode.
	// A single comment token is generated for all the stuff added in this mode
	// and we cannot associate its individual parts with addresses.
	else if (_commentModifierOn)
	{
		generate = false;
	}
	// Do not generate address if it is the same as the current top address.
	// It is unnecessary.
	else if (a == _addrs.top().first)
	{
		generate = false;
	}

	// Always do the push.
	_addrs.push({a, generate});

	if (generate)
	{
		generateAddressEntry(a);
		_addrToGenerate = std::make_pair(Address::Undefined, false);
	}
}

template <typename Writer>
void JsonOutputManager<Writer>::addressPop()
{
	// Never pop the last entry.
	if (_addrs.size() < 2)
	{
		return;
	}

	bool generated = _addrs.top().second;

	// Always do the pop.
	_addrs.pop();

	// If the popped entry was generated, re-generate the last entry.
	if (generated)
	{
		// Well actually, do not generate it right away because it is possible
		// that the next address is going to get pushed before the next token
		// is added, and therefore it would be unnecessary to re-generate the
		// address if no token actually was associated with it.
		_addrToGenerate = std::make_pair(_addrs.top().first, true);
	}
}

template <typename Writer>
void JsonOutputManager<Writer>::generateAddressEntry(Address a)
{
	writer.StartObject();

	writer.String(JSON_KEY_ADDRESS);
	writer.String(a.isDefined() ? a.toHexPrefixString() : "");

	writer.EndObject();
}

template <typename Writer>
void JsonOutputManager<Writer>::jsonToken(
		const std::string& k,
		const std::string& v)
{
	if (_addrToGenerate.second)
	{
		generateAddressEntry(_addrToGenerate.first);
		_addrToGenerate = std::make_pair(Address::Undefined, false);
	}

	writer.StartObject();

	writer.String(JSON_KEY_KIND);
	writer.String(k);

	writer.String(JSON_KEY_VALUE);
	writer.String(v);

	writer.EndObject();
}

template class JsonOutputManager<rapidjson::Writer<rapidjson::StringBuffer, rapidjson::ASCII<>>>;
template class JsonOutputManager<rapidjson::PrettyWriter<rapidjson::StringBuffer, rapidjson::ASCII<>>>;

} // namespace llvmir2hll
} // namespace retdec
