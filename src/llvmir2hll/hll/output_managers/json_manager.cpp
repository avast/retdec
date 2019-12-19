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
const std::string JSON_TOKEN_ID_VAR        = "i_var";
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

JsonOutputManager::JsonOutputManager(llvm::raw_ostream& out, bool humanReadable) :
		_out(out),
		_humanReadable(humanReadable),
		_tokens(Json::arrayValue)
{
	addressPush(Address::Undefined);
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

void JsonOutputManager::newLine()
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

	_tokens.append(jsonToken(JSON_TOKEN_NEWLINE, "\n"));
}

void JsonOutputManager::space(const std::string& space)
{
	HANDLE_COMMENT_MODIFIER(space);
	_tokens.append(jsonToken(JSON_TOKEN_SPACE, space));
}

void JsonOutputManager::punctuation(char p)
{
	HANDLE_COMMENT_MODIFIER(p);
	_tokens.append(jsonToken(JSON_TOKEN_PUNCTUATION, std::string(1, p)));
}

void JsonOutputManager::operatorX(const std::string& op)
{
	HANDLE_COMMENT_MODIFIER(op);
	_tokens.append(jsonToken(JSON_TOKEN_OPERATOR, op));
}

void JsonOutputManager::variableId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	_tokens.append(jsonToken(JSON_TOKEN_ID_VAR, id));
}

void JsonOutputManager::memberId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	_tokens.append(jsonToken(JSON_TOKEN_ID_MEMBER, id));
}

void JsonOutputManager::labelId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	_tokens.append(jsonToken(JSON_TOKEN_ID_LABEL, id));
}

void JsonOutputManager::functionId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	_tokens.append(jsonToken(JSON_TOKEN_ID_FUNCTION, id));
}

void JsonOutputManager::parameterId(const std::string& id)
{
	HANDLE_COMMENT_MODIFIER(id);
	_tokens.append(jsonToken(JSON_TOKEN_ID_PARAMETER, id));
}

void JsonOutputManager::keyword(const std::string& k)
{
	HANDLE_COMMENT_MODIFIER(k);
	_tokens.append(jsonToken(JSON_TOKEN_KEYWORD, k));
}

void JsonOutputManager::dataType(const std::string& t)
{
	HANDLE_COMMENT_MODIFIER(t);
	_tokens.append(jsonToken(JSON_TOKEN_DATA_TYPE, t));
}

void JsonOutputManager::preprocessor(const std::string& p)
{
	HANDLE_COMMENT_MODIFIER(p);
	_tokens.append(jsonToken(JSON_TOKEN_PREPROCESSOR, p));
}

void JsonOutputManager::include(const std::string& i)
{
	HANDLE_COMMENT_MODIFIER(i);
	_tokens.append(jsonToken(JSON_TOKEN_INCLUDE, "<" + i + ">"));
}

void JsonOutputManager::constantBool(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	_tokens.append(jsonToken(JSON_TOKEN_CONST_BOOL, c));
}

void JsonOutputManager::constantInt(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	_tokens.append(jsonToken(JSON_TOKEN_CONST_INT, c));
}

void JsonOutputManager::constantFloat(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	_tokens.append(jsonToken(JSON_TOKEN_CONST_FLOAT, c));
}

void JsonOutputManager::constantString(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	_tokens.append(jsonToken(JSON_TOKEN_CONST_STRING, c));
}

void JsonOutputManager::constantSymbol(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	_tokens.append(jsonToken(JSON_TOKEN_CONST_SYMBOL, c));
}

void JsonOutputManager::constantPointer(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(c);
	_tokens.append(jsonToken(JSON_TOKEN_CONST_POINTER, c));
}

void JsonOutputManager::comment(const std::string& c)
{
	HANDLE_COMMENT_MODIFIER(" " + c);
	std::string str = getCommentPrefix();
	if (!c.empty())
	{
		str += " " + utils::replaceCharsWithStrings(c, '\n', " ");
	}
	_tokens.append(jsonToken(JSON_TOKEN_COMMENT, str));
}

void JsonOutputManager::commentModifier()
{
	_commentModifierOn = true;
}

void JsonOutputManager::addressPush(Address a)
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

void JsonOutputManager::addressPop()
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

void JsonOutputManager::generateAddressEntry(Address a)
{
	Json::Value r;

	r[JSON_KEY_ADDRESS] = a.isDefined() ? a.toHexPrefixString() : "";

	_tokens.append(r);
}

Json::Value JsonOutputManager::jsonToken(
		const std::string& k,
		const std::string& v)
{
	if (_addrToGenerate.second)
	{
		generateAddressEntry(_addrToGenerate.first);
		_addrToGenerate = std::make_pair(Address::Undefined, false);
	}

	Json::Value r;
	r[JSON_KEY_KIND] = k;
	r[JSON_KEY_VALUE] = v;
	return r;
}

} // namespace llvmir2hll
} // namespace retdec
