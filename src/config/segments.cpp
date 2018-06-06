/**
 * @file src/config/segments.cpp
 * @brief Decompilation configuration manipulation: segments.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/config/segments.h"

namespace {

const std::string JSON_name      = "name";
const std::string JSON_comment   = "comment";
const std::string JSON_startAddr = "startAddr";
const std::string JSON_endAddr   = "endAddr";

} // anonymous namespace

namespace retdec {
namespace config {

Segment::Segment(const retdec::utils::Address& start)
{
	setStart(start);
}

/**
 * Reads JSON object (associative array) holding segment information.
 * @param val JSON object.
 */
Segment Segment::fromJsonValue(const Json::Value& val)
{
	checkJsonValueIsObject(val, "Segment");

	Segment ret( safeGetAddress(val, JSON_startAddr) );

	ret.setName( safeGetString(val, JSON_name) );
	ret.setComment( safeGetString(val, JSON_comment) );
	ret.setEnd( safeGetAddress(val, JSON_endAddr) );

	return ret;
}

/**
 * Returns JSON object (associative array) holding segment information.
 * @return JSON object.
 */
Json::Value Segment::getJsonValue() const
{
	Json::Value seg;

	if (!getName().empty()) seg[JSON_name] = getName();
	if (!getComment().empty()) seg[JSON_comment] = getComment();
	if (getStart().isDefined()) seg[JSON_startAddr] = toJsonValue(getStart());
	if (getEnd().isDefined()) seg[JSON_endAddr] = toJsonValue(getEnd());

	return seg;
}

void Segment::setName(const std::string& n)    { _name = n; }
void Segment::setComment(const std::string& c) { _comment = c; }

std::string Segment::getName() const           { return _name; }
std::string Segment::getComment() const        { return _comment; }

} // namespace config
} // namespace retdec
