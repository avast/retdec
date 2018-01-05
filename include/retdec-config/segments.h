/**
 * @file include/retdec-config/segments.h
 * @brief Decompilation configuration manipulation: segments.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_SEGMENTS_H
#define RETDEC_CONFIG_SEGMENTS_H

#include <string>

#include "retdec-config/base.h"
#include "retdec-config/objects.h"

namespace retdec_config  {

/**
 * Represents binary file's segment.
 * Segment is an address range plus name and comment.
 */
class Segment : public tl_cpputils::AddressRange
{
	public:
		explicit Segment(const tl_cpputils::Address& start);
		static Segment fromJsonValue(const Json::Value& val);

		Json::Value getJsonValue() const;

		/// @name Segment set methods.
		/// @{
		void setName(const std::string& n);
		void setComment(const std::string& c);
		/// @}

		/// @name Segment get methods.
		/// @{
		std::string getName() const;
		std::string getComment() const;
		/// @}

	private:
		std::string _name;
		std::string _comment;
};

/**
 * Set container for segments.
 * Segments' address ranges are set's keys.
 */
using SegmentContainer = BaseSetContainer<Segment>;

} // namespace retdec_config

#endif
