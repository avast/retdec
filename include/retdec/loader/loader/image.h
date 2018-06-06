/**
 * @file include/retdec/loader/loader/image.h
 * @brief Declaration of loadable image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LOADER_RETDEC_LOADER_IMAGE_H
#define RETDEC_LOADER_RETDEC_LOADER_IMAGE_H

#include <memory>

#include "retdec/utils/byte_value_storage.h"
#include "retdec/fileformat/fftypes.h"
#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/loader/loader/segment.h"
#include "retdec/loader/utils/name_generator.h"

namespace retdec {
namespace loader {

class Image : public retdec::utils::ByteValueStorage
{
public:
	Image(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat);
	virtual ~Image();

	/**
	 * Virtual method that should be overriden in every subclass of Image. Performs the logic of loading.
	 *
	 * @return True if loading was successful, otherwise false.
	 */
	virtual bool load() = 0;

	virtual retdec::utils::Endianness getEndianness() const override;
	virtual std::size_t getNibbleLength() const override;
	virtual std::size_t getByteLength() const override;
	virtual std::size_t getWordLength() const override;
	virtual std::size_t getBytesPerWord() const override;
	virtual std::size_t getNumberOfNibblesInByte() const override;
	virtual bool hasMixedEndianForDouble() const override;

	virtual bool getXByte(std::uint64_t address, std::uint64_t x, std::uint64_t& res, retdec::utils::Endianness e = retdec::utils::Endianness::UNKNOWN) const override;
	virtual bool getXBytes(std::uint64_t address, std::uint64_t x, std::vector<std::uint8_t>& res) const override;

	virtual bool setXByte(std::uint64_t address, std::uint64_t x, std::uint64_t val, retdec::utils::Endianness e = retdec::utils::Endianness::UNKNOWN) override;
	virtual bool setXBytes(std::uint64_t address, const std::vector<std::uint8_t>& res) override;

	retdec::fileformat::FileFormat* getFileFormat();
	const retdec::fileformat::FileFormat* getFileFormat() const;
	std::weak_ptr<retdec::fileformat::FileFormat> getFileFormatWptr() const;

	std::size_t getNumberOfSegments() const;
	const std::vector<std::unique_ptr<Segment>>& getSegments() const;

	std::uint64_t getBaseAddress() const;
	void setBaseAddress(std::uint64_t baseAddress);

	bool hasDataOnAddress(std::uint64_t address) const;
	bool hasDataInitializedOnAddress(std::uint64_t address) const;
	bool hasReadOnlyDataOnAddress(std::uint64_t address) const;
	bool hasSegmentOnAddress(std::uint64_t address) const;
	bool isPointer(std::uint64_t address, std::uint64_t* pointer = nullptr) const;

	Segment* getSegment(std::size_t index);
	Segment* getSegment(const std::string& name);
	Segment* getSegmentWithIndex(std::size_t index);
	Segment* getSegmentFromAddress(std::uint64_t address);
	const Segment* getSegment(std::size_t index) const;
	const Segment* getSegment(const std::string& name) const;
	const Segment* getSegmentWithIndex(std::size_t index) const;
	const Segment* getSegmentFromAddress(std::uint64_t address) const;
	const Segment* getEpSegment();

	std::pair<const std::uint8_t*, std::uint64_t> getRawSegmentData(std::uint64_t address) const;

	const std::string& getStatusMessage() const;
	const retdec::fileformat::LoaderErrorInfo & getLoaderErrorInfo() const;

protected:
	Segment* insertSegment(std::unique_ptr<Segment> segment);
	void removeSegment(Segment* segment);
	void nameSegment(Segment* segment);
	void sortSegments();

	void setStatusMessage(const std::string& message);

private:
	const Segment* _getSegment(std::size_t index) const;
	const Segment* _getSegment(const std::string& name) const;
	const Segment* _getSegmentWithIndex(std::size_t index) const;
	const Segment* _getSegmentFromAddress(std::uint64_t address) const;

	std::shared_ptr<retdec::fileformat::FileFormat> _fileFormat;
	std::vector<std::unique_ptr<Segment>> _segments;
	std::uint64_t _baseAddress;
	NameGenerator _namelessSegNameGen;
	std::string _statusMessage;
};

} // namespace loader
} // namespace retdec

#endif
