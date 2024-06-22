#include "tools/include/offline_frames_storage.hh"
#include "quick_share/include/exceptions.hh"

#include <iostream>
#include <fstream>

std::vector<std::unique_ptr<OfflineFrame>> parse_offline_frames_buffer(const uint8_t * buffer, size_t bufferSize) {
    std::vector<std::unique_ptr<OfflineFrame>> offlineFrames;
    size_t offset = 0;

    while (offset + sizeof(uint32_t) <= bufferSize) {
        // Read the length (uint32_t little endian)
        uint32_t frameLength;
        std::memcpy(&frameLength, buffer + offset, sizeof(frameLength));
        offset += sizeof(frameLength);

        // Check for end of buffer
        if (offset + frameLength > bufferSize) {
            throw InvalidParameterException("Failed parsing offline frames buffer - Incomplete frame in buffer");
        }

        // Read the serialized data
        std::string serializedData(buffer + offset, buffer + offset + frameLength);
        offset += frameLength;

        // Parse the serialized data into OfflineFrame
        auto offlineFrame = std::make_unique<OfflineFrame>();
        if (offlineFrame->ParseFromString(serializedData)) {
            // Successfully parsed, add to vector
            offlineFrames.push_back(std::move(offlineFrame));
        } else {
            std::cerr << "Error parsing OfflineFrame." << std::endl;
            // Handle error as needed
        }
    }

    return offlineFrames;
}

std::vector<std::unique_ptr<OfflineFrame>> parse_offline_frames_file(const char* filePath) {
    // Read the file into a buffer
    std::ifstream fileStream(filePath, std::ios::binary);
    if (!fileStream.is_open()) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        throw IOException("Failed opening the offline frames file");
    }

    fileStream.seekg(0, std::ios::end);
    std::streampos fileSize = fileStream.tellg();
    fileStream.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(fileSize);
    fileStream.read((char*)buffer.data(), fileSize);
    fileStream.close();

    return parse_offline_frames_buffer(buffer.data(), fileSize);
}