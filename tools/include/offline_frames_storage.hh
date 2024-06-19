#ifndef TOOLS_OFFLINE_FRAME_STORAGE
#define TOOLS_OFFLINE_FRAME_STORAGE

#include <vector>
#include <memory>

#include "quick_share/proto/offline_wire_formats.pb.h"

using OfflineFrame = ::location::nearby::connections::OfflineFrame;

std::vector<std::unique_ptr<OfflineFrame>> parse_offline_frames_file(const char * filePath);

std::vector<std::unique_ptr<OfflineFrame>> parse_offline_frames_buffer(const char* buffer, size_t bufferSize);

#endif /* TOOLS_OFFLINE_FRAME_STORAGE */
