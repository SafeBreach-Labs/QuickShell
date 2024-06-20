#ifndef TOOLS_INCLUDE_UTILS
#define TOOLS_INCLUDE_UTILS

#include <memory>
#include <vector>
#include <string>

size_t get_file_size(const char * file_path);

std::unique_ptr<std::vector<char>> read_file_content(const char * file_path);

std::vector<uint8_t> base64_decode(const std::string &encoded_string);

bool is_base64(char c);

#endif /* TOOLS_INCLUDE_UTILS */
