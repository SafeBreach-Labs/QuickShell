#include "tools/include/utils.hh"

#include <iostream>
#include <fstream>

#include "quick_share/include/exceptions.hh"

static const std::string BASE64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";


size_t get_file_size(const char * file_path) {
    std::ifstream file_stream(file_path, std::ios::binary);
    if (!file_stream.is_open()) {
        throw IOException("Failed opening the offline frames file");
    }

    file_stream.seekg(0, std::ios::end);
    std::streampos file_size = file_stream.tellg();
    file_stream.seekg(0, std::ios::beg);

    file_stream.close();

    return file_size;
}

std::unique_ptr<std::vector<char>> read_file_content(const char * file_path) {
    size_t file_size = get_file_size(file_path);
    auto file_content = std::make_unique<std::vector<char>>(file_size);

    std::ifstream file_stream(file_path, std::ios::binary);
    if (!file_stream.is_open()) {
        throw IOException("Failed opening the offline frames file");
    }

    file_stream.read(file_content->data(), file_size);
    file_stream.close();

    return file_content;
}

std::vector<char> base64_decode(const std::string &encoded_string) {
    std::vector<char> decoded;
    int in_len = static_cast<int>(encoded_string.size());

    int i = 0;
    int j = 0;
    int in_ = 0;
    char char_array_4[4], char_array_3[3];

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char_array_4[i] = static_cast<char>(BASE64_CHARS.find(char_array_4[i]));
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0x0F) << 4) + ((char_array_4[2] & 0x3C) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++) {
                decoded.push_back(char_array_3[i]);
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }

        for (j = 0; j < 4; j++) {
            char_array_4[j] = static_cast<char>(BASE64_CHARS.find(char_array_4[j]));
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0x0F) << 4) + ((char_array_4[2] & 0x3C) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++) {
            decoded.push_back(char_array_3[j]);
        }
    }

    return decoded;
}

bool is_base64(char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}