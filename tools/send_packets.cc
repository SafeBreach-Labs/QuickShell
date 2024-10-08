#include <vector>
#include <argparse/argparse.hpp>

#include "quick_share/include/quick_share_medium.hh"
#include "quick_share/include/quick_share_connection.hh"
#include "common/include/exceptions.hh"
#include "common/include/logger.hh"
#include "tools/tool_helpers/include/offline_frames_storage.hh"
#include "tools/tool_helpers/include/utils.hh"

static const GUID QUICK_SHARE_BT_GUID = {0xA82EFA21, 0xAE5C, 0x3DDE, {0x9B, 0xBC, 0xF1, 0x6D, 0xA7, 0xB1, 0x6C, 0x5A}};


void send_packets(IMedium * medium, const char * offline_frames_file_path) {
    unsigned int current_offline_frame_index = 0;

    std::vector<std::unique_ptr<OfflineFrame>> offline_frames = parse_offline_frames_file(offline_frames_file_path);

    QuickShareConnection quick_share_connection(medium);

    quick_share_connection.connect();

    // Send CONNECTION_REQUEST
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]));

    quick_share_connection.do_handshake();

    // Receive CONNECTION_RESPONSE
    quick_share_connection.recv_offline_frame();
    // Send CONNECTION_RESPONSE
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]));

    // Paired key encryption
    quick_share_connection.recv_offline_frame(true);
    quick_share_connection.recv_offline_frame(true);
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]), true);
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]), true);

    // Paired key result
    quick_share_connection.recv_offline_frame(true);
    quick_share_connection.recv_offline_frame(true);
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]), true);
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]), true);

    // File introduction
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]), true);
    quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]), true);
    quick_share_connection.recv_offline_frame(true);
    quick_share_connection.recv_offline_frame(true);

    // Sending the rest, should be the actual payload transfer
    for (unsigned int i = current_offline_frame_index; i < offline_frames.size(); i++)
    {
        quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]), true);
    }

    while (true)
    {
        try
        {
            quick_share_connection.recv_packet();
        }
        catch (SocketException e)
        {
            break;
        }
        catch (TimeoutException e)
        {
            break;
        }
    }
    quick_share_connection.disconnect();
}

int main(int argc, char **argv)
{
    int main_ret_val = 0;
    BluetoothMedium bt_medium;
    WifiLanMedium wifi_medium;
    IMedium *medium = nullptr;
    std::string offline_frames_file_path;
    argparse::ArgumentParser * chosen_parser = nullptr;

    argparse::ArgumentParser wifi_lan_parser("wifi_lan");
    wifi_lan_parser.add_description("Send the file over the WIFI_LAN medium");
    wifi_lan_parser.add_argument("ip").help("The ip address where the target Quick Share device is listening");
    wifi_lan_parser.add_argument("port").help("The port where the target Quick Share device is listening").scan<'u', unsigned int>();
    wifi_lan_parser.add_argument("offline_frames_file_path").help("Path to a file that contains serialized offline frames. The format is [DWORD little endian length][serialized offline frame]");

    argparse::ArgumentParser bt_parser("bt");
    bt_parser.add_description("Send the file over the BLUETOOTH medium");
    bt_parser.add_argument("mac_addr").help("The bluetooth MAC address of the target Quick Share device");
    bt_parser.add_argument("offline_frames_file_path").help("Path to a file that contains serialized offline frames. The format is [DWORD little endian length][serialized offline frame]");

    argparse::ArgumentParser parser("send_packets.exe");
    parser.add_description(
        "Sends a normal sequence of custom Offline Frame packets. The packet types should be in the following order (as always in a normal transfer):\n"
        "1. Connection Request\n"
        "2. Connection Response\n"
        "3. Payload Transfer Paired Key Encryption\n"
        "4. Payload Transfer Paired Key Result\n"
        "5. Payload Transfer Introduction\n"
        "6. Payload Transfer"
    );
    parser.add_subparser(wifi_lan_parser);
    parser.add_subparser(bt_parser);

    // Don't trust third party argparse library to not throw exceptions
    try {
        parser.parse_args(argc, argv);

        if (parser.is_subcommand_used("wifi_lan")) {
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

        offline_frames_file_path = chosen_parser->get("offline_frames_file_path");
    } catch (const std::exception &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << parser;
        return 1;
    }

    // Catch QuickShell exceptions and print them if there are any
    try {
        initialize_wsa(); // Must be called once in a program in order to use Windows sockets
        send_packets(medium, offline_frames_file_path.c_str());
    } catch (BaseException e) {
        logger_log(LoggerLogLevel::LEVEL_ERROR, "Got an exception:\n%s", e.what());
        main_ret_val = 1;
    }

    WSACleanup(); // Must be called before program exit if WSA was initialized
    return main_ret_val;
}