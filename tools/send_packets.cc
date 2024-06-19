#include <vector>

#include "quick_share/include/quick_share_medium.hh"
#include "quick_share/include/quick_share_connection.hh"
#include "quick_share/include/exceptions.hh"
#include "logger/include/logger.hh"
#include "tools/include/offline_frames_storage.hh"


static const GUID QUICK_SHARE_BT_GUID = {0xA82EFA21, 0xAE5C, 0x3DDE, {0x9B, 0xBC, 0xF1, 0x6D, 0xA7, 0xB1, 0x6C, 0x5A}};

static const unsigned int MEDIUM_TYPE_ARG_INDEX = 1;

enum WifiLanArgsIndex {
    WIFI_ARGS_IP = 2,
    WIFI_ARGS_PORT = 3,
    WIFI_ARGS_PACKETS_FILE_PATH = 4
};

enum BtArgsIndex {
    BT_ARGS_BT_ADDR = 2,
    BT_ARGS_PACKETS_FILE_PATH = 3
};

int send_packets_main(int argc, char ** argv) {
    size_t argv_index = 1;
    const std::string medium_type = argv[MEDIUM_TYPE_ARG_INDEX];

    BluetoothMedium bt_medium;
    WifiLanMedium wifi_medium;
    IMedium * medium = nullptr;
    const char * packets_file_path = NULL;
    unsigned int current_offline_frame_index = 0;

    if ("bluetooth" == medium_type) {
        bt_medium.set_target(argv[BT_ARGS_BT_ADDR], QUICK_SHARE_BT_GUID);
        packets_file_path = argv[BT_ARGS_PACKETS_FILE_PATH];
        medium = &bt_medium;
    }
    else if ("wifi_lan" == medium_type) {
        const char * ip = argv[WIFI_ARGS_IP];
        unsigned int port = atoi(argv[WIFI_ARGS_PORT]);
        packets_file_path = argv[WIFI_ARGS_PACKETS_FILE_PATH];
        wifi_medium.set_target(ip, port);
        medium = &wifi_medium;
    } else {
        throw InvalidParameterException("No such medium type");
    }

    std::vector<std::unique_ptr<OfflineFrame>> offline_frames = parse_offline_frames_file(packets_file_path);
    
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
    for (unsigned int i = current_offline_frame_index; i < offline_frames.size(); i++) {
        quick_share_connection.send_offline_frame(*(offline_frames[current_offline_frame_index++]), true);
    }

    printf("Waiting for recv packets!\n");
    while (true){
        try{
            quick_share_connection.recv_packet();
        }
        catch (SocketException e) {
            break;
        }
        catch (TimeoutException e){
            break;
        }
    }
    quick_share_connection.disconnect();


    return 0;
}

int main(int argc, char ** argv) {
    try {
        send_packets_main(argc, argv);
    } catch (std::exception e) {
        logger_log(LoggerLogLevel::LEVEL_ERROR, "Got Exception:\n%s", e.what());
    }
}