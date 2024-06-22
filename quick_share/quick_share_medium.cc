#include "quick_share/include/quick_share_medium.hh"
#include "logger/include/logger.hh"

#include <cstdlib>
#include <vector>
#include <Wlanapi.h>

#include "quick_share/include/exceptions.hh"

static void str2ba(const char *straddr, BTH_ADDR *btaddr);

static void str2ba(const char *straddr, BTH_ADDR *btaddr)
{
    int i;
    unsigned int aaddr[6];
    BTH_ADDR tmpaddr = 0;

    if (sscanf(straddr, "%02x:%02x:%02x:%02x:%02x:%02x",
               &aaddr[0], &aaddr[1], &aaddr[2],
               &aaddr[3], &aaddr[4], &aaddr[5]) != 6)
    {
        throw InvalidParameterException("MAC address is not in the right format");
    }
    *btaddr = 0;
    for (i = 0; i < 6; i++)
    {
        tmpaddr = (BTH_ADDR)(aaddr[i] & 0xff);
        *btaddr = ((*btaddr) << 8) + tmpaddr;
    }
}

BaseSocketMedium::BaseSocketMedium() {}

void BaseSocketMedium::connect()
{
    SOCKET specific_socket = INVALID_SOCKET;
    unsigned int timeout = 10000;
    int ret_val = -1;
    SOCKADDR *socket_address = get_socket_address();
    size_t socket_address_size = get_socket_address_size();

    logger_log(LoggerLogLevel::LEVEL_INFO, "Setting up medium socket");
    specific_socket = create_socket();
    if (INVALID_SOCKET == specific_socket)
    {
        throw SocketException("Failed initializing medium socket");
    }

    logger_log(LoggerLogLevel::LEVEL_DEBUG, "Setting socket timeout to %u milliseconds", timeout);
    ret_val = setsockopt(specific_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    if (SOCKET_ERROR == ret_val)
    {
        closesocket(specific_socket);
        throw SocketException("Failed setting timeout for medium socket");
    }

    logger_log(LoggerLogLevel::LEVEL_INFO, "Connecting to medium socket");
    ret_val = ::connect(specific_socket, socket_address, socket_address_size);
    if (SOCKET_ERROR == ret_val)
    {
        closesocket(specific_socket);
        throw SocketException("Failed connecting to target");
    }

    m_socket = specific_socket;
    logger_log(LoggerLogLevel::LEVEL_INFO, "Successfully connected to medium socket");
}

void BaseSocketMedium::disconnect()
{
    logger_log(LoggerLogLevel::LEVEL_INFO, "Disconnecting from medium socket");
    if (INVALID_SOCKET != m_socket)
    {
        closesocket(m_socket);
    }
}

void BaseSocketMedium::send(const char *buffer, size_t buffer_size)
{
    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending packet through socket");
    if (SOCKET_ERROR == ::send(m_socket, (char *)buffer, buffer_size, 0))
    {
        throw SocketException("Failed sending buffer over socket");
    }
}

std::vector<char> BaseSocketMedium::recv(size_t num_bytes_to_read)
{
    std::vector<char> received_data(num_bytes_to_read);
    logger_log(LoggerLogLevel::LEVEL_INFO, "Receiving packet from socket");
    int result = ::recv(m_socket, (char *)received_data.data(), num_bytes_to_read, 0);

    if (SOCKET_ERROR == result)
    {
        int wsa_error_code = WSAGetLastError();
        if (WSAETIMEDOUT == wsa_error_code)
        {
            throw TimeoutException("Receiving from socket timed out");
        }
        else
        {
            throw SocketException("Failed receiving buffer from socket");
        }
    }
    else if (0 == result)
    {
        throw SocketException("Socket was gracefully closed");
    }

    return received_data;
}

void WifiLanMedium::set_target(const char *target_ip, unsigned int target_port)
{
    m_sock_addr.sin_family = AF_INET;
    m_sock_addr.sin_port = htons(target_port);
    m_sock_addr.sin_addr.S_un.S_addr = inet_addr(target_ip);
}

SOCKET WifiLanMedium::create_socket()
{
    logger_log(LoggerLogLevel::LEVEL_INFO, "Creating WIFI_LAN socket");
    SOCKET wifi_lan_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

    if (INVALID_SOCKET == wifi_lan_socket)
    {
        throw SocketException("Couldn't create a TCP socket");
    }

    return wifi_lan_socket;
}

SOCKADDR *WifiLanMedium::get_socket_address()
{
    return (SOCKADDR *)&m_sock_addr;
}

size_t WifiLanMedium::get_socket_address_size()
{
    return sizeof(m_sock_addr);
}

void BluetoothMedium::set_target(const char *target_mac_address, GUID target_service_class_id)
{
    BTH_ADDR btAddr;

    m_bluetooth_server_addr.addressFamily = AF_BTH;

    // Convert the Bluetooth address from string to BTH_ADDR
    str2ba(target_mac_address, &btAddr);
    m_bluetooth_server_addr.btAddr = btAddr;

    // Manually set the service class UUID
    // m_bluetooth_server_addr.serviceClassId =  {0xA82EFA21, 0xAE5C, 0x3DDE, {0x9B, 0xBC, 0xF1, 0x6D, 0xA7, 0xB1, 0x6C, 0x5A}};
    m_bluetooth_server_addr.serviceClassId = target_service_class_id;
}

SOCKET BluetoothMedium::create_socket()
{
    logger_log(LoggerLogLevel::LEVEL_INFO, "Creating BLUETOOTH socket");
    SOCKET bluetooth_socket = ::socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
    if (INVALID_SOCKET == bluetooth_socket)
    {
        throw SocketException("Couldn't create a bluetooth socket");
    }

    return bluetooth_socket;
}

SOCKADDR *BluetoothMedium::get_socket_address()
{
    return (SOCKADDR *)&m_bluetooth_server_addr;
}

size_t BluetoothMedium::get_socket_address_size()
{
    return sizeof(m_bluetooth_server_addr);
}

unsigned int WifiHotspotMedium::bind(const char *hotspot_listen_ip, unsigned int listen_port)
{
    SOCKET server_socket = INVALID_SOCKET;
    int ret_val = -1;

    m_server_sock_addr.sin_family = AF_INET;
    m_server_sock_addr.sin_port = htons(listen_port);
    m_server_sock_addr.sin_addr.S_un.S_addr = inet_addr(hotspot_listen_ip);

    server_socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (INVALID_SOCKET == server_socket)
    {
        throw SocketException("Failed creating a socket for WifiHotspotMedium");
    }

    ret_val = ::bind(server_socket, (SOCKADDR *)&m_server_sock_addr, sizeof(m_server_sock_addr));
    if (SOCKET_ERROR == ret_val)
    {
        closesocket(server_socket);
        throw SocketException("Failed binding WifiHotspotMedium to the listening address");
    }

    if (0 == listen_port)
    {
        int sock_addr_size = sizeof(m_server_sock_addr);
        ret_val = getsockname(server_socket, (SOCKADDR *)&m_server_sock_addr, &sock_addr_size);
        if (SOCKET_ERROR == ret_val)
        {
            closesocket(server_socket);
            throw SocketException("Failed retrieving the socket address after a random available port was asked by the caller");
        }
    }

    m_server_socket = server_socket;
    return ntohs(m_server_sock_addr.sin_port);
}

void WifiHotspotMedium::connect()
{
    int ret_val = -1;
    SOCKET client_socket;
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(m_server_socket, &read_set);

    logger_log(LoggerLogLevel::LEVEL_INFO, "Listening for WIFI_HOTSPOT connections");
    ret_val = listen(m_server_socket, 1);
    if (SOCKET_ERROR == ret_val)
    {
        throw SocketException("WifiHotspotMedium failed listening");
    }

    logger_log(LoggerLogLevel::LEVEL_INFO, "Selecting WIFI_HOTSPOT connections");
    ret_val = select(0, &read_set, NULL, NULL, &m_accept_timeout);
    if (0 == ret_val)
    {
        throw TimeoutException("Timed out waiting for the client to connect");
    }
    else if (SOCKET_ERROR == ret_val)
    {
        throw SocketException("Failed waiting for the client to connect");
    }

    int sock_addr_size = sizeof(m_client_sock_addr);
    client_socket = accept(m_server_socket, (SOCKADDR *)&m_client_sock_addr, &sock_addr_size);
    if (INVALID_SOCKET == client_socket)
    {
        throw SocketException("Failed accepting connection from client");
    }

    m_socket = client_socket;
}

void WifiHotspotMedium::disconnect()
{
    logger_log(LoggerLogLevel::LEVEL_INFO, "Disconnecting WIFI_HOTSPOT socket");
    closesocket(m_server_socket);
    BaseSocketMedium::disconnect();
}

SOCKADDR_IN &WifiHotspotMedium::get_connected_client_sock_addr()
{
    return m_client_sock_addr;
}