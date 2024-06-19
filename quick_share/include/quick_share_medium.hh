#ifndef QUICK_SHARE_INCLUDE_QUICK_SHARE_MEDIUM
#define QUICK_SHARE_INCLUDE_QUICK_SHARE_MEDIUM

#define WIN32_LEAN_AND_MEAN
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "Wlanapi.lib")
#include <cstdlib>
#include <vector>
#include <winsock2.h>
#include <Windows.h>
#include <ws2bth.h>
#include <bluetoothapis.h>


class IMedium {
    public:
        virtual void connect() = 0;

        virtual void disconnect() = 0;

        virtual void send(const char * buffer, size_t buffer_size) = 0;

        virtual std::vector<char> recv(size_t num_bytes_to_read) = 0;

};


class BaseSocketMedium: public IMedium {
    public:
        BaseSocketMedium();

        virtual void connect() override;

        virtual void disconnect() override;

        virtual void send(const char * buffer, size_t buffer_size) override;

        virtual std::vector<char> recv(size_t num_bytes_to_read) override;

    protected:
        virtual SOCKET create_socket() = 0;
        virtual SOCKADDR * get_socket_address() = 0;
        virtual size_t get_socket_address_size() = 0;

        SOCKET m_socket = INVALID_SOCKET;
};


class WifiLanMedium: public BaseSocketMedium {
    public:
        void set_target(const char * target_ip, unsigned int target_port);

    protected:
        virtual SOCKET create_socket() override;
        virtual SOCKADDR * get_socket_address() override;
        virtual size_t get_socket_address_size() override;

    private:
        SOCKADDR_IN m_sock_addr = { 0 };
};

class BluetoothMedium: public BaseSocketMedium {
    public:
        void set_target(const char * target_mac_address, GUID target_service_class_id);

    protected:
        virtual SOCKET create_socket() override;
        virtual SOCKADDR * get_socket_address() override;
        virtual size_t get_socket_address_size() override;

    private:
        SOCKADDR_BTH m_bluetooth_server_addr = { 0 };
};

class WifiHotspotMedium: public BaseSocketMedium {
    public:
        WifiHotspotMedium(TIMEVAL accept_timeout) : m_accept_timeout(accept_timeout), BaseSocketMedium() {}
        unsigned int bind(const char * hotspot_listen_ip, unsigned int listen_port);
        SOCKADDR_IN & get_connected_client_sock_addr();
        
        virtual void connect() override;
        virtual void disconnect() override;

    protected:
        virtual SOCKET create_socket() override {return INVALID_SOCKET;}; // Not needed if connect() is overriden
        virtual SOCKADDR * get_socket_address() override {return nullptr;}; // Not needed if connect() is overriden
        virtual size_t get_socket_address_size() override {return 0;}; // Not needed if connect() is overriden

    private:
        TIMEVAL m_accept_timeout = {0};
        SOCKET m_server_socket = INVALID_SOCKET;
        SOCKADDR_IN m_server_sock_addr = { 0 };
        SOCKADDR_IN m_client_sock_addr = { 0 };
};


#endif /* QUICK_SHARE_INCLUDE_QUICK_SHARE_MEDIUM */
