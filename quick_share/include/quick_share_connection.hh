#ifndef QUICK_SHARE_INCLUDE_QUICK_SHARE_CONNECTION
#define QUICK_SHARE_INCLUDE_QUICK_SHARE_CONNECTION
#include <memory>

#include "quick_share/include/quick_share_medium.hh"
#include "quick_share/proto/offline_wire_formats.pb.h"
#include "securegcm/ukey2_handshake.h"

using namespace securegcm;
using OfflineFrame = ::location::nearby::connections::OfflineFrame;

class QuickShareConnection {
    public:
        QuickShareConnection(IMedium * medium): m_medium(medium) {}

        void connect();

        void disconnect();

        void set_medium(IMedium * medium);

        void do_handshake();

        void send_offline_frame(OfflineFrame & offline_frame, bool should_encrypt = false);

        std::unique_ptr<OfflineFrame> recv_offline_frame(bool should_decrypt = false);

        void send_packet(const char * packet, size_t packet_size);

        std::vector<char> recv_packet();
        
    private:

        IMedium * m_medium;
        std::unique_ptr<UKey2Handshake> m_ukey2_handshake;
        std::unique_ptr<D2DConnectionContextV1> m_connection_context;
};


#endif /* QUICK_SHARE_INCLUDE_QUICK_SHARE_CONNECTION */
