#include "quick_share/include/quick_share_connection.hh"

#include <string>
#include <memory>

#include "quick_share/include/exceptions.hh"

static const size_t VERIFICATION_STRING_LENGTH = 32;

void QuickShareConnection::connect() {
    m_medium->connect();
}

void QuickShareConnection::disconnect() {
    m_medium->disconnect();
}

void QuickShareConnection::set_medium(IMedium * medium) {
    m_medium = medium;
}

void QuickShareConnection::send_packet(const char * packet, size_t packet_size) {
    uint32_t packet_size_big_endian = htonl(packet_size);
    m_medium->send((char*)&packet_size_big_endian, sizeof(uint32_t));
    m_medium->send(packet, packet_size);
}

std::vector<char> QuickShareConnection::recv_packet() {
    std::vector<char> packet_size_bytes_big_endian = m_medium->recv(sizeof(uint32_t));
    size_t packet_size = ntohl(*(uint32_t*)packet_size_bytes_big_endian.data());

    return m_medium->recv(packet_size);
}

void QuickShareConnection::send_offline_frame(OfflineFrame & offline_frame, bool should_encrypt) {
    std::string offline_frame_bytes(offline_frame.SerializeAsString());
    printf("Sending offline frame:\n");
    printf(offline_frame.DebugString().c_str());

    if (should_encrypt) {
        std::unique_ptr<std::string> encoded_packet = m_connection_context->EncodeMessageToPeer(offline_frame_bytes);
        send_packet(encoded_packet->c_str(), encoded_packet->length());
    } else {
        send_packet(offline_frame_bytes.c_str(), offline_frame_bytes.length());
    }

}

std::unique_ptr<OfflineFrame> QuickShareConnection::recv_offline_frame(bool should_decrypt) {
    std::vector<char> packet_bytes = recv_packet();
    std::string packet_bytes_string(packet_bytes.begin(), packet_bytes.end());

    auto offline_frame = std::make_unique<OfflineFrame>();
    
    if (should_decrypt) {
        std::unique_ptr<std::string> decrypted_offline_frame_bytes = m_connection_context->DecodeMessageFromPeer(packet_bytes_string);
        if (!decrypted_offline_frame_bytes) {
            return nullptr;
        }
        offline_frame->ParseFromString(*decrypted_offline_frame_bytes);
    } else {
        offline_frame->ParseFromString(packet_bytes_string);
    }

    
    printf("Received offline frame:\n");
    printf(offline_frame->DebugString().c_str());

    return offline_frame;
}

void QuickShareConnection::do_handshake() {
    string packet_from_responder_string;
    std::vector<char> packet_from_responder;
    std::unique_ptr<string> auth_string = NULL;
    std::unique_ptr<string> packet_to_responder = nullptr;
    UKey2Handshake::ParseResult result;

    m_ukey2_handshake = UKey2Handshake::ForInitiator(UKey2Handshake::HandshakeCipher::P256_SHA512);
    if (nullptr == m_ukey2_handshake) {
        throw Ukey2Exception("ERROR: Failed creating the Ukey2Handshake object");
    }
    printf("handshake stage 1\n");

    packet_to_responder = m_ukey2_handshake->GetNextHandshakeMessage();
    if (nullptr == packet_to_responder) {
        throw Ukey2Exception("ERROR: Failed getting first handshake message to send");
    }

    printf("handshake stage 2\n");

    send_packet(packet_to_responder->c_str(), packet_to_responder->length());

    printf("handshake stage 3\n");

    packet_from_responder = recv_packet();

    printf("handshake stage 4\n");

    packet_from_responder_string = std::string(packet_from_responder.begin(), packet_from_responder.end());

    printf("handshake stage 5\n");

    result = m_ukey2_handshake->ParseHandshakeMessage(packet_from_responder_string);
    if (!result.success) {
        if (result.alert_to_send) {
                send_packet(result.alert_to_send->c_str(), result.alert_to_send->length());
        }
        throw Ukey2Exception("ERROR: Failed parsing first handshake message received from the other side");
    }

    printf("handshake stage 6\n");

    packet_to_responder = m_ukey2_handshake->GetNextHandshakeMessage();
    if (nullptr == packet_to_responder) {
        throw Ukey2Exception("Failed getting second handshake message to send");
    }

    printf("handshake stage 7\n");
    
    send_packet(packet_to_responder->c_str(), packet_to_responder->length());

    printf("handshake stage 8\n");

    auth_string = m_ukey2_handshake->GetVerificationString(VERIFICATION_STRING_LENGTH);
    if (nullptr == auth_string) {
        throw Ukey2Exception("Failed getting the verification string");
    }

    printf("handshake stage 9\n");

    if (false == m_ukey2_handshake->VerifyHandshake()) {
        throw Ukey2Exception("Failed verifying the handshake");
    }

    printf("handshake stage 10\n");
    
    m_connection_context = m_ukey2_handshake->ToConnectionContext();
    if (nullptr == m_connection_context) {
        throw Ukey2Exception("Failed getting the connection context object");
    }

    printf("handshake stage 11\n");
}