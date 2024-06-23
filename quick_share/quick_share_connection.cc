#include "include/quick_share_connection.hh"
#include "logger/include/logger.hh"

#include <string>
#include <memory>

#include "quick_share/include/exceptions.hh"

static const size_t VERIFICATION_STRING_LENGTH = 32;

void QuickShareConnection::connect()
{
    m_medium->connect();
}

void QuickShareConnection::disconnect()
{
    m_medium->disconnect();
}

void QuickShareConnection::set_medium(IMedium *medium)
{
    m_medium = medium;
}

void QuickShareConnection::send_packet(const char *packet, size_t packet_size)
{
    uint32_t packet_size_big_endian = htonl(packet_size);
    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending packet size packet through medium");
    m_medium->send((char *)&packet_size_big_endian, sizeof(uint32_t));
    logger_log(LoggerLogLevel::LEVEL_INFO, "Sending packet itself through medium");
    m_medium->send(packet, packet_size);
}

std::vector<char> QuickShareConnection::recv_packet()
{
    std::vector<char> packet_size_bytes_big_endian = m_medium->recv(sizeof(uint32_t));
    size_t packet_size = ntohl(*(uint32_t *)packet_size_bytes_big_endian.data());

    return m_medium->recv(packet_size);
}

void QuickShareConnection::send_offline_frame(OfflineFrame &offline_frame, bool should_encrypt)
{
    logger_log(LoggerLogLevel::LEVEL_DEBUG, "Sending offline frame:");
    logger_log(LoggerLogLevel::LEVEL_DEBUG, offline_frame.DebugString().c_str());

    std::string offline_frame_bytes(offline_frame.SerializeAsString());
    if (offline_frame_bytes.empty()) {
        throw ProtobufException("Failed serializing an Offline Frame");
    }

    if (should_encrypt)
    {
        std::unique_ptr<std::string> encoded_packet = m_connection_context->EncodeMessageToPeer(offline_frame_bytes);
        send_packet(encoded_packet->c_str(), encoded_packet->length());
    }
    else
    {
        send_packet(offline_frame_bytes.c_str(), offline_frame_bytes.length());
    }
}

std::unique_ptr<OfflineFrame> QuickShareConnection::recv_offline_frame(bool should_decrypt)
{
    std::vector<char> packet_bytes = recv_packet();
    std::string packet_bytes_string(packet_bytes.begin(), packet_bytes.end());
    auto offline_frame = std::make_unique<OfflineFrame>();
    std::unique_ptr<std::string> decrypted_offline_frame_bytes;
    std::string * bytes_to_parse;

    if (should_decrypt)
    {
        decrypted_offline_frame_bytes = m_connection_context->DecodeMessageFromPeer(packet_bytes_string);
        if (!decrypted_offline_frame_bytes)
        {
            return nullptr;
        }
        bytes_to_parse = decrypted_offline_frame_bytes.get();
    }
    else
    {
        bytes_to_parse = &packet_bytes_string;
    }

    if (!offline_frame->ParseFromString(*bytes_to_parse)) {
        throw ProtobufException("Failed parsing Offline Frame bytes into an Offline Frame object");
    }

    logger_log(LoggerLogLevel::LEVEL_DEBUG, "Received offline frame:");
    logger_log(LoggerLogLevel::LEVEL_DEBUG, offline_frame->DebugString().c_str());

    return offline_frame;
}

void QuickShareConnection::do_handshake()
{
    string packet_from_responder_string;
    std::vector<char> packet_from_responder;
    std::unique_ptr<string> auth_string = NULL;
    std::unique_ptr<string> packet_to_responder = nullptr;
    UKey2Handshake::ParseResult result;

    logger_log(LoggerLogLevel::LEVEL_INFO, "Initiating Ukey2 Handshake");

    m_ukey2_handshake = UKey2Handshake::ForInitiator(UKey2Handshake::HandshakeCipher::P256_SHA512);
    if (nullptr == m_ukey2_handshake)
    {
        throw Ukey2Exception("Failed creating the Ukey2Handshake object");
    }

    packet_to_responder = m_ukey2_handshake->GetNextHandshakeMessage();
    if (nullptr == packet_to_responder)
    {
        throw Ukey2Exception("Failed getting first handshake message to send");
    }

    logger_log(LoggerLogLevel::LEVEL_DEBUG, "Sending Ukey2 Client Init");
    send_packet(packet_to_responder->c_str(), packet_to_responder->length());

    logger_log(LoggerLogLevel::LEVEL_DEBUG, "Receiving Ukey2 Server Init");
    packet_from_responder = recv_packet();
    packet_from_responder_string = std::string(packet_from_responder.begin(), packet_from_responder.end());

    result = m_ukey2_handshake->ParseHandshakeMessage(packet_from_responder_string);
    if (!result.success)
    {
        if (result.alert_to_send)
        {
            send_packet(result.alert_to_send->c_str(), result.alert_to_send->length());
        }
        throw Ukey2Exception("Failed parsing first handshake message received from the other side");
    }

    packet_to_responder = m_ukey2_handshake->GetNextHandshakeMessage();
    if (nullptr == packet_to_responder)
    {
        throw Ukey2Exception("Failed getting second handshake message to send");
    }

    logger_log(LoggerLogLevel::LEVEL_DEBUG, "Sending Ukey2 Client Finish");
    send_packet(packet_to_responder->c_str(), packet_to_responder->length());

    auth_string = m_ukey2_handshake->GetVerificationString(VERIFICATION_STRING_LENGTH);
    if (nullptr == auth_string)
    {
        throw Ukey2Exception("Failed getting the verification string");
    }

    if (false == m_ukey2_handshake->VerifyHandshake())
    {
        throw Ukey2Exception("Failed verifying the handshake");
    }

    m_connection_context = m_ukey2_handshake->ToConnectionContext();
    if (nullptr == m_connection_context)
    {
        throw Ukey2Exception("Failed getting the connection context object");
    }

    logger_log(LoggerLogLevel::LEVEL_INFO, "Ukey2 Handshake finished successfully");
}