#include "tools/fuzzing/include/harness_offline_frames_validator.hh"

#include <cstdlib>
#include <regex>
#include "absl/strings/string_view.h"

#include "tools/fuzzing/proto/offline_wire_formats_for_mutator.pb.h"

using UpgradePathInfo = ::location::nearby::connections::BandwidthUpgradeNegotiationFrame::UpgradePathInfo;

using PayloadChunk =
    ::location::nearby::connections::PayloadTransferFrame::PayloadChunk;
using ControlMessage =
    ::location::nearby::connections::PayloadTransferFrame::ControlMessage;
using ClientIntroduction = ::location::nearby::connections::
    BandwidthUpgradeNegotiationFrame::ClientIntroduction;
using WifiHotspotCredentials = UpgradePathInfo::WifiHotspotCredentials;
using WifiLanSocket = UpgradePathInfo::WifiLanSocket;
using WifiAwareCredentials = UpgradePathInfo::WifiAwareCredentials;
using WifiDirectCredentials = UpgradePathInfo::WifiDirectCredentials;
using BluetoothCredentials = UpgradePathInfo::BluetoothCredentials;
using WebRtcCredentials = UpgradePathInfo::WebRtcCredentials;
using V1Frame = ::location::nearby::connections::V1Frame;
using ConnectionRequestFrame = ::location::nearby::connections::ConnectionRequestFrame;
using ConnectionResponseFrame = ::location::nearby::connections::ConnectionResponseFrame;
using PayloadTransferFrame = ::location::nearby::connections::PayloadTransferFrame;
using BandwidthUpgradeNegotiationFrame = ::location::nearby::connections::BandwidthUpgradeNegotiationFrame;

enum Medium : int {
  UNKNOWN_MEDIUM = 0,
  MDNS = 1,
  BLUETOOTH = 2,
  WIFI_HOTSPOT = 3,
  BLE = 4,
  WIFI_LAN = 5,
  WIFI_AWARE = 6,
  NFC = 7,
  WIFI_DIRECT = 8,
  WEB_RTC = 9,
  BLE_L2CAP = 10,
  USB = 11
};

constexpr absl::string_view kIpv4PatternString{
    "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$"};
constexpr absl::string_view kIpv6PatternString{
    "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$"};
constexpr absl::string_view kWifiDirectSsidPatternString{
    "^DIRECT-[a-zA-Z0-9]{2}.*$"};

constexpr int kWifiDirectSsidMaxLength = 32;
constexpr int kWifiPasswordSsidMinLength = 8;
constexpr int kWifiPasswordSsidMaxLength = 64;

static constexpr int kIndeterminateSize = -1;

inline bool WithinRange(int value, int min, int max) {
  return value >= min && value < max;
}

V1Frame::FrameType GetFrameType(const OfflineFrame& frame) {
  if ((frame.version() == OfflineFrame::V1) && frame.has_v1()) {
    return frame.v1().type();
  }

  return V1Frame::UNKNOWN_FRAME_TYPE;
}

bool EnsureValidConnectionRequestFrame(
    const ConnectionRequestFrame& frame) {
  if (!frame.has_endpoint_id()) return false;
  if (!frame.has_endpoint_name()) return false;

  // For backwards compatibility reasons, no other fields should be
  // null-checked for this frame. Parameter checking (eg. must be within this
  // range) is fine.
  return true;
}

bool EnsureValidConnectionResponseFrame(
    const ConnectionResponseFrame& frame) {
  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidPayloadTransferDataFrame(const PayloadTransferFrame::PayloadChunk& payload_chunk,
                                              std::int64_t totalSize) {
  if (!payload_chunk.has_flags()) return false;

  // Special case. The body can be null iff the chunk is flagged as the last
  // chunk.
  bool is_last_chunk = (payload_chunk.flags() &
                        PayloadTransferFrame::PayloadChunk::LAST_CHUNK) != 0;
  if (!payload_chunk.has_body() && !is_last_chunk)
    return false;
  if (!payload_chunk.has_offset() || payload_chunk.offset() < 0)
    return false;
  if (totalSize != kIndeterminateSize &&
      totalSize < payload_chunk.offset()) {
    return false;
  }

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidPayloadTransferControlFrame(
    const PayloadTransferFrame::ControlMessage& control_message, std::int64_t totalSize) {
  if (!control_message.has_offset() || control_message.offset() < 0)
    return false;
  if (totalSize != kIndeterminateSize &&
      totalSize < control_message.offset()) {
    return false;
  }

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidPayloadTransferFrame(const PayloadTransferFrame& frame) {
  if (!frame.has_payload_header()) return false;
  if (!frame.payload_header().has_total_size() ||
      (frame.payload_header().total_size() < 0 &&
       frame.payload_header().total_size() !=
           kIndeterminateSize))
    return false;
  if (!frame.has_packet_type()) return false;

  switch (frame.packet_type()) {
    case PayloadTransferFrame::DATA:
      if (frame.has_payload_chunk()) {
        return EnsureValidPayloadTransferDataFrame(
            frame.payload_chunk(), frame.payload_header().total_size());
      }
      return false;

    case PayloadTransferFrame::CONTROL:
      if (frame.has_control_message()) {
        return EnsureValidPayloadTransferControlFrame(
            frame.control_message(), frame.payload_header().total_size());
      }
      return false;

    default:
      break;
  }

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidBandwidthUpgradeWifiHotspotPathAvailableFrame(
    const WifiHotspotCredentials& wifi_hotspot_credentials) {
  if (!wifi_hotspot_credentials.has_ssid())
    return false;
  if (!wifi_hotspot_credentials.has_password() ||
      !WithinRange(wifi_hotspot_credentials.password().length(),
                   kWifiPasswordSsidMinLength, kWifiPasswordSsidMaxLength))
    return false;
  if (!wifi_hotspot_credentials.has_gateway())
    return false;
  const std::regex ip4_pattern(std::string(kIpv4PatternString).c_str());
  const std::regex ip6_pattern(std::string(kIpv6PatternString).c_str());
  if (!(std::regex_match(wifi_hotspot_credentials.gateway(), ip4_pattern) ||
        std::regex_match(wifi_hotspot_credentials.gateway(), ip6_pattern)))
    return false;

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidBandwidthUpgradeWifiLanPathAvailableFrame(
    const WifiLanSocket& wifi_lan_socket) {
  if (!wifi_lan_socket.has_ip_address())
    return false;
  if (!wifi_lan_socket.has_wifi_port() || wifi_lan_socket.wifi_port() < 0)
    return false;

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidBandwidthUpgradeWifiAwarePathAvailableFrame(
    const WifiAwareCredentials& wifi_aware_credentials) {
  if (!wifi_aware_credentials.has_service_id())
    return false;
  if (!wifi_aware_credentials.has_service_info())
    return false;

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidBandwidthUpgradeWifiDirectPathAvailableFrame(
    const WifiDirectCredentials& wifi_direct_credentials) {
  const std::regex ssid_pattern(
      std::string(kWifiDirectSsidPatternString).c_str());
  if (!wifi_direct_credentials.has_ssid() ||
      !(wifi_direct_credentials.ssid().length() < kWifiDirectSsidMaxLength &&
        std::regex_match(wifi_direct_credentials.ssid(), ssid_pattern)))
    return false;

  if (!wifi_direct_credentials.has_password() ||
      !WithinRange(wifi_direct_credentials.password().length(),
                   kWifiPasswordSsidMinLength, kWifiPasswordSsidMaxLength))
    return false;

  if (!wifi_direct_credentials.has_frequency() ||
      wifi_direct_credentials.frequency() < -1)
    return false;

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidBandwidthUpgradeBluetoothPathAvailableFrame(
    const BluetoothCredentials& bluetooth_credentials) {
  if (!bluetooth_credentials.has_service_name())
    return false;
  if (!bluetooth_credentials.has_mac_address())
    return false;

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidBandwidthUpgradeWebRtcPathAvailableFrame(
    const WebRtcCredentials& web_rtc_credentials) {
  if (!web_rtc_credentials.has_peer_id())
    return false;

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidBandwidthUpgradePathAvailableFrame(
    const UpgradePathInfo& upgrade_path_info) {
  if (!upgrade_path_info.has_medium())
    return false;
  switch (static_cast<Medium>(upgrade_path_info.medium())) {
    case Medium::WIFI_HOTSPOT:
      if (upgrade_path_info.has_wifi_hotspot_credentials()) {
        return EnsureValidBandwidthUpgradeWifiHotspotPathAvailableFrame(
            upgrade_path_info.wifi_hotspot_credentials());
      }
      return false;

    case Medium::WIFI_LAN:
      if (upgrade_path_info.has_wifi_lan_socket()) {
        return EnsureValidBandwidthUpgradeWifiLanPathAvailableFrame(
            upgrade_path_info.wifi_lan_socket());
      }
      return false;

    case Medium::WIFI_AWARE:
      if (upgrade_path_info.has_wifi_aware_credentials()) {
        return EnsureValidBandwidthUpgradeWifiAwarePathAvailableFrame(
            upgrade_path_info.wifi_aware_credentials());
      }
      return false;

    case Medium::WIFI_DIRECT:
      if (upgrade_path_info.has_wifi_direct_credentials()) {
        return EnsureValidBandwidthUpgradeWifiDirectPathAvailableFrame(
            upgrade_path_info.wifi_direct_credentials());
      }
      return false;

    case Medium::BLUETOOTH:
      if (upgrade_path_info.has_bluetooth_credentials()) {
        return EnsureValidBandwidthUpgradeBluetoothPathAvailableFrame(
            upgrade_path_info.bluetooth_credentials());
      }
      return false;

    case Medium::WEB_RTC:
      if (upgrade_path_info.has_web_rtc_credentials()) {
        return EnsureValidBandwidthUpgradeWebRtcPathAvailableFrame(
            upgrade_path_info.web_rtc_credentials());
      }
      return false;

    default:
      break;
  }

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidBandwidthUpgradeClientIntroductionFrame(
    const ClientIntroduction& client_introduction) {
  if (!client_introduction.has_endpoint_id())
    return false;

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidBandwidthUpgradeNegotiationFrame(
    const BandwidthUpgradeNegotiationFrame& frame) {
  if (!frame.has_event_type()) return false;

  switch (frame.event_type()) {
    case BandwidthUpgradeNegotiationFrame::UPGRADE_PATH_AVAILABLE:
      if (frame.has_upgrade_path_info()) {
        return EnsureValidBandwidthUpgradePathAvailableFrame(
            frame.upgrade_path_info());
      }
      return false;

    case BandwidthUpgradeNegotiationFrame::CLIENT_INTRODUCTION:
      if (frame.has_client_introduction()) {
        return EnsureValidBandwidthUpgradeClientIntroductionFrame(
            frame.client_introduction());
      }
      return false;

    default:
      break;
  }

  // For backwards compatibility reasons, no other fields should be null-checked
  // for this frame. Parameter checking (eg. must be within this range) is fine.
  return true;
}

bool EnsureValidOfflineFrame(OfflineFrame & offline_frame) {
  V1Frame::FrameType frame_type = GetFrameType(offline_frame);
  switch (frame_type) {
    case V1Frame::CONNECTION_REQUEST:
      if (offline_frame.has_v1() &&
          offline_frame.v1().has_connection_request()) {
        return EnsureValidConnectionRequestFrame(
            offline_frame.v1().connection_request());
      }
      return false;

    case V1Frame::CONNECTION_RESPONSE:
      if (offline_frame.has_v1() &&
          offline_frame.v1().has_connection_response()) {
        return EnsureValidConnectionResponseFrame(
            offline_frame.v1().connection_response());
      }
      return false;

    case V1Frame::PAYLOAD_TRANSFER:
      if (offline_frame.has_v1() && offline_frame.v1().has_payload_transfer()) {
        return EnsureValidPayloadTransferFrame(
            offline_frame.v1().payload_transfer());
      }
      return false;

    case V1Frame::BANDWIDTH_UPGRADE_NEGOTIATION:
      if (offline_frame.has_v1() &&
          offline_frame.v1().has_bandwidth_upgrade_negotiation()) {
        return EnsureValidBandwidthUpgradeNegotiationFrame(
            offline_frame.v1().bandwidth_upgrade_negotiation());
      }
      return false;

    case V1Frame::KEEP_ALIVE:
    case V1Frame::UNKNOWN_FRAME_TYPE:
    default:
      // Nothing to check for these frames.
      break;
  }
  return true;
}