#include <windows.h>
#include <tlhelp32.h>
#include <random>
#include <google/protobuf/util/json_util.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "tools/lib/bin/MinHook.x64.lib")
#include "lib/include/MinHook.h" // MinHook header
#include "common/include/logger.hh"
#include "quick_share/proto/offline_wire_formats.pb.h"
#include "quick_share/proto/wire_format.pb.h"

/*
 * * * * * * * Hooking Addresses * * * * * * *
 *
 * The following addresses (0x4EBE60, 0x4ECB20) are derived from the nearby_sharing_dart.dll:
 *
 * File Details:
 * SHA256 : 2CB6771D7352505893A6246EA4A46D135919BE391C4AC304F5E601FA61758713
 * MD5    : DB1F7439D34EDA248ACD47BC11FDA4A4
 */

const uintptr_t READ_PACKET_OFFSET = 0x4EBB60;
const uintptr_t WRITE_PACKET_OFFSET = 0x4EC820;

/* * * * * * * * * * * * * * * * * * * * * * * */

// IMPORTANT - Set these paths to your preferred paths
const std::string PACKET_FLOW_DIR_PATH = "C:\\Users\\User\\example\\path\\";
const std::string LOG_FILE_PATH = "C:\\Users\\User\\example\\path\\sniffer_logs.txt";
const unsigned int SEVEN_BYTES_IN_BITS = 56;

std::string g_packet_flow_initiator_to_responder_file_path;
std::string g_packet_flow_responder_to_initiator_file_path;
bool g_am_i_initiator;

// Define function pointer types
typedef __int64(__fastcall *BaseEndpointChannel_Read_t)(void *this_ptr, void *ret_value, void *packet_meta_data);
typedef __int64(__fastcall *BaseEndpointChannel_Write_t)(void *this_ptr, void **ret_value, void *data, void *packet_meta_data);

// Declare function pointers
BaseEndpointChannel_Read_t original_BaseEndpointChannel_read = nullptr;
BaseEndpointChannel_Write_t original_BaseEndpointChannel_write = nullptr;


using Frame = ::sharing::nearby::Frame;
using OfflineFrame = ::location::nearby::connections::OfflineFrame;
using V1Frame = ::location::nearby::connections::V1Frame;
using PayloadType = ::location::nearby::connections::PayloadTransferFrame_PayloadHeader_PayloadType;
using namespace google::protobuf::util;
using namespace nlohmann;

std::string generate_uuid()
{
    const std::string chars = "0123456789ABCDEF";

    std::string uuid;
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distr(0, chars.size() - 1);

    for (int i = 0; i < 36; ++i)
    {
        uuid += chars[distr(generator)];
    }

    // for the separators:
    uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';

    return uuid;
}

std::string get_pretty_json_for_offline_frame(OfflineFrame *offline_frame_result)
{
    /**
     * Converts an OfflineFrame protobuf message into a pretty-printed JSON string.
     * as well handling a sub-frame within the OfflineFrame.
     *
     * @param offline_frame_result A pointer to an OfflineFrame object.
     * @return A string containing the pretty-printed JSON representation.
     *
     */

    std::string nested_frame_json_str;
    std::string offlineFrame_json_str;

    google::protobuf::util::MessageToJsonString(*offline_frame_result, &offlineFrame_json_str);
    json json_output = json::parse(offlineFrame_json_str);

    if (offline_frame_result->v1().type() == V1Frame::PAYLOAD_TRANSFER && // checks that type is PayloadTransfer
        offline_frame_result->v1().has_payload_transfer() &&
        offline_frame_result->v1().payload_transfer().has_payload_header() && // check that we have payload_header
        offline_frame_result->v1().payload_transfer().payload_header().type() == PayloadType::PayloadTransferFrame_PayloadHeader_PayloadType_BYTES &&
        offline_frame_result->v1().payload_transfer().has_payload_chunk() &&
        offline_frame_result->v1().payload_transfer().payload_chunk().has_body())
    {
        Frame nested_frame;
        nested_frame.ParseFromArray(offline_frame_result->v1().payload_transfer().payload_chunk().body().c_str(), offline_frame_result->v1().payload_transfer().payload_chunk().body().size());

        google::protobuf::util::MessageToJsonString(nested_frame, &nested_frame_json_str);
        json nested_frame_json = json::parse(nested_frame_json_str);

        json_output["v1"]["payloadTransfer"]["payloadChunk"]["body"] = nested_frame_json;
    }

    return json_output.dump(4);
}

void append_offline_frame_to_packets_file(const std::string &file_path, OfflineFrame &offline_frame)
{
    /**
     * Writes the contents of an OfflineFrame protobuf message to a file with the following format:
     * [4 bytes - Length] [DATA in that Length]
     *
     * This is useful for saving a transfer session for later playback.
     * @param filename The name of the file to write to. This should include the full path
     *
     * @param packet_data A pointer to the OfflineFrame protobuf message to be written.
     *                    This pointer must not be null.
     *
     */
    if (0 == file_path.size()) {
        logger_log(LoggerLogLevel::LEVEL_ERROR, "Target packets flow file path is empty for some reason");
        return;
    }

    std::ofstream file(file_path, std::ios::binary | std::ios::app);
    if (!file)
    {
        logger_log(LoggerLogLevel::LEVEL_INFO, "Failed to open packets file");
        return;
    }

    // Write the length as 4 bytes in little-endian order
    uint32_t length = offline_frame.ByteSizeLong();
    file.write(reinterpret_cast<const char *>(&length), sizeof(length));

    // Write the packet data
    file.write(offline_frame.SerializeAsString().c_str(), length);

    file.close();
}

uint8_t * get_serialized_proto_buffer_ptr_from_byte_array_object(void * read_ret_val, size_t * out_bytes_length) {
    uint8_t * read_ret_val_buffer = reinterpret_cast<uint8_t*>(read_ret_val);
    uint8_t * protobuf_data = nullptr;
    size_t protobuf_size = 0;

    // The following logic happens due to SSO (Short String Optimization)
    protobuf_size = *(reinterpret_cast<size_t *>(read_ret_val_buffer) + 0x2);
    if (protobuf_size > 0x8000000000000000)
    {
        protobuf_data = *reinterpret_cast<uint8_t **>(read_ret_val_buffer);
        protobuf_size = protobuf_size & 0xFFFFFFFF;
    }
    else
    {
        protobuf_data = reinterpret_cast<uint8_t *>(read_ret_val_buffer);
        protobuf_size = protobuf_size >> SEVEN_BYTES_IN_BITS;
    }

    *out_bytes_length = protobuf_size;
    return protobuf_data;
}


void log_offline_frame(OfflineFrame offline_frame, bool is_from_responder_to_initiator) {
    std::string results = get_pretty_json_for_offline_frame(&offline_frame);

    if (is_from_responder_to_initiator) {
        logger_log(LoggerLogLevel::LEVEL_INFO, "(Responder -> Initiator):");
    } else {
        logger_log(LoggerLogLevel::LEVEL_INFO, "(Initiator -> Responder):");
    }

    logger_log(LoggerLogLevel::LEVEL_INFO, results.c_str());
}

void generate_packet_file_paths() {
    std::string uuid = generate_uuid();
    g_packet_flow_initiator_to_responder_file_path = PACKET_FLOW_DIR_PATH + uuid + "_initiator_to_responder" + ".bin";
    g_packet_flow_responder_to_initiator_file_path = PACKET_FLOW_DIR_PATH + uuid + "_responder_to_initiator" + ".bin";
}

void hook_baseEndpointChannel_read(void *this_ptr, void *ret_value, void *input)
{
    /*
    For hooking incoming OfflineFrames:
        1. open the nearby_sharing_dart DLL in a disassembler.
        2. find the string "Read an invalid number of bytes" within the DLL.
        3. locate the function that is xrefing this string.
        4. replace the address of READ_PACKET_OFFSET to the offset of where this function begins.
    */

    original_BaseEndpointChannel_read(this_ptr, ret_value, input);

    size_t proto_buffer_byte_length = 0;
    uint8_t * serialized_proto_buffer = get_serialized_proto_buffer_ptr_from_byte_array_object(ret_value, &proto_buffer_byte_length);
    logger_log(LoggerLogLevel::LEVEL_INFO, "BaseEndpointChannel:Read Hook - Read packet in size: %u", proto_buffer_byte_length);
    
    OfflineFrame offline_frame_result;
    offline_frame_result.ParseFromArray(serialized_proto_buffer, proto_buffer_byte_length);
    
    if (!offline_frame_result.has_version())
    {
        logger_log(LoggerLogLevel::LEVEL_INFO, "BaseEndpointChannel:Write Hook: Read packet is not an OfflineFrame");
        return;
    }

    if (offline_frame_result.v1().has_connection_request())
    {
        generate_packet_file_paths();
        // If we read a connection request then it means that the other side has initiated the connection
        g_am_i_initiator = false;
    }

    log_offline_frame(offline_frame_result, g_am_i_initiator);

    // This will write the packets into a file, for later reply
    std::string * target_packets_file_path = g_am_i_initiator ? &g_packet_flow_responder_to_initiator_file_path : &g_packet_flow_initiator_to_responder_file_path;
    append_offline_frame_to_packets_file(*target_packets_file_path, offline_frame_result);
    
}

void hook_baseEndpointChannel_write(void *this_ptr, void **ret_value, void *data, void *packet_meta_data)
{
    /*
      For hooking outgoing OfflineFrames:
          1. open the nearby_sharing_dart DLL in a disassembler.
          2. find the string "Failed to encrypt data" within the DLL.
          3. locate the function that is xrefing this string.
          4. replace the address of WRITE_PACKET_OFFSET to the offset of where this function begins.
    */
    size_t proto_buffer_byte_length = 0;
    uint8_t * serialized_proto_buffer = get_serialized_proto_buffer_ptr_from_byte_array_object(data, &proto_buffer_byte_length);
    logger_log(LoggerLogLevel::LEVEL_INFO, "BaseEndpointChannel:Write Hook - Writing packet in size: %u", proto_buffer_byte_length);

    OfflineFrame offline_frame_result;
    offline_frame_result.ParseFromArray(serialized_proto_buffer, proto_buffer_byte_length);
    
    if (offline_frame_result.has_version())
    {
        if (offline_frame_result.v1().has_connection_request())
        {
            generate_packet_file_paths();
            // If we write a connection request then it means that the other side has initiated the connection
            g_am_i_initiator = true;
        }
        
        log_offline_frame(offline_frame_result, false == g_am_i_initiator);
        std::string * target_packets_file_path = g_am_i_initiator ? &g_packet_flow_initiator_to_responder_file_path : &g_packet_flow_responder_to_initiator_file_path;
        append_offline_frame_to_packets_file(*target_packets_file_path, offline_frame_result);
    }
    else
    {
        logger_log(LoggerLogLevel::LEVEL_INFO, "BaseEndpointChannel:Write Hook: Written packet is not an OfflineFrame");
    }

    original_BaseEndpointChannel_write(this_ptr, ret_value, data, packet_meta_data);
}

uintptr_t get_module_base_address(const std::wstring &moduleName)
{
    /**
     * @Retrieves the base address of a specified module in the current process.
     *
     * @param moduleName The name of the module whose base address is to be retrieved.
     *                   The module name should include the file extension (e.g., "module.dll").
     *                   This name is case-insensitive.
     * @return uintptr_t The base address of the specified module. Returns 0 if the module
     *                   is not found or if an error occurs.
     */

    uintptr_t baseAddress = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W me;
        me.dwSize = sizeof(MODULEENTRY32W);
        if (Module32FirstW(hSnapshot, &me))
        {
            do
            {
                if (wcscmp(moduleName.c_str(), me.szModule) == 0)
                {
                    baseAddress = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                    break;
                }
            } while (Module32NextW(hSnapshot, &me));
        }
        CloseHandle(hSnapshot);
    }
    return baseAddress;
}

bool create_new_hook(LPVOID hook_target, LPVOID hook_function, LPVOID *original_func_ptr)
{
    /**
     * Creates a new function hook.
     *
     * @param hook_target The target function to be hooked. This is a pointer to the function's starting address.
     * @param hook_function The function to be executed in place of the original target function. This is a pointer
     *                      to the replacement function.
     * @param original_func_ptr A pointer to a location where the pointer to the original function will be stored.
     *                          This allows the hook function to call the original function if needed.
     * @return bool Returns true if the hook was successfully created, false otherwise.
     */

    MH_STATUS status = MH_UNKNOWN;

    if (MH_CreateHook(hook_target, hook_function, original_func_ptr) != MH_OK)
    {

        // logger->Log("Failed to MH_CreateHook");
        logger_log(LoggerLogLevel::LEVEL_ERROR, "Failed to MH_CreateHook");
        return false;
    }
    if (MH_EnableHook(hook_target) != MH_OK)
    {
        logger_log(LoggerLogLevel::LEVEL_ERROR, "Failed to MH_EnableHook");
        return false;
    }

    return true;
}

// DLL entry point
extern "C" __declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    uintptr_t WritePacketAddr = NULL;
    uintptr_t ReadPacketAddr = NULL;
    uintptr_t nearby_sharing_dart_base;

    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        Logger::get_instance().set_log_file(LOG_FILE_PATH);
        Logger::get_instance().set_log_destination(LoggerLogDestination::LOGGER_DEST_FILE);

        logger_log(LoggerLogLevel::LEVEL_INFO, "DLL_PROCESS_ATTACH");

        // Initialize MinHook
        if (MH_Initialize() != MH_OK)
        {
            logger_log(LoggerLogLevel::LEVEL_ERROR, "Failed to MH_Initialize");
            return FALSE;
        }

        // Address of the target function ()
        nearby_sharing_dart_base = get_module_base_address(L"nearby_sharing_dart.dll");
        WritePacketAddr = nearby_sharing_dart_base + WRITE_PACKET_OFFSET;
        ReadPacketAddr = nearby_sharing_dart_base + READ_PACKET_OFFSET;

        if (create_new_hook((LPVOID)ReadPacketAddr, hook_baseEndpointChannel_read, reinterpret_cast<LPVOID *>(&original_BaseEndpointChannel_read)))
        {
            logger_log(LoggerLogLevel::LEVEL_INFO, "Sucussfully hooked ReadPacket");
        }
        if (create_new_hook((LPVOID)WritePacketAddr, hook_baseEndpointChannel_write, reinterpret_cast<LPVOID *>(&original_BaseEndpointChannel_write)))
        {
            logger_log(LoggerLogLevel::LEVEL_INFO, "Sucussfully hooked WritePacket");
        }
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        // Cleanup MinHook
        MH_DisableHook(reinterpret_cast<void *>(WritePacketAddr));
        MH_DisableHook(reinterpret_cast<void *>(ReadPacketAddr));

        MH_Uninitialize();
    }
    return TRUE;
}
