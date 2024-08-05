#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdlib.h>
#include <span>
#include <random>


#include <port/protobuf.h>
#include <mutator.h>
#include "tools/fuzzing/include/harness_offline_frames_validator.hh"
#include "tools/fuzzing/proto/offline_wire_formats_for_mutator.pb.h"
#include "common/include/logger.hh"

#define _CRT_SECURE_NO_WARNINGS
#define _SECURE_SCL 0
#define _HAS_ITERATOR_DEBUGGING 0

#define CUSTOM_SERVER_API extern "C" __declspec(dllexport)


// using google::protobuf::Any;
using google::protobuf::Message;

using OfflineFrame = ::location::nearby::connections::OfflineFrame;

class MyProtobufMutator : public protobuf_mutator::Mutator {
 public:
  // Optionally redefine the Mutate* methods to perform more sophisticated mutations.
};

void Mutate(OfflineFrame* message) {
    std::random_device rd;
    MyProtobufMutator mutator;
    unsigned int seed = rd();

    mutator.Seed(seed);
    mutator.Mutate((Message*)message, message->ByteSizeLong() * 2);
}


CUSTOM_SERVER_API UINT8 APIENTRY dll_mutate_testcase(char **argv, UINT8 *buf, UINT32 len, UINT8 (*common_fuzz_stuff)(char**, UINT8*, UINT32));


CUSTOM_SERVER_API UINT8 APIENTRY dll_mutate_testcase(char **argv, UINT8 *buf, UINT32 len, UINT8 (*common_fuzz_stuff)(char**, UINT8*, UINT32))
{

    bool did_packets_end = false;
    size_t packets_buffer_offset = 0;
    UINT8 * packets_buffer_cursor = buf;

    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"dll_mutate_testcase called");

    unsigned int packet_count = 0;
    while (!did_packets_end) {
        DWORD current_fuzz_packet_len = *(DWORD *)packets_buffer_cursor;
        char * current_fuzz_packet = (char*)packets_buffer_cursor + sizeof(DWORD);
        bool should_recv_packet = false;
        char * mutated_packet = NULL;
        size_t mutated_packet_size = 0;
        unsigned int mutation_attempt_index = 0;
        const unsigned int mutation_max_attempts = 100;
                
        OfflineFrame current_offline_frame;
        do {
            current_offline_frame.ParseFromArray(current_fuzz_packet, current_fuzz_packet_len);
            Mutate(&current_offline_frame);
        } while (!EnsureValidOfflineFrame(current_offline_frame) && ++mutation_attempt_index < mutation_max_attempts);

        logger_log(LoggerLogLevel::LEVEL_DEBUG ,"dll_mutate_testcase: Tried to mutate the same packet for %u times", mutation_attempt_index);
        
        if (mutation_attempt_index == mutation_max_attempts) {
            logger_log(LoggerLogLevel::LEVEL_DEBUG ,"dll_mutate_testcase: Reached max attempts of mutation without producing a valid OfflineFrame, bailing out...");
            return 1;
        }
        mutated_packet_size = current_offline_frame.ByteSizeLong();
        mutated_packet = (char*)malloc(mutated_packet_size);
        if (NULL == mutated_packet) {
            logger_log(LoggerLogLevel::LEVEL_ERROR ,"ERROR: mutated_packet malloc failed");
            return 1;
        }

        current_offline_frame.SerializeToArray(mutated_packet, mutated_packet_size);
        // creating the new buffer for all the same packets with one changed
        size_t new_packets_buffer_len = len + (mutated_packet_size - current_fuzz_packet_len);
        UINT8 * new_packets_buffer = (UINT8*) malloc(new_packets_buffer_len);
        if (NULL == new_packets_buffer) {
            logger_log(LoggerLogLevel::LEVEL_ERROR ,"ERROR: new_packets_buffer malloc failed");
            free(mutated_packet);
            return 1;
        }

        // the length of all packets and their lengths until the current packets
        size_t length_until_current_packet = packets_buffer_cursor - buf;

        // copy all packets until the current packets and their lengths to the beginning of the new buffer (everything that stays the same)
        memcpy(new_packets_buffer, buf, length_until_current_packet);

        // setting the length of the new mutated packet in the new buffer
        *(DWORD*)(new_packets_buffer + length_until_current_packet) = mutated_packet_size;

        memcpy(new_packets_buffer + length_until_current_packet + sizeof(DWORD), mutated_packet, mutated_packet_size);

        packets_buffer_offset += sizeof(DWORD) + current_fuzz_packet_len;
        packets_buffer_cursor = buf + packets_buffer_offset;

        memcpy(new_packets_buffer + length_until_current_packet + sizeof(DWORD) + mutated_packet_size, packets_buffer_cursor, len - packets_buffer_offset);

        if (common_fuzz_stuff(argv, new_packets_buffer, new_packets_buffer_len)) {
            logger_log(LoggerLogLevel::LEVEL_DEBUG ,"common_fuzz_stuff returned true");
            return 1;
        }

        if (len == packets_buffer_offset) {
            logger_log(LoggerLogLevel::LEVEL_DEBUG ,"mutation packets ended in packets_buffer");
            did_packets_end = true;
        }

        free(new_packets_buffer);
        free(mutated_packet);
    }

    
    return 1;
}