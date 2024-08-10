#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <mutex>
#include <iostream>
#include <random>
#include <span>
#include <fstream>

#include <Psapi.h>
#include <iphlpapi.h>
#include <string>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")


#include "quick_fuzz/include/test_case.hh"
#include "quick_share/include/quick_share_connection.hh"
#include "common/include/exceptions.hh"
#include "tools/tool_helpers/include/offline_frames_storage.hh"
#include "tools/tool_helpers/include/utils.hh"
#include "common/include/logger.hh"
#include "common/include/exceptions.hh"

#define CUSTOM_SERVER_API extern "C" __declspec(dllexport)

// 1 is success, -1 is failure
CUSTOM_SERVER_API int APIENTRY dll_init();
// 1 is success, -1 is failure
CUSTOM_SERVER_API int APIENTRY dll_run(char *data, long size, int fuzz_iterations);

/* ---- Globals ---- */
HANDLE thread_handle = NULL;
WifiLanMedium wifi_medium;
QuickShareConnection quick_share_connection(&wifi_medium);
TestCase test_case;
/* ---- Globals ---- */

const std::wstring TARGET_PROCESS_NAME = L"nearby_share.exe";
const char * LOCALHOST = "127.0.0.1";


DWORD GetPortsForProcess(const std::wstring& processName) {
    // Enumerate all processes to find the one with the specified name
    DWORD processes[8192], cbNeeded, cProcesses;
    DWORD result_port;

    if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        cProcesses = cbNeeded / sizeof(DWORD);

        for (unsigned int i = 0; i < cProcesses; ++i) {
            if (processes[i] != 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
                if (hProcess != NULL) {
                    wchar_t szProcessName[MAX_PATH];
                    if (GetModuleBaseNameW(hProcess, NULL, szProcessName, sizeof(szProcessName) / sizeof(wchar_t)) != 0) {
                        if (_wcsicmp(szProcessName, processName.c_str()) == 0) {
                            MIB_TCPTABLE2* tcpTable;
                            DWORD size = 0;

                            // Get the size required for the TCP table
                            if (GetTcpTable2(NULL, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
                                tcpTable = (MIB_TCPTABLE2*)malloc(size);

                                // Get the TCP table
                                if (GetTcpTable2(tcpTable, &size, FALSE) == NO_ERROR) {
                                    // Iterate through the table
                                    for (DWORD j = 0; j < tcpTable->dwNumEntries; ++j) {
                                        if (tcpTable->table[j].dwOwningPid == processes[i] && tcpTable->table[j].dwState == MIB_TCP_STATE_LISTEN) {
                                            logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Found local port for nearby_share: %d", ntohs((u_short)tcpTable->table[j].dwLocalPort));
                                            result_port = ntohs((u_short)tcpTable->table[j].dwLocalPort);
                                            break;
                                        }
                                    }
                                }
                                else {
                                    std::cerr << "Error getting TCP table." << std::endl;
                                }

                                free(tcpTable);
                            }
                            else {
                                std::cerr << "Error getting TCP table size." << std::endl;
                            }
                        }
                    }

                    CloseHandle(hProcess);
                }
            }
        }
    }
    else {
        std::cerr << "Error enumerating processes." << std::endl;
    }

    return result_port;
}

int generateRandomNumber() {
    // TODO: Consider delete.
    // Seed the random number generator
    std::random_device rd;
    std::mt19937 gen(rd());

    std::uniform_int_distribution<int> distribution(0, UINT_MAX);
    int random_number = distribution(gen);

    return random_number;
}

CUSTOM_SERVER_API int APIENTRY dll_init() {
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"dll_init called");
out:
    return 1;
}

void generateRandomString(char* output) {
    std::random_device rd;
    srand(rd());

    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const int stringLength = 4;

    for (int i = 0; i < stringLength; ++i) {
        output[i] = charset[rand() % (sizeof(charset) - 1)];
    }

    output[stringLength] = '\0';
}

void connect_to_target() {
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Trying to connect to target (20 times max)");
    for (size_t i=0; i<20; i++){
        DWORD listen_port = GetPortsForProcess(TARGET_PROCESS_NAME);
        wifi_medium.set_target(LOCALHOST, listen_port);
        try{
            quick_share_connection.connect();
            return;
        }
        catch (SocketException e){
            logger_log(LoggerLogLevel::LEVEL_ERROR ,"Failed connecting to socket (SocketException), trying again in 1 sec");
        }
        catch (TimeoutException e){
            logger_log(LoggerLogLevel::LEVEL_ERROR ,"Timed out waiting for the client to connect, trying again in 1 sec");
        }
        Sleep(1000);
    }

    throw SocketException("Couldn't connect to the fuzzing target's");
}

void send_input_offline_frames_to_target(std::vector<std::unique_ptr<OfflineFrame>> & offline_frames) {
    auto offline_frames_iterator = offline_frames.begin();

    // Send CONNECTION_REQUEST
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Send CONNECTION_REQUEST");
    quick_share_connection.send_offline_frame(**offline_frames_iterator++);

    // HandShake
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Starting Handshake");
    quick_share_connection.do_handshake();

    // Receive CONNECTION_RESPONSE
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Waiting for CONNECTION_RESPONSE");
    quick_share_connection.recv_packet();

    // Send CONNECTION_RESPONSE
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Sending CONNECTION_RESPONSE");
    quick_share_connection.send_offline_frame(**offline_frames_iterator++);

    // Paired key encryption
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Waiting for paired key encryption");
    quick_share_connection.recv_packet();
    quick_share_connection.recv_packet();

    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Sending for paired key encryption");
    quick_share_connection.send_offline_frame(**offline_frames_iterator++, true);
    quick_share_connection.send_offline_frame(**offline_frames_iterator++, true);

    // Paired key result
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Wait for Paired key result");
    quick_share_connection.recv_packet();
    quick_share_connection.recv_packet();

    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Sending Paired key result");
    quick_share_connection.send_offline_frame(**offline_frames_iterator++, true);
    quick_share_connection.send_offline_frame(**offline_frames_iterator++, true);

    // File introduction
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Sending File Introduction");
    quick_share_connection.send_offline_frame(**offline_frames_iterator++, true);
    quick_share_connection.send_offline_frame(**offline_frames_iterator++, true);

    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Waiting for File Introduction response");
    quick_share_connection.recv_packet();
    quick_share_connection.recv_packet();
    
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Send all the rest of packets");
    while (offline_frames_iterator != offline_frames.end()) {
        quick_share_connection.send_offline_frame(**offline_frames_iterator++, true);
    }

    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Wait for all responses till timeout");
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
}

DWORD WINAPI perform_one_fuzzing_iteration(LPVOID lpParam) {
    DWORD listen_port;
    
    logger_log(LoggerLogLevel::LEVEL_INFO ,"perform_one_fuzzing_iteration called TID: [%d]", GetCurrentThreadId());

    if (0 == test_case.getFuzzIteration()) {
        // implemented in WINAFL's example as well, wait for the socket to open
        logger_log(LoggerLogLevel::LEVEL_INFO ,"Sleeping 45 seconds because nearby_share.exe was just started");
        Sleep(45000);
        logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Woke up from sleep!!");
        
        // May take a while, because it tries 20 times
        connect_to_target();
        // In case connection failed after 20 times, QuickShare probably crashed.
    }
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Parsing corpus input file");
    std::vector<std::unique_ptr<OfflineFrame>> offline_frames = parse_offline_frames_buffer(test_case.getData(), test_case.getDataSize()); 

    try {
        send_input_offline_frames_to_target(offline_frames);
    } catch (BaseException e) {
        logger_log(LoggerLogLevel::LEVEL_ERROR, "Got an exception:\n%s", e.what());
        return -1;
    }

    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Finishing the test case by disconnecting from the current socket and connecting to a new one");
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Disconnecting from current socket...");
    quick_share_connection.disconnect();
    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Trying to connect to nearby for the second time in a loop");
    
    connect_to_target();
    Sleep(10);
    return 1;
}

CUSTOM_SERVER_API int APIENTRY dll_run(char *data, long size, int fuzz_iterations) {
    /*
        The dll_run function is used to execute input data against a DLL for testing, particularly in fuzzing, to identify vulnerabilities or crashes.
        It processes the input data multiple times based on the provided iteration count.

        (param) data: A pointer to the input data buffer. This data is used for testing the DLL.
        (param) size: The size of the data buffer in bytes. It specifies how much of the buffer to process.
        (param) fuzz_iterations: The number of times the input data should be processed. This controls the iterations of fuzz testing.

        see example at: https://github.com/googleprojectzero/winafl/blob/master/custom_winafl_server.c
    */

	DWORD dwThreadId;
    int ret_val = -1;

    Logger::get_instance().set_log_file("C:\\fuzz_logs\\fuzzer_log.txt");
    Logger::get_instance().set_log_destination(LoggerLogDestination::LOGGER_DEST_FILE);

    logger_log(LoggerLogLevel::LEVEL_INFO ,"dll_run was called");
    if (0 == fuzz_iterations) {
        initialize_wsa();
    }

    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"before WaitForSingleObject");

    if (thread_handle != NULL)
        WaitForSingleObject(thread_handle, INFINITE); /* we have to wait our previous thread to finish exec */

    logger_log(LoggerLogLevel::LEVEL_DEBUG ,"Ater WaitForSingleObject, going to create thread");

    test_case.setFuzzIteration(fuzz_iterations);
    test_case.setDataSize(size);
    test_case.setData(reinterpret_cast<uint8_t*>(data), size);
    
    // We have to create a second thread to avoid blocking winAFL in recv
    thread_handle = CreateThread(NULL, 0, perform_one_fuzzing_iteration, NULL, 0, &dwThreadId);
    if (thread_handle == NULL) {
        logger_log(LoggerLogLevel::LEVEL_ERROR ,"Failed to create new thread!");
        return -1;
    }

    logger_log(LoggerLogLevel::LEVEL_INFO ,"DLL_RUN finished running successfully!");
	return 1;
}