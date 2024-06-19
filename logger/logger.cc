#include <cstdarg>
#include <cstdlib>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>


static std::mutex logMutex; // Define a mutex to protect the printing

auto g_now = std::chrono::system_clock::now();
auto g_ms = std::chrono::duration_cast<std::chrono::milliseconds>(g_now.time_since_epoch()) % 1000000000;
static std::string g_logFilePath = "C:\\fuzz_logs\\fuzzing_nearby_" + std::to_string(g_ms.count()) + ".log";    

void printf_logger(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

auto g_last_time_log = std::chrono::duration_cast<std::chrono::milliseconds>(g_now.time_since_epoch());

#include <unordered_map>
std::unordered_map<int, std::chrono::milliseconds> threads_time_dict;

bool check_if_key_exists(int key){
    auto it = threads_time_dict.find(key);
    return it != threads_time_dict.end();
}

void delete_thread_from_timedict(int tid) {
    threads_time_dict.erase(tid);
}

// void printf_logger(const char* format, ...) {
    
//     // Get the current time, including milliseconds
//     auto now = std::chrono::system_clock::now();
//     auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
//     int current_tid = GetCurrentThreadId();
//     unsigned long long time_delay_since_last_log = 0;

//     // Extract the time components
//     std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
//     std::tm timeInfo;
//     localtime_s(&timeInfo, &currentTime); // Use localtime_s for thread safety in Windows

//     // Create a string containing the timestamp (HH:MM:SS:MMM format)
//     char timestamp[32] = {0};
//     char time_delay_str[32] = {0};
//     char tid[32] = {0};

//     if (check_if_key_exists(current_tid))
//     {
//         time_delay_since_last_log = ms.count() - threads_time_dict[current_tid].count();
//     }

//     sprintf(tid, "\t[TID_%d]\t", current_tid);
//     if (time_delay_since_last_log > 1000)
//         sprintf(time_delay_str, " (delay (1000+) -> %lld)", time_delay_since_last_log);
//     else if (time_delay_since_last_log > 500)
//         sprintf(time_delay_str, " (delay (500+) -> %lld)", time_delay_since_last_log);
//     else if (time_delay_since_last_log > 100)
//         sprintf(time_delay_str, " (delay (100+) -> %lld)", time_delay_since_last_log);
//     else if (time_delay_since_last_log > 50)
//         sprintf(time_delay_str, " (delay (50+) -> %lld)", time_delay_since_last_log);
//     else if (time_delay_since_last_log > 5)
//         sprintf(time_delay_str, " (delay: %lld)", time_delay_since_last_log);


//     std::strftime(timestamp, sizeof(timestamp), "%H:%M:%S:", &timeInfo);
//     std::string timestampStr = timestamp + std::to_string(ms.count());

//     // Lock the mutex to ensure exclusive access to the log file
//     std::lock_guard<std::mutex> lock(logMutex);

//     // Open the log file
//     std::ofstream logFile(g_logFilePath, std::ios::app); // Open the file in append mode

//     if (logFile.is_open()) {

//         // Use variadic arguments to write the formatted message to the log file
//         va_list args;
//         va_start(args, format);
//         char logMessage[4096 * 10]; // Adjust the buffer size as needed
//         vsnprintf(logMessage, sizeof(logMessage), format, args);
//         va_end(args);
//         logFile << timestampStr << tid << logMessage << time_delay_str << std::endl;

//         // Close the log file
//         logFile.close();
//     }
//     threads_time_dict[current_tid] = ms;
// }