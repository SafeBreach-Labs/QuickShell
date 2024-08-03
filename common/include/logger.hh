#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <iostream>
#include <memory>
#include <cstdarg>

enum class LoggerLogDestination
{
    LOGGER_DEST_CONSOLE,
    LOGGER_DEST_FILE,
    LOGGER_DEST_BOTH,
};

enum class LoggerLogLevel
{
    LEVEL_DEBUG,
    LEVEL_INFO,
    LEVEL_WARNING,
    LEVEL_ERROR,
};

class Logger
{
public:
    static Logger &get_instance();
    void set_log_file(const std::string &filename);
    void set_log_destination(LoggerLogDestination destination);
    void set_log_level(LoggerLogLevel level);
    void log(LoggerLogLevel level, const char* format, va_list args);

private:
    Logger(); // Private constructor for Singleton pattern
    ~Logger();
    Logger(const Logger &) = delete;            // Delete copy constructor
    Logger &operator=(const Logger &) = delete; // Delete copy assignment operator

    std::ofstream log_file_;
    LoggerLogDestination log_destination_;
    LoggerLogLevel log_level_;
    std::string get_log_level_string(LoggerLogLevel level);
};

// Global functions for easy logging interface
void logger_set_log_file(const std::string &filename);
void logger_set_log_destination(LoggerLogDestination destination);
void logger_set_log_level(LoggerLogLevel level);
void logger_log(LoggerLogLevel level, const char* format, ...);

#endif // LOGGER_H
