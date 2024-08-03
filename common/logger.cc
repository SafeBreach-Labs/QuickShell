#include "common/include/logger.hh"

// Initialize static member
Logger &Logger::get_instance()
{
    static Logger instance;
    return instance;
}

Logger::Logger() : log_destination_(LoggerLogDestination::LOGGER_DEST_CONSOLE), log_level_(LoggerLogLevel::LEVEL_DEBUG) {}

Logger::~Logger()
{
    if (log_file_.is_open())
    {
        log_file_.close();
    }
}

void Logger::set_log_file(const std::string &filename)
{
    if (log_file_.is_open())
    {
        log_file_.close();
    }
    log_file_.open(filename, std::ios::out | std::ios::app);
    if (!log_file_.is_open())
    {
        std::cerr << "Failed to open log file: " << filename << std::endl;
    }
}

void Logger::set_log_destination(LoggerLogDestination destination)
{
    log_destination_ = destination;
}

void Logger::set_log_level(LoggerLogLevel level)
{
    log_level_ = level;
}

std::string Logger::get_log_level_string(LoggerLogLevel level)
{
    switch (level)
    {
    case LoggerLogLevel::LEVEL_DEBUG:
        return "DEBUG";
    case LoggerLogLevel::LEVEL_INFO:
        return "INFO";
    case LoggerLogLevel::LEVEL_WARNING:
        return "WARNING";
    case LoggerLogLevel::LEVEL_ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

void Logger::log(LoggerLogLevel level, const char *format, va_list args)
{
    if (level < log_level_)
    {
        return;
    }

    std::string log_message = "[" + get_log_level_string(level) + "] ";

    // Use vfprintf to format log message with variable arguments
    char buffer[8192]; // Adjust buffer size as needed
    vsnprintf(buffer, sizeof(buffer), format, args);
    log_message += buffer;

    if (log_destination_ == LoggerLogDestination::LOGGER_DEST_CONSOLE || log_destination_ == LoggerLogDestination::LOGGER_DEST_BOTH)
    {
        std::cout << log_message << std::endl;
    }
    if (log_destination_ == LoggerLogDestination::LOGGER_DEST_FILE || log_destination_ == LoggerLogDestination::LOGGER_DEST_BOTH)
    {
        if (log_file_.is_open())
        {
            log_file_ << log_message << std::endl;
        }
        else
        {
            std::cerr << "Log file is not open. Cannot log to file." << std::endl;
        }
    }
}

// Global functions for easy logging interface
void logger_set_log_file(const std::string &filename)
{
    Logger::get_instance().set_log_file(filename);
}

void logger_set_log_destination(LoggerLogDestination destination)
{
    Logger::get_instance().set_log_destination(destination);
}

void logger_set_log_level(LoggerLogLevel level)
{
    Logger::get_instance().set_log_level(level);
}

void logger_log(LoggerLogLevel level, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    Logger::get_instance().log(level, format, args);

    va_end(args);
}
