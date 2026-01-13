#ifndef LOGGER_H
#define LOGGER_H

#include <windows.h>
#include <cstdio>
#include <cstdarg>

namespace MiniProxifier {

// Simple file-based logger for debugging
class Logger {
public:
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    void init(const wchar_t* logPath) {
        if (m_file) {
            fclose(m_file);
        }
        _wfopen_s(&m_file, logPath, L"a");
    }

    void log(const char* format, ...) {
        if (!m_file) return;

        // Timestamp
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(m_file, "[%02d:%02d:%02d.%03d] ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        // Message
        va_list args;
        va_start(args, format);
        vfprintf(m_file, format, args);
        va_end(args);

        fprintf(m_file, "\n");
        fflush(m_file);
    }

    ~Logger() {
        if (m_file) {
            fclose(m_file);
            m_file = nullptr;
        }
    }

private:
    Logger() : m_file(nullptr) {}
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    FILE* m_file;
};

#define LOG(fmt, ...) MiniProxifier::Logger::getInstance().log(fmt, ##__VA_ARGS__)

} // namespace MiniProxifier

#endif // LOGGER_H
