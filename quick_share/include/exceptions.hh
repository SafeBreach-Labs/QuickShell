#ifndef QUICK_SHARE_INCLUDE_EXCEPTIONS
#define QUICK_SHARE_INCLUDE_EXCEPTIONS

#include <cstdlib>
#include <exception>


class BaseException : public std::exception {
    private:
        const char *message;
    public:
        BaseException(const char *msg) : std::exception(), message(msg) {}
        const char *what() { return message; }
};

#define CREATE_EXCEPTION_CLASS(ClassName) \
class ClassName : public BaseException { \
public: \
    ClassName(const char *msg) : BaseException(msg) {} \
}

CREATE_EXCEPTION_CLASS(SocketException);
CREATE_EXCEPTION_CLASS(InvalidParameterException);
CREATE_EXCEPTION_CLASS(MemoryException);
CREATE_EXCEPTION_CLASS(WsaException);
CREATE_EXCEPTION_CLASS(Ukey2Exception);
CREATE_EXCEPTION_CLASS(IOException);
CREATE_EXCEPTION_CLASS(HotspotException);
CREATE_EXCEPTION_CLASS(TimeoutException);

#endif /* QUICK_SHARE_INCLUDE_EXCEPTIONS */
