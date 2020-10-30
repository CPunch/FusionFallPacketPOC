#include <iostream>
#include <stdio.h>
#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#ifdef _WIN32
// windows
    #ifndef NOMINMAX
    #define NOMINMAX
    #endif
    #define _WINSOCK_DEPRECATED_NO_WARNINGS
    #include <winsock2.h>
    #include <windows.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "Ws2_32.lib")

    typedef char buffer_t;
    #define OF_ERRNO WSAGetLastError()
    #define OF_EWOULD WSAEWOULDBLOCK
    #define SOCKETINVALID(x) (x == INVALID_SOCKET)
    #define SOCKETERROR(x) (x == SOCKET_ERROR)
#else
// posix platform
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>

    typedef int SOCKET;
    typedef void buffer_t;
    #define OF_ERRNO errno
    #define OF_EWOULD EWOULDBLOCK
    #define SOCKETINVALID(x) (x < 0)
    #define SOCKETERROR(x) (x == -1)
#endif

#include <locale>
#include <string>
#include <string.h>
#include <codecvt>

#pragma pack(push)
#pragma pack(4)
struct sP_CL2LS_REQ_LOGIN {
	char16_t szID[33];
	char16_t szPassword[33];
	int32_t iClientVerA;
	int32_t iClientVerB;
	int32_t iClientVerC;
	int32_t iLoginType;
	uint8_t szCookie_TEGid[64];
	uint8_t szCookie_authid[255];
};

struct sP_LS2CL_REP_LOGIN_FAIL {
	int32_t iErrorCode;
	char16_t szID[33];
};
#pragma pack(pop)

namespace CNSocketObfuscation {
    static constexpr const char* defaultKey = "m@rQn~W#";
    static const unsigned int keyLength = 8;

    // literally C/P from the client and converted to C++ (does some byte swapping /shrug)
    int Encrypt_byte_change_A(int ERSize, uint8_t* data, int size) {
        int num = 0;
        int num2 = 0;
        int num3 = 0;

        while (num + ERSize <= size) {
            int num4 = num + num3;
            int num5 = num + (ERSize - 1 - num3);

            uint8_t b = data[num4];
            data[num4] = data[num5];
            data[num5] = b;
            num += ERSize;
            num3++;
            if (num3 > ERSize / 2) {
                num3 = 0;
            }
        }

        num2 = ERSize - (num + ERSize - size);
        return num + num2;
    }

    int xorData(uint8_t* buffer, uint8_t* key, int size) {
        // xor every 8 bytes with 8 byte key
        for (int i = 0; i < size; i++) {
            buffer[i] ^= key[i % keyLength];
        }

        return size;
    }

    int encryptData(uint8_t* buffer, uint8_t* key, int size) {
        int eRSize = size % (keyLength / 2 + 1) * 2 + keyLength; // C/P from client
        int size2 = xorData(buffer, key, size);
        return Encrypt_byte_change_A(eRSize, buffer, size2);
    }

    int decryptData(uint8_t* buffer, uint8_t* key, int size) {
        int eRSize = size % (keyLength / 2 + 1) * 2 + keyLength; // size % of 18????
        int size2 = Encrypt_byte_change_A(eRSize, buffer, size);
        return xorData(buffer, key, size2);
    }
}

std::string U16toU8(char16_t* src) {
    try {
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> convert;
        return convert.to_bytes(src);
    } catch(const std::exception& e) {
        return "";
    }
}

void sendPacket(SOCKET sock, uint32_t id, void *buff, size_t size) {
    size_t fullSize = size + (sizeof(uint32_t) * 2); // * 2 for the size & id
    size_t bodySize = size + sizeof(uint32_t);
    uint8_t fullPacket[fullSize]; // allocate enough for the struct & the packet type id

    uint8_t *bodyPacket = fullPacket + sizeof(uint32_t); // skips the location of where the size is

    // set the first 4 bytes of our actual packet (excluding the size) to our packet type
    memcpy(bodyPacket, (void*)(&id), sizeof(uint32_t));

    // set the rest of the packet to our struct
    memcpy(bodyPacket + sizeof(uint32_t), buff, size);

    // encrypt the body
    CNSocketObfuscation::encryptData((uint8_t*)bodyPacket, (uint8_t*)CNSocketObfuscation::defaultKey, bodySize); // encrypts the body of the packet

    // finally, set the size & send to the socket
    memcpy(fullPacket, (void*)&bodySize, sizeof(uint32_t));
    write(sock, fullPacket, fullSize);
}

void readPacket(SOCKET sock, uint32_t id, void *buff) {
    switch (id) {
        case 301989889: { // sP_CL2LS_REQ_LOGIN
            sP_CL2LS_REQ_LOGIN *loginInfo = (sP_CL2LS_REQ_LOGIN*)buff;
            std::cout << "[READ] Got login request:" << std::endl
                << "Client Ver: " << loginInfo->iClientVerA << "." << loginInfo->iClientVerB << "." << loginInfo->iClientVerC << std::endl
                << "Login type: " << loginInfo->iLoginType << std::endl
                << "ID: " << U16toU8(loginInfo->szID) << std::endl
                << "Password: " << U16toU8(loginInfo->szPassword) << std::endl;

            sP_LS2CL_REP_LOGIN_FAIL fail;
            memset((void*)&fail, 0, sizeof(sP_LS2CL_REP_LOGIN_FAIL)); // zeros out the data

            fail.iErrorCode = 6; // client version outdated
            sendPacket(sock, 553648130, (void*)&fail, sizeof(sP_LS2CL_REP_LOGIN_FAIL));
            break;
        }
        default:
            std::cout << "[READ] UNKNOWN ID: " << id << std::endl;
    }
}

void receivePacket(SOCKET sock) {
    uint8_t buff[4096];

    // first thing we do is read the packet size into our tmp buffer
    int size = read(sock, (buffer_t*)buff, sizeof(uint32_t));

    // now read the packet size (this includes the type)
    uint32_t packetSize = *((uint32_t*)buff);

    // now read the rest of the packet && deobfuscate it with the default key
    // (we'll also overwrite the packetSize in the buffer but thats fine bc we already read it)
    size = read(sock, (buffer_t*)buff, packetSize);
    CNSocketObfuscation::decryptData(buff, (uint8_t*)CNSocketObfuscation::defaultKey, packetSize);

    // now read the packet ID and send the pointer to the struct would be and pass it to readPacket()
    readPacket(sock, *((uint32_t*)buff), buff + sizeof(uint32_t));
}

// most of this boilerplate I already wrote for OF so I just C/P it over lol (except these sockets are blocking just to make things simpler)
int main() {
    socklen_t addressSize;
    struct sockaddr_in address;
    uint16_t port = 8001;

    // create socket file descriptor
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (SOCKETINVALID(sock)) {
        std::cerr << "[FATAL] socket failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    // attach socket to the port
    int opt = 1;
#ifdef _WIN32
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) != 0) {
#else
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
#endif
        std::cerr << "[FATAL] setsockopt failed" << std::endl;
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    addressSize = sizeof(address);

    // Bind to the port
    if (SOCKETERROR(bind(sock, (struct sockaddr *)&address, addressSize))) {
        std::cerr << "[FATAL] bind failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (SOCKETERROR(listen(sock, SOMAXCONN))) {
        std::cerr << "[FATAL] listen failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    // listen for a new connection
    std::cout << "waiting for connection..." << std::endl;
    SOCKET newConnectionSocket = accept(sock, (struct sockaddr *)&(address), (socklen_t*)&(addressSize));
    if (SOCKETINVALID(newConnectionSocket)) {
        std::cerr << "[FATAL] socket failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    // great!!! now accept packets from this connection
    while (true) {
        std::cout << "waiting for packet..." << std::endl;
        receivePacket(newConnectionSocket);
    }

    return 0;
}