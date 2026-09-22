#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include "network_mapper.hpp"
#include <sstream>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

namespace telemetry {

std::string NetworkMapper::TcpStateToString(uint32_t state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTENING";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT_1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT_2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                       return "UNKNOWN";
    }
}

void NetworkMapper::CollectTcp4(std::vector<SocketNode>& sockets) {
    DWORD dwSize = 0;
    if (GetExtendedTcpTable(nullptr, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    std::vector<uint8_t> buffer(dwSize);
    if (GetExtendedTcpTable(buffer.data(), &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            SocketNode node;
            node.pid = row.dwOwningPid;
            node.protocol = "TCP";

            IN_ADDR localAddr;
            localAddr.S_un.S_addr = row.dwLocalAddr;
            char localIp[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &localAddr, localIp, sizeof(localIp));
            node.local_address = localIp;
            node.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));

            IN_ADDR remoteAddr;
            remoteAddr.S_un.S_addr = row.dwRemoteAddr;
            char remoteIp[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &remoteAddr, remoteIp, sizeof(remoteIp));
            node.remote_address = remoteIp;
            node.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));

            node.state = TcpStateToString(row.dwState);

            std::ostringstream oss;
            oss << "sock_tcp4_" << node.pid << "_" << node.local_address << "_" << node.local_port
                << "_" << node.remote_address << "_" << node.remote_port;
            node.id = oss.str();

            sockets.push_back(std::move(node));
        }
    }
}

void NetworkMapper::CollectTcp6(std::vector<SocketNode>& sockets) {
    DWORD dwSize = 0;
    if (GetExtendedTcpTable(nullptr, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    std::vector<uint8_t> buffer(dwSize);
    if (GetExtendedTcpTable(buffer.data(), &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            SocketNode node;
            node.pid = row.dwOwningPid;
            node.protocol = "TCP6";

            char localIp[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, const_cast<UCHAR*>(row.ucLocalAddr), localIp, sizeof(localIp));
            node.local_address = localIp;
            node.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));

            char remoteIp[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, const_cast<UCHAR*>(row.ucRemoteAddr), remoteIp, sizeof(remoteIp));
            node.remote_address = remoteIp;
            node.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));

            node.state = TcpStateToString(row.dwState);

            std::ostringstream oss;
            oss << "sock_tcp6_" << node.pid << "_" << node.local_address << "_" << node.local_port
                << "_" << node.remote_address << "_" << node.remote_port;
            node.id = oss.str();

            sockets.push_back(std::move(node));
        }
    }
}

void NetworkMapper::CollectUdp4(std::vector<SocketNode>& sockets) {
    DWORD dwSize = 0;
    if (GetExtendedUdpTable(nullptr, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    std::vector<uint8_t> buffer(dwSize);
    if (GetExtendedUdpTable(buffer.data(), &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            SocketNode node;
            node.pid = row.dwOwningPid;
            node.protocol = "UDP";

            IN_ADDR localAddr;
            localAddr.S_un.S_addr = row.dwLocalAddr;
            char localIp[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &localAddr, localIp, sizeof(localIp));
            node.local_address = localIp;
            node.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));

            node.remote_address = "*";
            node.remote_port = 0;
            node.state = "*";

            std::ostringstream oss;
            oss << "sock_udp4_" << node.pid << "_" << node.local_address << "_" << node.local_port;
            node.id = oss.str();

            sockets.push_back(std::move(node));
        }
    }
}

void NetworkMapper::CollectUdp6(std::vector<SocketNode>& sockets) {
    DWORD dwSize = 0;
    if (GetExtendedUdpTable(nullptr, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    std::vector<uint8_t> buffer(dwSize);
    if (GetExtendedUdpTable(buffer.data(), &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        auto* table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            SocketNode node;
            node.pid = row.dwOwningPid;
            node.protocol = "UDP6";

            char localIp[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, const_cast<UCHAR*>(row.ucLocalAddr), localIp, sizeof(localIp));
            node.local_address = localIp;
            node.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));

            node.remote_address = "*";
            node.remote_port = 0;
            node.state = "*";

            std::ostringstream oss;
            oss << "sock_udp6_" << node.pid << "_" << node.local_address << "_" << node.local_port;
            node.id = oss.str();

            sockets.push_back(std::move(node));
        }
    }
}

std::vector<SocketNode> NetworkMapper::CollectSockets() {
    std::vector<SocketNode> sockets;
    CollectTcp4(sockets);
    CollectTcp6(sockets);
    CollectUdp4(sockets);
    CollectUdp6(sockets);
    return sockets;
}

} // namespace telemetry
