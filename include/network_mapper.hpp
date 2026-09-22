#pragma once

#include "telemetry_model.hpp"
#include <vector>

namespace telemetry {

class NetworkMapper {
public:
    NetworkMapper() = default;

    // Collect all active TCP and UDP sockets mapped to their owning Process IDs
    std::vector<SocketNode> CollectSockets();

private:
    void CollectTcp4(std::vector<SocketNode>& sockets);
    void CollectTcp6(std::vector<SocketNode>& sockets);
    void CollectUdp4(std::vector<SocketNode>& sockets);
    void CollectUdp6(std::vector<SocketNode>& sockets);

    static std::string TcpStateToString(uint32_t state);
};

} // namespace telemetry
