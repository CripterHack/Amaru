#include "behavior_sequence.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace amaru {
namespace detection {

// BehaviorAction implementation
BehaviorAction::BehaviorAction(ActionType type, const std::string& target, 
                           const std::unordered_map<std::string, std::string>& params)
    : m_type(type),
      m_target(target),
      m_timestamp(std::chrono::system_clock::now()),
      m_params(params),
      m_processId(0) {
}

void BehaviorAction::addParam(const std::string& name, const std::string& value) {
    m_params[name] = value;
}

void BehaviorAction::setFileOpType(FileOpType opType) {
    m_fileOpType = opType;
}

void BehaviorAction::setNetworkOpType(NetworkOpType opType) {
    m_networkOpType = opType;
}

void BehaviorAction::setRegistryOpType(RegistryOpType opType) {
    m_registryOpType = opType;
}

void BehaviorAction::setProcessOpType(ProcessOpType opType) {
    m_processOpType = opType;
}

void BehaviorAction::setMemoryOpType(MemoryOpType opType) {
    m_memoryOpType = opType;
}

void BehaviorAction::setProcessInfo(uint32_t pid, const std::string& processName, const std::string& path) {
    m_processId = pid;
    m_processName = processName;
    m_processPath = path;
}

std::string BehaviorAction::toString() const {
    std::stringstream ss;
    
    // Format timestamp
    auto timeT = std::chrono::system_clock::to_time_t(m_timestamp);
    ss << "[" << std::put_time(std::localtime(&timeT), "%Y-%m-%d %H:%M:%S") << "] ";
    
    // Process info
    ss << m_processName << " (PID: " << m_processId << ") - ";
    
    // Action type
    switch (m_type) {
        case ActionType::API_CALL:
            ss << "API Call: ";
            break;
        case ActionType::FILE_OPERATION:
            ss << "File Op: ";
            switch (m_fileOpType) {
                case FileOpType::CREATE: ss << "Create "; break;
                case FileOpType::MODIFY: ss << "Modify "; break;
                case FileOpType::DELETE: ss << "Delete "; break;
                case FileOpType::READ: ss << "Read "; break;
                case FileOpType::RENAME: ss << "Rename "; break;
                case FileOpType::COPY: ss << "Copy "; break;
                case FileOpType::CHANGE_ATTR: ss << "Change Attr "; break;
            }
            break;
        case ActionType::REGISTRY_OPERATION:
            ss << "Registry Op: ";
            switch (m_registryOpType) {
                case RegistryOpType::CREATE_KEY: ss << "Create Key "; break;
                case RegistryOpType::DELETE_KEY: ss << "Delete Key "; break;
                case RegistryOpType::SET_VALUE: ss << "Set Value "; break;
                case RegistryOpType::QUERY_VALUE: ss << "Query Value "; break;
                case RegistryOpType::ENUM_KEYS: ss << "Enum Keys "; break;
                case RegistryOpType::MODIFY_PERMISSIONS: ss << "Modify Permissions "; break;
            }
            break;
        case ActionType::NETWORK_OPERATION:
            ss << "Network Op: ";
            switch (m_networkOpType) {
                case NetworkOpType::CONNECT: ss << "Connect "; break;
                case NetworkOpType::SEND: ss << "Send "; break;
                case NetworkOpType::RECEIVE: ss << "Receive "; break;
                case NetworkOpType::DNS_QUERY: ss << "DNS Query "; break;
                case NetworkOpType::HTTP_REQUEST: ss << "HTTP Request "; break;
                case NetworkOpType::ENCRYPTED_TRAFFIC: ss << "Encrypted Traffic "; break;
            }
            break;
        case ActionType::PROCESS_OPERATION:
            ss << "Process Op: ";
            switch (m_processOpType) {
                case ProcessOpType::CREATE: ss << "Create "; break;
                case ProcessOpType::TERMINATE: ss << "Terminate "; break;
                case ProcessOpType::OPEN: ss << "Open "; break;
                case ProcessOpType::SUSPEND_RESUME: ss << "Suspend/Resume "; break;
                case ProcessOpType::MODULE_LOAD: ss << "Module Load "; break;
                case ProcessOpType::THREAD_CREATE: ss << "Thread Create "; break;
            }
            break;
        case ActionType::MEMORY_OPERATION:
            ss << "Memory Op: ";
            switch (m_memoryOpType) {
                case MemoryOpType::ALLOCATE: ss << "Allocate "; break;
                case MemoryOpType::FREE: ss << "Free "; break;
                case MemoryOpType::PROTECT: ss << "Protect "; break;
                case MemoryOpType::READ: ss << "Read "; break;
                case MemoryOpType::WRITE: ss << "Write "; break;
                case MemoryOpType::EXECUTE: ss << "Execute "; break;
            }
            break;
    }
    
    // Target
    ss << "Target: " << m_target;
    
    // Parameters
    if (!m_params.empty()) {
        ss << " Params: {";
        bool first = true;
        for (const auto& param : m_params) {
            if (!first) ss << ", ";
            ss << param.first << "=" << param.second;
            first = false;
        }
        ss << "}";
    }
    
    return ss.str();
}

// BehaviorSequence implementation
BehaviorSequence::BehaviorSequence() {
    // Generar un ID único basado en timestamp
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    
    std::stringstream ss;
    ss << "seq_" << millis;
    m_id = ss.str();
    
    m_source = "unknown";
}

void BehaviorSequence::addAction(const BehaviorAction& action) {
    m_actions.push_back(action);
}

std::vector<BehaviorAction> BehaviorSequence::filterByType(ActionType type) const {
    std::vector<BehaviorAction> result;
    
    for (const auto& action : m_actions) {
        if (action.getType() == type) {
            result.push_back(action);
        }
    }
    
    return result;
}

std::vector<BehaviorAction> BehaviorSequence::filterByProcess(uint32_t processId) const {
    std::vector<BehaviorAction> result;
    
    for (const auto& action : m_actions) {
        if (action.getProcessId() == processId) {
            result.push_back(action);
        }
    }
    
    return result;
}

std::vector<BehaviorAction> BehaviorSequence::filterByTimeRange(
    std::chrono::system_clock::time_point start,
    std::chrono::system_clock::time_point end) const {
    
    std::vector<BehaviorAction> result;
    
    for (const auto& action : m_actions) {
        auto timestamp = action.getTimestamp();
        if (timestamp >= start && timestamp <= end) {
            result.push_back(action);
        }
    }
    
    return result;
}

void BehaviorSequence::setMetadata(const std::string& key, const std::string& value) {
    m_metadata[key] = value;
}

std::string BehaviorSequence::getMetadata(const std::string& key) const {
    auto it = m_metadata.find(key);
    if (it != m_metadata.end()) {
        return it->second;
    }
    return "";
}

} // namespace detection
} // namespace amaru 