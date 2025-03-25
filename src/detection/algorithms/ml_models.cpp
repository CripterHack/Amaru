#include "ml_models.h"
#include "../../common/logging.h"
#include "../../common/config.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <chrono>
#include <iostream>
#include <random>
#include <sstream>
#include <thread>

namespace amaru {
namespace detection {

// Implementación de modelo CNN para análisis de secuencias binarias
CNNModel::CNNModel() 
    : m_isInitialized(false), m_useGPU(false), m_modelLoaded(false) {
    LOG_INFO("Initializing CNN Model for binary sequence analysis");
}

CNNModel::~CNNModel() {
    if (m_modelLoaded) {
        unloadModel();
    }
}

bool CNNModel::loadModel(const std::string& modelPath) {
    try {
        LOG_INFO("Loading CNN model from: " + modelPath);
        
        // Check if model file exists
        std::ifstream modelFile(modelPath);
        if (!modelFile.good()) {
            LOG_ERROR("CNN model file not found: " + modelPath);
            return false;
        }
        
        // Implementation would load the model weights and architecture here
        // This is a placeholder for the actual implementation
        
        m_modelLoaded = true;
        LOG_INFO("CNN model loaded successfully");
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Failed to load CNN model: " + std::string(e.what()));
        return false;
    }
}

void CNNModel::unloadModel() {
    if (m_modelLoaded) {
        // Implementation would free resources here
        m_modelLoaded = false;
        LOG_INFO("CNN model unloaded");
    }
}

void CNNModel::enableGPU(bool enable) {
    m_useGPU = enable;
    LOG_INFO(std::string("GPU acceleration for CNN model ") + 
             (enable ? "enabled" : "disabled"));
}

float CNNModel::predict(const std::vector<uint8_t>& binaryData) {
    if (!m_modelLoaded) {
        LOG_ERROR("Cannot predict: CNN model not loaded");
        return 0.0f;
    }
    
    try {
        // Preprocess input data
        std::vector<float> features = preprocessBinary(binaryData);
        
        // Implementation would perform the actual inference here
        // This is a placeholder for the actual implementation
        float result = runInference(features);
        
        LOG_DEBUG("CNN prediction result: " + std::to_string(result));
        return result;
    }
    catch (const std::exception& e) {
        LOG_ERROR("CNN prediction failed: " + std::string(e.what()));
        return 0.0f;
    }
}

std::vector<float> CNNModel::preprocessBinary(const std::vector<uint8_t>& binaryData) {
    // Convert binary data to format suitable for CNN input
    // This implementation would resize the data to the expected input dimensions
    // and normalize values to the range expected by the model
    
    const size_t maxSize = 2 * 1024 * 1024; // 2MB maximum as per documentation
    std::vector<float> features;
    
    // Resize or truncate to expected size
    size_t processSize = std::min(binaryData.size(), maxSize);
    features.reserve(processSize);
    
    // Normalize byte values to [0,1] range
    for (size_t i = 0; i < processSize; ++i) {
        features.push_back(static_cast<float>(binaryData[i]) / 255.0f);
    }
    
    // Pad if necessary
    if (processSize < maxSize) {
        features.resize(maxSize, 0.0f);
    }
    
    return features;
}

float CNNModel::runInference(const std::vector<float>& features) {
    // Placeholder for the actual inference implementation
    // In a real implementation, this would pass the data through the CNN layers
    
    // Simulation of potential malicious patterns
    // This is just a placeholder for demonstration
    float suspiciousScore = 0.0f;
    
    // Check for patterns of high entropy regions followed by specific sequences
    // These patterns might indicate encrypted malicious payloads
    float entropy = calculateEntropy(features);
    bool hasSpecificPatterns = checkForSuspiciousPatterns(features);
    
    if (entropy > 0.8f && hasSpecificPatterns) {
        suspiciousScore = 0.95f;
    }
    else if (entropy > 0.7f) {
        suspiciousScore = 0.6f;
    }
    else if (hasSpecificPatterns) {
        suspiciousScore = 0.7f;
    }
    else {
        suspiciousScore = 0.1f;
    }
    
    return suspiciousScore;
}

float CNNModel::calculateEntropy(const std::vector<float>& data) {
    // Simplified entropy calculation
    // In a real implementation, this would be more sophisticated
    
    std::vector<int> histogram(256, 0);
    for (float value : data) {
        int bin = static_cast<int>(value * 255.0f);
        if (bin >= 0 && bin < 256) {
            histogram[bin]++;
        }
    }
    
    float entropy = 0.0f;
    for (int count : histogram) {
        if (count > 0) {
            float probability = static_cast<float>(count) / data.size();
            entropy -= probability * std::log2(probability);
        }
    }
    
    // Normalize to [0,1]
    return entropy / 8.0f;
}

bool CNNModel::checkForSuspiciousPatterns(const std::vector<float>& data) {
    // Placeholder for pattern detection
    // This would be much more sophisticated in a real implementation
    
    // Check for specific patterns that might indicate malicious code
    // For example, look for specific sequences that often appear in shellcode
    
    // Simplified pattern check for demonstration
    for (size_t i = 0; i < data.size() - 10; ++i) {
        // Example pattern: sequence of bytes often used in shellcode
        if (data[i] > 0.5f && data[i+1] < 0.2f && data[i+2] > 0.8f) {
            return true;
        }
    }
    
    return false;
}

// Implementación de TransformerModel para secuencias de comportamiento
TransformerModel::TransformerModel() 
    : m_modelLoaded(false) {
    LOG_INFO("Initializing Transformer Model for behavior sequence analysis");
}

TransformerModel::~TransformerModel() {
    if (m_modelLoaded) {
        unloadModel();
    }
}

bool TransformerModel::loadModel(const std::string& modelPath) {
    try {
        LOG_INFO("Loading Transformer model from: " + modelPath);
        
        // Check if model file exists
        std::ifstream modelFile(modelPath);
        if (!modelFile.good()) {
            LOG_ERROR("Transformer model file not found: " + modelPath);
            return false;
        }
        
        // Implementation would load the model weights and architecture here
        
        m_modelLoaded = true;
        LOG_INFO("Transformer model loaded successfully");
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Failed to load Transformer model: " + std::string(e.what()));
        return false;
    }
}

void TransformerModel::unloadModel() {
    if (m_modelLoaded) {
        // Implementation would free resources here
        m_modelLoaded = false;
        LOG_INFO("Transformer model unloaded");
    }
}

float TransformerModel::analyzeBehaviorSequence(const BehaviorSequence& sequence) {
    if (!m_modelLoaded) {
        LOG_ERROR("Cannot analyze: Transformer model not loaded");
        return 0.0f;
    }
    
    try {
        // Convert behavior sequence to token IDs for transformer model
        std::vector<int> tokenIds = tokenizeBehavior(sequence);
        
        // Run inference
        float maliciousScore = processSequence(tokenIds);
        
        LOG_DEBUG("Transformer behavior analysis result: " + 
                  std::to_string(maliciousScore));
        
        return maliciousScore;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Transformer analysis failed: " + std::string(e.what()));
        return 0.0f;
    }
}

std::vector<int> TransformerModel::tokenizeBehavior(const BehaviorSequence& sequence) {
    // Convert behavior actions to token IDs for transformer model
    std::vector<int> tokens;
    tokens.reserve(sequence.actions.size());
    
    // In a real implementation, this would map API calls, file operations,
    // registry access, etc. to token IDs using a vocabulary
    
    for (const auto& action : sequence.actions) {
        // Simplified tokenization for demonstration
        // Different action types would have different token ranges
        
        if (action.type == BehaviorActionType::API_CALL) {
            // API calls would map to specific token IDs based on a vocabulary
            int tokenId = getApiTokenId(action.details);
            tokens.push_back(tokenId);
        }
        else if (action.type == BehaviorActionType::FILE_OPERATION) {
            int tokenId = getFileOpTokenId(action.details);
            tokens.push_back(tokenId);
        }
        else if (action.type == BehaviorActionType::REGISTRY_ACCESS) {
            int tokenId = getRegistryTokenId(action.details);
            tokens.push_back(tokenId);
        }
        else if (action.type == BehaviorActionType::NETWORK_ACTIVITY) {
            int tokenId = getNetworkTokenId(action.details);
            tokens.push_back(tokenId);
        }
        else {
            // Unknown action type gets a special token
            tokens.push_back(0);
        }
    }
    
    return tokens;
}

int TransformerModel::getApiTokenId(const std::string& apiDetails) {
    // Simplified mapping of API calls to token IDs
    // In a real implementation, this would use a proper vocabulary
    
    if (apiDetails.find("CreateFile") != std::string::npos) return 100;
    if (apiDetails.find("WriteFile") != std::string::npos) return 101;
    if (apiDetails.find("ReadFile") != std::string::npos) return 102;
    if (apiDetails.find("CreateProcess") != std::string::npos) return 103;
    if (apiDetails.find("VirtualAlloc") != std::string::npos) return 104;
    if (apiDetails.find("VirtualProtect") != std::string::npos) return 105;
    if (apiDetails.find("LoadLibrary") != std::string::npos) return 106;
    if (apiDetails.find("GetProcAddress") != std::string::npos) return 107;
    if (apiDetails.find("WSASocket") != std::string::npos) return 108;
    if (apiDetails.find("connect") != std::string::npos) return 109;
    if (apiDetails.find("CryptAcquireContext") != std::string::npos) return 110;
    if (apiDetails.find("CryptEncrypt") != std::string::npos) return 111;
    
    // Default token for unknown API
    return 199;
}

int TransformerModel::getFileOpTokenId(const std::string& fileDetails) {
    // Map file operations to token IDs
    if (fileDetails.find("create:") != std::string::npos) return 200;
    if (fileDetails.find("write:") != std::string::npos) return 201;
    if (fileDetails.find("read:") != std::string::npos) return 202;
    if (fileDetails.find("delete:") != std::string::npos) return 203;
    if (fileDetails.find("modify:") != std::string::npos) return 204;
    
    // Check for suspicious file extensions
    if (fileDetails.find(".exe") != std::string::npos) return 210;
    if (fileDetails.find(".dll") != std::string::npos) return 211;
    if (fileDetails.find(".sys") != std::string::npos) return 212;
    if (fileDetails.find(".bat") != std::string::npos) return 213;
    if (fileDetails.find(".ps1") != std::string::npos) return 214;
    
    // Default token for unknown file operation
    return 299;
}

int TransformerModel::getRegistryTokenId(const std::string& regDetails) {
    // Map registry operations to token IDs
    if (regDetails.find("read:") != std::string::npos) return 300;
    if (regDetails.find("write:") != std::string::npos) return 301;
    if (regDetails.find("delete:") != std::string::npos) return 302;
    if (regDetails.find("create:") != std::string::npos) return 303;
    
    // Check for suspicious registry locations
    if (regDetails.find("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos) return 310;
    if (regDetails.find("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos) return 311;
    if (regDetails.find("HKLM\\SYSTEM\\CurrentControlSet\\Services") != std::string::npos) return 312;
    
    // Default token for unknown registry operation
    return 399;
}

int TransformerModel::getNetworkTokenId(const std::string& netDetails) {
    // Map network operations to token IDs
    if (netDetails.find("connect:") != std::string::npos) return 400;
    if (netDetails.find("send:") != std::string::npos) return 401;
    if (netDetails.find("receive:") != std::string::npos) return 402;
    if (netDetails.find("dns:") != std::string::npos) return 403;
    if (netDetails.find("http:") != std::string::npos) return 404;
    if (netDetails.find("https:") != std::string::npos) return 405;
    if (netDetails.find("ftp:") != std::string::npos) return 406;
    
    // Default token for unknown network operation
    return 499;
}

float TransformerModel::processSequence(const std::vector<int>& tokenIds) {
    // Placeholder for actual transformer inference
    // In a real implementation, this would run the tokenized sequence through
    // the transformer model architecture with attention mechanisms
    
    // Example simplified logic to detect suspicious behavior patterns
    float suspiciousScore = 0.0f;
    
    // Check for patterns related to different types of malware behavior
    
    // Pattern 1: Process injection sequence
    bool hasProcessInjection = detectProcessInjection(tokenIds);
    
    // Pattern 2: Ransomware-like behavior
    bool hasRansomwareBehavior = detectRansomware(tokenIds);
    
    // Pattern 3: Data exfiltration behavior
    bool hasDataExfiltration = detectDataExfiltration(tokenIds);
    
    // Pattern 4: Persistence establishment
    bool hasPersistence = detectPersistence(tokenIds);
    
    // Combine detections to calculate final score
    if (hasProcessInjection) suspiciousScore += 0.3f;
    if (hasRansomwareBehavior) suspiciousScore += 0.4f;
    if (hasDataExfiltration) suspiciousScore += 0.25f;
    if (hasPersistence) suspiciousScore += 0.2f;
    
    // Cap at 1.0
    return std::min(suspiciousScore, 1.0f);
}

bool TransformerModel::detectProcessInjection(const std::vector<int>& tokens) {
    // Check for sequence patterns indicating process injection
    // This is a simplified demonstration
    
    // Look for VirtualAlloc/VirtualProtect followed by WriteProcessMemory
    // or CreateRemoteThread
    for (size_t i = 0; i < tokens.size() - 1; ++i) {
        if ((tokens[i] == 104 || tokens[i] == 105) && // VirtualAlloc or VirtualProtect
            (tokens[i+1] == 120 || tokens[i+1] == 121)) { // WriteProcessMemory or CreateRemoteThread (not defined above)
            return true;
        }
    }
    
    return false;
}

bool TransformerModel::detectRansomware(const std::vector<int>& tokens) {
    // Check for ransomware behavior patterns
    
    // Look for crypto API usage followed by numerous file writes with extension changes
    bool hasCryptoAPI = false;
    int fileModCount = 0;
    
    for (int token : tokens) {
        if (token == 110 || token == 111) { // CryptAcquireContext or CryptEncrypt
            hasCryptoAPI = true;
        }
        
        if (token == 201 || token == 204) { // File write or modify
            fileModCount++;
        }
    }
    
    // If we see crypto API usage and many file modifications, suspect ransomware
    return hasCryptoAPI && fileModCount > 10;
}

bool TransformerModel::detectDataExfiltration(const std::vector<int>& tokens) {
    // Check for data exfiltration patterns
    
    // Look for file reads followed by network activity
    bool hasFileReads = false;
    bool hasNetworkSend = false;
    
    for (int token : tokens) {
        if (token == 202) { // File read
            hasFileReads = true;
        }
        
        if (token == 401) { // Network send
            hasNetworkSend = true;
        }
    }
    
    // If we see file reads followed by network sends, suspect data exfiltration
    return hasFileReads && hasNetworkSend;
}

bool TransformerModel::detectPersistence(const std::vector<int>& tokens) {
    // Check for persistence establishment patterns
    
    // Look for registry writes to run keys or service creation
    for (int token : tokens) {
        if (token == 310 || token == 311 || token == 312) { // Registry writes to autorun locations
            return true;
        }
    }
    
    return false;
}

// Implementación de AnomalyDetectionModel para detección de comportamientos anómalos
AnomalyDetectionModel::AnomalyDetectionModel() 
    : m_isInitialized(false), m_modelLoaded(false) {
    LOG_INFO("Initializing Anomaly Detection Model");
}

AnomalyDetectionModel::~AnomalyDetectionModel() {
    if (m_modelLoaded) {
        unloadModel();
    }
}

bool AnomalyDetectionModel::initialize(const ModelConfig& config) {
    try {
        m_config = config;
        LOG_INFO("Initializing Anomaly Detection with threshold: " + 
                 std::to_string(m_config.anomalyThreshold));
        
        // Initialize internal state
        m_normalBehaviorProfiles.clear();
        
        // Load normal behavior profiles if specified
        if (!m_config.normalProfilesPath.empty()) {
            if (!loadNormalProfiles(m_config.normalProfilesPath)) {
                LOG_WARN("Failed to load normal profiles, starting with empty profile set");
            }
        }
        
        m_isInitialized = true;
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Failed to initialize Anomaly Detection: " + std::string(e.what()));
        return false;
    }
}

bool AnomalyDetectionModel::loadModel(const std::string& modelPath) {
    try {
        LOG_INFO("Loading Anomaly Detection model from: " + modelPath);
        
        // Check if model file exists
        std::ifstream modelFile(modelPath);
        if (!modelFile.good()) {
            LOG_ERROR("Anomaly Detection model file not found: " + modelPath);
            return false;
        }
        
        // Implementation would load model parameters here
        
        m_modelLoaded = true;
        LOG_INFO("Anomaly Detection model loaded successfully");
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Failed to load Anomaly Detection model: " + std::string(e.what()));
        return false;
    }
}

void AnomalyDetectionModel::unloadModel() {
    if (m_modelLoaded) {
        // Free resources
        m_modelLoaded = false;
        LOG_INFO("Anomaly Detection model unloaded");
    }
}

bool AnomalyDetectionModel::loadNormalProfiles(const std::string& profilesPath) {
    try {
        LOG_INFO("Loading normal behavior profiles from: " + profilesPath);
        
        // Check if profiles file exists
        std::ifstream profilesFile(profilesPath);
        if (!profilesFile.good()) {
            LOG_ERROR("Normal profiles file not found: " + profilesPath);
            return false;
        }
        
        // Implementation would load normal behavior profiles here
        // For example, each profile could be a set of feature distributions
        // representing normal behavior for different types of applications
        
        LOG_INFO("Normal behavior profiles loaded successfully");
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Failed to load normal profiles: " + std::string(e.what()));
        return false;
    }
}

AnomalyDetectionResult AnomalyDetectionModel::detectAnomalies(const BehaviorSequence& sequence) {
    if (!m_isInitialized || !m_modelLoaded) {
        LOG_ERROR("Cannot detect anomalies: model not initialized or loaded");
        return {0.0f, {}};
    }
    
    try {
        // Extract features from the behavior sequence
        FeatureVector features = extractFeatures(sequence);
        
        // Calculate anomaly score
        float anomalyScore = calculateAnomalyScore(features);
        
        // Identify specific anomalies if score is above threshold
        std::vector<Anomaly> anomalies;
        if (anomalyScore > m_config.anomalyThreshold) {
            anomalies = identifyAnomalies(features);
        }
        
        LOG_DEBUG("Anomaly detection result: " + std::to_string(anomalyScore) + 
                  " with " + std::to_string(anomalies.size()) + " specific anomalies");
        
        return {anomalyScore, anomalies};
    }
    catch (const std::exception& e) {
        LOG_ERROR("Anomaly detection failed: " + std::string(e.what()));
        return {0.0f, {}};
    }
}

AnomalyDetectionModel::FeatureVector AnomalyDetectionModel::extractFeatures(const BehaviorSequence& sequence) {
    // Extract numerical features from behavior sequence for anomaly detection
    FeatureVector features;
    
    // Initialize feature categories
    features["file_ops"] = 0;
    features["registry_ops"] = 0;
    features["network_ops"] = 0;
    features["process_ops"] = 0;
    features["memory_ops"] = 0;
    features["crypto_ops"] = 0;
    features["api_diversity"] = 0;
    
    // Count different types of operations
    std::set<std::string> uniqueApis;
    
    for (const auto& action : sequence.actions) {
        if (action.type == BehaviorActionType::API_CALL) {
            uniqueApis.insert(action.details);
            
            if (action.details.find("File") != std::string::npos ||
                action.details.find("Directory") != std::string::npos) {
                features["file_ops"]++;
            }
            else if (action.details.find("Reg") != std::string::npos) {
                features["registry_ops"]++;
            }
            else if (action.details.find("Socket") != std::string::npos ||
                     action.details.find("connect") != std::string::npos ||
                     action.details.find("send") != std::string::npos ||
                     action.details.find("recv") != std::string::npos) {
                features["network_ops"]++;
            }
            else if (action.details.find("Process") != std::string::npos ||
                     action.details.find("Thread") != std::string::npos) {
                features["process_ops"]++;
            }
            else if (action.details.find("Virtual") != std::string::npos ||
                     action.details.find("Heap") != std::string::npos ||
                     action.details.find("Memory") != std::string::npos) {
                features["memory_ops"]++;
            }
            else if (action.details.find("Crypt") != std::string::npos ||
                     action.details.find("Hash") != std::string::npos ||
                     action.details.find("Encrypt") != std::string::npos ||
                     action.details.find("Decrypt") != std::string::npos) {
                features["crypto_ops"]++;
            }
        }
    }
    
    // Calculate API diversity
    features["api_diversity"] = static_cast<float>(uniqueApis.size());
    
    // Calculate derived features
    if (sequence.actions.size() > 0) {
        features["file_ops_rate"] = features["file_ops"] / sequence.actions.size();
        features["registry_ops_rate"] = features["registry_ops"] / sequence.actions.size();
        features["network_ops_rate"] = features["network_ops"] / sequence.actions.size();
        features["process_ops_rate"] = features["process_ops"] / sequence.actions.size();
        features["memory_ops_rate"] = features["memory_ops"] / sequence.actions.size();
        features["crypto_ops_rate"] = features["crypto_ops"] / sequence.actions.size();
    }
    
    return features;
}

float AnomalyDetectionModel::calculateAnomalyScore(const FeatureVector& features) {
    // Calculate anomaly score using isolation forest or similar algorithm
    // This is a simplified implementation for demonstration
    
    float anomalyScore = 0.0f;
    
    // Check for anomalies in feature distributions compared to normal profiles
    // Higher scores indicate more anomalous behavior
    
    // Example: Check if operation rates are outside expected ranges
    if (features.find("file_ops_rate") != features.end()) {
        float fileRate = features.at("file_ops_rate");
        if (fileRate > 0.5f) { // Unusually high file operation rate
            anomalyScore += 0.2f;
        }
    }
    
    if (features.find("network_ops_rate") != features.end() && 
        features.find("file_ops_rate") != features.end()) {
        float netRate = features.at("network_ops_rate");
        float fileRate = features.at("file_ops_rate");
        
        // High network activity following high file activity could indicate data exfiltration
        if (netRate > 0.3f && fileRate > 0.3f) {
            anomalyScore += 0.3f;
        }
    }
    
    if (features.find("crypto_ops_rate") != features.end() && 
        features.find("file_ops_rate") != features.end()) {
        float cryptoRate = features.at("crypto_ops_rate");
        float fileRate = features.at("file_ops_rate");
        
        // High crypto activity with high file activity could indicate ransomware
        if (cryptoRate > 0.1f && fileRate > 0.4f) {
            anomalyScore += 0.4f;
        }
    }
    
    if (features.find("memory_ops_rate") != features.end() && 
        features.find("process_ops_rate") != features.end()) {
        float memRate = features.at("memory_ops_rate");
        float procRate = features.at("process_ops_rate");
        
        // High memory operations with process operations could indicate injection
        if (memRate > 0.2f && procRate > 0.1f) {
            anomalyScore += 0.3f;
        }
    }
    
    // Cap at 1.0
    return std::min(anomalyScore, 1.0f);
}

std::vector<AnomalyDetectionModel::Anomaly> AnomalyDetectionModel::identifyAnomalies(const FeatureVector& features) {
    // Identify specific anomalies in the behavior
    std::vector<Anomaly> anomalies;
    
    // Check for specific anomalous patterns based on features
    
    if (features.find("file_ops_rate") != features.end() && features.at("file_ops_rate") > 0.5f) {
        anomalies.push_back({
            "high_file_activity",
            "Unusually high rate of file operations",
            features.at("file_ops_rate")
        });
    }
    
    if (features.find("network_ops_rate") != features.end() && features.at("network_ops_rate") > 0.3f) {
        anomalies.push_back({
            "high_network_activity",
            "Unusually high rate of network operations",
            features.at("network_ops_rate")
        });
    }
    
    if (features.find("crypto_ops_rate") != features.end() && 
        features.find("file_ops_rate") != features.end() && 
        features.at("crypto_ops_rate") > 0.1f && 
        features.at("file_ops_rate") > 0.4f) {
        
        anomalies.push_back({
            "crypto_file_activity",
            "Suspicious combination of cryptographic and file operations",
            features.at("crypto_ops_rate") * features.at("file_ops_rate")
        });
    }
    
    if (features.find("memory_ops_rate") != features.end() && 
        features.find("process_ops_rate") != features.end() && 
        features.at("memory_ops_rate") > 0.2f && 
        features.at("process_ops_rate") > 0.1f) {
        
        anomalies.push_back({
            "memory_process_manipulation",
            "Suspicious memory and process manipulation",
            features.at("memory_ops_rate") * features.at("process_ops_rate")
        });
    }
    
    return anomalies;
}

} // namespace detection
} // namespace amaru 