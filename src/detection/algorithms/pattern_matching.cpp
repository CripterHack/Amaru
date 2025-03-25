#include "pattern_matching.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_set>
#include <chrono>
#include "../../common/logging.h"

namespace amaru {
namespace detection {

// Implementación de la clase base MalwarePattern
MalwarePattern::MalwarePattern(const std::string& id, PatternType type, 
                               const std::string& detectionName, PatternSeverity severity,
                               float confidenceThreshold)
    : m_id(id), 
      m_type(type), 
      m_detectionName(detectionName), 
      m_severity(severity), 
      m_confidenceThreshold(confidenceThreshold) {
}

// Implementación de BinaryPattern
BinaryPattern::BinaryPattern(const std::string& id, const std::string& detectionName,
                             PatternSeverity severity, float confidenceThreshold)
    : MalwarePattern(id, PatternType::BINARY_SEQUENCE, detectionName, severity, confidenceThreshold),
      m_logicalCondition(LogicalCondition::ALL) {
}

void BinaryPattern::addSequence(const Sequence& sequence) {
    m_sequences.push_back(sequence);
}

void BinaryPattern::setLogicalCondition(LogicalCondition condition) {
    m_logicalCondition = condition;
}

void BinaryPattern::setCustomLogicalExpression(const std::string& expression) {
    m_logicalCondition = LogicalCondition::CUSTOM;
    m_customLogicalExpression = expression;
}

std::string BinaryPattern::toJson() const {
    // Implementación pendiente - sería necesario incluir una biblioteca JSON
    // como nlohmann/json para una implementación completa
    std::stringstream ss;
    ss << "{\"id\":\"" << m_id << "\",\"type\":\"binary\",\"detection_name\":\"" 
       << m_detectionName << "\",\"severity\":" << static_cast<int>(m_severity) 
       << ",\"confidence_threshold\":" << m_confidenceThreshold << "}";
    return ss.str();
}

// Implementación de BehaviorPattern
BehaviorPattern::BehaviorPattern(const std::string& id, const std::string& detectionName,
                                 PatternSeverity severity, float confidenceThreshold)
    : MalwarePattern(id, PatternType::BEHAVIOR_PATTERN, detectionName, severity, confidenceThreshold),
      m_logicalCondition("ALL") {
}

void BehaviorPattern::addBehavior(const Behavior& behavior) {
    m_behaviors.push_back(behavior);
}

void BehaviorPattern::setLogicalCondition(const std::string& condition) {
    m_logicalCondition = condition;
}

std::string BehaviorPattern::toJson() const {
    // Implementación pendiente - sería necesario incluir una biblioteca JSON
    std::stringstream ss;
    ss << "{\"id\":\"" << m_id << "\",\"type\":\"behavior\",\"detection_name\":\"" 
       << m_detectionName << "\",\"severity\":" << static_cast<int>(m_severity) 
       << ",\"confidence_threshold\":" << m_confidenceThreshold << "}";
    return ss.str();
}

// Implementación de NetworkPattern
NetworkPattern::NetworkPattern(const std::string& id, const std::string& detectionName,
                               PatternSeverity severity, float confidenceThreshold)
    : MalwarePattern(id, PatternType::NETWORK_PATTERN, detectionName, severity, confidenceThreshold),
      m_logicalCondition("ANY") {
}

void NetworkPattern::addIndicator(const Indicator& indicator) {
    m_indicators.push_back(indicator);
}

void NetworkPattern::setLogicalCondition(const std::string& condition) {
    m_logicalCondition = condition;
}

std::string NetworkPattern::toJson() const {
    // Implementación pendiente - sería necesario incluir una biblioteca JSON
    std::stringstream ss;
    ss << "{\"id\":\"" << m_id << "\",\"type\":\"network\",\"detection_name\":\"" 
       << m_detectionName << "\",\"severity\":" << static_cast<int>(m_severity) 
       << ",\"confidence_threshold\":" << m_confidenceThreshold << "}";
    return ss.str();
}

// Clases de implementación para algoritmos optimizados

// Implementación simple de Aho-Corasick para búsqueda de múltiples patrones
class PatternMatchingSystem::AhoCorasickImpl {
private:
    struct Node {
        std::unordered_map<char, std::shared_ptr<Node>> children;
        std::vector<int> patternIds;
        std::shared_ptr<Node> failLink;
        
        Node() : failLink(nullptr) {}
    };
    
    std::shared_ptr<Node> m_root;
    std::vector<std::string> m_patterns;
    
public:
    AhoCorasickImpl() : m_root(std::make_shared<Node>()) {}
    
    void addPattern(int patternId, const std::string& pattern) {
        std::shared_ptr<Node> current = m_root;
        
        for (char c : pattern) {
            if (current->children.find(c) == current->children.end()) {
                current->children[c] = std::make_shared<Node>();
            }
            current = current->children[c];
        }
        
        current->patternIds.push_back(patternId);
        m_patterns.push_back(pattern);
    }
    
    void buildFailLinks() {
        std::queue<std::shared_ptr<Node>> q;
        
        // Nivel 1: enlaces de fallo al nodo raíz
        for (auto& pair : m_root->children) {
            pair.second->failLink = m_root;
            q.push(pair.second);
        }
        
        // Construir enlaces de fallo para niveles más profundos
        while (!q.empty()) {
            auto current = q.front();
            q.pop();
            
            for (auto& pair : current->children) {
                char c = pair.first;
                auto child = pair.second;
                q.push(child);
                
                auto failLink = current->failLink;
                while (failLink != nullptr && 
                      failLink->children.find(c) == failLink->children.end()) {
                    failLink = failLink->failLink;
                }
                
                if (failLink == nullptr) {
                    child->failLink = m_root;
                } else {
                    child->failLink = failLink->children[c];
                    // Copiar patternIds del enlace de fallo
                    for (int id : child->failLink->patternIds) {
                        child->patternIds.push_back(id);
                    }
                }
            }
        }
    }
    
    std::vector<std::pair<int, size_t>> search(const std::string& text) {
        std::vector<std::pair<int, size_t>> matches;
        auto current = m_root;
        
        for (size_t i = 0; i < text.size(); ++i) {
            char c = text[i];
            
            // Seguir enlaces de fallo hasta encontrar un nodo con transición para c
            while (current != m_root && 
                  current->children.find(c) == current->children.end()) {
                current = current->failLink;
            }
            
            // Comprobar si hay una transición para c
            if (current->children.find(c) != current->children.end()) {
                current = current->children[c];
                
                // Registrar todas las coincidencias en este nodo
                for (int patternId : current->patternIds) {
                    matches.push_back({patternId, i - m_patterns[patternId].size() + 1});
                }
            }
        }
        
        return matches;
    }
};

// Implementación simple de un Filtro de Bloom para pre-filtrado rápido
class PatternMatchingSystem::BloomFilterImpl {
private:
    std::vector<bool> m_bits;
    size_t m_numHashes;
    size_t m_size;
    
    // Funciones hash simples para demostración
    size_t hash1(const std::string& s) const {
        size_t h = 0;
        for (char c : s) {
            h = h * 31 + c;
        }
        return h % m_size;
    }
    
    size_t hash2(const std::string& s) const {
        size_t h = 0;
        for (char c : s) {
            h = (h * 37) ^ c;
        }
        return h % m_size;
    }
    
    size_t hash3(const std::string& s) const {
        size_t h = 0;
        for (size_t i = 0; i < s.size(); ++i) {
            h = (h * 41) + s[i] * (i + 1);
        }
        return h % m_size;
    }
    
public:
    BloomFilterImpl(size_t size = 1000000, size_t numHashes = 3) 
        : m_bits(size, false), m_numHashes(numHashes), m_size(size) {}
    
    void add(const std::string& s) {
        m_bits[hash1(s)] = true;
        m_bits[hash2(s)] = true;
        m_bits[hash3(s)] = true;
    }
    
    bool mightContain(const std::string& s) const {
        if (!m_bits[hash1(s)]) return false;
        if (!m_bits[hash2(s)]) return false;
        if (!m_bits[hash3(s)]) return false;
        return true;
    }
};

// -------------------- PatternMatchingSystem implementation --------------------

PatternMatchingSystem::PatternMatchingSystem() 
    : m_ahoCorasick(std::make_unique<AhoCorasickImpl>()),
      m_bloomFilter(std::make_unique<BloomFilterImpl>()),
      m_initialized(false) {
}

PatternMatchingSystem::~PatternMatchingSystem() = default;

bool PatternMatchingSystem::initialize() {
    try {
        buildAhoCorasickMachine();
        createBloomFilter();
        m_initialized = true;
        return true;
    } catch (const std::exception& e) {
        // Ideal: logging
        std::cerr << "Error initializing pattern matching system: " << e.what() << std::endl;
        m_initialized = false;
        return false;
    }
}

void PatternMatchingSystem::buildAhoCorasickMachine() {
    // Reconstruir la máquina Aho-Corasick con todos los patrones binarios
    m_ahoCorasick = std::make_unique<AhoCorasickImpl>();
    
    int patternId = 0;
    for (const auto& pattern : m_binaryPatterns) {
        for (const auto& seq : pattern->getSequences()) {
            m_ahoCorasick->addPattern(patternId++, seq.sequence);
        }
    }
    
    m_ahoCorasick->buildFailLinks();
}

void PatternMatchingSystem::createBloomFilter() {
    // Crear un nuevo filtro de Bloom para pre-filtrado rápido
    m_bloomFilter = std::make_unique<BloomFilterImpl>();
    
    for (const auto& pattern : m_binaryPatterns) {
        for (const auto& seq : pattern->getSequences()) {
            m_bloomFilter->add(seq.sequence);
        }
    }
}

int PatternMatchingSystem::loadPatterns(const std::string& patternsFilePath) {
    // Esta implementación es un esqueleto. En una implementación real,
    // cargaríamos patrones desde un formato JSON o similar.
    try {
        std::ifstream file(patternsFilePath);
        if (!file.is_open()) {
            std::cerr << "Failed to open patterns file: " << patternsFilePath << std::endl;
            return 0;
        }
        
        // Ejemplo: leer y procesar cada línea como un patrón
        std::string line;
        int patternCount = 0;
        
        while (std::getline(file, line)) {
            // Procesar línea como un patrón (simplificado)
            // En la realidad, utilizaríamos un parser JSON para esto
            if (line.empty() || line[0] == '#') continue; // Comentario o línea vacía
            
            // Ejemplo muy simplificado:
            size_t typePos = line.find("type=");
            if (typePos == std::string::npos) continue;
            
            std::string typeStr = line.substr(typePos + 5, 10);
            if (typeStr.find("binary") != std::string::npos) {
                // Crear un patrón binario
                auto pattern = std::make_shared<BinaryPattern>(
                    "pattern_" + std::to_string(patternCount),
                    "Example Detection " + std::to_string(patternCount),
                    PatternSeverity::MEDIUM,
                    0.7f
                );
                
                // Añadir secuencias
                BinaryPattern::Sequence seq;
                seq.offset = "variable";
                seq.sequence = "example_sequence";
                seq.weight = 1.0f;
                pattern->addSequence(seq);
                
                if (addPattern(pattern)) {
                    patternCount++;
                }
            }
            else if (typeStr.find("behavior") != std::string::npos) {
                // Crear un patrón de comportamiento
                auto pattern = std::make_shared<BehaviorPattern>(
                    "behavior_" + std::to_string(patternCount),
                    "Behavior Detection " + std::to_string(patternCount),
                    PatternSeverity::HIGH,
                    0.8f
                );
                
                // Añadir comportamientos
                BehaviorPattern::Behavior behavior;
                behavior.weight = 1.0f;
                
                BehaviorPattern::ApiSequence apiSeq;
                apiSeq.api = "CreateFile";
                apiSeq.params["path"] = "*.exe";
                apiSeq.repeat_min = 1;
                behavior.api_sequence.push_back(apiSeq);
                
                pattern->addBehavior(behavior);
                
                if (addPattern(pattern)) {
                    patternCount++;
                }
            }
        }
        
        if (patternCount > 0) {
            // Reconstruir estructuras optimizadas
            buildAhoCorasickMachine();
            createBloomFilter();
        }
        
        return patternCount;
    }
    catch (const std::exception& e) {
        std::cerr << "Error loading patterns: " << e.what() << std::endl;
        return 0;
    }
}

bool PatternMatchingSystem::addPattern(std::shared_ptr<MalwarePattern> pattern) {
    if (!pattern) return false;
    
    bool added = true;
    switch (pattern->getType()) {
        case PatternType::BINARY_SEQUENCE:
            m_binaryPatterns.push_back(std::static_pointer_cast<BinaryPattern>(pattern));
            break;
        case PatternType::BEHAVIOR_PATTERN:
            m_behaviorPatterns.push_back(std::static_pointer_cast<BehaviorPattern>(pattern));
            break;
        case PatternType::NETWORK_PATTERN:
            m_networkPatterns.push_back(std::static_pointer_cast<NetworkPattern>(pattern));
            break;
        default:
            added = false;
            break;
    }
    
    return added;
}

int PatternMatchingSystem::matchBinary(const std::vector<uint8_t>& data, std::vector<PatternMatch>& matches) {
    if (!m_initialized || data.empty()) return 0;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    int matchCount = 0;
    
    // Convertir vector de bytes a string para buscar (simplificado)
    std::string dataStr(data.begin(), data.end());
    
    // Para cada patrón binario, comprobar coincidencias
    for (const auto& pattern : m_binaryPatterns) {
        float confidence = 0.0f;
        if (matchBinaryPattern(pattern, data, confidence)) {
            PatternMatch match;
            match.patternId = pattern->getId();
            match.detectionName = pattern->getDetectionName();
            match.severity = pattern->getSeverity();
            match.confidence = confidence;
            match.details = "Binary pattern match";
            
            matches.push_back(match);
            matchCount++;
        }
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    // Ideal: logging
    std::cout << "Binary matching completed in " << duration << "ms. Found " 
              << matchCount << " matches." << std::endl;
    
    return matchCount;
}

bool PatternMatchingSystem::matchBinaryPattern(const std::shared_ptr<BinaryPattern>& pattern,
                                              const std::vector<uint8_t>& data,
                                              float& confidence) {
    if (!pattern || data.empty()) return false;
    
    std::vector<bool> sequenceMatches(pattern->getSequences().size(), false);
    std::vector<float> sequenceConfidences(pattern->getSequences().size(), 0.0f);
    
    // Convertir a string para búsqueda de subpatrones
    std::string dataStr(data.begin(), data.end());
    
    // Comprobar cada secuencia del patrón
    for (size_t i = 0; i < pattern->getSequences().size(); ++i) {
        const auto& sequence = pattern->getSequences()[i];
        
        // Comprobar si el filtro de Bloom indica que puede contener la secuencia
        if (!m_bloomFilter->mightContain(sequence.sequence)) {
            continue;
        }
        
        // Búsqueda exacta (podría ser más compleja con wildcards, etc.)
        size_t pos = dataStr.find(sequence.sequence);
        if (pos != std::string::npos) {
            sequenceMatches[i] = true;
            sequenceConfidences[i] = 1.0f * sequence.weight;
        }
    }
    
    // Determinar coincidencia según condición lógica
    bool isMatch = false;
    confidence = 0.0f;
    
    switch (pattern->getLogicalCondition()) {
        case BinaryPattern::LogicalCondition::ANY: {
            // Al menos una secuencia debe coincidir
            for (size_t i = 0; i < sequenceMatches.size(); ++i) {
                if (sequenceMatches[i]) {
                    isMatch = true;
                    confidence += sequenceConfidences[i];
                }
            }
            
            if (isMatch) {
                confidence /= pattern->getSequences().size();
            }
            break;
        }
        
        case BinaryPattern::LogicalCondition::ALL: {
            // Todas las secuencias deben coincidir
            isMatch = true;
            for (size_t i = 0; i < sequenceMatches.size(); ++i) {
                if (!sequenceMatches[i]) {
                    isMatch = false;
                    break;
                }
                confidence += sequenceConfidences[i];
            }
            
            if (isMatch) {
                confidence /= sequenceMatches.size();
            }
            break;
        }
        
        case BinaryPattern::LogicalCondition::CUSTOM: {
            // Para una condición personalizada, necesitaríamos un evaluador de expresiones
            // Esta implementación es un esqueleto
            isMatch = false;
            break;
        }
    }
    
    // Verificar umbral de confianza
    return isMatch && confidence >= pattern->getConfidenceThreshold();
}

// Esta es una implementación de ejemplo, ya que BehaviorSequence no está definida
// en el código proporcionado. En una implementación real, necesitaríamos la
// definición completa de BehaviorSequence.
int PatternMatchingSystem::matchBehavior(const BehaviorSequence& sequence, std::vector<PatternMatch>& matches) {
    if (!m_initialized) return 0;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    int matchCount = 0;
    
    // Para cada patrón de comportamiento, comprobar coincidencias
    for (const auto& pattern : m_behaviorPatterns) {
        float confidence = 0.0f;
        if (matchBehaviorPattern(pattern, sequence, confidence)) {
            PatternMatch match;
            match.patternId = pattern->getId();
            match.detectionName = pattern->getDetectionName();
            match.severity = pattern->getSeverity();
            match.confidence = confidence;
            match.details = "Behavior pattern match";
            
            matches.push_back(match);
            matchCount++;
        }
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    // Ideal: logging
    std::cout << "Behavior matching completed in " << duration << "ms. Found " 
              << matchCount << " matches." << std::endl;
    
    return matchCount;
}

bool PatternMatchingSystem::matchBehaviorPattern(const std::shared_ptr<BehaviorPattern>& pattern,
                                                const BehaviorSequence& sequence,
                                                float& confidence) {
    // Esta es una implementación de ejemplo
    // En una implementación real, analizaríamos la secuencia de comportamiento
    confidence = 0.0f;
    return false;
}

int PatternMatchingSystem::matchNetwork(const std::string& networkData, std::vector<PatternMatch>& matches) {
    if (!m_initialized || networkData.empty()) return 0;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    int matchCount = 0;
    
    // Para cada patrón de red, comprobar coincidencias
    for (const auto& pattern : m_networkPatterns) {
        float confidence = 0.0f;
        if (matchNetworkPattern(pattern, networkData, confidence)) {
            PatternMatch match;
            match.patternId = pattern->getId();
            match.detectionName = pattern->getDetectionName();
            match.severity = pattern->getSeverity();
            match.confidence = confidence;
            match.details = "Network pattern match";
            
            matches.push_back(match);
            matchCount++;
        }
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    // Ideal: logging
    std::cout << "Network matching completed in " << duration << "ms. Found " 
              << matchCount << " matches." << std::endl;
    
    return matchCount;
}

bool PatternMatchingSystem::matchNetworkPattern(const std::shared_ptr<NetworkPattern>& pattern,
                                               const std::string& networkData,
                                               float& confidence) {
    if (!pattern || networkData.empty()) return false;
    
    std::vector<bool> indicatorMatches(pattern->getIndicators().size(), false);
    std::vector<float> indicatorConfidences(pattern->getIndicators().size(), 0.0f);
    
    // Comprobar cada indicador del patrón
    for (size_t i = 0; i < pattern->getIndicators().size(); ++i) {
        const auto& indicator = pattern->getIndicators()[i];
        
        // Búsqueda simple (en una implementación real, haríamos análisis más complejo)
        size_t pos = networkData.find(indicator.pattern);
        if (pos != std::string::npos) {
            indicatorMatches[i] = true;
            indicatorConfidences[i] = 1.0f * indicator.weight;
        }
    }
    
    // Determinar coincidencia según condición lógica
    bool isMatch = false;
    confidence = 0.0f;
    
    if (pattern->getLogicalCondition() == "ANY") {
        // Al menos un indicador debe coincidir
        for (size_t i = 0; i < indicatorMatches.size(); ++i) {
            if (indicatorMatches[i]) {
                isMatch = true;
                confidence += indicatorConfidences[i];
            }
        }
        
        if (isMatch) {
            confidence /= pattern->getIndicators().size();
        }
    }
    else if (pattern->getLogicalCondition() == "ALL") {
        // Todos los indicadores deben coincidir
        isMatch = true;
        for (size_t i = 0; i < indicatorMatches.size(); ++i) {
            if (!indicatorMatches[i]) {
                isMatch = false;
                break;
            }
            confidence += indicatorConfidences[i];
        }
        
        if (isMatch) {
            confidence /= indicatorMatches.size();
        }
    }
    
    // Verificar umbral de confianza
    return isMatch && confidence >= pattern->getConfidenceThreshold();
}

} // namespace detection
} // namespace amaru 