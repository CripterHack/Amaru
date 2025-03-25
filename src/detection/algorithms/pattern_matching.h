#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace amaru {
namespace detection {

/**
 * @brief Tipos de patrones de malware soportados
 */
enum class PatternType {
    BINARY_SEQUENCE,   ///< Secuencia de bytes específica
    BEHAVIOR_PATTERN,  ///< Patrón de comportamiento
    NETWORK_PATTERN,   ///< Patrón de comunicación de red
    COMBINED_PATTERN   ///< Combinación de diferentes tipos de patrones
};

/**
 * @brief Niveles de severidad para patrones detectados
 */
enum class PatternSeverity {
    LOW,       ///< Bajo riesgo, potencialmente indeseado
    MEDIUM,    ///< Riesgo medio, sospechoso
    HIGH,      ///< Alto riesgo, malicioso
    CRITICAL   ///< Crítico, requiere atención inmediata
};

/**
 * @brief Clase base para todos los tipos de patrones
 */
class MalwarePattern {
public:
    MalwarePattern(const std::string& id, PatternType type, 
                   const std::string& detectionName, PatternSeverity severity,
                   float confidenceThreshold);
    
    virtual ~MalwarePattern() = default;
    
    /**
     * @brief Obtiene el identificador único del patrón
     * @return ID del patrón
     */
    const std::string& getId() const { return m_id; }
    
    /**
     * @brief Obtiene el tipo de patrón
     * @return Tipo de patrón
     */
    PatternType getType() const { return m_type; }
    
    /**
     * @brief Obtiene el nombre de detección asignado a este patrón
     * @return Nombre de la detección
     */
    const std::string& getDetectionName() const { return m_detectionName; }
    
    /**
     * @brief Obtiene el nivel de severidad del patrón
     * @return Nivel de severidad
     */
    PatternSeverity getSeverity() const { return m_severity; }
    
    /**
     * @brief Obtiene el umbral de confianza requerido para confirmar detección
     * @return Umbral de confianza (0.0-1.0)
     */
    float getConfidenceThreshold() const { return m_confidenceThreshold; }
    
    /**
     * @brief Obtiene las familias de malware relacionadas con este patrón
     * @return Vector de IDs de familias
     */
    const std::vector<std::string>& getFamilyRelations() const { return m_familyRelations; }
    
    /**
     * @brief Establece las relaciones con familias de malware
     * @param families Vector de IDs de familias
     */
    void setFamilyRelations(const std::vector<std::string>& families) { m_familyRelations = families; }
    
    /**
     * @brief Método virtual puro para serializar el patrón a JSON
     * @return Representación JSON del patrón
     */
    virtual std::string toJson() const = 0;
    
protected:
    std::string m_id;
    PatternType m_type;
    std::string m_detectionName;
    PatternSeverity m_severity;
    float m_confidenceThreshold;
    std::vector<std::string> m_familyRelations;
};

/**
 * @brief Patrón de secuencia binaria para detección en archivos
 */
class BinaryPattern : public MalwarePattern {
public:
    struct Sequence {
        std::string offset;     ///< Offset específico o "variable"
        std::string sequence;   ///< Secuencia hexadecimal
        std::string mask;       ///< Máscara opcional para wildcards
        float weight;           ///< Peso de esta secuencia (0.0-1.0)
    };
    
    enum class LogicalCondition {
        ANY,    ///< Al menos una secuencia debe coincidir
        ALL,    ///< Todas las secuencias deben coincidir
        CUSTOM  ///< Expresión lógica personalizada
    };
    
    BinaryPattern(const std::string& id, const std::string& detectionName,
                  PatternSeverity severity, float confidenceThreshold);
    
    /**
     * @brief Añade una secuencia al patrón
     * @param sequence Secuencia a añadir
     */
    void addSequence(const Sequence& sequence);
    
    /**
     * @brief Establece la condición lógica entre secuencias
     * @param condition Condición lógica
     */
    void setLogicalCondition(LogicalCondition condition);
    
    /**
     * @brief Establece una expresión lógica personalizada
     * @param expression Expresión lógica (formato a definir)
     */
    void setCustomLogicalExpression(const std::string& expression);
    
    /**
     * @brief Obtiene las secuencias que forman el patrón
     * @return Vector de secuencias
     */
    const std::vector<Sequence>& getSequences() const { return m_sequences; }
    
    /**
     * @brief Obtiene la condición lógica
     * @return Condición lógica
     */
    LogicalCondition getLogicalCondition() const { return m_logicalCondition; }
    
    /**
     * @brief Obtiene la expresión lógica personalizada
     * @return Expresión lógica (vacía si no es personalizada)
     */
    const std::string& getCustomLogicalExpression() const { return m_customLogicalExpression; }
    
    /**
     * @brief Serializa el patrón a formato JSON
     * @return Representación JSON del patrón
     */
    std::string toJson() const override;

private:
    std::vector<Sequence> m_sequences;
    LogicalCondition m_logicalCondition;
    std::string m_customLogicalExpression;
};

/**
 * @brief Patrón de comportamiento para detección basada en acciones
 */
class BehaviorPattern : public MalwarePattern {
public:
    struct ApiSequence {
        std::string api;                ///< Nombre de la API
        std::unordered_map<std::string, std::string> params;  ///< Parámetros específicos
        int repeat_min;                 ///< Mínimo de repeticiones requeridas
    };
    
    struct FileOperation {
        std::string pattern;            ///< Patrón de modificación de archivos
        int min_count;                  ///< Mínimo de operaciones a detectar
        int timeframe_seconds;          ///< Marco temporal para las operaciones
    };
    
    struct Behavior {
        std::vector<ApiSequence> api_sequence;  ///< Secuencia de APIs
        FileOperation file_operations;          ///< Operaciones de archivo
        float weight;                           ///< Peso de este comportamiento
    };
    
    BehaviorPattern(const std::string& id, const std::string& detectionName,
                    PatternSeverity severity, float confidenceThreshold);
    
    /**
     * @brief Añade un comportamiento al patrón
     * @param behavior Comportamiento a añadir
     */
    void addBehavior(const Behavior& behavior);
    
    /**
     * @brief Establece la condición lógica entre comportamientos
     * @param condition Condición lógica (ANY/ALL)
     */
    void setLogicalCondition(const std::string& condition);
    
    /**
     * @brief Obtiene los comportamientos que forman el patrón
     * @return Vector de comportamientos
     */
    const std::vector<Behavior>& getBehaviors() const { return m_behaviors; }
    
    /**
     * @brief Obtiene la condición lógica
     * @return Condición lógica
     */
    const std::string& getLogicalCondition() const { return m_logicalCondition; }
    
    /**
     * @brief Serializa el patrón a formato JSON
     * @return Representación JSON del patrón
     */
    std::string toJson() const override;

private:
    std::vector<Behavior> m_behaviors;
    std::string m_logicalCondition;
};

/**
 * @brief Patrón de red para detección basada en comunicaciones
 */
class NetworkPattern : public MalwarePattern {
public:
    struct Indicator {
        std::string type;                         ///< Tipo de indicador
        std::string pattern;                      ///< Patrón a detectar
        std::unordered_map<std::string, std::string> headers;  ///< Cabeceras para HTTP
        std::string method;                       ///< Método HTTP
        std::string uri_pattern;                  ///< Patrón URI
        float weight;                            ///< Peso de este indicador
    };
    
    NetworkPattern(const std::string& id, const std::string& detectionName,
                   PatternSeverity severity, float confidenceThreshold);
    
    /**
     * @brief Añade un indicador de red al patrón
     * @param indicator Indicador a añadir
     */
    void addIndicator(const Indicator& indicator);
    
    /**
     * @brief Establece la condición lógica entre indicadores
     * @param condition Condición lógica (ANY/ALL)
     */
    void setLogicalCondition(const std::string& condition);
    
    /**
     * @brief Obtiene los indicadores que forman el patrón
     * @return Vector de indicadores
     */
    const std::vector<Indicator>& getIndicators() const { return m_indicators; }
    
    /**
     * @brief Obtiene la condición lógica
     * @return Condición lógica
     */
    const std::string& getLogicalCondition() const { return m_logicalCondition; }
    
    /**
     * @brief Serializa el patrón a formato JSON
     * @return Representación JSON del patrón
     */
    std::string toJson() const override;

private:
    std::vector<Indicator> m_indicators;
    std::string m_logicalCondition;
};

/**
 * @brief Resultado de una coincidencia de patrón
 */
struct PatternMatch {
    std::string patternId;         ///< ID del patrón que coincidió
    std::string detectionName;     ///< Nombre de la detección
    PatternSeverity severity;      ///< Severidad de la detección
    float confidence;              ///< Confianza de la detección (0.0-1.0)
    std::string details;           ///< Detalles específicos de la coincidencia
};

/**
 * @brief Sistema de coincidencia de patrones optimizado
 */
class PatternMatchingSystem {
public:
    PatternMatchingSystem();
    ~PatternMatchingSystem();
    
    /**
     * @brief Inicializa el sistema con configuración específica
     * @return true si se inicializó correctamente
     */
    bool initialize();
    
    /**
     * @brief Carga patrones desde un archivo
     * @param patternsFilePath Ruta al archivo de patrones
     * @return Número de patrones cargados correctamente
     */
    int loadPatterns(const std::string& patternsFilePath);
    
    /**
     * @brief Añade un patrón al sistema
     * @param pattern Patrón a añadir
     * @return true si se añadió correctamente
     */
    bool addPattern(std::shared_ptr<MalwarePattern> pattern);
    
    /**
     * @brief Busca coincidencias en datos binarios
     * @param data Datos binarios a analizar
     * @param matches Vector donde se almacenarán las coincidencias
     * @return Número de coincidencias encontradas
     */
    int matchBinary(const std::vector<uint8_t>& data, std::vector<PatternMatch>& matches);
    
    /**
     * @brief Busca coincidencias en una secuencia de comportamiento
     * @param sequence Secuencia de comportamiento a analizar
     * @param matches Vector donde se almacenarán las coincidencias
     * @return Número de coincidencias encontradas
     */
    int matchBehavior(const BehaviorSequence& sequence, std::vector<PatternMatch>& matches);
    
    /**
     * @brief Busca coincidencias en actividad de red
     * @param networkData Datos de red a analizar
     * @param matches Vector donde se almacenarán las coincidencias
     * @return Número de coincidencias encontradas
     */
    int matchNetwork(const std::string& networkData, std::vector<PatternMatch>& matches);

private:
    // Implementaciones de algoritmos de coincidencia
    bool matchBinaryPattern(const std::shared_ptr<BinaryPattern>& pattern, 
                           const std::vector<uint8_t>& data,
                           float& confidence);
                           
    bool matchBehaviorPattern(const std::shared_ptr<BehaviorPattern>& pattern,
                             const BehaviorSequence& sequence,
                             float& confidence);
                             
    bool matchNetworkPattern(const std::shared_ptr<NetworkPattern>& pattern,
                            const std::string& networkData,
                            float& confidence);

    // Algoritmos optimizados
    void buildAhoCorasickMachine();
    void createBloomFilter();
    
    // Implementación Aho-Corasick para búsqueda múltiple eficiente
    class AhoCorasickImpl;
    std::unique_ptr<AhoCorasickImpl> m_ahoCorasick;
    
    // Filtro de Bloom para pre-filtrado rápido
    class BloomFilterImpl;
    std::unique_ptr<BloomFilterImpl> m_bloomFilter;
    
    // Almacén de patrones por tipo
    std::vector<std::shared_ptr<BinaryPattern>> m_binaryPatterns;
    std::vector<std::shared_ptr<BehaviorPattern>> m_behaviorPatterns;
    std::vector<std::shared_ptr<NetworkPattern>> m_networkPatterns;
    
    bool m_initialized;
};

} // namespace detection
} // namespace amaru 