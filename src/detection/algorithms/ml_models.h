#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

namespace amaru {
namespace detection {

// Definiciones para secuencias de comportamiento
enum class BehaviorActionType {
    API_CALL,
    FILE_OPERATION,
    REGISTRY_ACCESS,
    NETWORK_ACTIVITY,
    PROCESS_CREATION,
    MEMORY_OPERATION,
    UNKNOWN
};

struct BehaviorAction {
    BehaviorActionType type;
    std::string details;
    uint64_t timestamp;
};

struct BehaviorSequence {
    std::vector<BehaviorAction> actions;
    std::string processName;
    uint32_t processId;
    std::string contextInfo;
};

/**
 * @brief Modelo CNN para análisis de secuencias binarias
 * 
 * Implementa análisis de secuencias binarias utilizando redes neuronales
 * convolucionales (CNN) para detectar patrones potencialmente maliciosos.
 */
class CNNModel {
public:
    CNNModel();
    ~CNNModel();

    /**
     * @brief Carga un modelo CNN pre-entrenado desde un archivo
     * @param modelPath Ruta al archivo del modelo
     * @return true si se cargó correctamente, false en caso contrario
     */
    bool loadModel(const std::string& modelPath);
    
    /**
     * @brief Libera los recursos asociados al modelo
     */
    void unloadModel();
    
    /**
     * @brief Activa o desactiva la aceleración por GPU
     * @param enable true para activar, false para desactivar
     */
    void enableGPU(bool enable);
    
    /**
     * @brief Analiza los datos binarios y devuelve una puntuación de maliciosidad
     * @param binaryData Datos binarios a analizar
     * @return Puntuación entre 0.0 (benigno) y 1.0 (malicioso)
     */
    float predict(const std::vector<uint8_t>& binaryData);

private:
    /**
     * @brief Preprocesa los datos binarios para entrada al modelo CNN
     * @param binaryData Datos binarios crudos
     * @return Vector de características normalizadas
     */
    std::vector<float> preprocessBinary(const std::vector<uint8_t>& binaryData);
    
    /**
     * @brief Ejecuta la inferencia del modelo CNN
     * @param features Vector de características procesadas
     * @return Puntuación de maliciosidad
     */
    float runInference(const std::vector<float>& features);
    
    /**
     * @brief Calcula la entropía de un conjunto de datos
     * @param data Vector de datos
     * @return Valor de entropía normalizado entre 0.0 y 1.0
     */
    float calculateEntropy(const std::vector<float>& data);
    
    /**
     * @brief Busca patrones sospechosos específicos en los datos
     * @param data Vector de datos
     * @return true si se encontraron patrones sospechosos
     */
    bool checkForSuspiciousPatterns(const std::vector<float>& data);

    bool m_isInitialized;
    bool m_useGPU;
    bool m_modelLoaded;
    // Aquí irían los miembros necesarios para el modelo real
};

/**
 * @brief Modelo Transformer para análisis de secuencias de comportamiento
 * 
 * Implementa análisis de secuencias de comportamiento utilizando
 * arquitecturas de transformadores con mecanismos de atención para
 * detectar patrones maliciosos en secuencias de acciones.
 */
class TransformerModel {
public:
    TransformerModel();
    ~TransformerModel();
    
    /**
     * @brief Carga un modelo Transformer pre-entrenado desde un archivo
     * @param modelPath Ruta al archivo del modelo
     * @return true si se cargó correctamente, false en caso contrario
     */
    bool loadModel(const std::string& modelPath);
    
    /**
     * @brief Libera los recursos asociados al modelo
     */
    void unloadModel();
    
    /**
     * @brief Analiza una secuencia de comportamiento y devuelve una puntuación de maliciosidad
     * @param sequence Secuencia de acciones de comportamiento
     * @return Puntuación entre 0.0 (benigno) y 1.0 (malicioso)
     */
    float analyzeBehaviorSequence(const BehaviorSequence& sequence);

private:
    /**
     * @brief Convierte secuencia de comportamiento a tokens para el modelo
     * @param sequence Secuencia de comportamiento
     * @return Vector de IDs de tokens
     */
    std::vector<int> tokenizeBehavior(const BehaviorSequence& sequence);
    
    /**
     * @brief Mapea detalle de API a ID de token
     * @param apiDetails Detalles de la llamada a API
     * @return ID del token correspondiente
     */
    int getApiTokenId(const std::string& apiDetails);
    
    /**
     * @brief Mapea operación de archivo a ID de token
     * @param fileDetails Detalles de la operación de archivo
     * @return ID del token correspondiente
     */
    int getFileOpTokenId(const std::string& fileDetails);
    
    /**
     * @brief Mapea acceso a registro a ID de token
     * @param regDetails Detalles del acceso a registro
     * @return ID del token correspondiente
     */
    int getRegistryTokenId(const std::string& regDetails);
    
    /**
     * @brief Mapea actividad de red a ID de token
     * @param netDetails Detalles de la actividad de red
     * @return ID del token correspondiente
     */
    int getNetworkTokenId(const std::string& netDetails);
    
    /**
     * @brief Procesa la secuencia de tokens para generar una puntuación
     * @param tokenIds Vector de IDs de tokens
     * @return Puntuación de maliciosidad
     */
    float processSequence(const std::vector<int>& tokenIds);
    
    /**
     * @brief Detecta patrones de inyección de proceso
     * @param tokens Vector de tokens
     * @return true si se detecta patrón de inyección
     */
    bool detectProcessInjection(const std::vector<int>& tokens);
    
    /**
     * @brief Detecta patrones típicos de ransomware
     * @param tokens Vector de tokens
     * @return true si se detecta patrón de ransomware
     */
    bool detectRansomware(const std::vector<int>& tokens);
    
    /**
     * @brief Detecta patrones de exfiltración de datos
     * @param tokens Vector de tokens
     * @return true si se detecta patrón de exfiltración
     */
    bool detectDataExfiltration(const std::vector<int>& tokens);
    
    /**
     * @brief Detecta establecimiento de persistencia
     * @param tokens Vector de tokens
     * @return true si se detecta establecimiento de persistencia
     */
    bool detectPersistence(const std::vector<int>& tokens);

    bool m_modelLoaded;
    // Aquí irían los miembros necesarios para el modelo real
};

/**
 * @brief Estructura para resultados de detección de anomalías
 */
struct Anomaly {
    std::string id;
    std::string description;
    float score;
};

struct AnomalyDetectionResult {
    float anomalyScore;
    std::vector<Anomaly> anomalies;
};

/**
 * @brief Configuración del modelo de detección de anomalías
 */
struct ModelConfig {
    float anomalyThreshold;
    std::string normalProfilesPath;
    bool adaptiveMode;
};

/**
 * @brief Modelo de detección de anomalías para comportamientos inusuales
 * 
 * Implementa métodos de detección de anomalías para identificar
 * comportamientos que se desvían significativamente de los patrones normales.
 */
class AnomalyDetectionModel {
public:
    using FeatureVector = std::map<std::string, float>;
    
    AnomalyDetectionModel();
    ~AnomalyDetectionModel();
    
    /**
     * @brief Inicializa el modelo con la configuración especificada
     * @param config Configuración del modelo
     * @return true si se inicializó correctamente
     */
    bool initialize(const ModelConfig& config);
    
    /**
     * @brief Carga un modelo pre-entrenado desde un archivo
     * @param modelPath Ruta al archivo del modelo
     * @return true si se cargó correctamente
     */
    bool loadModel(const std::string& modelPath);
    
    /**
     * @brief Libera los recursos asociados al modelo
     */
    void unloadModel();
    
    /**
     * @brief Detecta anomalías en una secuencia de comportamiento
     * @param sequence Secuencia de comportamiento a analizar
     * @return Resultado con puntuación y anomalías específicas detectadas
     */
    AnomalyDetectionResult detectAnomalies(const BehaviorSequence& sequence);

private:
    /**
     * @brief Carga perfiles de comportamiento normal
     * @param profilesPath Ruta al archivo de perfiles normales
     * @return true si se cargaron correctamente
     */
    bool loadNormalProfiles(const std::string& profilesPath);
    
    /**
     * @brief Extrae características numéricas de una secuencia de comportamiento
     * @param sequence Secuencia de comportamiento
     * @return Vector de características
     */
    FeatureVector extractFeatures(const BehaviorSequence& sequence);
    
    /**
     * @brief Calcula puntuación de anomalía para un conjunto de características
     * @param features Vector de características
     * @return Puntuación de anomalía entre 0.0 y 1.0
     */
    float calculateAnomalyScore(const FeatureVector& features);
    
    /**
     * @brief Identifica anomalías específicas basadas en características
     * @param features Vector de características
     * @return Vector de anomalías identificadas
     */
    std::vector<Anomaly> identifyAnomalies(const FeatureVector& features);

    bool m_isInitialized;
    bool m_modelLoaded;
    ModelConfig m_config;
    std::vector<FeatureVector> m_normalBehaviorProfiles;
    // Aquí irían otros miembros necesarios para el modelo real
};

} // namespace detection
} // namespace amaru 