#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "behavior_sequence.h"

namespace amaru {
namespace detection {

/**
 * @brief Tipos de algoritmos de machine learning disponibles
 */
enum class MLModelType {
    CNN,                    ///< Convolutional Neural Network para análisis de binarios
    TRANSFORMER,            ///< Transformer para análisis de secuencias de comportamiento
    ANOMALY_DETECTION,      ///< Algoritmos de detección de anomalías
    ENSEMBLE,               ///< Combinación de múltiples modelos
    CLUSTERING              ///< Algoritmos de clustering
};

/**
 * @brief Categorías posibles para clasificación de amenazas
 */
enum class ThreatCategory {
    CLEAN,                  ///< No es una amenaza
    MALWARE,                ///< Malware genérico
    RANSOMWARE,             ///< Ransomware
    TROJAN,                 ///< Troyano
    BACKDOOR,               ///< Backdoor
    WORM,                   ///< Gusano
    SPYWARE,                ///< Spyware
    ADWARE,                 ///< Adware
    EXPLOIT,                ///< Exploit
    POTENTIALLY_UNWANTED,   ///< Programa potencialmente no deseado
    UNKNOWN                 ///< Categoría desconocida
};

/**
 * @brief Resultado de predicción de un modelo ML
 */
struct MLPredictionResult {
    float confidenceScore;            ///< Puntuación de confianza (0.0-1.0)
    ThreatCategory category;          ///< Categoría detectada
    std::string familyName;           ///< Nombre de familia de malware, si se conoce
    std::unordered_map<std::string, float> categoryScores; ///< Puntuaciones por categoría
    std::string detailsJson;          ///< Detalles adicionales en formato JSON
    std::chrono::milliseconds executionTime; ///< Tiempo de ejecución
};

/**
 * @brief Características específicas para anomaly detection
 */
struct AnomalyFeatures {
    float apiCallFrequency;           ///< Frecuencia de llamadas a API
    float fileOpRate;                 ///< Tasa de operaciones de archivo
    float registryOpRate;             ///< Tasa de operaciones de registro
    float networkConnections;         ///< Número de conexiones de red
    float processCreationRate;        ///< Tasa de creación de procesos
    float cryptoOperations;           ///< Operaciones criptográficas
    float memoryAllocations;          ///< Asignaciones de memoria
    float unusualApiCallsRate;        ///< Tasa de llamadas API inusuales
    std::unordered_map<std::string, float> customFeatures; ///< Características personalizadas
};

/**
 * @brief Resultado de detección de anomalías
 */
struct AnomalyDetectionResult {
    float anomalyScore;               ///< Puntuación de anomalía (0.0-1.0)
    std::vector<std::string> anomalies; ///< Anomalías específicas detectadas
    AnomalyFeatures features;         ///< Características extraídas de la secuencia
    std::string explanation;          ///< Explicación legible de la anomalía
};

/**
 * @brief Configuración para modelos de ML
 */
struct MLModelConfig {
    std::string modelPath;            ///< Ruta al archivo del modelo
    bool useGPU;                      ///< Si se debe usar GPU para aceleración
    float confidenceThreshold;        ///< Umbral de confianza para detecciones
    int batchSize;                    ///< Tamaño de lote para inferencia
    std::unordered_map<std::string, std::string> extraParams; ///< Parámetros adicionales
};

/**
 * @brief Clase base para todos los modelos de ML
 */
class MLModel {
public:
    MLModel(MLModelType type, const MLModelConfig& config);
    virtual ~MLModel() = default;
    
    /**
     * @brief Inicializa el modelo
     * @return true si se inicializó correctamente
     */
    virtual bool initialize() = 0;
    
    /**
     * @brief Descarga el modelo y libera recursos
     */
    virtual void unload() = 0;
    
    /**
     * @brief Obtiene el tipo de modelo
     * @return Tipo de modelo
     */
    MLModelType getType() const { return m_type; }
    
    /**
     * @brief Obtiene la configuración del modelo
     * @return Configuración del modelo
     */
    const MLModelConfig& getConfig() const { return m_config; }
    
    /**
     * @brief Comprueba si el modelo está inicializado
     * @return true si está inicializado
     */
    bool isInitialized() const { return m_initialized; }
    
    /**
     * @brief Actualiza el umbral de confianza
     * @param threshold Nuevo umbral (0.0-1.0)
     */
    void setConfidenceThreshold(float threshold) { m_config.confidenceThreshold = threshold; }
    
    /**
     * @brief Obtiene el umbral de confianza actual
     * @return Umbral de confianza
     */
    float getConfidenceThreshold() const { return m_config.confidenceThreshold; }
    
    /**
     * @brief Habilita o deshabilita el uso de GPU
     * @param useGPU true para habilitar GPU
     */
    virtual void enableGPU(bool useGPU) { m_config.useGPU = useGPU; }
    
protected:
    MLModelType m_type;
    MLModelConfig m_config;
    bool m_initialized;
};

/**
 * @brief Modelo CNN para análisis de binarios
 */
class CNNModel : public MLModel {
public:
    CNNModel(const MLModelConfig& config);
    
    /**
     * @brief Inicializa el modelo CNN
     * @return true si se inicializó correctamente
     */
    bool initialize() override;
    
    /**
     * @brief Descarga el modelo CNN
     */
    void unload() override;
    
    /**
     * @brief Analiza datos binarios con el modelo CNN
     * @param binaryData Datos binarios a analizar
     * @return Resultado de la predicción
     */
    MLPredictionResult predict(const std::vector<uint8_t>& binaryData);
    
private:
    // Procesa datos binarios para la entrada del CNN
    std::vector<float> preprocessBinary(const std::vector<uint8_t>& binaryData);
    
    // Ejecuta inferencia en el modelo CNN
    MLPredictionResult runInference(const std::vector<float>& processedData);
    
    // Implementación específica del modelo
    class CNNModelImpl;
    std::unique_ptr<CNNModelImpl> m_impl;
};

/**
 * @brief Modelo Transformer para análisis de secuencias de comportamiento
 */
class TransformerModel : public MLModel {
public:
    TransformerModel(const MLModelConfig& config);
    
    /**
     * @brief Inicializa el modelo Transformer
     * @return true si se inicializó correctamente
     */
    bool initialize() override;
    
    /**
     * @brief Descarga el modelo Transformer
     */
    void unload() override;
    
    /**
     * @brief Analiza una secuencia de comportamiento
     * @param sequence Secuencia de comportamiento
     * @return Resultado de la predicción
     */
    MLPredictionResult analyzeBehaviorSequence(const BehaviorSequence& sequence);
    
private:
    // Tokeniza acciones de comportamiento para el transformer
    std::vector<int> tokenizeBehavior(const BehaviorSequence& sequence);
    
    // Ejecuta inferencia en el modelo transformer
    MLPredictionResult runInference(const std::vector<int>& tokenizedSequence);
    
    // Implementación específica del modelo
    class TransformerModelImpl;
    std::unique_ptr<TransformerModelImpl> m_impl;
    
    // Mapa de tokens para tokenización
    std::unordered_map<std::string, int> m_tokenMap;
};

/**
 * @brief Modelo de detección de anomalías
 */
class AnomalyDetectionModel : public MLModel {
public:
    AnomalyDetectionModel(const MLModelConfig& config);
    
    /**
     * @brief Inicializa el modelo de detección de anomalías
     * @return true si se inicializó correctamente
     */
    bool initialize() override;
    
    /**
     * @brief Descarga el modelo de detección de anomalías
     */
    void unload() override;
    
    /**
     * @brief Carga perfiles de comportamiento normal
     * @param profilesPath Ruta a los perfiles
     * @return true si se cargaron correctamente
     */
    bool loadNormalProfiles(const std::string& profilesPath);
    
    /**
     * @brief Detecta anomalías en una secuencia de comportamiento
     * @param sequence Secuencia de comportamiento
     * @return Resultado de la detección de anomalías
     */
    AnomalyDetectionResult detectAnomalies(const BehaviorSequence& sequence);
    
private:
    // Extrae características para detección de anomalías
    AnomalyFeatures extractFeatures(const BehaviorSequence& sequence);
    
    // Compara con perfiles normales para detectar anomalías
    float compareWithNormalProfiles(const AnomalyFeatures& features);
    
    // Implementación específica del modelo
    class AnomalyDetectionModelImpl;
    std::unique_ptr<AnomalyDetectionModelImpl> m_impl;
    
    // Perfiles de comportamiento normal
    std::vector<AnomalyFeatures> m_normalProfiles;
};

/**
 * @brief Gestor de modelos de detección ML
 */
class MLDetectionManager {
public:
    MLDetectionManager();
    ~MLDetectionManager();
    
    /**
     * @brief Inicializa el gestor con una configuración global
     * @return true si se inicializó correctamente
     */
    bool initialize();
    
    /**
     * @brief Carga modelos desde un directorio
     * @param modelsDirectory Directorio que contiene los modelos
     * @return Número de modelos cargados correctamente
     */
    int loadModels(const std::string& modelsDirectory);
    
    /**
     * @brief Añade un modelo al gestor
     * @param model Modelo a añadir
     * @return true si se añadió correctamente
     */
    bool addModel(std::shared_ptr<MLModel> model);
    
    /**
     * @brief Analiza datos binarios con todos los modelos CNN disponibles
     * @param binaryData Datos binarios a analizar
     * @return Vector de resultados de predicción
     */
    std::vector<MLPredictionResult> analyzeBinary(const std::vector<uint8_t>& binaryData);
    
    /**
     * @brief Analiza una secuencia de comportamiento con todos los modelos disponibles
     * @param sequence Secuencia de comportamiento
     * @return Vector de resultados de predicción y anomalías
     */
    std::vector<MLPredictionResult> analyzeBehavior(const BehaviorSequence& sequence);
    
    /**
     * @brief Detecta anomalías en una secuencia de comportamiento
     * @param sequence Secuencia de comportamiento
     * @return Resultado de la detección de anomalías
     */
    AnomalyDetectionResult detectAnomalies(const BehaviorSequence& sequence);
    
    /**
     * @brief Obtiene todos los modelos de un tipo específico
     * @param type Tipo de modelo
     * @return Vector de modelos del tipo especificado
     */
    std::vector<std::shared_ptr<MLModel>> getModelsByType(MLModelType type) const;

private:
    // Organización de modelos por tipo
    std::unordered_map<MLModelType, std::vector<std::shared_ptr<MLModel>>> m_models;
    
    // Combina resultados de múltiples modelos
    MLPredictionResult combineResults(const std::vector<MLPredictionResult>& results);
    
    bool m_initialized;
};

} // namespace detection
} // namespace amaru 