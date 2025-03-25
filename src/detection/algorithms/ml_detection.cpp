#include "ml_detection.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include "../../common/logging.h"

namespace fs = std::filesystem;

namespace amaru {
namespace detection {

// Implementación de la clase base MLModel
MLModel::MLModel(MLModelType type, const MLModelConfig& config)
    : m_type(type),
      m_config(config),
      m_initialized(false) {
}

// Implementación de MLDetectionManager
MLDetectionManager::MLDetectionManager()
    : m_initialized(false) {
}

MLDetectionManager::~MLDetectionManager() {
    // Descargar todos los modelos
    for (auto& pair : m_models) {
        for (auto& model : pair.second) {
            if (model->isInitialized()) {
                model->unload();
            }
        }
    }
}

bool MLDetectionManager::initialize() {
    if (m_initialized) {
        return true;
    }
    
    try {
        // Inicialización básica del gestor
        m_initialized = true;
        std::cout << "ML Detection Manager initialized successfully" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error initializing ML Detection Manager: " << e.what() << std::endl;
        m_initialized = false;
        return false;
    }
}

int MLDetectionManager::loadModels(const std::string& modelsDirectory) {
    if (!m_initialized) {
        std::cerr << "ML Detection Manager not initialized" << std::endl;
        return 0;
    }
    
    int loadedModels = 0;
    
    try {
        // Verificar que el directorio existe
        if (!fs::exists(modelsDirectory) || !fs::is_directory(modelsDirectory)) {
            std::cerr << "Models directory does not exist: " << modelsDirectory << std::endl;
            return 0;
        }
        
        // Escanear el directorio para archivos de configuración de modelos
        for (const auto& entry : fs::directory_iterator(modelsDirectory)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                // Aquí tendríamos que cargar la configuración del modelo y crear la instancia adecuada
                // Para esta implementación, vamos a simular la carga de modelos
                
                std::string filename = entry.path().filename().string();
                MLModelConfig config;
                config.modelPath = entry.path().string();
                config.confidenceThreshold = 0.7f;
                config.useGPU = false;
                config.batchSize = 1;
                
                std::shared_ptr<MLModel> model;
                
                if (filename.find("cnn") != std::string::npos) {
                    model = std::make_shared<CNNModel>(config);
                } else if (filename.find("transformer") != std::string::npos) {
                    model = std::make_shared<TransformerModel>(config);
                } else if (filename.find("anomaly") != std::string::npos) {
                    model = std::make_shared<AnomalyDetectionModel>(config);
                } else {
                    continue;  // Tipo de modelo desconocido
                }
                
                if (model->initialize()) {
                    if (addModel(model)) {
                        loadedModels++;
                        std::cout << "Loaded model: " << filename << std::endl;
                    }
                } else {
                    std::cerr << "Failed to initialize model: " << filename << std::endl;
                }
            }
        }
        
        return loadedModels;
    } catch (const std::exception& e) {
        std::cerr << "Error loading models: " << e.what() << std::endl;
        return loadedModels;
    }
}

bool MLDetectionManager::addModel(std::shared_ptr<MLModel> model) {
    if (!model) return false;
    
    auto type = model->getType();
    m_models[type].push_back(model);
    return true;
}

std::vector<MLPredictionResult> MLDetectionManager::analyzeBinary(const std::vector<uint8_t>& binaryData) {
    if (!m_initialized || binaryData.empty()) {
        return {};
    }
    
    std::vector<MLPredictionResult> results;
    
    // Obtener todos los modelos CNN
    auto cnnModels = getModelsByType(MLModelType::CNN);
    
    for (auto& model : cnnModels) {
        auto cnnModel = std::static_pointer_cast<CNNModel>(model);
        auto result = cnnModel->predict(binaryData);
        
        // Solo agregar resultados que superen el umbral de confianza
        if (result.confidenceScore >= model->getConfidenceThreshold()) {
            results.push_back(result);
        }
    }
    
    return results;
}

std::vector<MLPredictionResult> MLDetectionManager::analyzeBehavior(const BehaviorSequence& sequence) {
    if (!m_initialized || sequence.empty()) {
        return {};
    }
    
    std::vector<MLPredictionResult> results;
    
    // Obtener todos los modelos de transformers
    auto transformerModels = getModelsByType(MLModelType::TRANSFORMER);
    
    for (auto& model : transformerModels) {
        auto transformerModel = std::static_pointer_cast<TransformerModel>(model);
        auto result = transformerModel->analyzeBehaviorSequence(sequence);
        
        // Solo agregar resultados que superen el umbral de confianza
        if (result.confidenceScore >= model->getConfidenceThreshold()) {
            results.push_back(result);
        }
    }
    
    return results;
}

AnomalyDetectionResult MLDetectionManager::detectAnomalies(const BehaviorSequence& sequence) {
    if (!m_initialized || sequence.empty()) {
        AnomalyDetectionResult emptyResult;
        emptyResult.anomalyScore = 0.0f;
        emptyResult.explanation = "No anomalies detected (empty sequence or manager not initialized)";
        return emptyResult;
    }
    
    // Obtener todos los modelos de detección de anomalías
    auto anomalyModels = getModelsByType(MLModelType::ANOMALY_DETECTION);
    
    if (anomalyModels.empty()) {
        AnomalyDetectionResult emptyResult;
        emptyResult.anomalyScore = 0.0f;
        emptyResult.explanation = "No anomaly detection models available";
        return emptyResult;
    }
    
    // Usar el primer modelo para la detección
    auto anomalyModel = std::static_pointer_cast<AnomalyDetectionModel>(anomalyModels[0]);
    return anomalyModel->detectAnomalies(sequence);
}

std::vector<std::shared_ptr<MLModel>> MLDetectionManager::getModelsByType(MLModelType type) const {
    auto it = m_models.find(type);
    if (it != m_models.end()) {
        return it->second;
    }
    return {};
}

MLPredictionResult MLDetectionManager::combineResults(const std::vector<MLPredictionResult>& results) {
    if (results.empty()) {
        MLPredictionResult emptyResult;
        emptyResult.confidenceScore = 0.0f;
        emptyResult.category = ThreatCategory::CLEAN;
        return emptyResult;
    }
    
    if (results.size() == 1) {
        return results[0];
    }
    
    // Implementación simple para combinar resultados:
    // 1. Acumula puntuaciones por categoría
    // 2. Selecciona la categoría con mayor puntuación
    // 3. Promedia la confianza general
    
    std::unordered_map<ThreatCategory, float> categoryScores;
    std::unordered_map<std::string, float> allCategoryScores;
    float totalConfidence = 0.0f;
    
    for (const auto& result : results) {
        categoryScores[result.category] += result.confidenceScore;
        totalConfidence += result.confidenceScore;
        
        for (const auto& score : result.categoryScores) {
            allCategoryScores[score.first] += score.second;
        }
    }
    
    // Encontrar la categoría con mayor puntuación
    ThreatCategory bestCategory = ThreatCategory::UNKNOWN;
    float bestScore = 0.0f;
    
    for (const auto& pair : categoryScores) {
        if (pair.second > bestScore) {
            bestScore = pair.second;
            bestCategory = pair.first;
        }
    }
    
    // Normalizar puntuaciones acumuladas
    for (auto& pair : allCategoryScores) {
        pair.second /= results.size();
    }
    
    // Crear resultado combinado
    MLPredictionResult combinedResult;
    combinedResult.confidenceScore = totalConfidence / results.size();
    combinedResult.category = bestCategory;
    combinedResult.categoryScores = allCategoryScores;
    
    // Determinar nombre de familia si hay consenso
    std::unordered_map<std::string, int> familyVotes;
    for (const auto& result : results) {
        if (!result.familyName.empty()) {
            familyVotes[result.familyName]++;
        }
    }
    
    if (!familyVotes.empty()) {
        auto bestFamily = std::max_element(
            familyVotes.begin(), familyVotes.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; }
        );
        
        int votes = bestFamily->second;
        if (votes > results.size() / 2) {  // Más de la mitad
            combinedResult.familyName = bestFamily->first;
        } else {
            combinedResult.familyName = "Multiple families";
        }
    }
    
    return combinedResult;
}

} // namespace detection
} // namespace amaru 