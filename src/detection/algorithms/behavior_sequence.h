#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace amaru {
namespace detection {

/**
 * @brief Tipos de acciones de comportamiento que pueden ser monitoreadas
 */
enum class ActionType {
    API_CALL,            ///< Llamada a API del sistema
    FILE_OPERATION,      ///< Operación en el sistema de archivos
    REGISTRY_OPERATION,  ///< Operación en el registro del sistema
    NETWORK_OPERATION,   ///< Operación de red
    PROCESS_OPERATION,   ///< Operación relacionada con procesos
    MEMORY_OPERATION     ///< Operación relacionada con memoria
};

/**
 * @brief Categoría de operación en el sistema de archivos
 */
enum class FileOpType {
    CREATE,       ///< Creación de archivo
    MODIFY,       ///< Modificación de archivo
    DELETE,       ///< Eliminación de archivo
    READ,         ///< Lectura de archivo
    RENAME,       ///< Renombramiento de archivo
    COPY,         ///< Copia de archivo
    CHANGE_ATTR   ///< Cambio de atributos
};

/**
 * @brief Operación de red
 */
enum class NetworkOpType {
    CONNECT,             ///< Conexión a un destino
    SEND,                ///< Envío de datos
    RECEIVE,             ///< Recepción de datos
    DNS_QUERY,           ///< Consulta DNS
    HTTP_REQUEST,        ///< Petición HTTP
    ENCRYPTED_TRAFFIC    ///< Tráfico encriptado
};

/**
 * @brief Operación en el registro
 */
enum class RegistryOpType {
    CREATE_KEY,          ///< Creación de clave
    DELETE_KEY,          ///< Eliminación de clave
    SET_VALUE,           ///< Establecer valor
    QUERY_VALUE,         ///< Consultar valor
    ENUM_KEYS,           ///< Enumerar claves
    MODIFY_PERMISSIONS   ///< Modificar permisos
};

/**
 * @brief Operación de proceso
 */
enum class ProcessOpType {
    CREATE,              ///< Creación de proceso
    TERMINATE,           ///< Terminación de proceso
    OPEN,                ///< Apertura de proceso
    SUSPEND_RESUME,      ///< Suspender/reanudar proceso
    MODULE_LOAD,         ///< Carga de módulo
    THREAD_CREATE        ///< Creación de hilo
};

/**
 * @brief Operación de memoria
 */
enum class MemoryOpType {
    ALLOCATE,            ///< Asignación de memoria
    FREE,                ///< Liberación de memoria
    PROTECT,             ///< Cambio de protección
    READ,                ///< Lectura de memoria
    WRITE,               ///< Escritura en memoria
    EXECUTE              ///< Ejecución de memoria
};

/**
 * @brief Representa una acción individual en una secuencia de comportamiento
 */
class BehaviorAction {
public:
    BehaviorAction(ActionType type,
                  const std::string& target,
                  const std::unordered_map<std::string, std::string>& params = {});
    
    ~BehaviorAction() = default;
    
    /**
     * @brief Obtiene el tipo de acción
     * @return Tipo de acción
     */
    ActionType getType() const { return m_type; }
    
    /**
     * @brief Obtiene el objetivo de la acción (archivo, clave de registro, etc.)
     * @return Objetivo de la acción
     */
    const std::string& getTarget() const { return m_target; }
    
    /**
     * @brief Obtiene el timestamp de la acción
     * @return Timestamp como punto en el tiempo
     */
    std::chrono::system_clock::time_point getTimestamp() const { return m_timestamp; }
    
    /**
     * @brief Obtiene los parámetros de la acción
     * @return Mapa de parámetros nombre-valor
     */
    const std::unordered_map<std::string, std::string>& getParams() const { return m_params; }
    
    /**
     * @brief Añade un parámetro a la acción
     * @param name Nombre del parámetro
     * @param value Valor del parámetro
     */
    void addParam(const std::string& name, const std::string& value);
    
    /**
     * @brief Establece el tipo de operación de archivo
     * @param opType Tipo de operación
     */
    void setFileOpType(FileOpType opType);
    
    /**
     * @brief Obtiene el tipo de operación de archivo
     * @return Tipo de operación o -1 si no es una operación de archivo
     */
    FileOpType getFileOpType() const { return m_fileOpType; }
    
    /**
     * @brief Establece el tipo de operación de red
     * @param opType Tipo de operación
     */
    void setNetworkOpType(NetworkOpType opType);
    
    /**
     * @brief Obtiene el tipo de operación de red
     * @return Tipo de operación o -1 si no es una operación de red
     */
    NetworkOpType getNetworkOpType() const { return m_networkOpType; }
    
    /**
     * @brief Establece el tipo de operación de registro
     * @param opType Tipo de operación
     */
    void setRegistryOpType(RegistryOpType opType);
    
    /**
     * @brief Obtiene el tipo de operación de registro
     * @return Tipo de operación o -1 si no es una operación de registro
     */
    RegistryOpType getRegistryOpType() const { return m_registryOpType; }
    
    /**
     * @brief Establece el tipo de operación de proceso
     * @param opType Tipo de operación
     */
    void setProcessOpType(ProcessOpType opType);
    
    /**
     * @brief Obtiene el tipo de operación de proceso
     * @return Tipo de operación o -1 si no es una operación de proceso
     */
    ProcessOpType getProcessOpType() const { return m_processOpType; }
    
    /**
     * @brief Establece el tipo de operación de memoria
     * @param opType Tipo de operación
     */
    void setMemoryOpType(MemoryOpType opType);
    
    /**
     * @brief Obtiene el tipo de operación de memoria
     * @return Tipo de operación o -1 si no es una operación de memoria
     */
    MemoryOpType getMemoryOpType() const { return m_memoryOpType; }
    
    /**
     * @brief Establece información del proceso que realizó la acción
     * @param pid ID del proceso
     * @param processName Nombre del proceso
     * @param path Ruta al ejecutable
     */
    void setProcessInfo(uint32_t pid, const std::string& processName, const std::string& path);
    
    /**
     * @brief Obtiene el ID del proceso
     * @return ID del proceso
     */
    uint32_t getProcessId() const { return m_processId; }
    
    /**
     * @brief Obtiene el nombre del proceso
     * @return Nombre del proceso
     */
    const std::string& getProcessName() const { return m_processName; }
    
    /**
     * @brief Obtiene la ruta del proceso
     * @return Ruta al ejecutable
     */
    const std::string& getProcessPath() const { return m_processPath; }
    
    /**
     * @brief Convierte la acción a formato de cadena para diagnóstico
     * @return Representación en cadena de la acción
     */
    std::string toString() const;

private:
    ActionType m_type;
    std::string m_target;
    std::chrono::system_clock::time_point m_timestamp;
    std::unordered_map<std::string, std::string> m_params;
    
    // Información específica por tipo de operación
    FileOpType m_fileOpType;
    NetworkOpType m_networkOpType;
    RegistryOpType m_registryOpType;
    ProcessOpType m_processOpType;
    MemoryOpType m_memoryOpType;
    
    // Información del proceso
    uint32_t m_processId;
    std::string m_processName;
    std::string m_processPath;
};

/**
 * @brief Secuencia de acciones de comportamiento para análisis
 */
class BehaviorSequence {
public:
    BehaviorSequence();
    ~BehaviorSequence() = default;
    
    /**
     * @brief Añade una acción a la secuencia
     * @param action Acción a añadir
     */
    void addAction(const BehaviorAction& action);
    
    /**
     * @brief Obtiene todas las acciones en la secuencia
     * @return Vector de acciones
     */
    const std::vector<BehaviorAction>& getActions() const { return m_actions; }
    
    /**
     * @brief Filtra acciones por tipo
     * @param type Tipo de acción a filtrar
     * @return Vector de acciones del tipo especificado
     */
    std::vector<BehaviorAction> filterByType(ActionType type) const;
    
    /**
     * @brief Filtra acciones por proceso
     * @param processId ID del proceso
     * @return Vector de acciones del proceso especificado
     */
    std::vector<BehaviorAction> filterByProcess(uint32_t processId) const;
    
    /**
     * @brief Filtra acciones por rango de tiempo
     * @param start Tiempo de inicio
     * @param end Tiempo de fin
     * @return Vector de acciones en el rango de tiempo
     */
    std::vector<BehaviorAction> filterByTimeRange(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end) const;
    
    /**
     * @brief Obtiene el número de acciones en la secuencia
     * @return Número de acciones
     */
    size_t size() const { return m_actions.size(); }
    
    /**
     * @brief Comprueba si la secuencia está vacía
     * @return true si está vacía, false en caso contrario
     */
    bool empty() const { return m_actions.empty(); }
    
    /**
     * @brief Limpia todas las acciones de la secuencia
     */
    void clear() { m_actions.clear(); }
    
    /**
     * @brief Establece un ID para la secuencia
     * @param id ID de la secuencia
     */
    void setId(const std::string& id) { m_id = id; }
    
    /**
     * @brief Obtiene el ID de la secuencia
     * @return ID de la secuencia
     */
    const std::string& getId() const { return m_id; }
    
    /**
     * @brief Establece metadatos para la secuencia
     * @param key Clave del metadato
     * @param value Valor del metadato
     */
    void setMetadata(const std::string& key, const std::string& value);
    
    /**
     * @brief Obtiene un metadato de la secuencia
     * @param key Clave del metadato
     * @return Valor del metadato o cadena vacía si no existe
     */
    std::string getMetadata(const std::string& key) const;
    
    /**
     * @brief Obtiene todos los metadatos de la secuencia
     * @return Mapa de metadatos
     */
    const std::unordered_map<std::string, std::string>& getAllMetadata() const { return m_metadata; }
    
    /**
     * @brief Establece el origen de la secuencia (ejemplo: análisis en tiempo real, sandbox, etc.)
     * @param source Origen de la secuencia
     */
    void setSource(const std::string& source) { m_source = source; }
    
    /**
     * @brief Obtiene el origen de la secuencia
     * @return Origen de la secuencia
     */
    const std::string& getSource() const { return m_source; }

private:
    std::string m_id;
    std::vector<BehaviorAction> m_actions;
    std::unordered_map<std::string, std::string> m_metadata;
    std::string m_source;
};

} // namespace detection
} // namespace amaru 