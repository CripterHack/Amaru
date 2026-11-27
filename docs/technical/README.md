# Documentación Técnica de Amaru Antivirus

Esta sección contiene documentación técnica detallada destinada a usuarios avanzados, administradores de sistemas, investigadores de seguridad y desarrolladores que necesitan entender en profundidad los aspectos técnicos de Amaru Antivirus.

## Propósito

Los documentos técnicos proporcionan información detallada sobre:

- Arquitectura interna de los componentes principales
- Algoritmos y métodos implementados
- Especificaciones de rendimiento y optimización
- Interfaces de programación y configuración avanzada
- Consideraciones técnicas para implementación y despliegue

Esta documentación es complementaria a las guías de usuario y está dirigida a un público con conocimientos técnicos avanzados.

## Documentos Disponibles

- [Arquitectura](./architecture.md) describe los componentes y su relación.
- [Motor de detección](./detection-engine.md) describe el análisis mediante firmas y heurísticas.
- [Validación con EICAR](./eicar-corpus.md) define el corpus y los resultados esperados.
- [Análisis local con YARA-X](./yara-x.md) explica cómo comprobar las reglas y analizar archivos con el motor opcional.
- [Referencia de API](./api-reference.md) recoge los contratos de integración previstos. El [informe de desarrollo](../../status_development.md) detalla su validación.

## Cobertura técnica pendiente

| Tema previsto | Referencia disponible | Qué debe cubrir la guía técnica |
|---|---|---|
| Protección en tiempo real | [Monitor](../../realtime-monitor/src/lib.rs) | Eventos admitidos, exclusiones y recuperación tras interrupciones. |
| Cuarentena | [Guía de usuario](../user-guides/quarantine.md) | Aislamiento, restauración y tratamiento de errores. |
| Análisis bajo demanda y programado | [Guía de análisis](../user-guides/analyzing.md) | Inicio, cancelación y estado del análisis, incluido el planificador pendiente. |
| Rendimiento y gestión de recursos | [Pruebas de rendimiento](../../tests/performance_tests.rs) | Mediciones reproducibles de CPU, memoria, disco y tiempo de análisis. |
| Configuración avanzada e implementación empresarial | [Configuración del repositorio](../../config.toml) e [instalador](../../installer/README.md) | Parámetros admitidos, instalación, actualización y reversión. |
| Desarrollo de extensiones | [Referencia de API](./api-reference.md) | Interfaces admitidas, compatibilidad de versiones y ejemplos verificados. |
| Formatos de intercambio de datos y comunicaciones seguras | [Arquitectura](./architecture.md) | Esquemas, transporte, autenticación y verificación de integridad. |

## Audiencia Objetivo

Esta documentación está destinada a:

- Administradores de TI y seguridad en entornos empresariales
- Profesionales de seguridad informática e investigadores
- Desarrolladores que integran Amaru con otros sistemas
- Usuarios avanzados que requieren configuración personalizada

## Mantenimiento y Actualización

Al cambiar un contrato o componente, actualiza su referencia y registra los resultados de las pruebas en el [informe de desarrollo](../../status_development.md).

## Contribuciones y Feedback

Si tienes comentarios técnicos, sugerencias o has identificado inexactitudes en la documentación, por favor contacta con nuestro equipo a través de [technical-docs@amaru-antivirus.com](mailto:technical-docs@amaru-antivirus.com).

---

**Nota**: La información contenida en estos documentos puede estar sujeta a acuerdos de confidencialidad. Consulta los términos específicos en cada documento.
