# Analizador estático con Radare2

El crate expone `Radare2Analyzer::analyze_file` para leer metadatos, secciones, importaciones y cadenas de un archivo local mediante Radare2. Devuelve un `AnalysisResult` y, si el cliente configura un emisor, notifica el inicio y el resultado del análisis. Los comportamientos y la puntuación de riesgo son inferencias heurísticas sobre los datos estáticos.

## Criterios de aceptación

- Un PE de control devuelve el tamaño, el SHA-256 y el tipo esperados, una sección de código con entropía calculada y al menos una importación conocida.
- Las rutas con espacios se pasan como un solo argumento. La ruta al ejecutable se puede indicar en `Radare2Config`, en `AMARU_RADARE2_PATH` o en `PATH`.
- Los indicadores de red y registro en un archivo de texto aparecen como evidencia. El archivo analizado se abre en modo de lectura.
- Ante un archivo ausente, un error de Radare2 o una respuesta JSON inválida, el análisis devuelve un error. El plazo configurado abarca el conjunto de consultas.

## Verificación

Con Rust y `r2` disponibles, ejecuta desde la raíz del repositorio:

```shell
cargo test --locked -p radare2-analyzer
```

Las pruebas de integración leen un ejecutable de identificación del compilador CMake incluido en el repositorio y un archivo de texto temporal. El análisis del PE cubre las salidas JSON de Radare2 5.8.8 y 6.2.6. La conexión de esta API con la aplicación principal de Windows requiere una prueba independiente.
