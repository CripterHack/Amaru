# Compatibilidad de reglas con YARA-X

Amaru incluye una herramienta opcional para comprobar sus reglas con YARA-X y analizar un archivo local. Permite evaluar la recomendación de la comunidad mientras el antivirus para Windows usa la biblioteca Rust `yara-engine` con YARA clásico. [Issue #2](https://github.com/CripterHack/Amaru/issues/2)

## Criterios de aceptación

- Compilar juntos todos los archivos `.yar` de `signatures/official` y `signatures/custom`, incluidos sus subdirectorios. Si falta el catálogo oficial o alguna regla resulta inválida o ilegible, el análisis debe terminar con un error.
- Leer un archivo ordinario y escribir en la salida estándar la lista JSON de identificadores coincidentes, ordenada alfabéticamente. El tiempo máximo de escaneo es de 30 segundos.
- Devolver código 0 cuando la lista está vacía, 1 cuando hay coincidencias y 2 cuando ocurre un error de entrada, compilación o escaneo. Los errores se escriben en la salida de diagnóstico.
- Ambos motores deben compilar el mismo catálogo. Las copias bajo `installer/signatures` deben coincidir con las fuentes.
- Ambos motores deben reconocer el control positivo EICAR y devolver una lista vacía ante los controles negativos. [Corpus y resultados esperados](./eicar-corpus.md)

## Ejecución

Desde la raíz del repositorio, instala las dependencias en un entorno virtual de Python 3.12. Las pruebas y los escaneos posteriores funcionan sin conexión.

```shell
python -m pip install --only-binary=:all: -r scripts/requirements-signatures.txt
python scripts/scan_yarax.py test-eicar.txt
python -m unittest discover -s tests -p "test_*.py" -v
```

El segundo comando devuelve `["EICAR_Test_File"]` y código 1. El resultado describe qué firmas coincidieron con el contenido. La eficacia frente a una familia de malware y la integración con el servicio de Windows requieren pruebas adicionales.

## Paquete de desarrollo

El trabajo `signatures` publica el artefacto `amaru-development-signatures` después de aprobar las pruebas del catálogo. Contiene las reglas oficiales y personalizadas, el escáner local, las versiones de sus dependencias y la licencia. Descarga el ZIP desde la ejecución de Actions de la revisión que quieras evaluar, extrae su contenido y ejecuta desde esa carpeta los comandos de instalación y análisis anteriores, indicando la ruta de tu archivo. El artefacto está disponible durante 14 días. [Validaciones en GitHub Actions](https://github.com/CripterHack/Amaru/actions/workflows/validation.yml)
