# Validación de firmas con EICAR

La regresión del issue #3 verifica que la regla distribuida `EICAR_Test_File` reconoce la cadena de prueba completa al principio, en medio y al final de un archivo. Usa la revisión `b1ba5e955314d7e673844c1366d9d2cf9b7e1180` del corpus de NDAAL. [Issue #3](https://github.com/CripterHack/Amaru/issues/3) · [Dataset fijado](https://gitlab.com/ndaal_open_source/ndaal_public_eicar_test_files/-/tree/b1ba5e955314d7e673844c1366d9d2cf9b7e1180/dataset)

## Criterios de aceptación

| Entradas del corpus | Cantidad | Resultado en YARA y YARA-X |
|---|---:|---|
| `eicar.com` (68 bytes) y `eicar.txt` (con salto de línea) | 2 | Coincide `EICAR_Test_File` |
| Serie completa `EICAR_position_variations`, con espacios o guiones bajos | 4 | Coincide `EICAR_Test_File` |
| Cinco series de `EICAR_128_characters`, con 1 a 129 repeticiones de CR, LF, Ctrl-Z, espacio o tabulador después de la cadena | 645 | Coincide `EICAR_Test_File` |
| Controles locales adicionales con un archivo vacío, texto ordinario y la cadena truncada | 3 | Cero coincidencias |

La cobertura comprende 651 entradas de NDAAL y tres controles por motor. Cada ejecución comprueba el SHA-256 de las seis muestras individuales y el identificador Git de cada uno de los cinco directorios reconstruidos. El archivo [test-eicar.txt](../../test-eicar.txt) contiene los 68 bytes de la muestra canónica. El resto de las entradas se reconstruye en memoria. Los tests leen la [regla de Amaru](../../signatures/official/eicar_test.yar) del checkout.

## Ejecución

Desde la raíz del repositorio, con un entorno virtual Python 3.10 o posterior activado, instala las dependencias y ejecuta la regresión.

```sh
python -m pip install -r scripts/requirements-signatures.txt
python -m unittest discover -s tests -p "test_eicar_corpus.py" -v
```

Con las dependencias instaladas, la prueba funciona sin red y devuelve un código de error si falla una comprobación. Los resultados corresponden al escaneo de bytes con las bibliotecas de YARA y YARA-X. La extracción de archivos comprimidos, la ejecución del servicio Windows y la respuesta de cuarentena requieren pruebas de integración independientes. [Prueba reproducible](../../tests/test_eicar_corpus.py)
