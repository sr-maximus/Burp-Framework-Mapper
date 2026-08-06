# Burp Framework Mapper

[![CI](https://github.com/sr-maximus/Burp-Framework-Mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/sr-maximus/Burp-Framework-Mapper/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sr-maximus/Burp-Framework-Mapper/actions/workflows/codeql.yml/badge.svg)](https://github.com/sr-maximus/Burp-Framework-Mapper/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Extensión defensiva para Burp Suite que clasifica hallazgos existentes y los
correlaciona de forma local, determinista y trazable con CWE, OWASP, MITRE y
CVSS v4.0. No genera tráfico, no explota objetivos, no llama servicios externos
y no presenta una correlación como prueba de actividad adversaria o cumplimiento.

[English documentation](README_EN.md)

## Qué aporta

- Entrada manual completa y envío desde el menú contextual de hallazgos Audit.
- Superficies separadas: Web, API, Mobile, AI/ML/LLM, Enterprise, ICS/OT,
  Fraud y Generic/Unknown.
- Catálogo curado de 86 reglas con versiones, URL oficial, fecha de verificación,
  relación semántica, explicación, límites y señales coincidentes.
- CVSS 4.0 calculado con el algoritmo de referencia oficial de FIRST.
- Resultados ordenables y filtrables con detalle “por qué”, resumen, matriz de
  correlación por hallazgo/framework y fuentes.
- Exportación local JSON, CSV, Markdown y SARIF 2.1.0, con esquema versionado.
- Validación de catálogo, pruebas unitarias, SpotBugs, CodeQL, SBOM CycloneDX y
  verificación de que Montoya no se empaqueta dentro del JAR.

## Instalación

Requisitos: Burp Suite con soporte Montoya y Java 21. Hasta completar la
[validación manual en Burp](docs/BURP-VALIDATION.md), compile el JAR desde una
copia revisada del código. Cuando exista una versión publicada, descárguela de
[Releases](https://github.com/sr-maximus/Burp-Framework-Mapper/releases),
verifique su SHA-256 publicado y en Burp abra **Extensions → Installed → Add →
Java**, seleccionando el archivo `burp-framework-mapper-*.jar`.

Para compilar desde una copia revisada del código:

```bash
./mvnw clean verify spotbugs:check
python3 tools/update_catalogs.py
python3 tools/verify_jar.py target/burp-framework-mapper-0.1.0.jar
```

El JAR sombreado queda en `target/`. Maven Wrapper descarga Maven 3.9.16 sobre
HTTPS; Java 21 es obligatorio.

## Uso

1. Abra la pestaña **Framework Mapper**.
2. Complete título, descripción, evidencia, activo, superficie, CWE/CVE, vector
   CVSS 4.0, contexto de negocio y etiquetas; o use **Send issue summary to
   Framework Mapper** desde un hallazgo Audit.
3. Seleccione **Analyze locally**.
4. Revise cada relación, confianza, señales, explicación, limitaciones y fuente.
5. Exporte solo tras revisar que los campos no contengan datos sensibles.

La importación desde Burp lee exclusivamente nombre, detalle, remediación, URL
base, severidad y confianza. Nunca lee ni exporta request/response, cookies,
cabeceras, cuerpo o interacciones Collaborator. Aun así, los textos de un
hallazgo pueden contener secretos; el importador aplica redacción y truncado,
pero la revisión humana sigue siendo obligatoria.

## Alcance y límites

El catálogo es un subconjunto curado, no una copia total de cada marco. Las
relaciones `CURATED_CORRELATION`, `CONTEXTUAL_ENABLEMENT` y
`DEFENSIVE_MITIGATION` expresan naturaleza distinta y nunca equivalencia. Un
resultado vacío es válido. Consulte [metodología](docs/MAPPING-METHODOLOGY.md),
[cobertura](docs/FRAMEWORK-COVERAGE.md), [fuentes](docs/DATA-SOURCES.md),
[privacidad](docs/PRIVACY.md) y [validación en Burp](docs/BURP-VALIDATION.md).

## Actualizar catálogos

`tools/generate_curated_catalog.py` reconstruye las 86 reglas revisadas.
`tools/update_catalogs.py --verify-upstream` valida estructura, unicidad, HTTPS,
conteos y los SHA-256 de las 15 fuentes. Un cambio upstream hace fallar la tarea
programada: no se acepta automáticamente y exige revisión humana del contenido,
licencia, versión, mapeo y pruebas antes de actualizar el manifiesto.

## Desarrollo y seguridad

Vea [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[arquitectura](docs/ARCHITECTURE.md) y [modelo de amenazas](docs/THREAT-MODEL.md).
No incluya datos reales de clientes en issues, pruebas o ejemplos.

Copyright © 2026 Edwin Javier Peñuela Camacho. Apache-2.0. Los marcos y marcas
de terceros conservan sus términos; vea [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
