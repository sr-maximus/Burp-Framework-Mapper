# Burp Framework Mapper

[![CI](https://github.com/sr-maximus/Burp-Framework-Mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/sr-maximus/Burp-Framework-Mapper/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sr-maximus/Burp-Framework-Mapper/actions/workflows/codeql.yml/badge.svg)](https://github.com/sr-maximus/Burp-Framework-Mapper/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Extensión defensiva para Burp Suite que transforma hallazgos existentes —de
Burp Audit o introducidos manualmente— en un mapa técnico explicable y
exportable. Correlaciona localmente con CWE; OWASP Web, API, Mobile, MASVS,
ASVS y GenAI/LLM; MITRE ATT&CK Enterprise, Mobile e ICS; MITRE D3FEND, ATLAS y
Fight Fraud Framework (F3); y calcula CVSS 4.0 con el algoritmo oficial de
FIRST. No genera tráfico, no explota objetivos, no llama servicios externos y
no presenta una correlación como prueba de actividad adversaria o cumplimiento.

[English documentation](README_EN.md)

## Autoría

**Burp Framework Mapper fue concebido, creado e impulsado por Edwin Javier
Peñuela Camacho**, creador y propietario del proyecto. CWE, OWASP, MITRE,
FIRST y PortSwigger aportan marcos, datos o interfaces de terceros; no son
autores, certificadores, aprobadores ni patrocinadores de esta extensión.

Consulte el [manual completo de instalación, configuración y uso](docs/USER-MANUAL.md).

## Potencial real

La extensión permite pasar de un hallazgo aislado a una vista común para
AppSec, pentesting autorizado, gestión de vulnerabilidades, threat-informed
defense, arquitectura y riesgo. Para cada relación conserva versión,
identificador, título, naturaleza de la relación, confianza matemática,
señales, explicación, fuente oficial, fecha, limitaciones y superficie.

| Capacidad | Contenido incluido |
|---|---|
| Debilidad raíz | 11 reglas CWE 4.20. |
| Seguridad Web y API | OWASP Web 2025 (10), API 2023 (10) y ASVS 5.0.0 (6). |
| Seguridad móvil | OWASP Mobile 2024 (10) y MASVS 2.1.0 (8). |
| IA generativa | OWASP GenAI/LLM 2025 (10) y MITRE ATLAS 2026.07 (5). |
| Contexto adversario | ATT&CK 19.1 Enterprise (3), Mobile (2) e ICS (2). |
| Defensa y fraude | D3FEND 1.5.0 (5) y Fight Fraud Framework/F3 1.1 (4). |
| Severidad y salida | CVSS 4.0, matriz hallazgo×framework y JSON/CSV/Markdown/SARIF. |

Son 86 reglas curadas, no 86 afirmaciones de equivalencia. La herramienta
distingue lo declarado por el analista, las referencias oficiales, las
correlaciones propias del proyecto, el posible contexto de conducta adversaria
y las mitigaciones defensivas. Esto permite comunicar mejor el hallazgo sin
inventar evidencia ni convertir el resultado en una certificación. Vea la
[cobertura exacta](docs/FRAMEWORK-COVERAGE.md) y la
[metodología](docs/MAPPING-METHODOLOGY.md).

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

Las instrucciones detalladas para Windows, macOS y Linux, configuración,
verificación, solución de problemas y desinstalación están en el
[manual de usuario](docs/USER-MANUAL.md).

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
[privacidad](docs/PRIVACY.md), [manual de usuario](docs/USER-MANUAL.md) y
[validación en Burp](docs/BURP-VALIDATION.md).

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
