# Manual de instalación, configuración y uso

## 1. Identidad y propósito

**Burp Framework Mapper fue concebido, creado e impulsado por Edwin Javier
Peñuela Camacho**, creador y propietario del proyecto.

Es una extensión defensiva de Burp Suite para organizar hallazgos ya existentes.
Recibe la descripción que introduce el analista o un resumen de uno o varios
hallazgos Audit y propone correlaciones locales, deterministas y trazables con
CWE, OWASP, MITRE y CVSS 4.0.

Sirve para:

- normalizar el lenguaje de un hallazgo sin sustituir el criterio profesional;
- relacionarlo con referencias útiles para análisis, priorización y comunicación;
- explicar por qué se propone cada relación y qué limitaciones tiene;
- separar afirmaciones del analista, referencias oficiales, correlaciones
  curadas, contexto adversario y mitigaciones defensivas;
- exportar resultados revisados a JSON, CSV, Markdown o SARIF 2.1.0.

No es un escáner, un explotador, una certificación de cumplimiento ni una
prueba de actividad adversaria. No genera tráfico, no envía payloads, no hace
fuerza bruta, no descarga exploits, no usa telemetría y no transmite hallazgos
a servicios externos.

### 1.1 Contenido real del catálogo

El catálogo `2026.08.06-2` aporta 96 reglas revisadas: CWE 4.20 (11); OWASP Top
10 Web 2025 (10), API Security 2023 (10), Mobile 2024 (10), MASVS 2.1.0 (8),
ASVS 5.0.0 (6) y GenAI/LLM 2025 (10); MITRE ATT&CK 19.1 Enterprise (3), Mobile
(2) e ICS (2); D3FEND 1.5.0 (5); ATLAS 2026.07 (5); AADAPT
2025.10.31-snapshot (10); y Fight Fraud Framework
(F3) 1.1 (4). CVSS 4.0 se calcula mediante la implementación de referencia de
FIRST.

La combinación permite observar el mismo hallazgo desde cinco ángulos sin
confundirlos: debilidad, verificación/control, posible contexto adversario,
defensa y severidad técnica. Los resultados alimentan filtros, detalle de
trazabilidad, resumen por framework, matriz hallazgo×framework y cuatro formatos
de exportación. La [tabla de cobertura](FRAMEWORK-COVERAGE.md) declara el alcance
real y las líneas que intencionalmente no se importan de forma masiva.

## 2. Usuarios y escenarios previstos

Está orientado a pentesters autorizados, analistas de seguridad, AppSec,
gestión de vulnerabilidades, equipos defensivos, arquitectura y riesgo.
Ejemplos de uso:

- enriquecer un hallazgo de SQL injection con CWE y controles OWASP aplicables;
- distinguir BOLA de coincidencias ambiguas en una API;
- contextualizar prompt injection o poisoning dentro de OWASP GenAI y ATLAS;
- contextualizar reentrancy, manipulación de oráculos, exposición de claves o
  replay de firmas dentro de AADAPT, sin afirmar que el comportamiento ocurrió;
- asociar almacenamiento móvil inseguro con OWASP Mobile y MASVS;
- documentar una posible técnica ATT&CK sin afirmar que el adversario la ejecutó;
- proponer una técnica D3FEND como consideración defensiva, no como garantía.

Use únicamente información obtenida dentro de un alcance autorizado. No copie
datos de clientes en issues públicos, ejemplos, capturas o repositorios.

## 3. Requisitos

- Burp Suite con soporte para la Montoya API utilizada por la extensión.
- Java 21. PortSwigger recomienda Java 21 para las extensiones Montoya actuales.
- Un JAR de Burp Framework Mapper construido y verificado.
- Para compilar: Git, conexión HTTPS para descargar Maven/dependencias y un JDK
  21. No es necesario instalar Maven globalmente porque se incluye Maven Wrapper.

La extensión compila contra Montoya API 2026.7 con alcance `provided`; Burp
aporta esa API en tiempo de ejecución y el JAR no debe contenerla.

## 4. Obtener el JAR

### 4.1 Estado previo a v0.1.0

El tag y release `v0.1.0` se publicarán únicamente después de completar la
[validación manual en Burp](BURP-VALIDATION.md). Mientras figure como pendiente,
compile desde una copia revisada del repositorio. No trate un artefacto de CI
como una versión liberada.

### 4.2 Compilar desde el código

En macOS o Linux:

```bash
git clone https://github.com/sr-maximus/Burp-Framework-Mapper.git
cd Burp-Framework-Mapper
./mvnw clean verify spotbugs:check
python3 tools/update_catalogs.py
python3 tools/verify_jar.py target/burp-framework-mapper-0.1.0.jar
```

En Windows PowerShell o Símbolo del sistema:

```powershell
git clone https://github.com/sr-maximus/Burp-Framework-Mapper.git
cd Burp-Framework-Mapper
.\mvnw.cmd clean verify spotbugs:check
python tools\update_catalogs.py
python tools\verify_jar.py target\burp-framework-mapper-0.1.0.jar
```

El artefacto queda en `target/burp-framework-mapper-0.1.0.jar`. La compilación
también produce `target/bom.json`, `target/bom.xml`, informes JUnit y cobertura
JaCoCo.

### 4.3 Descargar una versión publicada

Cuando exista una versión aprobada:

1. Abra [GitHub Releases](https://github.com/sr-maximus/Burp-Framework-Mapper/releases).
2. Descargue el JAR, `bom.json`, `bom.xml` y `SHA256SUMS.txt` del mismo release.
3. No mezcle archivos de versiones distintas.
4. Verifique la suma antes de cargar el JAR.

macOS o Linux:

```bash
shasum -a 256 burp-framework-mapper-0.1.0.jar
```

Windows PowerShell:

```powershell
Get-FileHash .\burp-framework-mapper-0.1.0.jar -Algorithm SHA256
```

El valor debe coincidir exactamente con `SHA256SUMS.txt` publicado.

## 5. Instalar en Burp Suite

1. Inicie Burp Suite.
2. Abra **Extensions → Installed**.
3. Seleccione **Add**.
4. Elija **Extension type: Java**.
5. En **Extension file**, seleccione `burp-framework-mapper-0.1.0.jar`.
6. Confirme la carga.
7. Revise el panel de errores de la extensión y compruebe que no haya errores.
8. Verifique que aparece la pestaña **Framework Mapper**.

No añada Jackson, Rhino ni Montoya como JAR separados. Las dependencias de
ejecución necesarias están sombreadas en el artefacto, salvo Montoya, que debe
ser aportada por Burp.

La carga real en Burp continúa documentada como pendiente hasta que se complete
la checklist reproducible de [BURP-VALIDATION.md](BURP-VALIDATION.md).

## 6. Configuración

Burp Framework Mapper no necesita cuenta, clave API, token, servidor, base de
datos ni archivo de configuración. Su configuración funcional se realiza por
hallazgo desde el formulario.

| Campo | Uso |
|---|---|
| Title | Nombre corto y específico del hallazgo; es obligatorio. |
| Description | Condición técnica observada, sin secretos innecesarios. |
| Evidence | Evidencia mínima y sintética o ya revisada. |
| Asset / URL | Activo o URL base; evite query strings sensibles. |
| Surface | Web, API, Mobile, AI/ML/LLM, Enterprise, ICS/OT, Digital Assets/Web3, Fraud o Generic/Unknown. |
| CWE | Uno o varios identificadores, separados por coma o espacio. |
| CVE | Referencia opcional; no altera por sí sola la correlación. |
| CVSS 4.0 | Vector completo que será validado y puntuado localmente. |
| Business context | Contexto para interpretación humana; no se transforma automáticamente en probabilidad. |
| Tags | Etiquetas locales separadas por coma. |

El encabezado de la pestaña muestra la versión del catálogo y el número de
reglas cargadas. La apariencia utiliza componentes Swing y hereda el tema de
Burp. No hay persistencia automática: al descargar la extensión se pierde el
estado no exportado.

## 7. Elegir la superficie

Seleccione la superficie real del hallazgo para reducir falsos positivos:

| Superficie | Cuándo usarla |
|---|---|
| Web | Navegadores, HTML, sesiones y aplicaciones web tradicionales. |
| API | REST, GraphQL u otras interfaces de servicio. |
| Mobile | Aplicaciones o controles propios de plataformas móviles. |
| AI/ML/LLM | Modelos, prompts, RAG, datos de entrenamiento o cadena de IA. |
| Enterprise | Entornos y comportamientos empresariales generales. |
| ICS/OT | Sistemas industriales y tecnología operacional. |
| Digital Assets / Web3 | Smart contracts, blockchain, wallets, oráculos, firmas y pagos con activos digitales. |
| Fraud | Abuso de cuentas, credenciales y escenarios de fraude. |
| Generic/Unknown | No existe evidencia suficiente para una superficie más precisa. |

Una palabra coincidente en una superficie incompatible no debe producir una
relación curada, salvo que el usuario haya declarado explícitamente un
identificador oficial. Un CWE exacto sí puede aparecer como identidad
taxonómica.

## 8. Analizar un hallazgo manual

1. Abra **Framework Mapper**.
2. Seleccione **Load safe example** si desea conocer el flujo sin datos reales.
3. Complete al menos **Title** y seleccione la superficie.
4. Añada solo evidencia necesaria y revisada.
5. Si dispone de CWE o CVSS, introdúzcalos explícitamente.
6. Pulse **Analyze locally**.
7. Espere el estado **Completed**; el análisis se ejecuta fuera del hilo de UI.
8. Revise **Results**, **Why / source**, **Summary** y **Correlation matrix**.
9. Aplique filtros por framework, relación y confianza.
10. Exporte únicamente después de revisar contenido, fuentes y limitaciones.

Un resultado sin correlaciones es válido. No modifique el texto para forzar una
coincidencia si no existe sustento técnico.

## 9. Importar hallazgos Audit desde Burp

1. Seleccione uno o varios `AuditIssue` en una vista compatible de Burp.
2. Abra el menú contextual.
3. Elija **Send issue summary to Framework Mapper**.
4. Abra la pestaña **Framework Mapper**.
5. Revise y corrija los campos importados antes de analizar.

El importador lee exclusivamente nombre, detalle, remediación, URL base,
severidad y confianza. No invoca solicitudes/respuestas, cookies, cabeceras,
cuerpos completos ni interacciones Collaborator. El texto se limita, se retira
contenido `script`/`style`, se redactan patrones comunes de secretos y la URL se
reduce a su base sin query ni fragmento. Estas medidas no sustituyen la revisión
humana porque formatos de secreto inusuales pueden permanecer.

Cuando el resumen contiene expresiones inequívocas como `smart contract`,
`blockchain`, `Web3`, `digital asset`, `oracle manipulation` o `reentrancy`, el
importador propone la superficie **Digital Assets / Web3**. Es solo una ayuda
determinista: el analista debe corregirla antes del análisis si el contexto real
es Web, API, fraude u otra superficie.

## 10. Interpretar los resultados

Cada fila contiene framework, versión, identificador, título, relación,
confianza, superficie y explicación. La vista de detalle añade señales, URL
oficial, fecha de verificación y limitaciones.

| Relación | Interpretación correcta |
|---|---|
| `INPUT_ASSERTED` | El identificador fue declarado por Burp o por el analista; no se redescubrió. |
| `OFFICIAL_REFERENCE` | La relación está expresamente sustentada por la fuente oficial indicada. |
| `CURATED_CORRELATION` | Es una relación revisada y documentada por el proyecto, no una equivalencia oficial. |
| `CONTEXTUAL_ENABLEMENT` | La debilidad podría facilitar una conducta; no prueba que esa conducta ocurrió. |
| `DEFENSIVE_MITIGATION` | La técnica defensiva puede ser pertinente; no garantiza remediación. |

La confianza es una puntuación determinista de coincidencia, no probabilidad de
explotación. El orden de señales es: CWE exacto, identificador declarado,
expresión inequívoca, segunda expresión, superficie y contexto. Consulte la
fórmula completa en [MAPPING-METHODOLOGY.md](MAPPING-METHODOLOGY.md).

La matriz cuenta correlaciones por hallazgo y framework. Sirve para comparar
cobertura; no convierte más coincidencias en mayor severidad o riesgo.

## 11. CVSS 4.0

Introduzca un vector completo que comience por `CVSS:4.0/`. El motor valida
versión, métricas obligatorias, orden y duplicados, y utiliza localmente los
archivos del calculador oficial de referencia de FIRST. Muestra vector,
puntuación y severidad.

CVSS mide severidad técnica bajo sus supuestos. No equivale automáticamente a
riesgo de negocio, probabilidad de explotación, prioridad final ni aceptación
de riesgo. Combine el resultado con exposición, controles, activos, impacto y
evidencia contextual; vea [RISK-INTERPRETATION.md](RISK-INTERPRETATION.md).

## 12. Exportar resultados

Los botones **Export JSON**, **Export CSV**, **Export Markdown** y **Export
SARIF** guardan archivos únicamente en la ruta elegida por el usuario.

- JSON usa esquema `1.0.0`; el contrato está en
  `src/main/resources/schema/analysis-report.schema.json`.
- CSV neutraliza celdas que podrían interpretarse como fórmulas.
- Markdown escapa HTML y separadores de tabla.
- SARIF 2.1.0 usa ubicaciones lógicas para evitar que un visor trate el activo
  como una URI física que deba abrirse.

La extensión exige un directorio padre existente, añade la extensión esperada,
rechaza enlaces simbólicos como destino, solicita confirmación antes de
sobrescribir y utiliza un archivo temporal con movimiento atómico cuando el
sistema de archivos lo permite.

Los reportes pueden seguir conteniendo información sensible introducida por el
usuario. Aplique las políticas de clasificación, retención y acceso de su
organización.

## 13. Catálogo y fuentes

El catálogo `2026.08.06-2` contiene 96 reglas curadas y no es una copia completa
de cada framework. `SOURCE_MANIFEST.json` registra 16 fuentes oficiales con
versión, consulta, URL, términos, SHA-256, dominio y conteos.

Para verificar el catálogo embebido:

```bash
python3 tools/update_catalogs.py
```

Para volver a descargar los artefactos oficiales fijados y comprobar sus
digests:

```bash
python3 tools/update_catalogs.py --verify-upstream
```

Para regenerar las reglas curadas desde el generador revisado:

```bash
python3 tools/generate_curated_catalog.py
git diff -- src/main/resources/mappings/correlations.json
```

Un cambio upstream debe detener la automatización. No actualice un digest sin
revisar versión, contenido, licencia, conteos, títulos, mapeos y pruebas.

## 14. Privacidad y seguridad operacional

- El análisis principal no realiza llamadas de red.
- La extensión no contiene credenciales ni configuración de telemetría.
- Solo el actualizador ejecutado conscientemente por un desarrollador descarga
  fuentes oficiales HTTPS.
- Los errores de UI se muestran de forma resumida; no se registran cuerpos HTTP.
- El HTML proveniente del texto de Burp se trata como texto, no como contenido
  activo renderizable.
- El vector CVSS no se concatena como código; se valida y pasa como argumento a
  una función fija en un entorno Rhino sin acceso a clases Java.

Consulte [PRIVACY.md](PRIVACY.md), [THREAT-MODEL.md](THREAT-MODEL.md) y
[SECURITY.md](../SECURITY.md).

## 15. Solución de problemas

### No aparece la pestaña

- Confirme que añadió el JAR como extensión **Java**.
- Revise **Extensions → Installed** y el registro de errores.
- Verifique Java 21 y que el JAR no esté corrupto.
- No cargue el JAR original sin dependencias; use el artefacto sombreado final.

### Error de clase Montoya

- Actualice Burp a una versión compatible con Montoya 2026.7.
- No añada `montoya-api` dentro del JAR ni como dependencia duplicada.

### El análisis no devuelve resultados

- Compruebe la superficie, CWE y expresiones técnicas.
- Consulte [FRAMEWORK-COVERAGE.md](FRAMEWORK-COVERAGE.md).
- Recuerde que el catálogo es finito y que una salida vacía es válida.

### CVSS aparece como inválido

- Use un vector completo `CVSS:4.0/...`.
- Compruebe métricas base obligatorias, orden y duplicados.
- No incluya saltos de línea ni texto ejecutable.

### No se puede exportar

- Elija un directorio existente con permisos de escritura.
- Use la extensión sugerida.
- No seleccione un enlace simbólico.
- Confirme conscientemente la sobrescritura cuando el archivo ya exista.

### La interfaz parece bloqueada o incompatible

- Registre la versión/edición de Burp, sistema operativo y Java.
- Reproduzca con el ejemplo sintético, sin datos de cliente.
- Consulte la checklist y reporte el problema según [SECURITY.md](../SECURITY.md)
  o el sistema de issues, según corresponda.

## 16. Actualizar la extensión

1. Exporte y proteja cualquier resultado que necesite conservar.
2. Descargue o compile la nueva versión.
3. Verifique su SHA-256 y notas de release.
4. En **Extensions → Installed**, retire la versión anterior.
5. Añada el nuevo JAR y repita las comprobaciones de carga.

No asuma compatibilidad de catálogos o esquemas entre versiones; revise el
changelog y la versión de esquema exportada.

## 17. Desinstalar

1. Abra **Extensions → Installed**.
2. Seleccione Burp Framework Mapper.
3. Pulse **Remove**.
4. Elimine por separado los reportes exportados según su política de datos.

La extensión no crea cuentas, servicios, bases de datos, demonios ni
configuración persistente. Al retirarla no debe quedar actividad en segundo
plano.

## 18. Verificación para desarrolladores

Antes de proponer un cambio:

```bash
./mvnw clean verify spotbugs:check
python3 tools/update_catalogs.py
python3 tools/verify_jar.py target/burp-framework-mapper-0.1.0.jar
```

Para una comprobación completa de procedencia, añada
`python3 tools/update_catalogs.py --verify-upstream`. No publique tag o release
si CI, CodeQL, revisión de dependencias, inspección del JAR o validación manual
obligatoria están pendientes.

## 19. Autoría, licencia y terceros

Burp Framework Mapper y su lógica original son obra de **Edwin Javier Peñuela
Camacho**, creador, propietario e impulsor del proyecto. El código del proyecto
se distribuye bajo Apache-2.0.

Los nombres, marcas, identificadores, datos e implementaciones de terceros
conservan sus propios términos. Su referencia permite interoperabilidad y
clasificación; no implica que MITRE, OWASP, FIRST, PortSwigger ni el Center for
Threat-Informed Defense sean autores, certifiquen, aprueben o patrocinen Burp
Framework Mapper. Consulte [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md),
`SOURCE_MANIFEST.json`, `LICENSE` y `NOTICE`.
