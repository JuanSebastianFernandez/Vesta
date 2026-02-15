# 🛡️ Proyecto VESTA: Resumen Ejecutivo y Técnico

**Objetivo:** Crear una solución europea integral de ciberseguridad para proteger **Smart Grids** (Redes Eléctricas Inteligentes) contra ataques de **Ransomware** y **Phishing**.

## 🏗️ 1. Arquitectura de Tres Pilares (Casos de Uso)

### A. Prevención (UC Prevención-01) - *Source Code Analyser*

Es la primera línea de defensa. Analiza el código fuente antes de que se despliegue.

* **Análisis Estático (SAST):** Usa un metamodelo de ML (SVM + CNN + Regresión Logística) para predecir si un archivo es malicioso.
* **El Motor de Extracción:** Se basa en **12 características clave** (originalmente de archivos ejecutables PE) que hemos "traducido" al código fuente mediante:
1. **ANTLR4:** Para un análisis gramatical profundo en Java (AST).
2. **Limpieza Heurística:** Una función de limpieza que elimina comentarios y strings para evitar falsos positivos en el conteo de palabras clave en otros lenguajes.


* **Análisis Dinámico (DAST):** Ejecución en sandboxes de **Docker** aislados, monitoreando tráfico de red con **Tshark/Wireshark** y llamadas al sistema.

### B. Defensa Activa (UC Defensa-02) - *Network Traffic Analyser*

Monitorización en tiempo real del tráfico de red de la Smart Grid.

* **Función:** Detectar anomalías, movimientos laterales y accesos no autorizados mediante modelos de Deep Learning.
* **Respuesta:** Si detecta una amenaza, dispara alertas al Dashboard y activa triggers automáticos (gRPC) hacia el módulo de contención o el Honeypot.

### C. Contención y Mitigación (UC Contención-03)

La última línea. Si el ataque penetra, este módulo aísla los nodos comprometidos y restaura el sistema usando backups, minimizando el tiempo de inactividad.

---

## 🧠 2. El "Core" de la IA: Las 12 Características Maestras

El modelo espera un vector de 12 valores numéricos. Para código fuente, usamos "proxies" (equivalentes lógicos):

| Característica | Definición en PE (Original) | Proxy en Código Fuente (Vesta) |
| --- | --- | --- |
| **SectionsMeanEntropy** | Entropía promedio de secciones. | Entropía del archivo limpio. |
| **ResourcesMaxEntropy** | Entropía máxima de recursos. | Entropía del bloque más complejo. |
| **SectionsMeanVirtualsize** | Tamaño promedio en memoria. | Tamaño total del código limpio. |
| **SizeOfStackCommit** | Memoria inicial de pila. | Conteo de la palabra clave `class`. |
| **MajorOSVersion** | Versión mayor del SO. | Conteo de la palabra clave `import`. |
| **ResourcesMeanEntropy** | Entropía promedio de recursos. | Entropía del archivo limpio (redundante). |
| **Name** | Longitud del nombre del archivo. | Longitud del nombre del archivo. |
| **SectionsMinRawsize** | Tamaño mínimo en disco. | `min(len(content), 1024)`. |
| **MinorSubsystemVersion** | Versión menor del subsistema. | Valor constante (Placeholder: 1). |
| **LoaderFlags** | Banderas del cargador. | Conteo de la palabra clave `static`. |
| **ImportsNbDLL** | Nº de DLLs importadas. | Conteo de la palabra clave `package`. |
| **ImageBase** | Dirección de carga preferida. | Conteo de la palabra clave `void`. |

---

Debido a que el requisito del proyecto exige tener datos sinteticos se ha creado un procesador de datos con codebert el cual crea una base de datos en paralelo que se encarga de ir llenando una base de datos con datos de codigos analizados para en el futuro entrenar un modelo de IA avanzado con redes neuronales.

## 🛠️ 3. Stack Tecnológico y Componentes Clave

* **Backend:** FastAPI (Python 3.12).
* **Analizador Estático:**
* `pefile`: Para archivos `.exe`/`.dll`.
* `ANTLR4`: Para parsing de Java.
* `Regex`: Para limpieza de código y conteo en Python, C++, etc.


* **Analizador Dinámico:** Docker SDK para Python, Tshark para análisis de PCAPs.
* **Machine Learning:** Scikit-learn (SVM, LR), TensorFlow/Keras (CNN), Joblib para carga de modelos.
* **Defensa:** Honeypots (Email/Network) integrados vía APIs y gRPC.

---

## 🚀 4. Lógica de Procesamiento (Workflow)

1. **Ingesta:** Se recibe un Webhook de GitHub/GitLab.
2. **Clonación:** El repositorio se descarga temporalmente.
3. **SAST:** * Limpieza de código (quitar comentarios/strings).
* Extracción de las 12 características.
* Predicción con el metamodelo de IA.


4. **DAST:**
* Se levanta un contenedor Docker efímero.
* Se ejecuta el código y se captura tráfico de red.
* Se analizan anomalías en el comportamiento.


5. **Reporte:** Se genera un JSON unificado con un **Score de Riesgo** y se envía al Dashboard.

---

## ⚠️ 5. Consideraciones Críticas para Programar

* **Inconsistencia de Versiones:** Los modelos fueron entrenados en `scikit-learn 1.4.0`. Si usas una versión superior (como 1.6.1), los archivos `.pkl` darán error de atributo (`transform_input`). **Solución:** Reentrenar o degradar la librería.
* **Seguridad del Sandbox:** Los contenedores Docker deben correr con privilegios limitados (`--cap-drop=ALL`) y red aislada.
* **Asincronía:** El análisis dinámico es lento; debe usarse `BackgroundTasks` o Celery para no bloquear la API.

---


