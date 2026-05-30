// About → "Learn about Sentinella" help-topic content.
//
// Long-form prose lives here (not in the flat i18n string map) because each
// section is an array of paragraphs. The page picks the active locale's record
// via getLocale(); English is the fallback for any future locale.

import {
  Cpu, ShieldCheck, Layers, Microscope, Box, Server, Zap, Gauge, GitBranch, EyeOff,
} from "lucide-react";

export type HelpTopic =
  | "what-is-sentinella"
  | "what-is-argus"
  | "why-clamav"
  | "why-sandbox"
  | "why-workers"
  | "why-realtime-first"
  | "performance"
  | "open-source"
  | "privacy"
  | "technical-architecture";

export interface TopicData {
  icon: typeof Cpu;
  title: string;
  subtitle: string;
  sections: { heading: string; body: string[] }[];
}

const en: Record<HelpTopic, TopicData> = {
  "what-is-sentinella": {
    icon: ShieldCheck,
    title: "What is Sentinella?",
    subtitle: "A local-first antivirus built to protect your computer — not fight against it",
    sections: [
      {
        heading: "",
        body: [
          "Sentinella is an open-source antivirus suite for Windows designed around a simple idea: security software should be understandable, lightweight, and respectful of the machine it protects.",
          "Everything runs locally on your computer. No cloud dependency, no hidden telemetry, and no subscriptions required.",
          "Sentinella combines trusted signature scanning with layered behavioral analysis to help detect both known threats and suspicious activity, while staying responsive during everyday use.",
        ],
      },
      {
        heading: "How protection works",
        body: [
          "Real-time protection watches important areas like Downloads and Desktop for new or modified files. Background scans run quietly when your system is idle and yield automatically under pressure. Suspicious files can be isolated in a secure quarantine and analyzed safely. Manual scans never interrupt real-time protection.",
        ],
      },
      {
        heading: "Design philosophy",
        body: [
          "Real-time protection comes first. Your computer should stay responsive. Detections should be explainable. Quarantined files should be recoverable. Open-source software should be auditable. Security should not rely on fear or mystery.",
          "Sentinella was built for people who want security software they can trust — not just because it detects threats, but because it explains itself honestly.",
        ],
      },
    ],
  },
  "what-is-argus": {
    icon: Layers,
    title: "What is ARGUS?",
    subtitle: "Sentinella's layered suspicion engine",
    sections: [
      {
        heading: "Beyond binary verdicts",
        body: [
          "Traditional antivirus gives binary answers: infected or clean. ARGUS, powered by ASTRA adaptive analysis, takes a different approach. It assigns a suspicion score from 0 to 100 based on evidence from multiple independent analysis layers. No single layer can declare a file malicious alone.",
          "This means a file with one suspicious trait stays in the \"Unusual\" range, while a file exhibiting credential theft patterns, network exfiltration, and process injection converges toward \"Malicious\" through multiple independent signals.",
        ],
      },
      {
        heading: "The layers",
        body: [
          "Layer 0 (Signatures): ClamAV's database of known malware signatures. Layer 1 (MIME/Type): Detects files disguised as other formats, double extensions, and right-to-left override tricks. Layer 2 (PE Heuristics): Analyzes Windows executables for exploit techniques, suspicious imports, packing, and structural anomalies.",
          "Layer 3 (Reputation): Checks file metadata against known software patterns. Layer 4 (Context): Considers where the file was found, how it was named, and suspicious environmental signals. Layer 5 (IOC): Matches file hashes against known indicators of compromise.",
          "Layer 6 (YARA): Custom behavioral rules written in the YARA pattern matching language. Layer 7 (Correlation): Cross-references findings across all layers to build convergence chains and detect multi-stage attack patterns. Layer 8 (Behavioral Runtime): Optional sandbox detonation feeds behavioral observations back into the scoring system.",
        ],
      },
      {
        heading: "Convergence, not thresholds",
        body: [
          "ARGUS scores, driven by ASTRA's adaptive convergence logic, are not arbitrary thresholds. A file reaches \"High Risk\" or \"Malicious\" only when multiple categories of evidence converge: credential theft + network activity, or process injection + persistence + anti-analysis. Single-category findings are capped to prevent one noisy signal from triggering false positives.",
          "Every finding carries a BehaviorTag, an AttackStage, and a confidence weight. The final score reflects how many independent lines of evidence point to the same conclusion.",
        ],
      },
    ],
  },
  "why-clamav": {
    icon: Microscope,
    title: "Why ClamAV?",
    subtitle: "Battle-tested open-source signature engine",
    sections: [
      {
        heading: "Known threats, known answers",
        body: [
          "For malware that has already been identified and catalogued, signature scanning is fast and definitive. ClamAV maintains a database of millions of malware signatures that can identify known threats in milliseconds.",
          "ARGUS handles the unknown; ClamAV handles the known. Together, they cover both sides of the detection problem without either component trying to do everything.",
        ],
      },
      {
        heading: "Open-source trust",
        body: [
          "ClamAV is developed by Cisco's Talos Intelligence Group and is the most widely deployed open-source antivirus engine in the world. Its signature database is updated multiple times per day and is freely available.",
          "Using ClamAV means Sentinella's signature scanning is not a black box. The engine's source code, signature format, and detection logic are publicly auditable.",
        ],
      },
      {
        heading: "Subprocess isolation",
        body: [
          "ClamAV loads a large signature database into memory (~400 MB). Sentinella optionally runs ClamAV in an isolated subprocess (clamavd) so that if a malformed sample triggers a crash in the parsing engine, only the worker process dies. The daemon survives and can spawn a new worker.",
          "This crash isolation is configurable. For machines with limited RAM, in-process scanning uses the already-loaded engine with no extra memory cost.",
        ],
      },
    ],
  },
  "why-sandbox": {
    icon: Box,
    title: "Why behavioral sandboxing?",
    subtitle: "Observing what suspicious files actually do",
    sections: [
      {
        heading: "The gap between static and dynamic",
        body: [
          "Static analysis (reading a file's structure) can only tell you what a program could do. Behavioral analysis tells you what it actually does when executed. Some malware is designed specifically to look clean under static analysis and only reveals its true behavior at runtime.",
          "Sentinella's sandbox runs suspicious files in a tightly controlled environment, observes their behavior, and feeds the results back into the ARGUS scoring system.",
        ],
      },
      {
        heading: "Containment layers",
        body: [
          "Sandboxed processes run with a restricted Windows token (most privileges stripped), at Low Integrity level (cannot write to system locations), inside a Job Object (cannot spawn escape processes, limited to 512 MB memory), and with per-process firewall rules blocking all network access.",
          "The process is created in a suspended state. All containment is applied before the first instruction runs. There is no window where the sample can act before restrictions take effect.",
        ],
      },
      {
        heading: "ETW runtime observation",
        body: [
          "Event Tracing for Windows (ETW) is a kernel-level instrumentation framework built into Windows. Sentinella uses ETW to observe sandboxed processes without injecting code or modifying the sample. This captures process creation, DLL loading from suspicious paths, registry persistence attempts, and network connection attempts.",
          "ETW is a local observation mechanism. It does not transmit data anywhere. It is the same infrastructure that Windows uses internally for performance monitoring and debugging.",
        ],
      },
      {
        heading: "Non-blocking by design",
        body: [
          "Sandbox detonation can take 30+ seconds. Real-time protection never waits for it. When the watcher identifies a file that needs sandboxing, detonation runs on a background thread while the watcher continues scanning the next file immediately. If the sandbox later determines the file is dangerous, quarantine happens asynchronously.",
        ],
      },
    ],
  },
  "why-workers": {
    icon: Server,
    title: "Why modular workers?",
    subtitle: "Process isolation for resilience",
    sections: [
      {
        heading: "The crash boundary principle",
        body: [
          "Sentinella separates its work into independent processes: the main daemon (sentinelld), the ClamAV scanner (clamavd), the behavioral sandbox (sandboxd), and optionally an external ARGUS worker. Each runs as a separate OS process.",
          "If ClamAV crashes while parsing a malformed PDF, only clamavd dies. The daemon continues running, real-time protection stays active, and the user sees no interruption. A new clamavd worker is spawned on the next scan.",
        ],
      },
      {
        heading: "Memory boundaries",
        body: [
          "Each ClamAV subprocess loads ~400 MB of signatures independently. Sentinella limits concurrent ClamAV workers to prevent memory explosion. The sandbox worker runs at most one detonation at a time. These are hard limits enforced by atomic counters, not configuration suggestions.",
        ],
      },
      {
        heading: "Panic recovery",
        body: [
          "Inside the daemon, the scan orchestrator uses panic-catching wrappers around every job. If a scan thread panics (a programming error, not a security event), the worker thread recovers, increments a crash counter for diagnostics, and continues processing the next job. No user intervention required.",
        ],
      },
    ],
  },
  "why-realtime-first": {
    icon: Zap,
    title: "Why realtime-first?",
    subtitle: "Protection that never yields",
    sections: [
      {
        heading: "The non-negotiable rule",
        body: [
          "Real-time protection is the most important function of any antivirus. If a user starts a full disk scan, real-time protection must continue working at full speed. If the system is under memory pressure, manual scans degrade first. Real-time never degrades silently.",
        ],
      },
      {
        heading: "Architectural separation",
        body: [
          "The real-time watcher runs on its own dedicated thread, independent of the scan orchestrator. Manual scans (quick, folder, full) run on separate worker threads. The idle background scanner runs on yet another thread and automatically pauses when a manual scan is active.",
          "These are not priorities in a shared queue. They are physically separate execution paths. The watcher cannot be starved by a busy scan queue because it does not use the scan queue.",
        ],
      },
      {
        heading: "Graceful degradation",
        body: [
          "When system resources are constrained, Sentinella degrades in a specific order: the idle scanner pauses first (CPU, disk, battery, fullscreen, memory pressure all trigger pause). Manual scans continue but with bounded thread count. Real-time protection continues unconditionally.",
          "If ClamAV subprocess slots are all occupied by manual scans, the watcher falls back to in-process ClamAV scanning. This is slightly less isolated but functionally identical. Detection quality is never reduced.",
        ],
      },
    ],
  },
  performance: {
    icon: Gauge,
    title: "Performance philosophy",
    subtitle: "Your computer is yours",
    sections: [
      {
        heading: "Invisible when idle",
        body: [
          "The idle background scanner monitors CPU load, disk I/O, battery state, and whether the user is in a fullscreen application. It only scans when system resources are genuinely available. During compilation, gaming, or video editing, it pauses automatically.",
          "There is no fixed scan schedule that interrupts work. The scanner asks: \"Can I scan without the user noticing?\" If the answer is no, it waits.",
        ],
      },
      {
        heading: "Smart file filtering",
        body: [
          "Not every file needs deep analysis. ARGUS uses a scan strategy system: known-safe file types (images, fonts, logs) get signature-only checks. Executables and scripts get full multi-layer analysis. Build artifacts and package caches are skipped entirely during quick scans.",
          "The real-time watcher applies extension filtering to avoid scanning files that cannot contain executable code: images, fonts, audio/video, lock files, and build intermediates.",
        ],
      },
      {
        heading: "Bounded resource usage",
        body: [
          "Manual scans use a fixed thread count (4 workers). ClamAV subprocesses are capped at 2 concurrent instances. Sandbox detonations are limited to 1 at a time. These are hard limits, not suggestions. Sentinella will never scale up to consume all available CPU or RAM.",
          "A memory pressure system monitors the daemon's RSS. Under elevated pressure, new scans route to external workers to keep the daemon's memory footprint stable. Under critical pressure, the idle scanner pauses entirely.",
        ],
      },
    ],
  },
  "open-source": {
    icon: GitBranch,
    title: "Open-source philosophy",
    subtitle: "Security through transparency",
    sections: [
      {
        heading: "Why open source matters for security",
        body: [
          "An antivirus runs with some of the highest privileges on your system. It reads every file, monitors every process, and can quarantine anything it deems suspicious. You should be able to read its source code and verify that it does exactly what it claims.",
          "Sentinella is licensed under GPLv2. The detection logic, the quarantine implementation, the IPC protocol, and every scan decision are publicly auditable. There is no proprietary detection engine hiding behind a marketing name.",
        ],
      },
      {
        heading: "Explainable detections",
        body: [
          "Every ARGUS finding includes the layer that produced it, the behavior tag it matched, the confidence weight assigned, and the attack stage classification. When Sentinella quarantines a file, you can see exactly why: which rules fired, what evidence converged, and what the final score was.",
          "This is not just for developers. It means you can distinguish between a false positive (one rule firing on a legitimate installer) and a real threat (multiple independent signals converging on credential theft + exfiltration).",
        ],
      },
      {
        heading: "Community and attribution",
        body: [
          "Sentinella is built by Lucent Open Software and the Sentinella community. It uses ClamAV (developed by Cisco's Talos Intelligence Group) for signature scanning and the YARA pattern matching engine for behavioral rules. All dependencies are open-source and properly attributed.",
        ],
      },
    ],
  },
  privacy: {
    icon: EyeOff,
    title: "Privacy & telemetry",
    subtitle: "What Sentinella does not do",
    sections: [
      {
        heading: "Zero telemetry",
        body: [
          "Sentinella does not collect, transmit, or store any usage data, scan results, detection statistics, or system information. There is no analytics endpoint, no crash reporting service, no \"anonymous usage data\" toggle. The daemon makes exactly one type of outgoing network connection: downloading ClamAV signature updates from ClamAV's official mirror.",
        ],
      },
      {
        heading: "No cloud scanning",
        body: [
          "Your files are never uploaded anywhere. All analysis (ClamAV scanning, ARGUS heuristics, YARA rules, behavioral sandbox) runs locally on your machine. There is no cloud lookup, no hash submission, no file sample sharing. This is a deliberate design choice, not a limitation.",
          "Commercial antivirus products often upload suspicious files or file hashes to cloud services for additional analysis. Sentinella does not. The trade-off is that Sentinella relies on its local engines and cannot benefit from real-time cloud intelligence. The benefit is that your files stay on your machine.",
        ],
      },
      {
        heading: "No HTTPS interception",
        body: [
          "Sentinella does not install root certificates, proxy HTTPS traffic, or inspect encrypted network connections. Some security products intercept TLS connections to scan web traffic. This approach weakens the security of every HTTPS connection on the machine and is architecturally incompatible with Sentinella's philosophy.",
        ],
      },
      {
        heading: "No kernel driver (v1)",
        body: [
          "Sentinella v1 operates entirely in user mode. It does not install kernel drivers, minifilter filesystem drivers, or kernel-level hooks. This limits some detection capabilities (pre-execution blocking, kernel rootkit detection) but eliminates an entire class of system stability risks.",
          "The real-time watcher uses ReadDirectoryChangesW (a standard Windows API) and the behavioral sandbox uses ETW (Event Tracing for Windows) for runtime observation. Both are documented, stable, user-mode interfaces.",
        ],
      },
    ],
  },
  "technical-architecture": {
    icon: Cpu,
    title: "Technical architecture",
    subtitle: "Developer-oriented reference for Sentinella's internals",
    sections: [
      {
        heading: "System architecture",
        body: [
          "Sentinella runs as a Rust daemon (sentinelld) that exposes a JSON-RPC 2.0 API over Windows named pipes. The GUI is a Tauri 2.x application (React + TypeScript) that communicates with the daemon for all security operations. The daemon owns all state: scan engine, quarantine vault, real-time watcher, and background scanner.",
          "Protection layers run independently: a real-time filesystem watcher monitors Downloads, Desktop, and Temp for new files; an idle background scanner proactively checks dormant files during low system activity; and user-initiated scans (quick, folder, full) run on demand without interfering with real-time protection.",
        ],
      },
      {
        heading: "Scan orchestrator",
        body: [
          "The orchestrator manages three independent queues: Realtime (1 worker), Manual (2 workers), and Idle (1 worker). Each queue has its own mpsc channel and worker threads. Jobs carry a CancellationToken for cooperative cancellation. Worker threads use panic-catching wrappers for crash recovery.",
          "Queue pressure is monitored via atomic counters. Idle workers add a 250ms delay between jobs to prevent CPU spikes. Manual scan workers use a core-relative thread pool with chunked file distribution.",
        ],
      },
      {
        heading: "Process model",
        body: [
          "Sentinella separates work into independent OS processes for crash isolation: sentinelld (main daemon), clamavd (isolated ClamAV scanner, max 2 concurrent), sandboxd (behavioral detonation, max 1 concurrent), and optionally an external ARGUS worker. Each process boundary means a crash in one component does not bring down the others.",
          "ClamAV subprocess isolation is configurable. Each clamavd instance loads ~400 MB of signatures independently. Concurrency is gated by atomic counters with RAII guards for automatic cleanup.",
        ],
      },
      {
        heading: "Behavioral sandbox internals",
        body: [
          "Sandboxed processes run with a restricted Windows token (DISABLE_MAX_PRIVILEGE), at Low Integrity level (S-1-16-4096), inside a Job Object (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, no breakaway, 512 MB memory cap), and with per-PID firewall rules (netsh advfirewall) blocking all network access.",
          "The process is created via CreateProcessAsUserW in CREATE_SUSPENDED state. All containment (Job Object assignment, firewall rules) is applied before ResumeThread is called. ETW kernel sessions (StartTraceW/OpenTraceW/ProcessTrace) monitor process creation, DLL loads, registry persistence, and TCP connections via EVENT_RECORD callbacks.",
        ],
      },
      {
        heading: "IPC protocol",
        body: [
          "The daemon listens on a named pipe (\\\\.\\pipe\\sentinella). Requests use JSON-RPC 2.0 with method routing (scan.start, scan.status, quarantine.list, etc.). Dangerous commands (quarantine.restore, protection.set_critical) require a challenge-response flow: the GUI requests a single-use token via challenge.request (authenticated with an IPC secret), then passes the token to the protected command.",
          "Scan status uses a lock-free fast path: atomic counters (files_scanned, threats_found, status) are read without acquiring the inner mutex, so IPC polling never blocks scan worker threads.",
        ],
      },
      {
        heading: "ARGUS engine layers · ASTRA adaptive analysis",
        body: [
          "Layer 0: ClamAV signature database. Layer 1: MIME/type analysis (double extensions, RTLO, PE-as-PDF). Layer 2: PE heuristic analysis (exploit detection, import analysis, packing, structural anomalies). Layer 3: Reputation matching (domain-gated, word-boundary patterns). Layer 4: Context analysis (path, filename, environmental signals). Layer 5: IOC hash matching. Layer 6: YARA behavioral rules. Layer 7: Cross-layer correlation (convergence chains, attack stage progression). Layer 8: Behavioral runtime (sandbox detonation feedback). ASTRA orchestrates these layers with profile-aware bounded execution, ensuring deterministic and resource-intelligent analysis.",
          "Scores are not arbitrary thresholds. Single-category findings are capped. A file reaches High Risk or Malicious only through multi-category convergence. Every finding carries a BehaviorTag, AttackStage, confidence weight, and ThreatMaturity classification.",
        ],
      },
    ],
  },
};

const es: Record<HelpTopic, TopicData> = {
  "what-is-sentinella": {
    icon: ShieldCheck,
    title: "¿Qué es Sentinella?",
    subtitle: "Un antivirus local primero, hecho para proteger tu computadora — no para pelear contra ella",
    sections: [
      {
        heading: "",
        body: [
          "Sentinella es una suite antivirus de código abierto para Windows diseñada en torno a una idea simple: el software de seguridad debe ser comprensible, ligero y respetuoso con la máquina que protege.",
          "Todo se ejecuta localmente en tu computadora. Sin dependencia de la nube, sin telemetría oculta y sin suscripciones.",
          "Sentinella combina el escaneo de firmas confiable con análisis de comportamiento por capas para detectar tanto amenazas conocidas como actividad sospechosa, manteniéndose ágil durante el uso diario.",
        ],
      },
      {
        heading: "Cómo funciona la protección",
        body: [
          "La protección en tiempo real vigila áreas importantes como Descargas y Escritorio en busca de archivos nuevos o modificados. Los escaneos en segundo plano se ejecutan en silencio cuando el sistema está inactivo y ceden automáticamente bajo presión. Los archivos sospechosos pueden aislarse en una cuarentena segura y analizarse sin riesgo. Los escaneos manuales nunca interrumpen la protección en tiempo real.",
        ],
      },
      {
        heading: "Filosofía de diseño",
        body: [
          "La protección en tiempo real va primero. Tu computadora debe seguir ágil. Las detecciones deben ser explicables. Los archivos en cuarentena deben ser recuperables. El software de código abierto debe ser auditable. La seguridad no debe basarse en el miedo ni en el misterio.",
          "Sentinella fue creado para personas que quieren software de seguridad en el que puedan confiar — no solo porque detecta amenazas, sino porque se explica con honestidad.",
        ],
      },
    ],
  },
  "what-is-argus": {
    icon: Layers,
    title: "¿Qué es ARGUS?",
    subtitle: "El motor de sospecha por capas de Sentinella",
    sections: [
      {
        heading: "Más allá de los veredictos binarios",
        body: [
          "El antivirus tradicional da respuestas binarias: infectado o limpio. ARGUS, impulsado por el análisis adaptativo ASTRA, toma un enfoque distinto. Asigna una puntuación de sospecha de 0 a 100 basada en evidencia de múltiples capas de análisis independientes. Ninguna capa por sí sola puede declarar un archivo malicioso.",
          "Esto significa que un archivo con un solo rasgo sospechoso permanece en el rango \"Inusual\", mientras que un archivo que exhibe patrones de robo de credenciales, exfiltración de red e inyección de procesos converge hacia \"Malicioso\" a través de múltiples señales independientes.",
        ],
      },
      {
        heading: "Las capas",
        body: [
          "Capa 0 (Firmas): la base de datos de firmas de malware conocido de ClamAV. Capa 1 (MIME/Tipo): detecta archivos disfrazados de otros formatos, dobles extensiones y trucos de anulación de derecha a izquierda. Capa 2 (Heurística PE): analiza ejecutables de Windows en busca de técnicas de explotación, importaciones sospechosas, empaquetado y anomalías estructurales.",
          "Capa 3 (Reputación): compara los metadatos del archivo con patrones de software conocidos. Capa 4 (Contexto): considera dónde se encontró el archivo, cómo se nombró y señales ambientales sospechosas. Capa 5 (IOC): coteja los hashes del archivo con indicadores de compromiso conocidos.",
          "Capa 6 (YARA): reglas de comportamiento personalizadas escritas en el lenguaje de coincidencia de patrones YARA. Capa 7 (Correlación): cruza los hallazgos de todas las capas para construir cadenas de convergencia y detectar patrones de ataque de varias etapas. Capa 8 (Comportamiento en tiempo de ejecución): la detonación opcional en sandbox retroalimenta observaciones de comportamiento al sistema de puntuación.",
        ],
      },
      {
        heading: "Convergencia, no umbrales",
        body: [
          "Las puntuaciones de ARGUS, regidas por la lógica de convergencia adaptativa de ASTRA, no son umbrales arbitrarios. Un archivo alcanza \"Riesgo alto\" o \"Malicioso\" solo cuando convergen varias categorías de evidencia: robo de credenciales + actividad de red, o inyección de procesos + persistencia + anti-análisis. Los hallazgos de una sola categoría se limitan para evitar que una señal ruidosa genere falsos positivos.",
          "Cada hallazgo lleva una BehaviorTag, una AttackStage y un peso de confianza. La puntuación final refleja cuántas líneas de evidencia independientes apuntan a la misma conclusión.",
        ],
      },
    ],
  },
  "why-clamav": {
    icon: Microscope,
    title: "¿Por qué ClamAV?",
    subtitle: "Motor de firmas de código abierto probado en batalla",
    sections: [
      {
        heading: "Amenazas conocidas, respuestas conocidas",
        body: [
          "Para el malware que ya ha sido identificado y catalogado, el escaneo de firmas es rápido y definitivo. ClamAV mantiene una base de datos de millones de firmas de malware que puede identificar amenazas conocidas en milisegundos.",
          "ARGUS se encarga de lo desconocido; ClamAV se encarga de lo conocido. Juntos cubren ambos lados del problema de detección sin que ningún componente intente hacerlo todo.",
        ],
      },
      {
        heading: "Confianza de código abierto",
        body: [
          "ClamAV es desarrollado por el Talos Intelligence Group de Cisco y es el motor antivirus de código abierto más utilizado del mundo. Su base de datos de firmas se actualiza varias veces al día y está disponible libremente.",
          "Usar ClamAV significa que el escaneo de firmas de Sentinella no es una caja negra. El código fuente del motor, el formato de firmas y la lógica de detección son públicamente auditables.",
        ],
      },
      {
        heading: "Aislamiento por subproceso",
        body: [
          "ClamAV carga una gran base de datos de firmas en memoria (~400 MB). Sentinella opcionalmente ejecuta ClamAV en un subproceso aislado (clamavd) de modo que, si una muestra malformada provoca un fallo en el motor de análisis, solo muere el proceso de trabajo. El servicio sobrevive y puede lanzar uno nuevo.",
          "Este aislamiento de fallos es configurable. En máquinas con poca RAM, el escaneo en proceso usa el motor ya cargado sin costo de memoria adicional.",
        ],
      },
    ],
  },
  "why-sandbox": {
    icon: Box,
    title: "¿Por qué el sandbox de comportamiento?",
    subtitle: "Observar lo que los archivos sospechosos realmente hacen",
    sections: [
      {
        heading: "La brecha entre lo estático y lo dinámico",
        body: [
          "El análisis estático (leer la estructura de un archivo) solo puede decir qué podría hacer un programa. El análisis de comportamiento revela lo que realmente hace al ejecutarse. Cierto malware está diseñado específicamente para parecer limpio bajo análisis estático y solo revela su verdadero comportamiento en tiempo de ejecución.",
          "El sandbox de Sentinella ejecuta los archivos sospechosos en un entorno estrictamente controlado, observa su comportamiento y retroalimenta los resultados al sistema de puntuación de ARGUS.",
        ],
      },
      {
        heading: "Capas de contención",
        body: [
          "Los procesos en sandbox se ejecutan con un token de Windows restringido (la mayoría de privilegios eliminados), en nivel de Integridad Baja (no pueden escribir en ubicaciones del sistema), dentro de un Job Object (no pueden generar procesos de escape, limitados a 512 MB de memoria) y con reglas de firewall por proceso que bloquean todo acceso a la red.",
          "El proceso se crea en estado suspendido. Toda la contención se aplica antes de que se ejecute la primera instrucción. No hay ventana en la que la muestra pueda actuar antes de que las restricciones surtan efecto.",
        ],
      },
      {
        heading: "Observación en tiempo de ejecución con ETW",
        body: [
          "Event Tracing for Windows (ETW) es un marco de instrumentación a nivel de kernel integrado en Windows. Sentinella usa ETW para observar los procesos en sandbox sin inyectar código ni modificar la muestra. Esto captura la creación de procesos, la carga de DLL desde rutas sospechosas, los intentos de persistencia en el registro y los intentos de conexión de red.",
          "ETW es un mecanismo de observación local. No transmite datos a ningún lugar. Es la misma infraestructura que Windows usa internamente para la supervisión de rendimiento y la depuración.",
        ],
      },
      {
        heading: "No bloqueante por diseño",
        body: [
          "La detonación en sandbox puede tardar más de 30 segundos. La protección en tiempo real nunca la espera. Cuando el vigía identifica un archivo que necesita sandbox, la detonación se ejecuta en un hilo en segundo plano mientras el vigía continúa escaneando el siguiente archivo de inmediato. Si el sandbox determina luego que el archivo es peligroso, la cuarentena ocurre de forma asíncrona.",
        ],
      },
    ],
  },
  "why-workers": {
    icon: Server,
    title: "¿Por qué procesos modulares?",
    subtitle: "Aislamiento de procesos para la resiliencia",
    sections: [
      {
        heading: "El principio de la frontera de fallos",
        body: [
          "Sentinella separa su trabajo en procesos independientes: el servicio principal (sentinelld), el escáner ClamAV (clamavd), el sandbox de comportamiento (sandboxd) y, opcionalmente, un proceso ARGUS externo. Cada uno se ejecuta como un proceso del sistema operativo separado.",
          "Si ClamAV falla al analizar un PDF malformado, solo muere clamavd. El servicio sigue funcionando, la protección en tiempo real permanece activa y el usuario no ve ninguna interrupción. Se lanza un nuevo clamavd en el siguiente escaneo.",
        ],
      },
      {
        heading: "Fronteras de memoria",
        body: [
          "Cada subproceso de ClamAV carga ~400 MB de firmas de forma independiente. Sentinella limita los procesos ClamAV concurrentes para evitar la explosión de memoria. El proceso de sandbox ejecuta como máximo una detonación a la vez. Estos son límites estrictos impuestos por contadores atómicos, no sugerencias de configuración.",
        ],
      },
      {
        heading: "Recuperación de pánicos",
        body: [
          "Dentro del servicio, el orquestador de escaneo usa envolturas que capturan pánicos alrededor de cada tarea. Si un hilo de escaneo entra en pánico (un error de programación, no un evento de seguridad), el hilo de trabajo se recupera, incrementa un contador de fallos para diagnóstico y continúa procesando la siguiente tarea. Sin intervención del usuario.",
        ],
      },
    ],
  },
  "why-realtime-first": {
    icon: Zap,
    title: "¿Por qué tiempo real primero?",
    subtitle: "Protección que nunca cede",
    sections: [
      {
        heading: "La regla innegociable",
        body: [
          "La protección en tiempo real es la función más importante de cualquier antivirus. Si un usuario inicia un escaneo de disco completo, la protección en tiempo real debe seguir funcionando a toda velocidad. Si el sistema está bajo presión de memoria, los escaneos manuales se degradan primero. El tiempo real nunca se degrada en silencio.",
        ],
      },
      {
        heading: "Separación arquitectónica",
        body: [
          "El vigía en tiempo real se ejecuta en su propio hilo dedicado, independiente del orquestador de escaneo. Los escaneos manuales (rápido, carpeta, completo) se ejecutan en hilos de trabajo separados. El escáner inactivo en segundo plano se ejecuta en otro hilo más y se pausa automáticamente cuando hay un escaneo manual activo.",
          "No son prioridades en una cola compartida. Son rutas de ejecución físicamente separadas. El vigía no puede ser privado de recursos por una cola de escaneo ocupada porque no usa la cola de escaneo.",
        ],
      },
      {
        heading: "Degradación elegante",
        body: [
          "Cuando los recursos del sistema están limitados, Sentinella se degrada en un orden específico: el escáner inactivo se pausa primero (CPU, disco, batería, pantalla completa y presión de memoria activan la pausa). Los escaneos manuales continúan pero con un número de hilos acotado. La protección en tiempo real continúa incondicionalmente.",
          "Si todas las ranuras de subproceso de ClamAV están ocupadas por escaneos manuales, el vigía recurre al escaneo ClamAV en proceso. Esto es algo menos aislado pero funcionalmente idéntico. La calidad de detección nunca se reduce.",
        ],
      },
    ],
  },
  performance: {
    icon: Gauge,
    title: "Filosofía de rendimiento",
    subtitle: "Tu computadora es tuya",
    sections: [
      {
        heading: "Invisible cuando está inactivo",
        body: [
          "El escáner inactivo en segundo plano supervisa la carga de CPU, la E/S de disco, el estado de la batería y si el usuario está en una aplicación de pantalla completa. Solo escanea cuando los recursos del sistema están realmente disponibles. Durante la compilación, los juegos o la edición de video, se pausa automáticamente.",
          "No hay un horario fijo de escaneo que interrumpa el trabajo. El escáner se pregunta: \"¿Puedo escanear sin que el usuario lo note?\" Si la respuesta es no, espera.",
        ],
      },
      {
        heading: "Filtrado inteligente de archivos",
        body: [
          "No todos los archivos necesitan un análisis profundo. ARGUS usa un sistema de estrategia de escaneo: los tipos de archivo conocidos como seguros (imágenes, fuentes, registros) reciben solo comprobaciones de firmas. Los ejecutables y scripts reciben un análisis completo de múltiples capas. Los artefactos de compilación y las cachés de paquetes se omiten por completo durante los escaneos rápidos.",
          "El vigía en tiempo real aplica un filtrado por extensión para evitar escanear archivos que no pueden contener código ejecutable: imágenes, fuentes, audio/video, archivos de bloqueo e intermedios de compilación.",
        ],
      },
      {
        heading: "Uso acotado de recursos",
        body: [
          "Los escaneos manuales usan un número de hilos relativo a los núcleos. Los subprocesos de ClamAV se limitan a 2 instancias concurrentes. Las detonaciones en sandbox se limitan a 1 a la vez. Estos son límites estrictos, no sugerencias. Sentinella nunca escalará hasta consumir toda la CPU o la RAM disponibles.",
          "Un sistema de presión de memoria supervisa la RSS del servicio. Bajo presión elevada, los nuevos escaneos se enrutan a procesos externos para mantener estable la huella de memoria del servicio. Bajo presión crítica, el escáner inactivo se pausa por completo.",
        ],
      },
    ],
  },
  "open-source": {
    icon: GitBranch,
    title: "Filosofía de código abierto",
    subtitle: "Seguridad por transparencia",
    sections: [
      {
        heading: "Por qué el código abierto importa para la seguridad",
        body: [
          "Un antivirus se ejecuta con algunos de los privilegios más altos del sistema. Lee cada archivo, supervisa cada proceso y puede poner en cuarentena cualquier cosa que considere sospechosa. Deberías poder leer su código fuente y verificar que hace exactamente lo que afirma.",
          "Sentinella está bajo licencia GPLv2. La lógica de detección, la implementación de la cuarentena, el protocolo IPC y cada decisión de escaneo son públicamente auditables. No hay un motor de detección propietario escondido tras un nombre de marketing.",
        ],
      },
      {
        heading: "Detecciones explicables",
        body: [
          "Cada hallazgo de ARGUS incluye la capa que lo produjo, la etiqueta de comportamiento que coincidió, el peso de confianza asignado y la clasificación de etapa de ataque. Cuando Sentinella pone un archivo en cuarentena, puedes ver exactamente por qué: qué reglas se activaron, qué evidencia convergió y cuál fue la puntuación final.",
          "Esto no es solo para desarrolladores. Significa que puedes distinguir entre un falso positivo (una regla que se activa en un instalador legítimo) y una amenaza real (múltiples señales independientes que convergen en robo de credenciales + exfiltración).",
        ],
      },
      {
        heading: "Comunidad y atribución",
        body: [
          "Sentinella está construido por Lucent Open Software y la comunidad de Sentinella. Usa ClamAV (desarrollado por el Talos Intelligence Group de Cisco) para el escaneo de firmas y el motor de coincidencia de patrones YARA para las reglas de comportamiento. Todas las dependencias son de código abierto y están debidamente atribuidas.",
        ],
      },
    ],
  },
  privacy: {
    icon: EyeOff,
    title: "Privacidad y telemetría",
    subtitle: "Lo que Sentinella no hace",
    sections: [
      {
        heading: "Cero telemetría",
        body: [
          "Sentinella no recopila, transmite ni almacena ningún dato de uso, resultado de escaneo, estadística de detección ni información del sistema. No hay un punto de análisis, ni un servicio de reporte de fallos, ni una opción de \"datos de uso anónimos\". El servicio realiza exactamente un tipo de conexión de red saliente: descargar las actualizaciones de firmas de ClamAV desde su servidor oficial.",
        ],
      },
      {
        heading: "Sin escaneo en la nube",
        body: [
          "Tus archivos nunca se suben a ningún lugar. Todo el análisis (escaneo de ClamAV, heurística de ARGUS, reglas YARA, sandbox de comportamiento) se ejecuta localmente en tu máquina. No hay consulta en la nube, ni envío de hashes, ni compartición de muestras de archivos. Es una decisión de diseño deliberada, no una limitación.",
          "Los productos antivirus comerciales a menudo suben archivos sospechosos o hashes de archivos a servicios en la nube para análisis adicional. Sentinella no lo hace. La contrapartida es que Sentinella depende de sus motores locales y no puede beneficiarse de inteligencia en la nube en tiempo real. El beneficio es que tus archivos permanecen en tu máquina.",
        ],
      },
      {
        heading: "Sin interceptación de HTTPS",
        body: [
          "Sentinella no instala certificados raíz, ni hace de proxy del tráfico HTTPS, ni inspecciona conexiones de red cifradas. Algunos productos de seguridad interceptan las conexiones TLS para escanear el tráfico web. Ese enfoque debilita la seguridad de cada conexión HTTPS de la máquina y es arquitectónicamente incompatible con la filosofía de Sentinella.",
        ],
      },
      {
        heading: "Sin controlador de kernel (v1)",
        body: [
          "Sentinella v1 opera enteramente en modo usuario. No instala controladores de kernel, ni controladores minifilter de sistema de archivos, ni ganchos a nivel de kernel. Esto limita algunas capacidades de detección (bloqueo previo a la ejecución, detección de rootkits de kernel) pero elimina toda una clase de riesgos de estabilidad del sistema.",
          "El vigía en tiempo real usa ReadDirectoryChangesW (una API estándar de Windows) y el sandbox de comportamiento usa ETW (Event Tracing for Windows) para la observación en tiempo de ejecución. Ambas son interfaces documentadas, estables y de modo usuario.",
        ],
      },
    ],
  },
  "technical-architecture": {
    icon: Cpu,
    title: "Arquitectura técnica",
    subtitle: "Referencia orientada a desarrolladores sobre los internos de Sentinella",
    sections: [
      {
        heading: "Arquitectura del sistema",
        body: [
          "Sentinella se ejecuta como un servicio en Rust (sentinelld) que expone una API JSON-RPC 2.0 a través de tuberías con nombre de Windows. La interfaz es una aplicación Tauri 2.x (React + TypeScript) que se comunica con el servicio para todas las operaciones de seguridad. El servicio posee todo el estado: motor de escaneo, bóveda de cuarentena, vigía en tiempo real y escáner en segundo plano.",
          "Las capas de protección se ejecutan de forma independiente: un vigía del sistema de archivos en tiempo real supervisa Descargas, Escritorio y Temp en busca de archivos nuevos; un escáner inactivo en segundo plano comprueba proactivamente los archivos en reposo durante baja actividad del sistema; y los escaneos iniciados por el usuario (rápido, carpeta, completo) se ejecutan bajo demanda sin interferir con la protección en tiempo real.",
        ],
      },
      {
        heading: "Orquestador de escaneo",
        body: [
          "El orquestador gestiona tres colas independientes: Tiempo real (1 proceso), Manual (2 procesos) e Inactivo (1 proceso). Cada cola tiene su propio canal mpsc e hilos de trabajo. Las tareas llevan un CancellationToken para la cancelación cooperativa. Los hilos de trabajo usan envolturas que capturan pánicos para la recuperación de fallos.",
          "La presión de la cola se supervisa mediante contadores atómicos. Los procesos inactivos añaden un retardo de 250 ms entre tareas para evitar picos de CPU. Los procesos de escaneo manual usan un grupo de hilos relativo a los núcleos con distribución de archivos por lotes.",
        ],
      },
      {
        heading: "Modelo de procesos",
        body: [
          "Sentinella separa el trabajo en procesos independientes del sistema operativo para el aislamiento de fallos: sentinelld (servicio principal), clamavd (escáner ClamAV aislado, máx. 2 concurrentes), sandboxd (detonación de comportamiento, máx. 1 concurrente) y, opcionalmente, un proceso ARGUS externo. Cada frontera de proceso significa que un fallo en un componente no derriba a los demás.",
          "El aislamiento por subproceso de ClamAV es configurable. Cada instancia de clamavd carga ~400 MB de firmas de forma independiente. La concurrencia se controla mediante contadores atómicos con guardas RAII para la limpieza automática.",
        ],
      },
      {
        heading: "Internos del sandbox de comportamiento",
        body: [
          "Los procesos en sandbox se ejecutan con un token de Windows restringido (DISABLE_MAX_PRIVILEGE), en nivel de Integridad Baja (S-1-16-4096), dentro de un Job Object (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, sin breakaway, límite de 512 MB de memoria) y con reglas de firewall por PID (netsh advfirewall) que bloquean todo acceso a la red.",
          "El proceso se crea mediante CreateProcessAsUserW en estado CREATE_SUSPENDED. Toda la contención (asignación al Job Object, reglas de firewall) se aplica antes de llamar a ResumeThread. Las sesiones de kernel ETW (StartTraceW/OpenTraceW/ProcessTrace) supervisan la creación de procesos, la carga de DLL, la persistencia en el registro y las conexiones TCP mediante callbacks EVENT_RECORD.",
        ],
      },
      {
        heading: "Protocolo IPC",
        body: [
          "El servicio escucha en una tubería con nombre (\\\\.\\pipe\\sentinella). Las solicitudes usan JSON-RPC 2.0 con enrutamiento de métodos (scan.start, scan.status, quarantine.list, etc.). Los comandos peligrosos (quarantine.restore, protection.set_critical) requieren un flujo de desafío-respuesta: la interfaz solicita un token de un solo uso vía challenge.request (autenticado con un secreto IPC) y luego pasa el token al comando protegido.",
          "El estado del escaneo usa una ruta rápida sin bloqueos: los contadores atómicos (files_scanned, threats_found, status) se leen sin adquirir el mutex interno, de modo que el sondeo por IPC nunca bloquea los hilos de trabajo del escaneo.",
        ],
      },
      {
        heading: "Capas del motor ARGUS · análisis adaptativo ASTRA",
        body: [
          "Capa 0: base de datos de firmas de ClamAV. Capa 1: análisis MIME/tipo (dobles extensiones, RTLO, PE-como-PDF). Capa 2: análisis heurístico de PE (detección de exploits, análisis de importaciones, empaquetado, anomalías estructurales). Capa 3: coincidencia de reputación (con límite de dominio, patrones de límite de palabra). Capa 4: análisis de contexto (ruta, nombre de archivo, señales ambientales). Capa 5: coincidencia de hashes IOC. Capa 6: reglas de comportamiento YARA. Capa 7: correlación entre capas (cadenas de convergencia, progresión de etapas de ataque). Capa 8: comportamiento en tiempo de ejecución (retroalimentación de detonación en sandbox). ASTRA orquesta estas capas con ejecución acotada según el perfil, asegurando un análisis determinista e inteligente con los recursos.",
          "Las puntuaciones no son umbrales arbitrarios. Los hallazgos de una sola categoría se limitan. Un archivo alcanza Riesgo alto o Malicioso solo mediante la convergencia de varias categorías. Cada hallazgo lleva una BehaviorTag, una AttackStage, un peso de confianza y una clasificación de ThreatMaturity.",
        ],
      },
    ],
  },
};

/** Topic content for the active locale ("en" fallback). */
export function topicContentFor(locale: string): Record<HelpTopic, TopicData> {
  return locale === "es" ? es : en;
}
