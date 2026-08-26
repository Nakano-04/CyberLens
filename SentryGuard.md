# SentryGuard

### El EDR de MercenaryCorp Inc., conectado de forma nativa con CyberLens.

SentryGuard es el **EDR (Endpoint Detection and Response)** del ecosistema
**MercenaryCorp Inc.** (**Cybersecurity & Digital Defense**): monitoriza los endpoints,
genera telemetría continua, mantiene reglas de detección y — con aprobación — ejecuta
respuestas sobre la infraestructura.

---

## Rol en el ecosistema

| Producto | Rol |
|----------|-----|
| **ExploitStrike** | Amplificador de desarrollo de exploits (operan sobre C2-DECT, se detectan con SentryGuard) |
| **C2-DECT** | Framework de comando y control: los agentes que SentryGuard observa en los endpoints |
| **CyberLens** | Motor de operaciones y cobertura: consume la telemetría de SentryGuard |
| **SentryGuard** | EDR: detección y respuesta en endpoints |

---

## Cómo se conecta con CyberLens

```
┌────────────┐   telemetría (eventos, logs, EDR)   ┌────────────┐
│ SentryGuard│ ─────────────────────────────────▶ │  CyberLens │
│   EDR/SOC  │                                     │  blue team │
│            │ ◀───────────────────────────────── │            │
└────────────┘  recomendaciones e indicadores       └────────────┘
```

| Flujo | Dirección | Detalle |
|-------|-----------|---------|
| **Telemetría** | SentryGuard → CyberLens | Los eventos del EDR se ingieren como telemetría blue y disparan el motor de detección (reglas SIGMA, burst, deduplicación) al instante |
| **Reglas** | Bidireccional | Los catálogos de reglas y firmas de SentryGuard se reutilizan como reglas de detección dentro del ejercicio; las reglas validadas en CyberLens se despliegan a SentryGuard |
| **Respuesta** | SentryGuard (delegada) | CyberLens **no ejecuta acciones**: documenta recomendaciones auditadas que SentryGuard ejecuta en los endpoints con aprobación humana (playbooks con doble firma) |
| **Contexto** | SentryGuard → CyberLens | IOCs, hallazgos y técnicas MITRE enriquecen el contexto ofensivo del red team |

---

## Beneficios del despliegue conjunto

- **Cobertura medida, no supuesta**: cada ataque emulado en CyberLens (operado vía
  C2-DECT) se contrasta contra las reglas reales de SentryGuard → `detection_rate` y
  brechas accionables.
- **SOC sin falsa confianza**: la matriz de cobertura muestra qué técnicas del
  adversario SentryGuard detecta hoy, no en teoría.
- **Respuesta controlada**: el ciclo se cierra con playbooks aprobados por humano y
  registrados en la auditoría de ambos productos.
- **Un solo vocabulario**: técnicas MITRE ATT&CK v16 + ATLAS, evidencias y alertas
  sin traducción entre equipos.

---

## Hoja de ruta de la integración

| Fase | Capacidad |
|------|-----------|
| Ya disponible | Providers HTTP (catálogo de técnicas y escaneo de firmas); ingestión de telemetría vía API de CyberLens |
| T1 · v0.5 | Conector nativo SentryGuard: ingesta push de eventos y reutilización de reglas |
| T2 · v0.6 | Playbooks de respuesta con doble aprobación y delegación de acciones al EDR |
| T3 · v0.7 | Difusión de reglas nuevas a flotas de sensores SentryGuard |

Detalles y fechas en el [Roadmap de CyberLens](README.md#roadmap).

---

Contacto: ventas@mercenarycorp.com · www.mercenarycorp.com