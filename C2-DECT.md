# C2-DECT

### Framework de comando y control (C2) de MercenaryCorp Inc. para operaciones ofensivas.

C2-DECT es el framework de comando y control del ecosistema **MercenaryCorp Inc.**
(**Cybersecurity & Digital Defense**): gestiona los canales de comunicación, los
agentes y la orquestación de las operaciones ofensivas de los equipos rojos.

---

## Rol en el ecosistema

```
ExploitStrike (desarrollo de exploits)
        │
        ▼
   C2-DECT ──▶ canales y agentes de C2
        │  operación ofensiva en vivo
        ▼
 CyberLens (red team: contexto, evidencia, grafo)
        │  emulación
        ▼
 SentryGuard (EDR: detección en endpoints)
        ▶ CyberLens (blue + purple: cobertura)
```

| Producto | Rol |
|----------|-----|
| **C2-DECT** | Framework C2: canales de comunicación, agentes implantados y control de operaciones |
| **CyberLens** | Motor de contexto y cobertura: registra cada canal y agente C2-DECT como evidencia del ejercicio |
| **SentryGuard** | EDR: detecta la actividad del agente en los endpoints |
| **ExploitStrike** | Amplificador de desarrollo de exploits que operan a través de C2-DECT |

---

## Cómo se conecta con CyberLens

| Flujo | Dirección | Detalle |
|-------|-----------|---------|
| **Operación** | C2-DECT → CyberLens | Los canales y agentes activos durante el ejercicio se registran como nodos y evidencia del red team |
| **Validación** | CyberLens → C2-DECT | Cada fase del ejercicio puede desplegar o validar comandos a través de los canales disponibles |
| **Cobertura** | Bidireccional | Lo que C2-DECT alcanza se contrasta con lo que SentryGuard detecta — la medición de cobertura de CyberLens |

Beneficios del despliegue conjunto: operación ofensiva real, evidencia trazable de cada
canal, y detección medida contra la misma infraestructura.

---

## Relación con ExploitStrike

**ExploitStrike** es el amplificador de desarrollo de exploits de MercenaryCorp:
automatiza el desarrollo y validación de exploits diseñados para operar sobre los
canales de C2-DECT y ser detectados (o no) por SentryGuard. El ciclo completo:

1. **ExploitStrike** desarrolla y valida el exploit.
2. **C2-DECT** lo despliega en los canales de la operación.
3. **CyberLens** registra la emulación como evidencia red.
4. **SentryGuard** detecta en los endpoints.
5. **CyberLens purple** mide la brecha de cobertura y cierra el ciclo.

---

Contacto: ventas@mercenarycorp.com · www.mercenarycorp.com