# C2-DECT

### Plataforma de simulación de adversarios de MercenaryCorp Inc.: de la entrada inicial a la explotación y el beaconing.

C2-DECT es la plataforma de simulación de adversarios del ecosistema
**MercenaryCorp Inc.** (**Cybersecurity & Digital Defense**): reproduce la cadena de
ataque completa - acceso inicial, reconocimiento, explotación, post-explotación y
beaconing - dentro de un laboratorio acotado, para que el equipo azul pueda medir su
detección y contención sobre la misma secuencia de técnicas, tráfico y artefactos que
vería en un ataque real. El canal de beaconing es el transporte de telemetría de la
simulación, no el producto.

---

## Rol en el ecosistema

```
ExploitStrike (desarrollo de exploits)
        │
        ▼
   C2-DECT ──▶ cadena completa: acceso, explotación y beaconing
        │  emulación controlada de la cadena
        ▼
 CyberLens (red team: contexto, evidencia, grafo)
        │  emulación
        ▼
 SentryGuard (EDR: detección en endpoints)
        ▶ CyberLens (blue + purple: cobertura)
```

| Producto | Rol |
|----------|-----|
| **C2-DECT** | Plataforma de simulación: acceso inicial, reconocimiento, explotación, post-explotación y beaconing |
| **CyberLens** | Motor de contexto y cobertura: registra cada canal y agente C2-DECT como evidencia del ejercicio |
| **SentryGuard** | EDR: detecta la actividad del agente en los endpoints |
| **ExploitStrike** | Amplificador de desarrollo de exploits que operan a través de C2-DECT |

---

## Cómo se conecta con CyberLens

| Flujo | Dirección | Detalle |
|-------|-----------|---------|
| **Ejercicio** | C2-DECT → CyberLens | Los canales y agentes activos durante el ejercicio se registran como nodos y evidencia del red team |
| **Validación** | CyberLens → C2-DECT | Cada fase del ejercicio puede desplegar o validar comandos a través de los canales disponibles |
| **Cobertura** | Bidireccional | Lo que la simulación alcanza se contrasta con lo que SentryGuard detecta - la medición de cobertura de CyberLens |

Beneficios del despliegue conjunto: emulación controlada de la cadena completa, evidencia
trazable de cada canal, y detección medida contra la misma infraestructura.

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

## Bridge del motor de exploits (c2-dect/exploits/exploit-engine)

Ademas del beaconing en si, el motor de exploits de c2-dect registra cada
publish via `_bridge_cyberlens` (contrato en `CyberLens/README.md`, seccion
de integracion). Sin CyberLens el motor sigue (modo lab-honesto); con el,
cada `mutador_*` queda auditado como sesion red-team.
