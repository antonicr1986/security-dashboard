# Informe de seguridad

Generado: 2026-11-23T18:09:31+00:00 · Repos analizados: 5

## Quality gate

❌ **NO SUPERADO**

- high: 1 abiertas (máximo 0)

## KPIs

| KPI | Valor |
|---|---|
| Vulnerabilidades abiertas (crítica / alta / media / baja) | 0 / 1 / 1 / 0 |
| Secretos expuestos abiertos | 0 |
| Tiempo medio de resolución | 2.4 días (n=141) |
| Alerta abierta más antigua | 5 días |
| Alertas resueltas en plazo (SLA) | 99 % (140 de 141) |
| PRs de Dependabot pendientes | 0 |
| Cobertura de controles de seguridad | 100 % |
| Actions fijadas por SHA | 100 % (72 de 72) |
| Workflows con permisos mínimos declarados | 100 % |
| Riesgos aceptados (alertas descartadas a mano) | 7 |

## Alertas abiertas por repo

| Repo | Crítica | Alta | Media | Baja | Secretos |
|---|---|---|---|---|---|
| antonicr1986/FinanceTracker | 0 | 0 | 1 | 0 | 0 |
| antonicr1986/financetracker-web | 0 | 1 | 0 | 0 | 0 |
| antonicr1986/financetracker-android | 0 | 0 | 0 | 0 | 0 |
| antonicr1986/financetracker-desktop | 0 | 0 | 0 | 0 | 0 |
| antonicr1986/antonio-cv | 0 | 0 | 0 | 0 | 0 |

## Plazos de corrección (SLA)

Días máximos para corregir una alerta según su severidad. Una alerta abierta que supera su plazo cuenta como incumplida.

| Severidad | Plazo | Resueltas en plazo | Abiertas fuera de plazo |
|---|---|---|---|
| Crítica | 7 días | 9 de 10 (90 %) | 0 |
| Alta | 30 días | 70 de 70 (100 %) | 0 |
| Media | 90 días | 56 de 56 (100 %) | 0 |
| Baja | 180 días | 5 de 5 (100 %) | 0 |

## Controles por repo

| Repo | SAST | SCA | Secretos | Contenedores/IaC | DAST |
|---|---|---|---|---|---|
| antonicr1986/FinanceTracker | ✅ | ✅ | ✅ | ✅ | ✅ |
| antonicr1986/financetracker-web | ✅ | ✅ | ✅ | N/A | ✅ |
| antonicr1986/financetracker-android | ✅ | ✅ | ✅ | N/A | N/A |
| antonicr1986/financetracker-desktop | ✅ | ✅ | ✅ | N/A | N/A |
| antonicr1986/antonio-cv | 🔒 | ✅ | ✅ | N/A | ✅ |
| **Cobertura** | 100 % | 100 % | 100 % | 100 % | 100 % |

## Cadena de suministro

Higiene de los workflows de GitHub Actions de cada repo.

| Repo | Actions fijadas por SHA | Workflows con `permissions:` |
|---|---|---|
| antonicr1986/FinanceTracker | ✅ 27 de 27 | ✅ 4 de 4 |
| antonicr1986/financetracker-web | ✅ 7 de 7 | ✅ 2 de 2 |
| antonicr1986/financetracker-android | ✅ 15 de 15 | ✅ 3 de 3 |
| antonicr1986/financetracker-desktop | ✅ 11 de 11 | ✅ 3 de 3 |
| antonicr1986/antonio-cv | ✅ 12 de 12 | ✅ 1 de 1 |

## Actualizaciones pendientes

PRs abiertas por Dependabot sin fusionar. Fijar versiones solo es seguro si luego se actualizan: una PR con más de 30 días está fuera de plazo.

| Repo | PRs abiertas | La más antigua | Fuera de plazo |
|---|---|---|---|
| antonicr1986/FinanceTracker | 0 | — | 0 |
| antonicr1986/financetracker-web | 0 | — | 0 |
| antonicr1986/financetracker-android | 0 | — | 0 |
| antonicr1986/financetracker-desktop | 0 | — | 0 |
| antonicr1986/antonio-cv | 0 | — | 0 |

## Riesgos aceptados

🔒 Controles que el repo no tiene por ser privado (en repos privados requieren licencia de GitHub Advanced Security). No cuentan en la cobertura:

- antonicr1986/antonio-cv: SAST

📝 Alertas de Dependabot descartadas a mano. No cuentan como abiertas, pero siguen sin corregir: cada una necesita un motivo y una justificación escrita.

- antonicr1986/financetracker-android: 1 alerta (alta) · código vulnerable no usado · ✅ justificada
- antonicr1986/financetracker-android: 1 alerta (alta) · código vulnerable no usado · ✅ justificada
- antonicr1986/financetracker-android: 1 alerta (crítica) · código vulnerable no usado · ✅ justificada
- antonicr1986/financetracker-android: 1 alerta (media) · código vulnerable no usado · ✅ justificada
- antonicr1986/financetracker-android: 1 alerta (media) · código vulnerable no usado · ✅ justificada
- antonicr1986/financetracker-android: 1 alerta (media) · código vulnerable no usado · ✅ justificada
- antonicr1986/antonio-cv: 1 alerta (media) · código vulnerable no usado · ✅ justificada

## Datos no disponibles

Fuente no habilitada en el repo o sin permiso en el token (cuenta como 0 alertas en las tablas):

- antonicr1986/antonio-cv: CodeQL, secret scanning

## Evolución semanal

| Fecha | Crítica | Alta | Media | Baja | Secretos | Cobertura | Actions por SHA | Riesgos aceptados | En plazo (SLA) | PRs pendientes |
|---|---|---|---|---|---|---|---|---|---|---|
| 2026-11-23 | 0 | 1 | 1 | 0 | 0 | 100 % | 100 % | 7 | 99 % | 0 |
| 2026-11-16 | 0 | 0 | 0 | 0 | 0 | 100 % | 100 % | 8 | 99 % | 0 |
| 2026-11-14 | 0 | 0 | 1 | 0 | 0 | 100 % | 100 % | 7 | 99 % | 1 |
| 2026-11-11 | 0 | 0 | 0 | 0 | 0 | 100 % | N/A | N/A | N/A | N/A |
