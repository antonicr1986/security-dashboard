# security-dashboard

Panel de KPIs de seguridad para mis repos de GitHub. Cada lunes un workflow de GitHub Actions lee las alertas y los controles de cada repo, calcula los indicadores, aplica un **quality gate** y guarda el informe en [`REPORT.md`](REPORT.md).

> 🇬🇧 **English:** security KPI dashboard for my GitHub repos. A weekly GitHub Actions job reads Dependabot, CodeQL and secret-scanning alerts plus the security controls each repo runs, computes the KPIs below, applies a configurable quality gate and commits the report to `REPORT.md`. Python standard library only, no dependencies.

## Qué mide

| KPI | Cómo se calcula |
|---|---|
| Vulnerabilidades abiertas por severidad | Alertas abiertas de Dependabot y CodeQL (crítica / alta / media / baja) |
| Secretos expuestos abiertos | Alertas abiertas de secret scanning |
| Tiempo medio de resolución (MTTR) | Media de días entre que se abre y se corrige una alerta (solo las corregidas) |
| Alerta abierta más antigua | Días que lleva abierta la más vieja |
| Cobertura de controles | % de controles presentes: SAST (CodeQL), SCA (Dependabot, npm audit, dotnet --vulnerable, dependency review), secretos (gitleaks), contenedores/IaC (Trivy) y DAST (OWASP ZAP) |
| Evolución semanal | Foto de cada ejecución en [`data/history.json`](data), para ver la tendencia |

### Quality gate

Se define en `config.json`. Por defecto no se admite ninguna vulnerabilidad crítica ni alta ni ningún secreto abierto:

```json
"gate": { "critical": 0, "high": 0, "secrets": 0 }
```

Los repos se listan en el mismo archivo. Un repo puede indicar los controles que no le aplican:

```json
"repos": [
  "antonicr1986/FinanceTracker",
  { "name": "antonicr1986/financetracker-desktop", "not_applicable": ["Contenedores/IaC", "DAST"] }
]
```

Las severidades que no aparecen (media, baja) solo se informan, no bloquean: la seguridad avisa de todo, pero solo frena lo que importa. Si el gate no se supera, el workflow termina en rojo, **después** de guardar el informe.

## Cómo funciona

```
GitHub API ──► collect.py ──► kpis.py (cálculo, sin red) ──► report.py ──► REPORT.md + data/
 alertas y                      │
 workflows                      └─► quality gate ──► código de salida 1 si falla
```

- `dashboard/github_api.py`: cliente mínimo de la API REST (paginación y gestión de errores).
- `dashboard/kpis.py`: funciones puras con los cálculos; son lo que cubren los tests.
- `dashboard/collect.py` y `report.py`: recogida por repo e informe en Markdown.
- `.github/workflows/`: `ci.yml` (tests en cada push) y `weekly-report.yml` (informe semanal).

## Puesta en marcha

1. **Token de solo lectura.** Las alertas de otros repos no se pueden leer con el `GITHUB_TOKEN` del workflow, así que hace falta un PAT *fine-grained*:
   - Settings → Developer settings → Fine-grained tokens → *Generate new token*.
   - Acceso solo a los repos de `config.json`.
   - Permisos de **solo lectura**: *Dependabot alerts*, *Code scanning alerts*, *Secret scanning alerts*, *Contents* y *Metadata*.
   - Caducidad corta (90 días).
2. Guárdalo como secreto del repo con el nombre **`DASHBOARD_TOKEN`** (Settings → Secrets and variables → Actions).
3. Lanza el workflow a mano: Actions → *Weekly security report* → *Run workflow*.

En local:

```bash
export GH_TOKEN=<tu_token>            # PowerShell: $env:GH_TOKEN = "<tu_token>"
python -m dashboard --fail-on-gate
python -m unittest discover -s tests -t . -v
```

## Decisiones y límites

- **Sin dependencias**: biblioteca estándar de Python, así no hay nada que actualizar ni que vigilar en la cadena de suministro.
- **Mínimo privilegio**: el workflow arranca sin permisos y solo el job pide `contents: write` para guardar el informe; el token que lee las alertas es de solo lectura; las actions están fijadas por SHA.
- **"No disponible" no es "cero"**: si una fuente no está habilitada en un repo o el token no tiene permiso, el informe lo lista en *Datos no disponibles*. Si el repo entero no se puede leer, el programa falla en lugar de informar de 0 alertas.
- **Riesgos aceptados en repos privados**: CodeQL en un repo privado requiere licencia de GitHub Advanced Security. Si un repo es privado y no tiene code scanning, su SAST sale como 🔒 en lugar de ❌, no cuenta en la cobertura y aparece en la sección *Riesgos aceptados* del informe: es una decisión documentada, no un hueco escondido.
- **Los controles se detectan por texto** en los workflows (por ejemplo `gitleaks` o `zaproxy`) y por la configuración del repo (Dependabot, CodeQL por defecto). Es una aproximación: dice que el control está en el pipeline, no que esté bien configurado.
- **Cobertura solo sobre lo aplicable**: cada repo puede declarar en `config.json` los controles que no le corresponden (`not_applicable`). En el informe salen como **N/A** y no cuentan en la cobertura, para que un repo sin API no baje el % de DAST. Lo que no se declara se exige, así que un repo nuevo empieza con todos los controles.
