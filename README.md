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
| Alertas resueltas en plazo (SLA) | % de alertas corregidas dentro del plazo de su severidad (por defecto: crítica 7 días, alta 30, media 90, baja 180). Una alerta abierta que supera su plazo cuenta como incumplida |
| Actions fijadas por SHA | % de `uses:` de los workflows que apuntan al SHA completo de un commit (no a un tag ni a una rama) |
| Workflows con permisos mínimos | % de workflows que declaran su propio `permissions:` para el `GITHUB_TOKEN` |
| Riesgos aceptados | Alertas de Dependabot descartadas a mano, con su motivo y si llevan justificación escrita |
| Evolución semanal | Foto de cada ejecución en [`data/history.json`](data), para ver la tendencia |

### Quality gate

Se define en `config.json`. Por defecto no se admite ninguna vulnerabilidad crítica ni alta, ningún secreto abierto, ninguna action sin fijar, ningún workflow sin `permissions:` ni ningún riesgo aceptado sin justificar:

```json
"gate": {
  "critical": 0, "high": 0, "secrets": 0,
  "unpinned_actions": 0, "workflows_without_permissions": 0, "accepted_without_comment": 0
}
```

Un límite que no aparece no se aplica: el dato sale en el informe, pero no bloquea. Por ejemplo, `"overdue_alerts": 0` haría fallar el gate si alguna alerta abierta supera su plazo de corrección.

Los plazos de corrección se definen en el mismo archivo, en días por severidad:

```json
"sla_days": { "critical": 7, "high": 30, "medium": 90, "low": 180 }
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
- **La media no basta**: el MTTR puede ser bueno aunque una alerta crítica tardara un mes, porque muchas correcciones rápidas la tapan. Por eso el informe mide también cuántas se corrigieron dentro del plazo de su severidad. Una alerta abierta solo cuenta cuando ya ha superado su plazo (como incumplida); las descartadas y los secretos quedan fuera, y una severidad sin plazo en `sla_days` no se mide.
- **Cadena de suministro**: un tag (`@v4`) lo puede mover quien controle el repo de la action; un SHA no. Es lo que pasó con `tj-actions/changed-files` (2025) y con `trivy-action` (marzo de 2026), donde se reescribieron los tags para robar secretos de los pipelines. Por eso el informe cuenta las actions sin fijar y el gate no admite ninguna. Se analiza el texto de los workflows: las actions locales (`./ruta`) no cuentan y una imagen `docker://` cuenta como fijada si va por digest. Lo que se instala dentro de un `run:` (un binario con `curl`, una imagen con `docker run`) no se ve desde aquí.
- **Permisos del `GITHUB_TOKEN`**: se comprueba que cada workflow declara `permissions:` a nivel de workflow, no que los permisos declarados sean los mínimos posibles.
- **Una alerta descartada no desaparece**: descartar una alerta de Dependabot la saca del recuento de abiertas, pero la vulnerabilidad sigue ahí. El informe las lista en *Riesgos aceptados* con su motivo, y marca las que no tienen comentario: sin justificación escrita no es una aceptación de riesgo, es ignorar la alerta. Las que GitHub descarta solo (`auto_dismissed`) no cuentan. Por defecto no se publica ni el paquete ni el comentario (`"accepted_risk_details": false`), porque en un repo público sería una lista de vulnerabilidades conocidas y sin corregir.
- **Cobertura solo sobre lo aplicable**: cada repo puede declarar en `config.json` los controles que no le corresponden (`not_applicable`). En el informe salen como **N/A** y no cuentan en la cobertura, para que un repo sin API no baje el % de DAST. Lo que no se declara se exige, así que un repo nuevo empieza con todos los controles.
