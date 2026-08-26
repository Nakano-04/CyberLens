from __future__ import annotations

import json
import os


def load_sigma_yaml(path: str) -> list[dict]:
    """Carga YAML SIGMA -> list[RuleCreate dicts] (name, pattern_stdout, severity, technique_id)."""
    if not path or not os.path.exists(path):
        return []
    try:
        import yaml  # type: ignore

        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except ImportError:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
            try:
                data = json.loads(raw)
            except Exception:
                return []
    except Exception:
        return []
    if data is None:
        return []
    if isinstance(data, dict) and "rules" in data:
        data = data["rules"]
    items = data if isinstance(data, list) else [data]
    out: list[dict] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("title") or entry.get("name") or entry.get("id") or "sigma-rule")
        severity = str(entry.get("level") or entry.get("severity") or "medium").lower()
        if severity not in ("low", "medium", "high", "critical"):
            severity = "medium"
        technique_id = ""
        tags = entry.get("tags") or []
        if isinstance(tags, list):
            for t in tags:
                tl = str(t).lower()
                if tl.startswith("attack.t") or tl.startswith("t1"):
                    technique_id = str(t).split(".")[-1].upper() if "." in str(t) else str(t).upper()
                    break
        if not technique_id:
            technique_id = str(entry.get("technique_id") or entry.get("technique") or entry.get("attack") or "")
        pattern_stdout = ""
        det = entry.get("detection") or {}
        if isinstance(det, dict):
            sel = det.get("selection") or det.get("keywords") or {}
            if isinstance(sel, dict):
                vals = []
                for v in sel.values():
                    if isinstance(v, list):
                        vals.extend(str(x) for x in v)
                    else:
                        vals.append(str(v))
                if vals:
                    pattern_stdout = vals[0]
            elif isinstance(sel, list) and sel:
                pattern_stdout = str(sel[0])
        if not pattern_stdout:
            pattern_stdout = str(entry.get("pattern") or entry.get("pattern_stdout") or entry.get("search") or name)
        out.append({"name": name, "pattern_stdout": pattern_stdout, "severity": severity, "technique_id": technique_id})
    return out
