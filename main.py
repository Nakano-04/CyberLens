from __future__ import annotations

import argparse
import os

import uvicorn
import yaml


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def build_mediator(config: dict):
    from core.compactor import Compactor
    from core.mediator import Mediator
    from core.storage import Storage
    from providers.http_provider import HttpScannerProvider, HttpTechniqueProvider
    from providers.scanner import YaraScannerProvider
    from providers.technique import BuiltinTechniqueProvider

    llm = config.get("llm", {})
    compactor = Compactor(
        base_url=llm.get("base_url", "") or "",
        api_key=llm.get("api_key", "") or "",
        model=llm.get("model", "") or "",
        min_results=config.get("compaction", {}).get("min_results", 20),
    )

    providers = config.get("providers", {})
    if providers.get("techniques") == "http":
        techniques = HttpTechniqueProvider(
            providers.get("techniques_url", ""),
            providers.get("techniques_api_key", ""),
        )
    else:
        techniques = BuiltinTechniqueProvider()
    if providers.get("scanner") == "http":
        scanner = HttpScannerProvider(
            providers.get("scanner_url", ""),
            providers.get("scanner_api_key", ""),
        )
    else:
        scanner = YaraScannerProvider(binary=providers.get("scanner_binary", "yara"))

    storage_config = config.get("storage", {})
    storage = Storage(storage_config["path"]) if storage_config.get("enabled") else None

    scope_config = config.get("scope", {})
    executor_config = config.get("executor", {})
    graph_config = config.get("graph", {})
    detection_config = config.get("detection", {})

    return Mediator(
        allowed_hosts=config.get("allowed_hosts") or None,
        denied_prefixes=config.get("denied_prefixes") or None,
        command_timeout=config.get("command_timeout", 60),
        max_results_in_context=config.get("max_results_in_context", 15),
        compactor=compactor,
        priorities=config.get("assessment_priorities") or [],
        techniques=techniques,
        scanner=scanner,
        storage=storage,
        deny_evasions=scope_config.get("deny_evasions", True),
        require_approval_patterns=scope_config.get("require_approval_patterns") or None,
        sandbox=executor_config.get("sandbox") or None,
        sandbox_image=executor_config.get("sandbox_image", "alpine"),
        node_ttl_seconds=(
            int(graph_config.get("node_ttl_hours", 0) * 3600)
            if graph_config.get("node_ttl_hours")
            else None
        ),
        max_nodes_per_kind=graph_config.get("max_nodes_per_kind") or None,
        prune_min_confidence=graph_config.get("prune_min_confidence", 0.5),
        session_budget_steps=config.get("session_budget_steps") or None,
        dedup_window_seconds=detection_config.get("dedup_window_seconds", 300),
        max_alerts=detection_config.get("max_alerts") or None,
        auto_register_nodes=detection_config.get("auto_register_nodes", True),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Offensive Context Engine")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    server_config = config.get("server", {})
    host = args.host or server_config.get("host", "127.0.0.1")
    port = args.port or server_config.get("port", 8000)

    from api.server import create_app

    mediator = build_mediator(config)
    api_config = config.get("api", {})
    token = os.environ.get("MEDIADOR_API_TOKEN", "") or api_config.get("token", "") or None
    app = create_app(
        mediator,
        api_token=token,
        sentryguard_rules_dir=(
            config.get("debrief", {}).get("sentryguard_rules_dir") or None
        ),
    )
    if token:
        print("Auth de API habilitada (token requerido)")
    print(f"Offensive Context Engine escuchando en http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
