import json
from datetime import datetime, timezone
from typing import Any


def audit_log(
    event: str,
    request_id: str,
    user_id: str | None,
    src_ip: str | None,
    decision: str,
    **extra: Any,
) -> None:
    """Emite un evento de auditoría en JSON por stdout.

    No debe incluir nunca contenido plano de PII (DNI, secretos, prompt crudo).
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "request_id": request_id,
        "user_id": user_id,
        "src_ip": src_ip,
        "decision": decision,
        **extra,
    }
    print(json.dumps(record, ensure_ascii=False, separators=(",", ":")), flush=True)
