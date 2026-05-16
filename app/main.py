import time
import uuid

from fastapi import FastAPI, Request

from app.audit import audit_log
from app.schemas import (
    ChatCompletionChoice,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
)

app = FastAPI(
    title="DLP Guardrails Proxy",
    description="Proxy inverso DLP para uso corporativo de LLMs",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(
    payload: ChatCompletionRequest,
    request: Request,
) -> ChatCompletionResponse:
    request_id = f"req_{uuid.uuid4().hex}"
    src_ip = request.client.host if request.client else None
    user_id = payload.user or request.headers.get("x-user-id")

    audit_log(
        event="chat_completion.received",
        request_id=request_id,
        user_id=user_id,
        src_ip=src_ip,
        decision="allow",
        model=payload.model,
        n_messages=len(payload.messages),
    )

    # TODO Fase 2: sanitize() -> proxy upstream -> rehydrate()
    reply = ChatMessage(
        role="assistant",
        content="[stub] respuesta pendiente de integrar con LLM upstream",
    )

    audit_log(
        event="chat_completion.responded",
        request_id=request_id,
        user_id=user_id,
        src_ip=src_ip,
        decision="allow",
        model=payload.model,
    )

    return ChatCompletionResponse(
        id=f"chatcmpl-{uuid.uuid4().hex}",
        created=int(time.time()),
        model=payload.model,
        choices=[ChatCompletionChoice(index=0, message=reply)],
    )
