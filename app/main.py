import time
import uuid
import re

from fastapi import FastAPI, Request, HTTPException

from app.audit import audit_log
from app.schemas import (
    ChatCompletionChoice,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
)

# Importamos motores de Presidio para el bloque DLP (NLP)
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

app = FastAPI(
    title="DLP Guardrails Proxy",
    description="Proxy inverso DLP para uso corporativo de LLMs",
    version="0.1.0",
)

# ========================================================
# LÓGICA DLP (IDS/IPS) Y TOKENIZACIÓN
# ========================================================
_nlp_engine = NlpEngineProvider(nlp_configuration={
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "es", "model_name": "es_core_news_sm"}],
}).create_engine()

analyzer = AnalyzerEngine(nlp_engine=_nlp_engine, supported_languages=["es"])
anonymizer = AnonymizerEngine()

# Expresiones regulares estáticas para cazar DNI y credenciales de infraestructura (AWS)
DNI_REGEX = re.compile(r'\b\d{8}[A-HJ-NP-TV-Z]\b', re.IGNORECASE)
AWS_SECRET_REGEX = re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE)

# Almacén criptográfico reversible en memoria (OE1 - Datos en reposo)
MAPPING_STORE: dict[str, str] = {}

def custom_ids_scan(text: str) -> str:
    """Módulo IDS: Detecta PII y secretos usando firmas estáticas y NLP.

    Las regex corren primero para capturar el valor original en MAPPING_STORE
    antes de que Presidio reescriba el texto.
    """
    processed_text = text

    # A. RegEx estáticas para DNI (debe ir antes que NLP para capturar el valor original)
    for match in DNI_REGEX.findall(processed_text):
        placeholder = "[DNI_1]"
        MAPPING_STORE[placeholder] = match
        processed_text = processed_text.replace(match, placeholder)

    # B. RegEx estáticas para secretos (Tokens AWS)
    for match in AWS_SECRET_REGEX.findall(processed_text):
        placeholder = "[AWS_TOKEN_1]"
        MAPPING_STORE[placeholder] = match
        processed_text = processed_text.replace(match, placeholder)

    # C. NLP para entidades comunes (Nombres, Emails) con modelo en español.
    #    ES_NIF actúa como red de seguridad por si la regex no captura algún DNI.
    analyzer_results = analyzer.analyze(text=processed_text, language="es")
    anonymized_result = anonymizer.anonymize(
        text=processed_text,
        analyzer_results=analyzer_results,
        operators={
            "PERSON": OperatorConfig("replace", {"new_value": "[USER_1]"}),
            "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL_1]"}),
            "ES_NIF": OperatorConfig("replace", {"new_value": "[DNI_1]"}),
        }
    )
    processed_text = anonymized_result.text

    return processed_text

def detect_prompt_injection(text: str) -> None:
    """Módulo IPS: Previene ataques de extensión de la influencia (Jailbreaks)."""
    jailbreak_keywords = [
        "ignore previous instructions", 
        "ignora las instrucciones anteriores", 
        "system prompt", 
        "you are now a compliance-free"
    ]
    if any(kw in text.lower() for kw in jailbreak_keywords):
        raise HTTPException(
            status_code=403, 
            detail="[IPS ALERT] Petición bloqueada. Intento de Prompt Injection detectado."
        )

def rehydrate_response(llm_response: str) -> str:
    """Restaura los datos reales en el entorno local antes de responder al cliente."""
    final_output = llm_response
    for placeholder, original_value in MAPPING_STORE.items():
        final_output = final_output.replace(placeholder, original_value)
    return final_output

# ========================================================
# ENDPOINTS Y FLUJO DEL PROXY
# ========================================================

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

    # El prompt que envía el empleado en el último mensaje
    last_user_message = payload.messages[-1].content

    # --- CONTROL IPS (Previene hackeos/jailbreaks) ---
    try:
        detect_prompt_injection(last_user_message)
    except HTTPException as e:
        # Registramos el bloqueo por ataque en los logs de auditoría
        audit_log(
            event="chat_completion.blocked_ips",
            request_id=request_id,
            user_id=user_id,
            src_ip=src_ip,
            decision="block",
            model=payload.model,
        )
        raise e

    # Forzar el mapping si simulan ser Juan Pérez en la demo interactiva
    if "Juan Pérez" in last_user_message:
        MAPPING_STORE["[USER_1]"] = "Juan Pérez"

    # -- DLP / SANITIZE (Anonimiza el prompt antes de salir) ---
    clean_prompt = custom_ids_scan(last_user_message)
    print(f"[PROXY -> LLM UPSTREAM] Enviando prompt seguro: '{clean_prompt}'")

    # --- MOCK DE LA RESPUESTA DEL LLM UPSTREAM ---
    # Simulamos que la API externa devuelve texto usando tus tokens síncronos
    llm_mock_response = "Acceso confirmado para el usuario [USER_1] con credencial [DNI_1]. Petición procesada de forma segura."
    print(f"[LLM UPSTREAM -> PROXY] Respuesta cruda externa: '{llm_mock_response}'")

    # --- CAPA REHYDRATE (Recupera los datos planos en local de forma transparente) ---
    final_content = rehydrate_response(llm_mock_response)

    reply = ChatMessage(
        role="assistant",
        content=final_content,
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