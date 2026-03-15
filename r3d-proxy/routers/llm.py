"""LLM proxy and dashboard AI analysis."""

import litellm
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.auth import verify_api_key
from core.config import DEFAULT_MODEL

router = APIRouter(tags=["llm"])

# ─── Request Models ──────────────────────────────────────────────────


class ChatCompletionRequest(BaseModel):
    model: str | None = None
    messages: list[dict] = []
    max_tokens: int = 2048
    temperature: float = 0.3
    response_format: dict | None = None


class AnalyzeRequest(BaseModel):
    prompt: str = ""


_ANALYZE_SYSTEM_PROMPT = (
    "You are R3D, an offensive security intelligence system. Be precise, actionable, "
    "and compliance-aware (GDPR, SOX, HIPAA, PCI-DSS, SOC2). "
    "Every response MUST be valid JSON and MUST include ALL of these top-level keys:\n"
    '  "executiveSummary" — 2-3 sentence C-suite-ready overview of risk posture\n'
    '  "tldr" — single sentence, max 30 words, plain English\n'
    '  "businessImpact" — concrete business consequences (revenue, reputation, regulatory fines)\n'
    '  "sampleCurl" — a ready-to-paste curl command that demonstrates or validates the '
    "highest-severity finding (use realistic but safe placeholder values like example.com)\n\n"
    "FINDING VALIDATION: Findings have a 'status' field: confirmed, likely, hypothesis, or false_positive. "
    "Treat these differently:\n"
    "  - 'confirmed' findings have direct evidence (e.g. weak CSP observed in headers)\n"
    "  - 'likely' findings have strong indicators but incomplete validation\n"
    "  - 'hypothesis' findings are pattern-match only (e.g. parameter named redirect_uri exists "
    "but server-side allowlist was not tested) — DO NOT present these as confirmed vulnerabilities. "
    "Instead, note what validation is needed.\n"
    "  - 'false_positive' findings should be excluded from risk assessment\n"
    "When a finding says 'hypothesis' or has LOW confidence, explicitly state: "
    "'This requires manual verification before confirming exploitability.'\n"
    "NEVER amplify an unvalidated pattern match into an alarming P0 finding.\n\n"
    "SYSTEM PROFILING: When analyzing a system, always identify WHAT it is based on "
    "URL patterns, endpoints, headers, and behavior. Classify it as internal app, "
    "internal API, third-party SaaS, identity provider, etc. "
    "RED TEAM RELEVANCE: The operator is red teaming INTERNAL applications. "
    "External SaaS platforms (Gmail, Google Workspace, Okta, Salesforce, Slack, etc.) "
    "should be flagged as SKIP/low-priority UNLESS the analysis reveals leaked tokens, "
    "tenant-specific misconfigurations, or OAuth/SAML weaknesses exploitable from our tenant. "
    "Always include a clear ENGAGE or SKIP verdict with reasoning.\n\n"
    "Then include whatever additional keys the user's prompt requests."
)

# ─── Endpoints ───────────────────────────────────────────────────────


@router.post("/v1/chat/completions", dependencies=[Depends(verify_api_key)])
async def chat_completions(body: ChatCompletionRequest):
    """OpenAI-compatible chat completions via LiteLLM."""
    try:
        kwargs = dict(
            model=body.model or DEFAULT_MODEL,
            messages=body.messages,
            max_tokens=body.max_tokens,
            temperature=body.temperature,
        )
        if body.response_format:
            kwargs["response_format"] = body.response_format
        response = await litellm.acompletion(**kwargs)
        return JSONResponse(content=response.model_dump())
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": str(e)})


@router.post("/r3d/analyze", dependencies=[Depends(verify_api_key)])
async def analyze(body: AnalyzeRequest):
    """Run an AI analysis from the dashboard."""
    try:
        response = await litellm.acompletion(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": _ANALYZE_SYSTEM_PROMPT},
                {"role": "user", "content": body.prompt},
            ],
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content or ""
        return {"ok": True, "content": content, "model": response.model or DEFAULT_MODEL}
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": str(e)})
