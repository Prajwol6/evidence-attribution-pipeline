import json
import time

import anthropic

from utils import logger

_REASON_SYSTEM = (
    "You are a forensic analyst examining security event timelines. "
    "Analyze the events and generate hypotheses about potential security incidents. "
    "The 'support' field in each hypothesis must be the exact source file path "
    "from the corresponding timeline event — do not summarize or paraphrase it."
)

_REASON_SCHEMA = {
    "format": {
        "type": "json_schema",
        "schema": {
            "type": "object",
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "claim": {"type": "string"},
                            "support": {"type": "string"},
                        },
                        "required": ["claim", "support"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["hypotheses"],
            "additionalProperties": False,
        },
    }
}

_MAX_RETRIES = 3


def llm_reason(timeline):
    logger.info("llm_reason_start", extra={"data": {"event_count": len(timeline)}})
    t0 = time.monotonic()
    client = anthropic.Anthropic()

    messages = [{
        "role": "user",
        "content": (
            "Analyze this forensic timeline and generate hypotheses:\n\n"
            + json.dumps(timeline, indent=2)
        ),
    }]

    last_exc = None

    for attempt in range(1, _MAX_RETRIES + 1):
        response = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=4096,
            thinking={"type": "adaptive"},
            system=_REASON_SYSTEM,
            messages=messages,
            output_config=_REASON_SCHEMA,
        )

        text_block = next((b for b in response.content if b.type == "text"), None)

        try:
            if text_block is None:
                raise ValueError("response contained no text block")

            hypotheses = json.loads(text_block.text).get("hypotheses")

            if not hypotheses:
                raise ValueError("hypotheses list is empty")

            usage = response.usage
            logger.info("llm_reason_complete", extra={"data": {
                "attempt": attempt,
                "hypothesis_count": len(hypotheses),
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "total_tokens": usage.input_tokens + usage.output_tokens,
                "duration_s": round(time.monotonic() - t0, 3),
            }})
            return hypotheses

        except (json.JSONDecodeError, ValueError) as exc:
            last_exc = exc
            raw_output = text_block.text[:300] if text_block else "(none)"
            logger.warning("llm_reason_retry", extra={"data": {
                "attempt": attempt,
                "max_retries": _MAX_RETRIES,
                "error": str(exc),
                "raw_output": raw_output,
            }})

            if attempt < _MAX_RETRIES:
                # Self-correction: feed the bad response back and tell the model
                # exactly what was wrong so it can fix its own output.
                messages.append({"role": "assistant", "content": response.content})
                messages.append({
                    "role": "user",
                    "content": (
                        f"Your previous response was invalid: {exc}. "
                        "Return a valid JSON object with a non-empty 'hypotheses' array. "
                        "Each item must have 'claim' (string describing the finding) and "
                        "'support' (exact source file path from the timeline). "
                        "Do not return an empty hypotheses list."
                    ),
                })

    raise RuntimeError(
        f"llm_reason failed after {_MAX_RETRIES} attempts. Last error: {last_exc}"
    )
