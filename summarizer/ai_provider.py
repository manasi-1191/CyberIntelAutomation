"""
Provider-agnostic AI client factory.

Set AI_PROVIDER env var to select a provider:
  xai        — Grok via xAI (requires XAI_API_KEY)
  anthropic  — Claude via Anthropic (requires ANTHROPIC_API_KEY)
  gemini     — Gemini via Google (requires GEMINI_API_KEY)
  none       — AI disabled (default; summaries remain as placeholder text)

Optionally set AI_MODEL to override the provider's default model.
"""
import logging

logger = logging.getLogger(__name__)


class _XAIClient:
    def __init__(self, api_key: str, model: str):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError("openai package required for xAI: pip install openai") from exc
        self._client = OpenAI(api_key=api_key, base_url="https://api.x.ai/v1")
        self._model = model or "grok-3-mini"

    @property
    def model(self) -> str:
        return self._model

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> str | None:
        try:
            resp = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                max_tokens=max_tokens,
                temperature=0.1,
            )
            return resp.choices[0].message.content
        except Exception as exc:
            logger.error("xAI API error: %s", exc)
            return None


class _AnthropicClient:
    def __init__(self, api_key: str, model: str):
        try:
            import anthropic as _anthropic  # noqa: F401
        except ImportError as exc:
            raise RuntimeError("anthropic package required: pip install anthropic") from exc
        self._api_key = api_key
        self._model = model or "claude-haiku-4-5-20251001"

    @property
    def model(self) -> str:
        return self._model

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> str | None:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self._api_key)
            msg = client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return msg.content[0].text
        except Exception as exc:
            logger.error("Anthropic API error: %s", exc)
            return None


class _GeminiClient:
    def __init__(self, api_key: str, model: str):
        try:
            import google.generativeai  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "google-generativeai package required for Gemini: "
                "pip install google-generativeai"
            ) from exc
        self._api_key = api_key
        self._model = model or "gemini-2.5-flash"

    @property
    def model(self) -> str:
        return self._model

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> str | None:
        """
        Call the Gemini API and return the response text, or None on failure.

        gemini-2.5-flash uses "thinking" tokens by default. Thinking tokens count
        against max_output_tokens, so the caller's budget (designed for output length)
        would be almost entirely consumed by reasoning, leaving only a handful of tokens
        for actual text. We fix this two ways:

        1. Disable thinking (thinking_budget=0) via the generation config dict.
           The dict form is used because older SDK versions may not expose
           ThinkingConfig as a typed class; on failure we fall back silently.
        2. Scale max_output_tokens by 6× (minimum 2048) so even if thinking cannot
           be disabled, the output has ample headroom.
        """
        try:
            import google.generativeai as genai
            genai.configure(api_key=self._api_key)
            gemini_model = genai.GenerativeModel(
                model_name=self._model,
                system_instruction=system,
            )

            # Scale the budget to absorb thinking-token overhead
            scaled_tokens = max(max_tokens * 6, 2048)

            # Attempt 1: disable thinking via dict-based config (SDK-version agnostic)
            try:
                config = {
                    "max_output_tokens": scaled_tokens,
                    "temperature": 0.1,
                    "thinking_config": {"thinking_budget": 0},
                }
                response = gemini_model.generate_content(user, generation_config=config)
            except Exception:
                # Fallback: SDK does not support thinking_config — use scaled budget only
                fallback_config = genai.types.GenerationConfig(
                    max_output_tokens=scaled_tokens,
                    temperature=0.1,
                )
                response = gemini_model.generate_content(user, generation_config=fallback_config)

            # response.text raises ValueError when the response was blocked by safety filters
            try:
                text = response.text
            except (ValueError, AttributeError) as exc:
                logger.warning(
                    "Gemini response.text unavailable (safety block or stopped early): %s", exc
                )
                return None

            if text is None:
                logger.warning("Gemini returned None response text")
                return None

            logger.debug("Gemini raw response: %d chars", len(text))
            return text

        except Exception as exc:
            logger.error("Gemini API error: %s", exc)
            return None


def get_ai_client():
    """
    Return an AI client for the configured provider, or None if AI is disabled.
    Never raises — logs warnings and returns None on misconfiguration.
    """
    from config.settings import settings

    provider = settings.ai_provider.lower().strip()

    if provider == "xai":
        if not settings.xai_api_key:
            logger.warning("AI_PROVIDER=xai but XAI_API_KEY is not set — AI disabled")
            return None
        try:
            return _XAIClient(api_key=settings.xai_api_key, model=settings.ai_model)
        except Exception as exc:
            logger.error("Failed to initialise xAI client: %s", exc)
            return None

    if provider == "anthropic":
        if not settings.anthropic_api_key:
            logger.warning("AI_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set — AI disabled")
            return None
        try:
            return _AnthropicClient(api_key=settings.anthropic_api_key, model=settings.ai_model)
        except Exception as exc:
            logger.error("Failed to initialise Anthropic client: %s", exc)
            return None

    if provider == "gemini":
        if not settings.gemini_api_key:
            logger.warning("AI_PROVIDER=gemini but GEMINI_API_KEY is not set — AI disabled")
            return None
        try:
            return _GeminiClient(api_key=settings.gemini_api_key, model=settings.ai_model)
        except Exception as exc:
            logger.error("Failed to initialise Gemini client: %s", exc)
            return None

    if provider != "none":
        logger.warning(
            "Unknown AI_PROVIDER=%r — AI disabled (use xai, anthropic, gemini, or none)",
            provider,
        )
    return None
