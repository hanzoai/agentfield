"""
Media Provider Abstraction for AgentField

Provides a unified interface for different media generation backends:
- OpenRouter (via LiteLLM)
- OpenAI DALL-E (via LiteLLM)
- Fal.ai
- Future: ElevenLabs, Replicate, etc.

Each provider implements the same interface, making it easy to swap
backends or add new ones without changing agent code.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from agentfield.multimodal_response import (
    AudioOutput,
    ImageOutput,
    MultimodalResponse,
)


class MediaProvider(ABC):
    """
    Abstract base class for media generation providers.

    Subclass this to add support for new image/audio generation backends.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for identification."""
        pass

    @property
    @abstractmethod
    def supported_modalities(self) -> List[str]:
        """List of supported modalities: 'image', 'audio', 'video'."""
        pass

    @abstractmethod
    async def generate_image(
        self,
        prompt: str,
        model: Optional[str] = None,
        size: str = "1024x1024",
        quality: str = "standard",
        **kwargs,
    ) -> MultimodalResponse:
        """
        Generate an image from a text prompt.

        Args:
            prompt: Text description of the image
            model: Model to use (provider-specific)
            size: Image dimensions
            quality: Quality level
            **kwargs: Provider-specific options

        Returns:
            MultimodalResponse with generated image(s)
        """
        pass

    @abstractmethod
    async def generate_audio(
        self,
        text: str,
        model: Optional[str] = None,
        voice: str = "alloy",
        format: str = "wav",
        **kwargs,
    ) -> MultimodalResponse:
        """
        Generate audio/speech from text.

        Args:
            text: Text to convert to speech
            model: TTS model to use
            voice: Voice identifier
            format: Audio format
            **kwargs: Provider-specific options

        Returns:
            MultimodalResponse with generated audio
        """
        pass


class FalProvider(MediaProvider):
    """
    Fal.ai provider for image and audio generation.

    Supports models like:
    - fal-ai/flux-pro - High-quality image generation
    - fal-ai/flux-dev - Development image model
    - fal-ai/stable-diffusion-xl - SDXL
    - fal-ai/f5-tts - Text-to-speech

    Requires FAL_KEY environment variable or explicit api_key.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Fal provider.

        Args:
            api_key: Fal.ai API key. If not provided, uses FAL_KEY env var.
        """
        self._api_key = api_key
        self._client = None

    @property
    def name(self) -> str:
        return "fal"

    @property
    def supported_modalities(self) -> List[str]:
        return ["image", "audio"]

    def _get_client(self):
        """Lazy initialization of fal client."""
        if self._client is None:
            try:
                import fal_client

                if self._api_key:
                    import os
                    os.environ["FAL_KEY"] = self._api_key

                self._client = fal_client
            except ImportError:
                raise ImportError(
                    "fal-client is not installed. Install it with: pip install fal-client"
                )
        return self._client

    async def generate_image(
        self,
        prompt: str,
        model: Optional[str] = None,
        size: str = "1024x1024",
        quality: str = "standard",
        num_images: int = 1,
        **kwargs,
    ) -> MultimodalResponse:
        """
        Generate image using Fal.ai.

        Args:
            prompt: Text prompt for image generation
            model: Fal model (defaults to "fal-ai/flux-pro")
            size: Image size (parsed into width/height)
            quality: Quality preset (maps to num_inference_steps)
            num_images: Number of images to generate
            **kwargs: Additional fal-specific parameters

        Returns:
            MultimodalResponse with generated images
        """
        client = self._get_client()

        # Default model
        if model is None:
            model = "fal-ai/flux-pro"

        # Parse size
        width, height = 1024, 1024
        if "x" in size:
            parts = size.split("x")
            width, height = int(parts[0]), int(parts[1])

        # Map quality to inference steps
        inference_steps = 25 if quality == "standard" else 50

        # Build request arguments
        fal_args = {
            "prompt": prompt,
            "image_size": {"width": width, "height": height},
            "num_inference_steps": inference_steps,
            "num_images": num_images,
            **kwargs,
        }

        try:
            # Run fal model
            result = await client.run_async(model, arguments=fal_args)

            # Extract images from result
            images = []
            if "images" in result:
                for img_data in result["images"]:
                    url = img_data.get("url")
                    if url:
                        images.append(
                            ImageOutput(
                                url=url,
                                b64_json=None,
                                revised_prompt=prompt,
                            )
                        )

            return MultimodalResponse(
                text=prompt,
                audio=None,
                images=images,
                files=[],
                raw_response=result,
            )

        except Exception as e:
            from agentfield.logger import log_error

            log_error(f"Fal image generation failed: {e}")
            raise

    async def generate_audio(
        self,
        text: str,
        model: Optional[str] = None,
        voice: str = "alloy",
        format: str = "wav",
        **kwargs,
    ) -> MultimodalResponse:
        """
        Generate audio using Fal.ai TTS.

        Args:
            text: Text to convert to speech
            model: Fal TTS model (defaults to "fal-ai/f5-tts")
            voice: Voice reference (can be URL to reference audio)
            format: Audio format
            **kwargs: Additional fal-specific parameters

        Returns:
            MultimodalResponse with generated audio
        """
        client = self._get_client()

        # Default model
        if model is None:
            model = "fal-ai/f5-tts"

        # Build request arguments
        fal_args = {
            "gen_text": text,
            **kwargs,
        }

        # Add voice reference if provided as URL
        if voice and (voice.startswith("http") or voice.startswith("data:")):
            fal_args["ref_audio_url"] = voice

        try:
            result = await client.run_async(model, arguments=fal_args)

            # Extract audio from result
            audio = None
            if "audio_url" in result:
                audio = AudioOutput(
                    url=result["audio_url"],
                    data=None,
                    format=format,
                )

            return MultimodalResponse(
                text=text,
                audio=audio,
                images=[],
                files=[],
                raw_response=result,
            )

        except Exception as e:
            from agentfield.logger import log_error

            log_error(f"Fal audio generation failed: {e}")
            raise


class LiteLLMProvider(MediaProvider):
    """
    LiteLLM-based provider for OpenAI, Azure, and other LiteLLM-supported backends.

    Uses LiteLLM's image_generation and speech APIs.
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "litellm"

    @property
    def supported_modalities(self) -> List[str]:
        return ["image", "audio"]

    async def generate_image(
        self,
        prompt: str,
        model: Optional[str] = None,
        size: str = "1024x1024",
        quality: str = "standard",
        style: Optional[str] = None,
        response_format: str = "url",
        **kwargs,
    ) -> MultimodalResponse:
        """Generate image using LiteLLM (DALL-E, Azure DALL-E, etc.)."""
        from agentfield import vision

        model = model or "dall-e-3"

        return await vision.generate_image_litellm(
            prompt=prompt,
            model=model,
            size=size,
            quality=quality,
            style=style,
            response_format=response_format,
            **kwargs,
        )

    async def generate_audio(
        self,
        text: str,
        model: Optional[str] = None,
        voice: str = "alloy",
        format: str = "wav",
        speed: float = 1.0,
        **kwargs,
    ) -> MultimodalResponse:
        """Generate audio using LiteLLM TTS."""
        try:
            import litellm

            litellm.suppress_debug_info = True
        except ImportError:
            raise ImportError(
                "litellm is not installed. Install it with: pip install litellm"
            )

        model = model or "tts-1"

        try:
            response = await litellm.aspeech(
                model=model,
                input=text,
                voice=voice,
                speed=speed,
                **kwargs,
            )

            # Extract audio data
            audio_data = None
            if hasattr(response, "content"):
                import base64

                audio_data = base64.b64encode(response.content).decode("utf-8")

            audio = AudioOutput(
                data=audio_data,
                format=format,
                url=None,
            )

            return MultimodalResponse(
                text=text,
                audio=audio,
                images=[],
                files=[],
                raw_response=response,
            )

        except Exception as e:
            from agentfield.logger import log_error

            log_error(f"LiteLLM audio generation failed: {e}")
            raise


class OpenRouterProvider(MediaProvider):
    """
    OpenRouter provider for image generation via chat completions.

    Supports models like:
    - google/gemini-2.5-flash-image-preview
    - Other OpenRouter models with image generation
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "openrouter"

    @property
    def supported_modalities(self) -> List[str]:
        return ["image"]  # OpenRouter primarily supports image generation

    async def generate_image(
        self,
        prompt: str,
        model: Optional[str] = None,
        size: str = "1024x1024",
        quality: str = "standard",
        **kwargs,
    ) -> MultimodalResponse:
        """Generate image using OpenRouter's chat completions API."""
        from agentfield import vision

        model = model or "openrouter/google/gemini-2.5-flash-image-preview"

        # Ensure model has openrouter prefix
        if not model.startswith("openrouter/"):
            model = f"openrouter/{model}"

        return await vision.generate_image_openrouter(
            prompt=prompt,
            model=model,
            size=size,
            quality=quality,
            style=None,
            response_format="url",
            **kwargs,
        )

    async def generate_audio(
        self,
        text: str,
        model: Optional[str] = None,
        voice: str = "alloy",
        format: str = "wav",
        **kwargs,
    ) -> MultimodalResponse:
        """OpenRouter doesn't support TTS directly."""
        raise NotImplementedError(
            "OpenRouter doesn't support audio generation. Use LiteLLMProvider or FalProvider."
        )


# Provider registry for easy access
_PROVIDERS: Dict[str, type] = {
    "fal": FalProvider,
    "litellm": LiteLLMProvider,
    "openrouter": OpenRouterProvider,
}


def get_provider(name: str, **kwargs) -> MediaProvider:
    """
    Get a media provider instance by name.

    Args:
        name: Provider name ('fal', 'litellm', 'openrouter')
        **kwargs: Provider-specific initialization arguments

    Returns:
        MediaProvider instance

    Example:
        provider = get_provider("fal", api_key="...")
        result = await provider.generate_image("A sunset")
    """
    if name not in _PROVIDERS:
        raise ValueError(
            f"Unknown provider: {name}. Available: {list(_PROVIDERS.keys())}"
        )
    return _PROVIDERS[name](**kwargs)


def register_provider(name: str, provider_class: type):
    """
    Register a custom media provider.

    Args:
        name: Provider name for lookup
        provider_class: MediaProvider subclass

    Example:
        class MyProvider(MediaProvider):
            ...

        register_provider("my_provider", MyProvider)
    """
    if not issubclass(provider_class, MediaProvider):
        raise TypeError("provider_class must be a MediaProvider subclass")
    _PROVIDERS[name] = provider_class
