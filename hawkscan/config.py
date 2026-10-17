"""HawkScan Configuration & Environment Settings"""

import os
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load root .env
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))


class Settings(BaseModel):
    HAWKSCAN_HOST: str = Field(default_factory=lambda: os.getenv("HAWKSCAN_HOST", os.getenv("SHANNON_HOST", "127.0.0.1")))
    HAWKSCAN_PORT: int = Field(default_factory=lambda: int(os.getenv("HAWKSCAN_PORT", os.getenv("SHANNON_PORT", "9090"))))
    DEFAULT_TARGET_URL: str = os.getenv("TARGET_URL", "http://127.0.0.1:8000")
    DEFAULT_REPO_PATH: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # API Keys
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    TINYFISH_API_KEY: str = os.getenv("TINYFISH_API_KEY", "")
    TINYFISH_API_URL: str = os.getenv("TINYFISH_API_URL", "https://api.browser.tinyfish.ai")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")

    DEFAULT_LLM_MODEL: str = os.getenv("DEFAULT_LLM_MODEL", "gemini/gemini-3.5-flash")

    @property
    def SHANNON_HOST(self) -> str:
        return self.HAWKSCAN_HOST

    @property
    def SHANNON_PORT(self) -> int:
        return self.HAWKSCAN_PORT


settings = Settings()
