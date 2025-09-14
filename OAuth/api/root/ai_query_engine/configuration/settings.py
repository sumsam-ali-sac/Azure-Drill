from typing import Optional

from dotenv import find_dotenv, load_dotenv
from pydantic_settings import BaseSettings

load_dotenv()

# todo: rework to remove deployment names.  these should be set by the concrete class
class EngineSettings(BaseSettings):
    """
    environment variables required to work with langchain and openAI libraries (openAI, Azure openAI specific)
    """
    azure_openai_api_key: str
    azure_openai_endpoint: str
    openai_api_type: str
    openai_api_version: str
    openai_chat_engine: Optional[str] = None


engine_settings = EngineSettings()
