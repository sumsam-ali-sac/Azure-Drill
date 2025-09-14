from functools import lru_cache
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# Load environment variables from .env file
load_dotenv()


class BaseConfig(BaseSettings):
    """Base configuration class for common settings."""
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        validate_assignment = True
        # Allow extra fields to be ignored if they are not defined in the model
        # This is useful if a .env file has more variables than the model expects.
        extra = "ignore"

# You can use lru_cache here if you want to ensure settings are loaded only once
# @lru_cache()
# def get_settings():
#     return Settings() # Assuming a main Settings class that combines all
