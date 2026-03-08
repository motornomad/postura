from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "postura_dev"
    redis_url: str = "redis://localhost:6379/0"

    github_webhook_secret: str = ""
    github_token: str = ""

    llm_provider: str = "anthropic"         # "anthropic" | "openai"
    llm_model: str = "claude-sonnet-4-20250514"
    llm_api_key: str = ""

    vector_store: str = "chromadb"          # "chromadb" | "qdrant"
    embedding_model: str = "BAAI/bge-m3"
    knowledge_store_path: str = "./knowledge_store"

    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    log_level: str = "INFO"

    class Config:
        env_file = ".env"
        env_prefix = "POSTURA_"


settings = Settings()
