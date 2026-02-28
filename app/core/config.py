import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


def _env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}

class Settings(BaseSettings):
    """
    VESTA App Conguration, charging from enviorenment variables.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "VESTA Backend API"
    PROJECT_VERSION: str = "0.1.0"
    PROJECT_DESCRIPTION: str = "Artificial Intelligence for Cibersecurity"

    # Cors settings
    CORS_ALLOW_ORIGINS: list[str] = ["http://localhost", "http://localhost:8080"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list[str] = ["*"]
    CORS_ALLOW_HEADERS: list[str] = ["*"]

    # Path to the modules and models
    # BASE_DIR is pointing to the 'vesta_backend/' directory
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent

    ML_MODELS_DIR: Path = BASE_DIR / "ml_models"
    SVM_MODEL_PATH: Path = ML_MODELS_DIR / "svm_1.4.0.pkl"
    CNN_MODEL_PATH: Path = ML_MODELS_DIR / "cnn_1.4.0.h5"
    META_MODEL_PATH: Path = ML_MODELS_DIR / "LR_meta_model_1.4.0.pkl"
    SCALER_PATH: Path = ML_MODELS_DIR / "vesta_scaler.pkl"

    # Directory for cloned repositories

    # Ensure the directory exists
    if not os.path.exists(Path.home() / "vesta_cloned_repos"):
        os.mkdir(Path.home() / "vesta_cloned_repos")

    CLONED_REPOS_BASE_DIR: Path = Path.home() / "vesta_cloned_repos"
    
    # Set GitHub/GitLab Webhooks (samples for testing purposes)
    GITHUB_WEBHOOK_SECRET: str = os.getenv("GITHUB_WEBHOOK_SECRET", "secretgithubkey")
    GITLAB_WEBHOOK_SECRET: str = os.getenv("GITLAB_WEBHOOK_SECRET", "secretgitlabkey")
    AVAILABLE_SERVER: bool = _env_bool("AVAILABLE_SERVER", "false")
    PASSWORD_POSTGRESQL: str = os.getenv("PASSWORD_POSTGRESQL", "vesta_password")
    ROLE_NAME_POSTGRESQL: str = os.getenv("ROLE_NAME_POSTGRESQL", "vesta_role")
    SERVER_WEB: str = os.getenv("SERVER_WEB", "")

    TRANSFORMER_MODEL_NAME: str = "microsoft/codebert-base"
    PREDICTION_THRESHOLD_SUSPICIOUS: float = float(os.getenv("PREDICTION_THRESHOLD_SUSPICIOUS", "0.45"))
    PREDICTION_THRESHOLD_MALICIOUS: float = float(os.getenv("PREDICTION_THRESHOLD_MALICIOUS", "0.75"))
    DAST_ENABLED: bool = _env_bool("DAST_ENABLED", "true")
    DAST_DOCKER_IMAGE: str = os.getenv("DAST_DOCKER_IMAGE", "python:3.12-alpine")
    DAST_TIMEOUT_SECONDS: int = int(os.getenv("DAST_TIMEOUT_SECONDS", "45"))
    DAST_MEMORY_LIMIT: str = os.getenv("DAST_MEMORY_LIMIT", "256m")
    DAST_PIDS_LIMIT: int = int(os.getenv("DAST_PIDS_LIMIT", "128"))
    DAST_CPU_QUOTA: int = int(os.getenv("DAST_CPU_QUOTA", "50000"))
    DAST_NETWORK_MODE: str = os.getenv("DAST_NETWORK_MODE", "none")
    DAST_TSHARK_ENABLED: bool = _env_bool("DAST_TSHARK_ENABLED", "false")
    DAST_TSHARK_PATH: str = os.getenv("DAST_TSHARK_PATH", "tshark")
    DAST_TSHARK_INTERFACE: str = os.getenv("DAST_TSHARK_INTERFACE", "any")

    @property
    def URL_DATABASE(self) -> str:
        if self.AVAILABLE_SERVER:
            return self.SERVER_WEB
        else:
            return f"postgresql://{self.ROLE_NAME_POSTGRESQL}:{self.PASSWORD_POSTGRESQL}@localhost:5432/vesta_db"



settings = Settings()   # Only one called we don't need more calls in other classes

    

if __name__ == "__main__":
    settings = Settings()
    print(settings.BASE_DIR)
    print(settings.SVM_MODEL_PATH)
    print(settings.CNN_MODEL_PATH)
    print(settings.META_MODEL_PATH)
    print(settings.SCALER_PATH)
    print(settings.CLONED_REPOS_BASE_DIR)
    print(os.path.exists(settings.CLONED_REPOS_BASE_DIR))
    print(settings.AVAILABLE_SERVER)
    print(settings.URL_DATABASE)

