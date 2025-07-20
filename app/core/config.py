import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

class Settings(BaseSettings):
    """
    VESTA App Conguration, charging from enviorenment variables.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "VESTA Backend API"
    PROJECT_VERSION: str = "0.1.0"
    PROJECT_DESCRIPTION: str = "Artificial Intelligence for Cibersecurity"

    # Cros settings
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

