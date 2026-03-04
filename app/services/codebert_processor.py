from typing import Any, Tuple

import numpy as np

from app.utilities.logger import logger
from app.core.config import settings

MODEL_NAME = settings.TRANSFORMER_MODEL_NAME


def _import_transformers_runtime() -> tuple[Any, Any]:
    """
    Lazy import for heavyweight ML runtime dependencies.

    This keeps lightweight test/CI flows from requiring torch/transformers
    until CodeBERT is actually needed.
    """
    try:
        from transformers import AutoModel, AutoTokenizer  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise ImportError(
            "transformers runtime is required to load CodeBERT. "
            "Install optional ML dependencies (torch + transformers)."
        ) from exc
    return AutoModel, AutoTokenizer


def _import_torch_runtime() -> Any:
    try:
        import torch  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise ImportError(
            "torch runtime is required to generate CodeBERT embeddings."
        ) from exc
    return torch


def load_codebert_model() -> Tuple[Any, Any]:
    """
    Download and charge the CodeBERT model and tokenizer.
    
    The first time it runs, it will download the model (approx. 500 MB)
    and save it to a local cache. Subsequent times, it will load it
    directly from the disk.
    
    Returns:
        Tuple[AutoModel, AutoTokenizer]: A tuple containing the loaded model and tokenizer.
    """

    logger.info("Loading CodeBERT model and tokenizer...")
    
    AutoModel, AutoTokenizer = _import_transformers_runtime()

    # Charging the tokenizer and model from Hugging Face
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModel.from_pretrained(MODEL_NAME) # type: ignore
    
    logger.info("✅ Model and Tokenizer loaded successfully.")
    return model, tokenizer

def get_code_embedding(source_code: str, model: Any, tokenizer: Any) -> np.ndarray:
    """
    Generate a embedding vector for a source code snippet.

    Args:
        source_code (str): Code to analyze.
        model (AutoModel): CODEBERT Model.
        tokenizer (AutoTokenizer): CodeBERT Tokenizer.

    Returns:
        np.ndarray: Numpy vector with 768 dimensions that represents the code.
    """
    torch = _import_torch_runtime()

    # Deteced a disponible gpu
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model.to(device) # type: ignore

    logger.info(f"Generating embedding for the provided code snippet on device: {device}")

    # Tokenizer: To convert all of code text to numbers that the model will understand.
    inputs = tokenizer(
        source_code, 
        return_tensors="pt", 
        padding=True, 
        truncation=True, 
        max_length=512
    ).to(device) # type: ignore

    # Inference: Pass the token to the model. 
    # torch.no_grad() disable gradient descending and model is faster and don't need more memory.
    with torch.no_grad():
        outputs = model(**inputs) # type: ignore

    # Extract embeddings of special token [CLS], has the meaning for the vector in the multidimensional space.
    # .squeeze() delet unnecessary dimensions.
    # .cpu().numpy() transform to array.
    embedding = outputs.last_hidden_state[:, 0, :].squeeze().cpu().numpy()
    
    return embedding

# --- Example code ---
if __name__ == "__main__":
    
    # 1. Charge the model and tokenizer
    codebert_model, codebert_tokenizer = load_codebert_model()
    
    # 2. Example code snippet to analyze
    sample_python_code = """
    import os
    
    def list_files(path):
        # List all files in a given directory
        files = os.listdir(path)
        for file in files:
            print(f"Found file: {file}")
    """
    
    print("\n" + "="*50)
    print("🔍 Analyzing the provided code snippet...")
    
    # 3. Generete the embedding
    embedding_vector = get_code_embedding(sample_python_code, codebert_model, codebert_tokenizer)
    
    # 4. Show results
    print(f"✅ Embedding generated successfully!")
    print(f"   - Dimensions of the vector: {embedding_vector.shape}")
    print(f"   - First 5 values: {embedding_vector[:5]}")
    print("="*50)
