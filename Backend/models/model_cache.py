import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from typing import Dict, Any, Optional
import logging
import gc

logger = logging.getLogger(__name__)

if torch.cuda.is_available():
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
        bnb_4bit_quant_type="nf4"
    )
else:
    bnb_config = None 


class ModelCache:
    """ Model Cache to loaded Model Once """
    _instance = None
    _models : Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelCache,cls).__new__(cls)
        return cls._instance
    

    def get_model(
            self,
            model_name:str = "Qwen/Qwen2.5-Coder-3B-Instruct",
            device: str = "auto",
            force_reload:bool = False
            ):
        """ Get once loaded model """

        cache_key = f"text::{model_name}"

        if cache_key in self._models and not force_reload:
            logger.info(f"Using cached text model: {model_name}")
            return self._models[cache_key]
        
        logger.info(f"Loading text model: {model_name}")

        try:
            # 1. Load Tokenizer
            try:
                tokenizer = AutoTokenizer.from_pretrained(
                    model_name,
                    use_fast=True,
                    trust_remote_code=True,
                    local_files_only=True
                )
                logger.info("Loaded tokenizer from local cache.")
            except Exception:
                logger.info("Tokenizer not found in local cache. Attempting download with timeout.")
                tokenizer = AutoTokenizer.from_pretrained(
                    model_name,
                    use_fast=True,
                    trust_remote_code=True,
                    local_files_only=False,
                    timeout=15
                )
            
            # Set padding token if not exists
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
                tokenizer.pad_token_id = tokenizer.eos_token_id


            # 2. Load Causal LM Model
            if torch.cuda.is_available() and bnb_config is not None:
                logger.info("Using 4-bit quantization")
                try:
                    model = AutoModelForCausalLM.from_pretrained(
                        model_name,
                        quantization_config=bnb_config,
                        torch_dtype=torch.bfloat16,
                        device_map=device,
                        low_cpu_mem_usage=True,
                        local_files_only=True
                    )
                    logger.info("Loaded quantized model from local cache.")
                except Exception:
                    logger.info("Quantized model not found in local cache. Attempting download with timeout.")
                    model = AutoModelForCausalLM.from_pretrained(
                        model_name,
                        quantization_config=bnb_config,
                        torch_dtype=torch.bfloat16,
                        device_map=device,
                        low_cpu_mem_usage=True,
                        local_files_only=False,
                        timeout=15
                    )
            else:
                try:
                    model = AutoModelForCausalLM.from_pretrained(
                        model_name,
                        torch_dtype=torch.bfloat16,
                        device_map=device,
                        low_cpu_mem_usage=True,
                        local_files_only=True
                    )
                    logger.info("Loaded model from local cache.")
                except Exception:
                    logger.info("Model not found in local cache. Attempting download with timeout.")
                    model = AutoModelForCausalLM.from_pretrained(
                        model_name,
                        torch_dtype=torch.bfloat16,
                        device_map=device,
                        low_cpu_mem_usage=True,
                        local_files_only=False,
                        timeout=15
                    )

            # Optimizing model for inference
            model.eval()

            # Enable optimizations
            if hasattr(model.config, "use_cache"):
                model.config.use_cache = True


            self._models[cache_key] = {
                "model" : model,
                "tokenizer" : tokenizer
            }

            logger.info(f"Text model loaded and cached")

            return self._models[cache_key]
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise


        
    def clear_cache(self):
        """ Clearing the model cache """
        logger.info("Clearing model Cache")

        for key in list(self._models.keys()):
            del self._models[key]

        self._models.clear()

        # Clearing memory of GPU if available
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            
        gc.collect()
        logger.info("Model Cache Cleared :) ")

    def get_cache_info(self):
        """Get information about cached models"""
        return {
            'cached_models': list(self._models.keys()),
            'count': len(self._models)
        }

model_cache = ModelCache()