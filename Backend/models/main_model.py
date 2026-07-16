# Load model directly
from transformers import AutoTokenizer, AutoModelForMaskedLM,AutoModelForCausalLM
from trl import PPOTrainer, PPOConfig
import torch
import requests
import os
from PIL import Image
from io import BytesIO 
import logging

from message_template.message import message_template
from utils.preprocessImage import preprocess_image
from models.intent_classifier import model_prediction
from models.model_cache import model_cache
from transformers import Qwen2VLForConditionalGeneration,AutoProcessor

model_path = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
# model_path = "Qwen/Qwen2.5-Coder-3B-Instruct"
# model_path = "deepseek-ai/deepseek-coder-6.7b-instruct"
# image_model = Qwen2VLForConditionalGeneration.from_pretrained("Qwen/Qwen2-VL-7B-Instruct", device_map="auto")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BugHawkModel:
    def __init__(self):
        self.message_template = message_template
        logger.info(f"Initializing BugHawk Model with {model_path}")

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"Using device: {self.device}")

        text_model_cache = model_cache.get_model(model_path, device="auto")
        self.model = text_model_cache["model"]
        self.tokenizer = text_model_cache["tokenizer"]

        # Load processor
        try:
            try:
                self.processor = AutoProcessor.from_pretrained(model_path, local_files_only=True)
                logger.info("Processor loaded from local cache.")
            except Exception:
                logger.info("Processor not found in local cache. Attempting download with timeout.")
                self.processor = AutoProcessor.from_pretrained(model_path, local_files_only=False, timeout=15)
                logger.info("Processor loaded.")
        except Exception as e:
            logger.warning(f"Could not load processor, using tokenizer: {e}")
            self.processor = self.tokenizer

        # Set model to evaluation mode
        self.model.eval()
        logger.info("Model set to evaluation mode")

        self.preprocess_image = preprocess_image

        # Model configuration
        self.max_input_length = 2048
        self.max_output_length = 1024
        self.dtype = torch.float16 if torch.cuda.is_available() else torch.float32
        # self.d_type = torch.int8 # Trying Quantization

        # Move global model to device
        # self.model.to(self.device)


    def training_Config(self,model):

        training_config = {
            "model": {"pretrained_model_name":self.model,"max_length":512},
            "verbose":True
        }
        return {"model":training_config["model"]}
    
    def tokenization(self,batch):
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        tokenized = self.tokenizer(
            batch,
            padding="max_length",
            truncation=True,
            max_length=self.training_Config(self.model)["model"]
        )
        tokenized["labels"] = tokenized["input_ids"].copy()
        return tokenized
    
    def format_input_type(self,input_type,user_query):
        """ Formatting the input type for model processing """
        if input_type == "image":
            try:
                if user_query.startswith(("http://","https://")):
                    response = requests.get(user_query)
                    response.raise_for_status()
                    image = Image.open(BytesIO(response.content))
                    image = self.preprocess_image(image)
                else:
                    image = Image.open(user_query)
                    image = self.preprocess_image(image)
                print(f"PreProcessed Image loaded")
                return image
            except Exception as e:
                raise ValueError(f"Error in loading image: {e}")
        elif input_type == "text":
            return user_query
        else:
            raise ValueError("Unsupported input type.")
        


    def detect_input_type(self,user_query):
        """ Detect the inpu type : text or image"""
        if isinstance(user_query,str) and user_query.endswith(('.png', '.jpg', '.jpeg','webp')):
            return "image"
        elif isinstance(user_query,str) and user_query.startswith(("http://", "https://")):
            return "image"
        elif isinstance(user_query,str) and user_query.endswith(('.mp4', '.avi', '.mov')):
            return ValueError("Video input is not Supported For Now... :) ")
        else:
            return "text"
        

    def inference(
            self,
            user_query : str,
            max_tokens: int = 512,
            temperature: float = 0.1,
            top_p: float = 0.9,
            do_sample: bool = False,
            ) -> str:
        """ Generate Output from Query Inputted by User """

        try:

            input_type = self.detect_input_type(user_query)
            print(f"Detected input type: {input_type}")
            logger.info(f"Detected input type: {input_type}")

            formatted_input = self.format_input_type(input_type, user_query)

            messages = self.message_template(input_type, formatted_input)
            
            if self.model is None or self.tokenizer is None:
                raise ValueError("Model not loaded. Call IntentChoosen() first.")

            model_device = next(self.model.parameters()).device
            logger.info(f"Model is on device: {model_device}")

            # Chat template
            if hasattr(self.processor, 'apply_chat_template'):
                inputs = self.processor.apply_chat_template(
                    messages,
                    add_generation_prompt=True,
                    tokenize=True,
                    return_dict=True,
                    return_tensors="pt"
                )
            else:
                formatted_text = "\n".join([f"{msg['role']}: {msg['content']}" for msg in messages])

                inputs = self.tokenizer(
                    formatted_text,
                    return_tensors="pt",
                    truncation=True,
                    max_length=self.max_input_length,
                    padding=True,
                )
                

            # Moving all tensors in the dict to the model device
            inputs = {k: v.to(model_device) for k,v in inputs.items()}
            input_len = inputs["input_ids"].shape[-1]


            if input_len >= self.max_input_length:
                logger.warning(f"Input length ({input_len}) exceeds max ({self.max_input_length})")
                logger.warning("Truncating input...")


            print(f"Input length: {input_len} tokens")
            print(f"Generating response (max {max_tokens} new tokens)...")

            # Generate
            with torch.no_grad():
                output = self.model.generate(
                    **inputs,
                    max_new_tokens=max_tokens,
                    temperature=temperature if do_sample else None,
                    top_p=top_p if do_sample else None,
                    do_sample=do_sample,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                    use_cache=True,
                    num_return_sequences=1,
                    early_stopping=True,
                    num_beams=1,
                    repetition_penalty=1.1,
                    )
                
            # Decode
            response = self.processor.batch_decode(output[:,input_len:],skip_special_tokens=True)[0]

            if not response or not response.strip():
                logger.warning("Empty response generated!")
                return "I apologize, but I couldn't generate a proper response. Please try rephrasing your question."
            
            logger.info(f"Generated response ({len(response)} characters)")
            logger.info(f"Response preview: {response[:100]}...")

            return response.strip()
        except Exception as e:
            logger.error(f"Error in inference: {e}")
            import traceback
            logger.error(traceback.format_exc())
            raise Exception(f"Inference failed: {str(e)}")

    def rlft_loop(self):
        """ Apply Self Learning Loop """
        ppo_config = PPOConfig(
            model_name = model_path,
            learning_rate=1e-6,
            batch_size=2,
            gradient_accumulation_steps=4,
        )

        # PPO Trainer
        ppo_trainer = PPOTrainer(
            model=self.model,
            tokenizer=self.tokenizer,
            config = ppo_config,
        )

        # # Self LOOP

        # for steps, (query,reference_fix) in enumerate()

    
    def eval_reward(self,query,response,reference_fix):

        try:
            exec(response)
            test_case = True
        except Exception as e:
            test_case = False
            raise ValueError("Test Case Abort !!")
        
        reward = 1.0 if test_case else 0.0

        return reward
    


