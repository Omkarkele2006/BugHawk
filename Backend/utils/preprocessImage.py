import requests
import os
from PIL import Image
from io import BytesIO 

def preprocess_image(image_path: Image.Image) -> Image.Image:
    """ Preprocess the image for model Input/Path """
    try:
        if image_path.mode != 'RGB':
            print(f"Converting Image to RGB mode from {image_path}")
            image_path = image_path.convert('RGB')
        # Resize the image to a standard size ie 512x512
        target_size = (512,512)

        # Calculate the aspect ratio, preserving resize
        original_width, original_height = image_path.size
        aspect_ratio = original_width / original_height
        if aspect_ratio > 1:
            # Width is greater
            new_width = target_size[0]
            new_height = int(target_size[1] / aspect_ratio)
        else:
            # Height is larger or equal
            new_height = target_size[1]
            new_width =  int(target_size[0] / aspect_ratio)
        # Resizing the image with maintaining aspect ratio
        image_path = image_path.resize((new_width,new_height),Image.Resampling.LANCZOS)

        # Creating new image with target size and white background
        processed_image = Image.new("RGB", target_size,(255,255,255))

        # Calculating position to centre the image
        x_offset = (target_size[0] - new_width) // 2
        y_offset = (target_size[1] - new_height) // 2

        processed_image.paste(image_path,(x_offset,y_offset))

        return processed_image
    except Exception as e:
        raise ValueError(f"Error in processing image: {e}")
    
