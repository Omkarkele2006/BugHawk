from prompt.debugger_system_prompt import text_prompt, image_prompt

debugger_text_prompt = text_prompt
debugger_image_prompt = image_prompt

def message_template(input_type, formatted_input):
    """Prepares messages with system prompt and user query based on input type."""


    if input_type == "text":
        messages = [
        {
            "role": "assistant", 
            "content": debugger_text_prompt
            # "content": {
            #     "type": "text","text": debugger_text_prompt
            # },
        },
        {
            "role": "user", 
            "content": f"User Query:{formatted_input}" ,
                # {
                #     "type": "text", "text": f"User Query:{formatted_input}" ,
                # }
            
        }
    ]
    else: 
        messages = [

        {
            "role": "user", "content": [
                {
                    "type": "image", "image": formatted_input 
                },
            
        ]
        },
        {
            "role": "assistant", "content": 
            [
            {
                "type": "text","text": debugger_image_prompt,

            }
            ]
        }
        ]
    return messages