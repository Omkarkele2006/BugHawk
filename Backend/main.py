import asyncio
from fastapi import FastAPI,HTTPException,Request
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel,HttpUrl
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import traceback

from models.main_model import BugHawkModel
import uvicorn

bm = BugHawkModel()

class QueryRequest(BaseModel):
    query: str
    max_tokens: int = 512
    stream: bool = False

class QueryReport(BaseModel):
    name: str
    query: str
    problem_type: str
    date: datetime

app = FastAPI(
    title="BugHawk API",
    description="API for Advance Debugging and Maintaince of the code ",
    version="1.0.0"
)

# CORS middleware for development
origins = [
    "http://localhost:3000",
    "http://localhost:4000", 
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:4000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:4001",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:8081",
    "http://127.0.0.1:8081",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    # allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "API FOR BUGHAWK LOADED"}

@app.post("/submit")
async def query_submit(response: QueryRequest):
    """ API Endpoint for Saving query in db and getting model response """
    if not bm :
        ValueError("No Model Loaded...")
    try:
        query = response.query

        print(f"Received query: {query}")
        print(f"Query type: {type(query)}")

        print("Detecting input type...")
        input_type = bm.detect_input_type(query)
        print(f"Input type: {input_type}")


        print("Running inference...")

        response = bm.inference(query)


        print(f"Response: {response}")
        print(f"Response type: {type(response)}")

        return {"status": "success","response": response}
    
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"Error: {e}")
        print(f"Traceback:\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Error in processing query: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=False,
        workers=1,
        log_level="info"
    )
# Run: uv run fastapi dev main.py    

# EXAMPLES: 
# getting wrong ans: def is_even(num):     if num % 2 == 1:         return True     else:         return False


# class Node:
#     def __init__(self):
#         self.next = None
#         self.prev = None

# a = Node()
# b = Node()
# a.next = b
# b.prev = a
# Bug Type: Reference cycle → memory leak if not broken before deletion

# def login(user, password): query = f"SELECT * FROM users WHERE username='{user}' AND password='{password}'" cursor.execute(query) i amgetting error in this sql and is this code safe to run?