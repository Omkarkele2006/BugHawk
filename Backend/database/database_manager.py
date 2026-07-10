
from typing import Dict,List,Optional,Any
from datetime import datetime,date
import json
import uuid
from dataclasses import dataclass

@dataclass
class QueryStore:
    # query_id
    name: str
    query: str
    problem_type: str
    date: datetime


class DatabaseManager:
    """ Advance Database manager for query fetching and retrival """

    def __init__(self):
        self._state = "connected"
        self.connected = False
        self._init_connection()
    
    def _init_connection(self):
        """ Initialize Database Connection with error handling """
        pass

