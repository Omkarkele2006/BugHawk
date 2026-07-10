from dataclasses import dataclass
from typing import Optional
from .report import Report

@dataclass
class ScanJob:
    job_id: str
    repository_url: str
    status: str                         # "PENDING", "RUNNING", "COMPLETED", "FAILED"
    created_at: str                     # ISO datetime string
    started_at: Optional[str] = None     # ISO datetime string
    completed_at: Optional[str] = None   # ISO datetime string
    progress: int = 0                   # Progress percentage (0 to 100)
    error_message: Optional[str] = None  # Exception message if failed
    report: Optional[Report] = None     # Reference to compiled Report if completed
