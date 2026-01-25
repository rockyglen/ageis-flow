import subprocess
import os
import threading
import queue
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from mcp_server.database import reset_to_vulnerable, get_all_status, init_db

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure DB exists
init_db()

TERRAFORM_DIR = os.path.join(os.getcwd(), "infrastructure", "terraform")

# --- GLOBAL PROCESS STATE ---
# This allows us to "pause" the agent and resume it from a different API call
class ProcessManager:
    def __init__(self):
        self.process = None
        self.output_queue = queue.Queue()
        self.is_running = False
        self.waiting_for_approval = False

    def start_agent(self):
        """Starts the agent process in a separate thread"""
        if self.is_running and self.process.poll() is None:
            return # Already running

        self.process = subprocess.Popen(
            ['python','-u', 'main.py'],
            cwd=os.getcwd(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        self.is_running = True
        self.waiting_for_approval = False
        
        # Start a thread to read output non-blockingly
        t = threading.Thread(target=self._read_output)
        t.daemon = True
        t.start()

    def _read_output(self):
        """Reads stdout and pushes to queue. Detects Safety Gate."""
        for line in iter(self.process.stdout.readline, ''):
            if line:
                # DETECT SAFETY GATE
                if "PAUSING FOR HUMAN REVIEW" in line:
                    self.waiting_for_approval = True
                    self.output_queue.put("[ACTION_REQUIRED] WAITING_FOR_APPROVAL")
                
                self.output_queue.put(line)
        
        self.process.stdout.close()
        self.is_running = False

    def send_approval(self):
        """Writes 'approve' to the process stdin"""
        if self.process and self.waiting_for_approval:
            self.process.stdin.write("approve\n")
            self.process.stdin.flush()
            self.waiting_for_approval = False
            return True
        return False

    def stream_logs(self):
        """Generator that yields logs from the queue"""
        while self.is_running or not self.output_queue.empty():
            try:
                line = self.output_queue.get(timeout=1)
                yield line
            except queue.Empty:
                continue

agent_manager = ProcessManager()

# --- ROUTES ---

@app.get("/api/status")
def get_status():
    return JSONResponse(content=get_all_status())

@app.get("/api/run-agent")
def run_agent():
    """Starts the agent and streams logs. Does NOT auto-approve."""
    agent_manager.start_agent()
    return StreamingResponse(agent_manager.stream_logs(), media_type="text/plain")

@app.post("/api/approve")
def approve_remediation():
    """Sends the 'approve' signal to the paused agent"""
    success = agent_manager.send_approval()
    if success:
        return {"status": "approved"}
    raise HTTPException(status_code=400, detail="No agent waiting for approval")

def execute_terraform(command):
    """Simple runner for Terraform (no interaction needed)"""
    try:
        process = subprocess.Popen(
            command, cwd=TERRAFORM_DIR, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        for line in iter(process.stdout.readline, ''):
            if line: yield line
        process.stdout.close()
        process.wait()
    except Exception as e:
        yield f"\n[CRITICAL ERROR] {str(e)}\n"

@app.get("/api/reset")
def reset_lab():
    def reset_sequence():
        yield "\n>>> [PHASE 1] INITIALIZING DESTRUCTION...\n"
        for line in execute_terraform("terraform destroy -auto-approve"): yield line
        
        yield "\n>>> [PHASE 2] INJECTING VULNERABILITIES (DB UPDATE)...\n"
        reset_to_vulnerable()
        yield ">>> [DB] DASHBOARD STATUS SET TO: 🔴 VULNERABLE\n"

        yield "\n>>> [PHASE 3] DEPLOYING VULNERABLE INFRASTRUCTURE...\n"
        for line in execute_terraform("terraform apply -auto-approve"): yield line
        yield "\n>>> [COMPLETE] ENVIRONMENT COMPROMISED.\n"

    return StreamingResponse(reset_sequence(), media_type="text/plain")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)