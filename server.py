import subprocess
import os
import sys
import signal
import threading
import queue
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from mcp_server.database import reset_to_vulnerable, get_all_status, init_db

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure DB exists
max_retries = 5
for i in range(max_retries):
    try:
        init_db()
        print("✅ Database initialized successfully.")
        break
    except Exception as e:
        if i == max_retries - 1:
            print(f"❌ [CRITICAL] Database Connection Failed after {max_retries} attempts: {e}")
            print("💡 TIP: Check Cloud SQL API, IAM Roles, and ensure the database exists.")
            raise e
        print(f"⚠️ Database connection failed (attempt {i+1}/{max_retries}). Retrying in 3s...")
        time.sleep(3)

# Allow overriding Terraform directory via env var (useful for persistent volume mounts)
TERRAFORM_DIR = os.environ.get("TERRAFORM_DIR", os.path.join(os.getcwd(), "infrastructure", "terraform"))
simulation_lock = threading.Lock()
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

# --- SIGNAL HANDLING ---
def handle_sigterm(*args):
    """Gracefully handle Cloud Run shutdown signals"""
    print("[SYSTEM] Received SIGTERM. Shutting down agent...")
    if agent_manager.process and agent_manager.process.poll() is None:
        agent_manager.process.terminate()
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)

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
        # 1. Force non-interactive mode to prevent hanging on missing vars
        if "terraform" in command and "-input=false" not in command:
            command += " -input=false"

        # 2. Pass environment variables (Crucial for Cloud Run auth & vars)
        env = os.environ.copy()
        env["TF_IN_AUTOMATION"] = "true"

        process = subprocess.Popen(
            command, cwd=TERRAFORM_DIR, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            env=env
        )
        for line in iter(process.stdout.readline, ''):
            if line: yield line
        process.stdout.close()
        if process.wait() != 0:
            yield "\n[ERROR] Terraform command failed. Check logs above for details.\n"
    except Exception as e:
        yield f"\n[CRITICAL ERROR] {str(e)}\n"

@app.get("/api/reset")
def reset_lab():
    if not simulation_lock.acquire(blocking=False):
        raise HTTPException(
            status_code=429, 
            detail="⚠️ Demo in progress! Another user is currently running a simulation. Please try again in a minute."
        )

    def reset_sequence():
        try:
            yield "\n>>> [PHASE 1] INITIALIZING DESTRUCTION...\n"
            for line in execute_terraform("terraform destroy -auto-approve"): yield line
            
            yield "\n>>> [PHASE 2] INJECTING VULNERABILITIES (DB UPDATE)...\n"
            reset_to_vulnerable()
            yield ">>> [DB] DASHBOARD STATUS SET TO: 🔴 VULNERABLE\n"

            yield "\n>>> [PHASE 3] DEPLOYING VULNERABLE INFRASTRUCTURE...\n"
            for line in execute_terraform("terraform apply -auto-approve"): yield line
            yield "\n>>> [COMPLETE] ENVIRONMENT COMPROMISED.\n"
        
        except Exception as e:
            yield f"\n[INTERNAL ERROR] {str(e)}\n"
        
        finally:
            # 2. Release Lock when stream finishes or client disconnects
            simulation_lock.release()

    return StreamingResponse(reset_sequence(), media_type="text/plain")

@app.post("/api/admin/force-unlock")
def force_unlock():
    """Emergency valve to clear the lock if the server gets stuck."""
    if simulation_lock.locked():
        simulation_lock.release()
        return {"status": "lock_released", "message": "System is now free for new simulations."}
    return {"status": "already_free", "message": "No lock was active."}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)