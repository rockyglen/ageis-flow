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

# Global tracker for the active subprocess (Terraform) to allow cancellation
active_process = None

# [DEBUG] Verify Environment on Startup
print(f"🚀 AEGIS SERVER STARTING... (Build Time: {int(time.time())}) - VERSION: FORCE_UPDATE_003")
print(f"[SYSTEM] AWS CLI Version: {subprocess.getoutput('aws --version')}")

# Ensure DB exists
max_retries = 30  # Increased to handle Cloud SQL cold starts (can take 45s+)
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
        print(f"⚠️ Database connection failed (attempt {i+1}/{max_retries}): {e}")
        time.sleep(2)

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

        # Pass environment variables to ensure Cloud SQL connection works in subprocess
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        self.process = subprocess.Popen(
            ['python','-u', 'main.py'],
            cwd=os.getcwd(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
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
    global active_process
    try:
        # 1. Force non-interactive mode to prevent hanging on missing vars
        if "terraform" in command and "-input=false" not in command:
            command += " -input=false"

        # 2. Pass environment variables (Crucial for Cloud Run auth & vars)
        env = os.environ.copy()
        env["TF_IN_AUTOMATION"] = "true"

        active_process = subprocess.Popen(
            command, cwd=TERRAFORM_DIR, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            env=env
        )
        for line in iter(active_process.stdout.readline, ''):
            if line: yield line
        
        active_process.stdout.close()
        return_code = active_process.wait()
        active_process = None
        
        if return_code != 0:
            yield "\n[ERROR] Terraform command failed. Check logs above for details.\n"
            raise Exception("Terraform command failed")
    except Exception as e:
        raise e

@app.get("/api/reset")
def reset_lab():
    if not simulation_lock.acquire(blocking=False):
        raise HTTPException(
            status_code=429, 
            detail="⚠️ Demo in progress! Another user is currently running a simulation. Please try again in a minute."
        )

    def reset_sequence():
        try:
            # [FIX] Ensure Terraform is initialized with the backend at runtime
            # This is crucial because build-time init lacks GCS credentials
            yield "\n>>> [PHASE -1] INITIALIZING TERRAFORM BACKEND...\n"
            for line in execute_terraform("terraform init -reconfigure -input=false"):
                yield line

            # [FIX] Force remove the null_resource from state to prevent "aws: not found" errors
            # during destroy if the previous state contains the old shell-based provisioner.
            yield "\n>>> [PHASE 0] SANITIZING STATE (Removing stuck resources)...\n"
            rm_proc = subprocess.run(
                "terraform state rm null_resource.insider_threat_simulation",
                cwd=TERRAFORM_DIR, shell=True, capture_output=True, text=True
            )
            if rm_proc.returncode != 0 and "No such resource" not in rm_proc.stderr:
                 yield f"[INFO] State rm output: {rm_proc.stderr}\n"

            yield "\n>>> [PHASE 1] INITIALIZING DESTRUCTION...\n"
            for line in execute_terraform("terraform destroy -auto-approve"): yield line
            
            yield "\n>>> [PHASE 2] INJECTING VULNERABILITIES (DB UPDATE)...\n"
            reset_to_vulnerable()
            
            # Verify DB update
            statuses = get_all_status()
            vuln_count = sum(1 for s in statuses if s['status'] == 'VULNERABLE')
            yield f">>> [DB] DASHBOARD STATUS SET TO: 🔴 VULNERABLE ({vuln_count} checks updated)\n"

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

@app.post("/api/stop")
def stop_process():
    """Kills any running Terraform or Agent process."""
    global active_process
    
    # 1. Stop Terraform / Reset
    if active_process:
        if active_process.poll() is None:
            print("[SYSTEM] Killing active Terraform process...")
            active_process.terminate()
            try:
                active_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                active_process.kill()
        active_process = None

    # 2. Stop Agent
    if agent_manager.is_running and agent_manager.process:
        print("[SYSTEM] Killing active Agent process...")
        agent_manager.process.terminate()

    return {"status": "stopped"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)