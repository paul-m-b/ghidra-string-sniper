import os
import subprocess
import argparse
import json
import requests
from dotenv import load_dotenv

# --- Configuration ---
# Load environment variables from .env file for API keys
load_dotenv()

# Initialize the Openrouter client.
# IMPORTANT: Make sure your OPENROUTER_API_KEY is set in a .env file in the same directory,
# or as an environment variable.


# --- Core Functions ---

def analyze_project(project_path, max_files=100):
    """
    Analyzes the project directory to identify key files by walking the directory tree.
    Returns a list of file paths relative to the project root.
    """
    print(f"INFO: Analyzing project structure at: {project_path}")
    file_list = []
    try:
        for root, dirs, files in os.walk(project_path):
            # Exclude common large or irrelevant directories
            dirs[:] = [d for d in dirs if d not in [
                'node_modules', '.git', 'venv', '__pycache__', 'build', 'dist', '.idea', '.vscode'
            ]]
            
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, project_path)
                file_list.append(relative_path)
                if len(file_list) >= max_files:
                    break
            if len(file_list) >= max_files:
                break
    except Exception as e:
        print(f"ERROR: Failed to analyze project directory: {e}")
        return None

    print(f"INFO: Found {len(file_list)} relevant files to analyze (up to a max of {max_files}).")
    return file_list

def determine_build_process(file_list, last_error=""):
    """
    Uses OpenRouter's REST API with the 'requests' library to determine the build process.
    """
    print("INFO: Asking agent to determine build process via REST API...")

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("ERROR: OPENROUTER_API_KEY not found. Please set it in your .env file.")
        return None

    api_url = "https://openrouter.ai/api/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:3000", # Can be a simple placeholder for CLI agent
        "X-Title": "Gemini CLI Agent" # Optional: A title for your app
    }

    # Base prompt
    prompt_intro = """
    You are an expert build engineer. Your task is to determine the build and testing process for a software project.
    Based on the following list of project files, provide a sequence of shell commands to build and test the project.

    Your response MUST be a valid JSON object with two keys:
    1. "build": A list of strings, where each string is a shell command to build the project.
    2. "test": A list of strings, where each string is a shell command to run the project's tests.

    If a step is not necessary (e.g., no build is needed for a simple Python script), provide an empty list.
    """

    # Add error context if a previous attempt failed
    error_context = ""
    if last_error:
        error_context = f"""
        A previous attempt to build the project failed with the following error.
        Use this error to correct the build plan.

        Error log:
        ---
        {last_error}
        ---
        """

    full_prompt = f"{prompt_intro}\n{error_context}\nProject file list:\n{json.dumps(file_list, indent=2)}"

    data = {
        "model": "google/gemini-2.5-pro", # Using the specified model
        "messages": [
            {"role": "system", "content": "You are an expert build engineer providing build plans in JSON format."},
            {"role": "user", "content": full_prompt}
        ],
        "response_format": {"type": "json_object"}
    }

    try:
        response = requests.post(api_url, headers=headers, json=data)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        response_json = response.json()
        
        # OpenRouter API might return an error structure directly
        if "error" in response_json:
            print(f"ERROR: OpenRouter API error: {response_json['error']['message']}")
            return None

        # Extract the content from the response
        plan_str = response_json['choices'][0]['message']['content']
        print("INFO: Agent provided a build plan.")
        return json.loads(plan_str)

    except requests.exceptions.HTTPError as e:
        print(f"ERROR: HTTP Error communicating with agent: {e}")
        print(f"Response body: {e.response.text}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to communicate with agent: {e}")
        return None
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        print(f"ERROR: Could not parse agent response or extract content: {e}")
        if 'response' in locals() and hasattr(response, 'text'):
            print(f"Raw response: {response.text}")
        return None

def execute_commands(project_path, commands, step_name):
    """
    Executes a list of shell commands in the project directory for a given step (build or test).
    Returns a tuple: (success: bool, output: str).
    """
    if not commands:
        print(f"INFO: No commands to execute for '{step_name}' step.")
        return True, ""

    print(f"--- Executing {step_name.upper()} Step ---")
    full_output = []
    for command in commands:

        print(f"`{command}` @ {project_path}")
        USER_VERIFY = input(f"Execute command ('y' for yes)? ")
        if (USER_VERIFY != 'y'):
            return False,"\nUSER REJECTED COMMAND."

        print(f"RUNNING: {command}")
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                cwd=project_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            print(result.stdout)
            full_output.append(f"SUCCESS: {command}\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            error_message = f"COMMAND FAILED: {command}\nEXIT CODE: {e.returncode}\nSTDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}"
            print(f"ERROR: {error_message}")
            full_output.append(error_message)
            return False, "\n".join(full_output) # Failure
            
    return True, "\n".join(full_output) # Success

def agentic_compiler_workflow(project_path, max_retries=5):
    """
    The main agentic workflow to compile and test a project.
    """
    print(f"--- Starting Agentic Compilation for: {project_path} ---")
    
    last_error_log = ""
    for attempt in range(1, max_retries + 1):
        print(f"\n--- Attempt {attempt}/{max_retries} ---")
        
        # 1. Analyze the project directory
        file_list = analyze_project(project_path)
        if file_list is None:
            print("CRITICAL: Halting due to analysis failure.")
            break

        # 2. Ask agent to determine the build process
        build_plan = determine_build_process(file_list, last_error_log)
        if build_plan is None or 'build' not in build_plan or 'test' not in build_plan:
            print("ERROR: Could not determine a valid build plan. Retrying...")
            last_error_log = "Agent failed to provide a valid JSON build plan."
            continue
            
        build_commands = build_plan.get('build', [])
        test_commands = build_plan.get('test', [])
        print(f"INFO: Plan received. Build commands: {build_commands}, Test commands: {test_commands}")

        # 3. Execute build commands
        build_success, build_output = execute_commands(project_path, build_commands, "build")
        if not build_success:
            print("ERROR: Build step failed. The agent will now analyze the error and retry.")
            last_error_log = build_output
            continue

        # 4. Execute test commands
        test_success, test_output = execute_commands(project_path, test_commands, "test")
        if not test_success:
            print("ERROR: Test step failed. The agent will now analyze the error and retry.")
            last_error_log = test_output
            continue
        
        # 5. Success
        print("\n--- Agentic Compilation Successful! ---")
        print("Project was built and tested successfully.")
        return

    print(f"\n--- Agentic Compilation Failed ---")
    print(f"Could not build and test the project after {max_retries} attempts.")
    print("Final error log:")
    print(last_error_log)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="An agentic compiler/builder for GitHub projects.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "project_path", 
        help="Path to the root directory of the project to build."
    )
    parser.add_argument(
        "--retries", 
        type=int, 
        default=5,
        help="Maximum number of attempts the agent should make to build the project."
    )
    args = parser.parse_args()
    
    if not os.path.isdir(args.project_path):
        print(f"CRITICAL ERROR: Project path not found at '{args.project_path}'")
    else:
        agentic_compiler_workflow(args.project_path, args.retries)
