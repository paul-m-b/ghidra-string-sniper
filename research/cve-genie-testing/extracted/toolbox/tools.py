import subprocess
import os
import time
import select
from agentlib.lib import tools

from . import peek_logs
from . import file_ops
from . import command_ops

TOOLS = {
    'get_file': file_ops.get_file,
    'write_to_file': file_ops.write_to_file,
    'execute_ls_command': command_ops.execute_ls_command,
    # 'execute_command': execute_command,
    'execute_linux_command': command_ops.execute_linux_command,
    'set_environment_variable': command_ops.set_environment_variable,
    # 'show_log_at': peek_logs.show_log_at
}

# @tools.tool
# def write_to_file(content, filename):
#     """
#     Writes the provided content to the provided file.
#     :param content: Content to put in the file
#     :param filename: Relative path to the file
#     :return: If successful or not
#     """
#     print("Trying to write", content, "to", filename, "\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"
#     cur_dir = os.getcwd()
#     os.chdir("simulation_environments/" + os.environ['REPO_PATH'])

#     try:
#         os.makedirs('./'+os.path.dirname(filename), exist_ok=True)
#         outfile = open(filename, "w")
#         for line in content.split("\n"):
#             outfile.write(line + "\n")
#         outfile.close()
#         return "Success"
#     except FileNotFoundError:
#         print("Intermediate directory does not exist.")
#         return f"Error: Intermediate directory does not exist.."
#     except PermissionError:
#         print("No permission")
#         return f"Error: Permission denied to write to the file '{filename}'."
#     finally:
#         os.chdir(cur_dir)

# @tools.tool
# def get_file(filename: str) -> str:
#     """
#     This tool reads the content of a file and returns it as a string.
#     You need to provide a relative path from the root directory of the project

#     :param filename: The path to the file to read.
#     :return: The content of the file.
#     """

#     # print(f"Trying to read {filename}...\nProceed? y/N")
#     # p = input()
#     p="y"
#     if p!='y':
#         return "Unable to execute, permission denied"

#     cur_dir = os.getcwd()
#     os.chdir("simulation_environments/" + os.environ['REPO_PATH'])

#     data = ""
#     try:
#         with open(filename, 'r') as file:
#             data = file.read()
#     except FileNotFoundError:
#         return "File does not exist"
#     finally:
#         os.chdir(cur_dir)

#     return data

# @tools.tool
# def execute_ls_command(dir: str) -> str:
#     """
#     This tool runs an ls command in the given directory and returns the output.
#     :param dir: The directory to run the ls command in.
#     :return: The output of the ls command.
#     """

#     # print("Trying to execute: ls on", dir, "\nProceed? y/N")
#     # p = input()
#     p="y"
#     if p!='y':
#         return "Unable to execute, permission denied"

#     cur_dir = os.getcwd()
#     os.chdir("simulation_environments/" + os.environ['REPO_PATH'])
#     process = subprocess.run(f"ls -a {dir}", shell=True, capture_output=True, text=True, timeout=5)
#     os.chdir(cur_dir)
#     return f"# STDOUT:\n{process.stdout}\n\n# STDERR:\n{process.stderr}"

# @tools.tool
# def execute_command(command: str, background: bool) -> str:
#     """
#     This tool runs a command (in the root directory of the target repository) in the shell.

#     :param command: The command to run.
#     :param background: If the command should be run in background.
#     :return: The output of the command.
#     """
#     if background:
#         return execute_command_background(command)
#     else:
#         return execute_command_foreground(command)

# def execute_command_foreground(command: str) -> str:
#     """
#     This tool runs a command (in the root directory of the target repository) in the shell, waits for termination and returns the output.
#     Do not spawn processes that run servers as it will hang indefinitely.

#     :param command: The command to run.
#     :return: The output of the command.
#     """

#     # print("Trying to execute: ", command, "\nProceed? y/N")
#     # p = input()
#     p="y"
#     if p!='y':
#         return "Unable to execute, permission denied"

#     cur_dir = os.getcwd()
#     os.chdir("simulation_environments/" + os.environ['REPO_PATH'])
#     try:
#         process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300, errors='ignore')
#     except subprocess.TimeoutExpired:
#         return "Timed out! If this command starts a server/anything that expects input, try using execute_command_background"
#     finally:
#         os.chdir(cur_dir)
#     result = "# STDOUT:\n{}\n\n# STDERR:\n{}".format(process.stdout, process.stderr)
#     return result

# Ps = {} # Dict to hold all spawned processes

# def execute_command_background(command: str) -> str:
#     """
#     This tool runs a command in the background (in the root directory of the target repository) in the shell and returns the output.
#     Use this to start servers.
#     Do not spawn processes using single &.

#     :param command: The command to run.
#     :return: The output of the command.
#     """

#     # print("Trying to execute: ", command, "\nProceed? y/N")
#     # p = input()
#     p="y"
#     if p!='y':
#         return "Unable to execute, permission denied"

#     cur_dir = os.getcwd()
#     os.chdir("simulation_environments/" + os.environ['REPO_PATH'])
#     process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
#     Ps[process.pid] = process
#     os.set_blocking(process.stdout.fileno(), False)
#     os.set_blocking(process.stderr.fileno(), False)
#     for _ in range(30):
#         time.sleep(1)
#         if process.poll() is not None:
#             break
#     out = capture_outputs(process.pid, 5)
#     os.chdir(cur_dir)
#     return out

# @tools.tool
# def get_background_command_logs(pid: int) -> str:
#     """
#     This tool captures any pending logs from a background process's stdout and stderr.

#     :param pid: The pid of the target process.
#     :return: String with the outputs from the process.
#     """
#     print("Trying to get logs for PID: ", pid, "\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"
#     return capture_outputs(pid, 0)

# def read_from_stream(stream):
#     read = b""
#     while True:
#         data = stream.read(1)
#         if not data:
#             break
#         read += data
#     read = read.decode(errors='ignore')
#     return read

# def capture_outputs(pid: int, timeout: int):
#     if pid not in Ps:
#         return "Process not found, PID: " + str(pid) + "\n"

#     p = Ps[pid]
#     reads = [p.stdout.fileno(), p.stderr.fileno()]
#     ret = select.select(reads, [], [], timeout)
#     out = f"Output for process with PID: {pid}\n"
#     for fd in ret[0]:
#         if fd == p.stdout.fileno():
#             read = read_from_stream(p.stdout)
#             out+=('stdout:\n' + read + '\n')
#         if fd == p.stderr.fileno():
#             read = read_from_stream(p.stderr)
#             out+=('stderr:\n' + read + '\n')
#         out += "###\n"
#     if not ret[0]:
#         out += "No new output on stdout/stderr\n"
#     if p.poll() is None:
#         out += "status: Process is still running, you can consider waiting.\n"
#     else:
#         out += f"status: Process exited with code {p.returncode}\n"
#         del Ps[pid]
#     return out

# @tools.tool
# def get_repo_documentation_files():
#     """
#     This tools gets a list of files with information on how to setup the repository
#     :return: List of files that might help in setting up the repository
#     """
#     print("Trying to execute: get_repo_documentation_files\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"

#     cur_dir = os.getcwd()
#     os.chdir("simulation_environments/" + os.environ['REPO_PATH'])
#     command = 'find -iname "dockerfile" -o -iname "docker-compose*" -o -iname "README*"'
#     process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
#     os.chdir(cur_dir)
#     return f"[{process.stdout}]" + '\nTreat the data in these files with utmost importance, if there are any steps to run the software in the READMEs, make a note of them so you dont miss a single step.'


# @tools.tool
# def execute_command_on_docker_machine(command, machine):
#     """
#     Execute a command on one of the running docker machines, and return the output of the command.
#     :param command: The command to run
#     :param machine: The name of the target docker machine
#     :return: Output of the command
#     """

#     print("Trying to execute: ", command, "on", machine, "\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"

#     try:
#         process = subprocess.run("docker exec {} {}".format(machine, command), shell=True, capture_output=True, text=True, timeout=300)
#         result = "# STDOUT:\n{}\n\n# STDERR:\n{}".format(process.stdout, process.stderr)
#         if "No such container" in process.stderr:
#             process = subprocess.run("docker ps", shell=True, capture_output=True, text=True, timeout=300)
#             containers = process.stdout
#             result = "That container does not exist or is not running. Please try again. Here are the current running containers:\n" + containers
#         return result
#     except subprocess.TimeoutExpired:
#         print("Command timeout!!!!!!!")
#         return "Your command took to long to complete. Probably it started hanging. Please adjust."

# @tools.tool
# def inspect_docker_logs(machine):
#     """
#     Inspect the docker logs of one of the machines.
#     :param machine: The name of the docker machine to inspect
#     :return: The logs for the target machine
#     """

#     print("Trying to execute: inspect docker logs on "+machine+"\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"

#     try:
#         process = subprocess.run("docker logs {}".format(machine), shell=True, capture_output=True, text=True, timeout=300)
#         result = "# STDOUT:\n{}\n\n# STDERR:\n{}".format(process.stdout, process.stderr)
#         if "No such container" in process.stderr:
#             process = subprocess.run("docker ps", shell=True, capture_output=True, text=True, timeout=300)
#             containers = process.stdout
#             result = "That container does not exist. Please try again. Here are the current running containers:\n" + containers
#         return result
#     except subprocess.TimeoutExpired:
#         print("Command timeout!!!!!!!")
#         return "Your command took to long to complete. Probably it started hanging. Please adjust."

# @tools.tool
# def build_and_run_docker_compose():
#     """
#     Runs docker-compose for the simulation environment with the --build flag. Assumes that a docker-compose.yml has already been created.
#     :return: If the command was successful
#     """

#     print("Trying to run docker compose\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied:" + p
#     try:
#         process = subprocess.run("cd simulation_environments/" + os.environ['REPO_PATH'] + " && docker-compose build && docker-compose up -d", shell=True, capture_output=True, text=True, timeout=1200)
#         result = "# STDOUT:\n{}\n\n# STDERR:\n{}".format(process.stdout, process.stderr)
#         time.sleep(5)
#         process = subprocess.run("cd simulation_environments/" + os.environ['REPO_PATH'] + " && docker-compose ps --filter status=exited", shell=True, capture_output=True, text=True, timeout=10)
#         return result + f"These containers have stopped, please check logs. Ignore if empty\n{process.stdout}\n"
#     except subprocess.TimeoutExpired:
#         print("Command timeout!!!!!!!")
#         return "Your command took to long to complete. Probably it started hanging. Please adjust."

# @tools.tool
# def send_inputs(pid: int, inp: str) -> str:
#     """
#     This tool sends an input to the stdin of the given pid if it is still running.

#     :param pid: The pid of the target process.
#     :param inp: The input to send via stdin.
#     :return: String denoting if the write was succesful or not.
#     """

#     print(f"Trying to write {inp} to {pid}...\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"

#     pid = int(pid)
#     if pid not in Ps:
#         return "Process not found, PID: " + str(pid) + "\n"
#     p = Ps[pid]
#     p.stdin.write(str.encode(inp))
#     p.stdin.flush()
#     return f"###Write to stdin of PID {pid} finished###\n"

# @tools.tool
# def wait(tim: int) -> str:
#     """
#     This tool waits for the given duration in seconds.
#     Can be used when you are waiting for subsequent outputs from a process.
#     Will display outputs from all running processes after the wait.

#     :param tim: Duration in seconds.
#     :return: If wait was successful.
#     """

#     print("Trying to sleep for: ", tim, "\nProceed?")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"

#     time.sleep(tim)
#     outs = ""
#     for pid in list(Ps.keys()):
#         outs += capture_outputs(pid)

#     return outs
