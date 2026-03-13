# This script will automate the process of using Ghidra's Version Tracking tool.
# It will take two binary files as input and perform function matching analysis.

import os
import subprocess
import sys

def main():
    """
    Main function to orchestrate the Ghidra Version Tracking process.
    """
    if len(sys.argv) != 5:
        print("Usage: python ghidra_version_tracker.py <ghidra_path> <project_name> <binary_1> <binary_2>")
        sys.exit(1)

    ghidra_path = sys.argv[1]
    project_name = sys.argv[2]
    binary_1 = sys.argv[3]
    binary_2 = sys.argv[4]

    if not os.path.exists(ghidra_path):
        print(f"Error: Ghidra installation not found at '{ghidra_path}'")
        sys.exit(1)

    if not os.path.exists(binary_1):
        print(f"Error: Binary file not found at '{binary_1}'")
        sys.exit(1)

    if not os.path.exists(binary_2):
        print(f"Error: Binary file not found at '{binary_2}'")
        sys.exit(1)

    analyze_headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
    project_path = os.path.join(os.getcwd(), "ghidra_projects")
    script_path = os.path.abspath(os.path.dirname(__file__))

    # We need to create a project directory for Ghidra
    if not os.path.exists(project_path):
        os.makedirs(project_path)

    # We need to import the binaries with names that our script can recognize
    #binary_1_name = f"source_{os.path.basename(binary_1)}"
    #binary_2_name = f"destination_{os.path.basename(binary_2)}"
    binary_1_name = f"{os.path.basename(binary_1)}"
    binary_2_name = f"{os.path.basename(binary_2)}"


    create_command = [
        analyze_headless,
        project_path,
        project_name,
        "-import",
        binary_1,
        binary_2,
        "-scriptPath",
        "/home/paul/VERSIONTRACKING-AGENT",
        "-postScript",
        "HelloWorld.py",
        "-overwrite"
    ]

    run_script_command = [
        analyze_headless,
        project_path,
        project_name,
        "-postScript",
        "HelloWorld.py",
        "-scriptPath",
        script_path,
        "-overwrite"
    ]

    print(f"Creating Ghidra project...\n{' '.join(create_command)}")
    try:
        result = subprocess.run(create_command, check=True, text=True, capture_output=True)
        print("Ghidra project created.")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error creating Ghidra project:\n{e.stderr}")
        sys.exit(1)

    '''
    print(f"Running Ghidra script...\n{' '.join(run_script_command)}")
    try:
        subprocess.run(run_script_command, check=True, text=True, capture_output=True)
        print("Ghidra script complete. Check the project for results.")
    except subprocess.CalledProcessError as e:
        print(f"Error running Ghidra script:\n{e.stderr}")
        sys.exit(1)
    '''


if __name__ == "__main__":
    main()
