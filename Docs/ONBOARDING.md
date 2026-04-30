# ONBOARDING.md - Ghidra String Sniper Setup Guide

This document guides you through the process of setting up the Ghidra String Sniper plugin. Follow the steps below to install and configure everything needed to analyze binary files effectively.

---

## Prerequisites
Before you start, make sure you have the following:
1. Ghidra installed and running on your machine.
2. Binary file that you want to analyze using the plugin.
3. OpenRouter API key to enable communication with the LLM for analysis.

---

## Installation Steps:

1. Install the plugin
    Clone or download the Ghidra String Sniper plugin from the repository.
2. Configure API Key
    * Navigate to:    
    C:\Users\...\ghidra_string_sniper_ext\data\python
    * Create a new file named TOKEN in this directory.
    * Paste your OpenRouter API key into the file to allow the script to query the LLM.
3. Deploy the Plugin
    * Go to:
    C:\Users\...\ghidra_string_sniper_ext
    * Run the appropriate installation script:
        * Windows: Run Windowsdeploy.bat
        * Linux: Run LinuxBuildInstall.sh

If you’re using Windows, during the setup, you will need to specify file paths for several components, which the script will use to store information and outputs.

---

## Running Ghidra with String Sniper

1. Start Ghidra
    * Open Ghidra and create a new project.
2. Import the Binary
    * Import the binary file you want to analyze into the project.
3. Confiure the Tool 
    * Go to File > Configure Tool > Ghidra Core (configure).
    * In the configuration window, select the Ghidra String Sniper plugin.
4. Open the CodeBrowser
    * With your binary file selected, open it in the CodeBrowser tool.
5. Launch Ghidra String Sniper
    * From the Window tab at the top of the screen, open the dropdown menu.
6. Begin Analysis
    * Once the Ghidra String Sniper panel opens, click the green refresh arrow in the top-right corner to start the analysis.
    * Wait for the analysis to complete. This may take several minutes depending on the binary’s size.