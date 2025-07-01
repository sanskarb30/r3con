R3CON Tool by Sanskar Bhobaskar is a Python command-line recon utility. It offers HTTP recon, subdomain/directory bruteforce (custom wordlists), flexible port scanning, banner grabbing, robots.txt analysis, DNS lookup, service version scan, and OS inference. Results are logged to a `results/` folder. For ethical use on Linux.

````
## Installation (for Debian-based Linux)

Follow these steps to set up R3CON Tool on your Debian-based Linux system.

1.  **Download the Tool:**
    First, download the `secbreach.py` Python script and the `setup_r3con.sh` installation script from the repository. You can do this by cloning the repository:
    ```bash
    git clone [https://github.com/YourGitHubUsername/R3CON-Tool.git](https://github.com/YourGitHubUsername/R3CON-Tool.git)
    cd R3CON-Tool
    ```
    *(Replace `YourGitHubUsername` with your actual GitHub username and `R3CON-Tool.git` with your repository name)*

2.  **Make the Setup Script Executable:**
    Open your terminal, navigate to the directory where you downloaded the files, and run:
    ```bash
    chmod +x setup_r3con.sh
    ```

3.  **Run the Setup Script:**
    Execute the installation script:
    ```bash
    ./setup_r3con.sh
    ```
    This script will:
    * Update your system's package lists.
    * Install `python3`, `python3-pip`, `python3-venv`, and `dos2unix`.
    * Convert `secbreach.py` to Unix line endings (important for Linux compatibility).
    * Create a Python virtual environment named `venv`.
    * Activate the virtual environment.
    * Upgrade `pip` (Python package installer).
    * Install the `requests` Python library, which is required by the tool.

4.  **Create the Results Folder:**
    The tool saves all its output to a dedicated folder. Create this folder manually in the same directory where `secbreach.py` is located:
    ```bash
    mkdir results
    ```

## Usage

After installation, you need to activate the virtual environment and then run the tool.

1.  **Activate the Virtual Environment:**
    Before running the tool each time, you must activate its virtual environment. Do this from the tool's main directory:
    ```bash
    source venv/bin/activate
    ```

2.  **Run the R3CON Tool:**
    Now you can run the tool by providing the target domain or IP address as a command-line argument:
    ```bash
    python3 secbreach.py <target_domain_or_ip>
    ```
    **Examples:**
    * To scan a domain (e.g., `example.com`):
        ```bash
        python3 secbreach.py example.com
        ```
    * To scan an IP address (e.g., `192.168.1.1`):
        ```bash
        python3 secbreach.py 192.168.1.1
        ```

    Once executed, the tool will display its "R3CON TOOL" banner and an interactive menu. You can then select different reconnaissance modules by entering the corresponding number.

3.  **Interactive Menu Navigation:**
    * Enter the number of the module you wish to run (e.g., `1` for HTTP Recon).
    * For modules like "Subdomain Enumeration," "Directory Bruteforce," and "Port Scan," you will be prompted for additional choices (e.g., using a custom wordlist or specifying a port range).
    * After each module completes, the tool will pause and prompt you to "Press Enter to continue recon...". Press Enter to return to the main menu and select another module.
    * To exit the tool and save all the collected results to a file, type `q` and press Enter.

4.  **Accessing Results:**
    All output generated during your session will be saved to a timestamped text file within the `results/` folder (e.g., `results_example.com_20250701_153045.txt`).
````
