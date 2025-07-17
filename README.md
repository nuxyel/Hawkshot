# 🦅 HAWKSHOT

```
   ▄█    █▄       ▄████████  ▄█     █▄     ▄█   ▄█▄    ▄████████    ▄█    █▄     ▄██████▄      ███     
  ███    ███     ███    ███ ███     ███   ███ ▄███▀   ███    ███   ███    ███   ███    ███ ▀█████████▄ 
  ███    ███     ███    ███ ███     ███   ███▐██▀     ███    █▀    ███    ███   ███    ███    ▀███▀▀██ 
 ▄███▄▄▄▄███▄▄   ███    ███ ███     ███  ▄█████▀      ███         ▄███▄▄▄▄███▄▄ ███    ███     ███   ▀ 
▀▀███▀▀▀▀███▀  ▀███████████ ███     ███ ▀▀█████▄    ▀███████████ ▀▀███▀▀▀▀███▀  ███    ███     ███     
  ███    ███     ███    ███ ███     ███   ███▐██▄            ███   ███    ███   ███    ███     ███     
  ███    ███     ███    ███ ███ ▄█▄ ███   ███ ▀███▄    ▄█    ███   ███    ███   ███    ███     ███     
  ███    █▀      ███    █▀   ▀███▀███▀    ███   ▀█▀  ▄████████▀    ███    █▀     ▀██████▀     ▄████▀   
                                          ▀                                                            
                            v3.0 - by r3n4n
```

<div align="center">
  <img alt="Language" src="https://img.shields.io/badge/Language-Python-blue?style=for-the-badge">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
  <img alt="Pentesting" src="https://img.shields.io/badge/Usage-Pentesting%20%7C%20Recon-red?style=for-the-badge">
</div>

**HAWKSHOT** is a fast and efficient multi-purpose reconnaissance tool written in Python. It is designed to map the external attack surface of a target by specializing in both **DNS subdomain enumeration** and **web directory/file scanning**.

## From a Simple Script to a Powerful Toolkit

This project began as a simple, single-threaded DNS brute-force script, the concept of which was taught in a **Solyd** cybersecurity course. The initial version was a great starting point for understanding the basic logic of reconnaissance.

This repository represents a significant evolution from that original concept. The script was completely rewritten and modularized to transform it into a practical and powerful toolkit for real-world scenarios.

### Key Features

-   **🚀 High Performance with Multithreading:** Both the DNS and Web modules use a multi-threaded worker/queue model, allowing them to perform hundreds of requests concurrently and drastically reducing scan times.
-   **🔎 Dual Reconnaissance Modules:**
    -   **`enum` module:** Performs in-depth DNS enumeration, supporting multiple record types (`A`, `AAAA`, `CNAME`, `MX`, etc.).
    -   **`dir` module:** Scans web servers for hidden directories, files, and endpoints.
-   **💻 Professional CLI:** A robust command-line interface built with Python's `argparse` module, featuring subcommands for clear separation of functionalities and a helpful `--help` menu.
-   **🎨 Colored Output:** Results are color-coded for better readability, making it easy to spot successful finds, timeouts, and different HTTP status codes.
-   **💾 File Output:** Both modules include the ability to save results to a text file with the `-o` flag, perfect for documentation and for piping into other tools.

## ⚙️ Installation

Follow these steps to install HAWKSHOT and make it available as a global command on your Linux system.

### Step 1: Clone the Repository
```
git clone (https://github.com/nuxyel/hawkshot.git)
cd hawkshot
```

### Step 2: Install Dependencies

The directory scanning module adds a new dependency (`requests`).

```b
pip install dnspython termcolor requests
```

### Step 3: Make it a Global Command

This will allow you to run `hawkshot` from any directory in your terminal.

```
# Ensure the script has the shebang line #!/usr/bin/env python3 at the top.
# Then, make the script executable:
chmod +x hawkshot.py

# Now, create a symbolic link to a directory in your system's PATH (requires sudo)
sudo ln -s "$(pwd)/hawkshot.py" /usr/local/bin/hawkshot
```

After this, open a **new terminal window** to start using the `hawkshot` command.

## 🚀 Usage

HAWKSHOT now operates using subcommands: `enum` for DNS tasks and `dir` for web scanning.

### Help Menu

To view all available options and commands:

```
# General help, shows the available commands (enum, dir)
hawkshot --help

# Help specific to the DNS enumeration module
hawkshot enum --help

# Help specific to the directory scanning module
hawkshot dir --help
```

### Practical Examples

#### 1\. DNS Enumeration (`enum`)

*Searches for `A`, `AAAA`, and `CNAME` records, using 100 threads for higher speed.*

```
hawkshot enum target.com wordlist_dns.txt -t 100 -T A AAAA CNAME
```

#### 2\. Directory Scanning (`dir`)

*Scans a web server for common directories and saves the output to a file.*

```
hawkshot dir [http://target.com](http://target.com) wordlist_web.txt -t 50 -o results_dir.txt
```

### Example Output

#### DNS Enum Output

```
[*] Target: target.com
[*] Wordlist: wordlist_dns.txt (5000 subdomains)
[*] Threads: 50
--- Starting DNS Enumeration ---
[A   ] [www.target.com](https://www.target.com)                 -> 93.184.216.34
[CNAME] store.target.com                                        -> shops.myshopify.com
```

#### Directory Scan Output

```
[*] Target URL: [http://target.com](http://target.com)
[*] Wordlist: wordlist_web.txt (2000 paths)
[*] Threads: 50
--- Starting Directory Scan ---
[200] [http://target.com/admin](http://target.com/admin) (Length: 2140)
[301] [http://target.com/login](http://target.com/login) (Length: 178)
[403] [http://target.com/.git/config](http://target.com/.git/config) (Length: 121)
```

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/nuxyel/Hawkshot/blob/main/LICENSE) file for more details.

## Acknowledgments

  - To **Solyd** for providing the foundational knowledge and inspiration for this project.

by *r3n4n*
