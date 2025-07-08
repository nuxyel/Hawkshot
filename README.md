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
                            v2.7 - by r3n4n
```
<p align="center">
  <img alt="Language" src="https://img.shields.io/badge/Language-Python-blue?style=for-the-badge">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
  <img alt="Pentesting" src="https://img.shields.io/badge/Usage-Pentesting%20%7C%20Recon-red?style=for-the-badge">
</p>

**HAWKSHOT** is a fast and efficient multi-threaded DNS subdomain enumerator written in Python. It is designed for the reconnaissance (RECON) phase of penetration testing, helping security professionals and enthusiasts to map the attack surface of a target domain.

## From a Simple Script to a Powerful Tool

This project began as a simple, single-threaded DNS brute-force script, the concept of which was taught in a **Solyd** cybersecurity course. The initial version was a great starting point for understanding the basic logic of subdomain enumeration.

This repository represents a significant evolution from that original concept. The script was completely rewritten and enhanced with new features to transform it into a practical and powerful tool for real-world scenarios.

### Key Improvements and Features

-   **🚀 High Performance with Multithreading:** The original single-threaded script was slow. HAWKSHOT now uses a multi-threaded worker/queue model, allowing it to perform hundreds of DNS queries concurrently, drastically reducing scan times.
-   **📚 Support for Multiple Record Types:** While the basic script only looked for `A` records, HAWKSHOT can query multiple types, including `A`, `AAAA`, `CNAME`, `MX`, `TXT`, and `NS`, providing a much richer set of data.
-   **💻 Professional CLI:** The `sys.argv` handling was replaced with Python's `argparse` module, offering a robust command-line interface with clear options, arguments, and a helpful `--help` menu.
-   **🎨 Colored Output:** Results are now color-coded for better readability using the `termcolor` library. Found domains are green, timeouts are yellow, and errors are red, making it easy to parse the output visually.
-   **💾 File Output:** Added the crucial ability to save all found subdomains to a text file with the `-o` flag, perfect for documentation and for piping into other tools.
-   **🎯 Specific Error Handling:** The `try...except` block was replaced with specific handlers for different `dnspython` exceptions (`NXDOMAIN`, `NoAnswer`, `Timeout`), making the tool more stable and reliable.
-   **🌎 Universal Codebase:** All user-facing strings, comments, and documentation have been translated to English to make the tool accessible to a global audience.

## ⚙️ Installation

HAWKSHOT is developed in Python 3. You will need `git` and `pip` installed.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/nuxyel/hawkshot.git](https://github.com/nuxyel/hawkshot.git)
    cd hawkshot
    ```

2.  **Install dependencies:**
    Make sure the required Python libraries `dnspython` and `termcolor` are installed.
    ```bash
    pip install dnspython termcolor
    ```

## 🚀 Usage

The tool is run from the command line, requiring a target domain and a wordlist.

### Help Menu
To view all available options and commands:
```bash
python3 hawkshot.py --help
```

### Practical Examples

**1. Basic Scan**
*Searches for `A` records using 20 threads (default).*

```bash
python3 hawkshot.py target.com wordlist.txt
```

**2. Comprehensive Scan**
*Searches for `A`, `AAAA`, and `CNAME` records, using 100 threads for higher speed.*

```bash
python3 hawkshot.py target.com wordlist.txt -t 100 -T A AAAA CNAME
```

**3. Scan with File Output**
*Performs a scan and saves all found subdomains to the `results.txt` file.*

```bash
python3 hawkshot.py target.com wordlist.txt -t 50 -o results.txt
```

### Example Output

```
[*] Target: target.com
[*] Wordlist: wordlist.txt (5000 subdomains)
[*] Threads: 50
[*] Record Types: A, CNAME

--- Starting Scan ---
[A   ] [www.target.com](https://www.target.com)                 -> 93.184.216.34
[A   ] dev.target.com                 -> 192.168.0.10
[CNAME] store.target.com               -> shops.myshopify.com
[TIMEOUT] old.target.com

--- Scan Finished ---
[+] Subdomains found: 3
[*] Saving results to 'results.txt'...
[+] Results saved successfully!
```

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/nuxyel/Hawkshot/blob/main/LICENSE) file for more details.

## Acknowledgments

  - To **Solyd** for providing the foundational knowledge and inspiration for this project.

by _r3n4n_
