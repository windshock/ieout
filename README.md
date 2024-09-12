# IEOut

**IEOut** is a Python-based tool designed to detect and test programs that still rely on outdated Internet Explorer components, such as legacy DLLs (`mshtml.dll`, `ieframe.dll`, etc.). As Internet Explorer has been deprecated, these components may introduce security vulnerabilities to systems. IEOut helps identify such programs, run security tests, and raise awareness about updating to modern, secure web technologies.

## Features

### IEOut (Main Tool: `ie.py`)
- Detects processes using Internet Explorer-related DLLs.
- Sends notifications to alert users about detected processes.

### IEOut Test Suite (Test Tool: `ievultest.py`)
- Injects test pages into HTTP/HTTPS traffic using **mitmproxy**.
- Executes target programs using **proxinjector** and monitors their behavior.
- Monitors processes (e.g., `notepad.exe`) during tests.
- Terminates processes after test success or timeout.

## Requirements

- Python 3.x
- `plyer` for notifications (used in `ie.py`)
- `psutil` for process monitoring
- `mitmproxy` for HTTP/HTTPS proxy integration (used in `ievultest.py`)
- `proxinjector` for executing and testing target programs (used in `ievultest.py`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/windshock/ieout.git
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install **mitmproxy** (for the test suite):
   ```bash
   pip install mitmproxy
   ```

4. Set up the **mitmproxy** certificate for HTTPS interception (for the test suite):
   ```bash
   mitmproxy --cert C:\Users\skplanet\.mitmproxy\mitmproxy-ca-cert.pem
   ```

## Usage

### IEOut (`ie.py`)

1. Run the tool to detect processes using Internet Explorer-related components:
   ```bash
   python ie.py
   ```

2. The tool will monitor running processes, check if any are using Internet Explorer-related components, and trigger notifications for detected processes.

### IEOut Test Suite (`ievultest.py`)

1. Run the test suite with a target program:
   ```bash
   python ievultest.py <test_file>
   ```

   Example:
   ```bash
   python ievultest.py "C:\Program Files (x86)\Hnc\Office NEO\HOfficeViewer96\Bin\HwpViewer.exe"
   ```

2. The test suite will:
   - Intercept network traffic using **mitmproxy** in SOCKS5 mode.
   - Redirect all HTTP/HTTPS requests to a test page (`https://windshock.github.io/invite.html`).
   - Monitor for specific process creation (e.g., `notepad.exe`).
   - Terminate the target program and related processes after testing is completed or when a timeout occurs.

## Example Commands

- To run the detection tool:
   ```bash
   python ie.py
   ```

- To run the test suite:
   ```bash
   python ievultest.py "C:\Program Files (x86)\Hnc\Office NEO\HOfficeViewer96\Bin\HwpViewer.exe"
   ```

## Contribution

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or additional features.
