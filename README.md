# IEOut

**IEOut** is a Python-based tool designed to detect programs that still rely on outdated Internet Explorer components, such as legacy DLLs (`mshtml.dll`, `ieframe.dll`, etc.). As Internet Explorer has been deprecated, these components may introduce security vulnerabilities to systems. IEOut helps identify such programs and raises awareness about updating to modern, secure web technologies.

## Features

- Detects processes using Internet Explorer-related DLLs.
- Sends notifications to alert users about the detected processes.

## Requirements

- Python 3.x
- `plyer` for notifications
- `psutil` for process monitoring

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ieout.git
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the tool:
   ```bash
   python ieout.py
   ```

## Usage

- The tool monitors running processes and checks if any are using Internet Explorer-related components.
- Detected processes are logged, and notifications are triggered to inform the user.

---

## Contribution

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or additional features.

---

This description gives a clear overview of the tool, its purpose, features, and how to get started.
