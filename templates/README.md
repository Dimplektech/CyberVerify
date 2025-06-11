# CyberVerify

A web application that checks the security status of domains, IP addresses, and file hashes using the VirusTotal API.

## Features

- Domain security checking
- IP address reputation analysis
- File hash verification
- Detailed security reports with threat intelligence
- User-friendly interface with clear security status indicators

## Technologies Used

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **API Integration**: VirusTotal API v3
- **Validation**: Pydantic for input validation

## Getting Started

### Prerequisites

- Python 3.8 or higher
- VirusTotal API key (free tier available at [VirusTotal](https://github.com/Dimplektech/CyberVerify.git))

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Dimplektech/CyberVerify.git
cd cyberverify
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a .env file in the project root with your VirusTotal API key:
```
VIRUSTOTAL_API_KEY=your_api_key_here
```

### Running the Application

Start the Flask server:
```bash
python api.py
```

Visit `http://localhost:5000` in your web browser.

## Usage

1. Select the check type: Domain, IP Address, or File Hash
2. Enter the value to check
3. Click "Check Security"
4. View the comprehensive security report

### Example Inputs

- **Domain**: google.com, example.com
- **IP Address**: 8.8.8.8, 1.1.1.1
- **File Hash**: 
  - MD5: 44d88612fea8a8f36de82e1278abb02f
  - SHA-1: 3395856ce81f2b7382dee72602f798b642f14140
  - SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

## Security Status Explained

The application provides detailed security information:

- **Safe**: No security threats detected
- **Suspicious**: Potentially unwanted behavior detected
- **Malicious**: Known security threat detected

For each check, you'll receive:
- Overall security status
- Blacklist status from major security vendors
- Detailed malware and security information

## Limitations

- Free VirusTotal API has request rate limits
- Results depend on VirusTotal's database coverage
- Analysis is based on existing threat intelligence, not real-time scanning

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- [VirusTotal](https://www.virustotal.com/) for providing the security API
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [Pydantic](https://docs.pydantic.dev/) for input validation

## Contact

Your Name - your.email@example.com

Project Link: https://github.com/yourusername/cyberverify