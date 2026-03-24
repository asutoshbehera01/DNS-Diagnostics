# CrateDNS

CrateDNS is a high-speed, professional-grade DNS lookup and diagnostic tool built with Python (FastAPI + dnspython). It provides a structured JSON API for instantaneous DNS record resolution and a modern, developer-friendly interface.

## Features
- **FastAPI Backend**: High-performance asynchronous API endpoints.
- **dnspython Engine**: Robust and reliable core for DNS resolution (A, AAAA, MX, CNAME, TXT, NS).
- **Developer-Friendly JSON API**: Structured, easy-to-parse responses for quick diagnosis.
- **Error Handling**: Comprehensive handling of NXDOMAIN, timeouts, and other DNS-related errors.
- **Modern UI**: Dark-themed, responsive web interface mimicking the aesthetics of enterprise developer tools.

## Getting Started
To run locally:
1. Ensure Python 3 is installed.
2. Install dependencies: `pip install -r requirements.txt`
3. Run the development server: `uvicorn main:app --reload`
4. Access the application at `http://localhost:8000`.
