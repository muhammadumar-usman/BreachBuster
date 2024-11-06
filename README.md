Here's the updated `README.md` content in markdown format:


# BreachBuster - Cybersecurity Chatbot for Vulnerability Analysis

BreachBuster is an interactive cybersecurity chatbot designed to assist users in identifying and analyzing vulnerabilities through guided penetration testing. This tool empowers users by guiding them through essential steps of pentesting, providing customizable reporting, and integrating a web-based shell for real-time command execution.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
- [Installation](#installation)
- [Usage](#usage)
- [Technologies Used](#technologies-used)
- [Project Structure](#project-structure)

## Features

- **User-Guided Vulnerability Analysis**: BreachBuster prompts users step-by-step through phases of pentesting (scanning, enumeration, exploitation, and documentation).
- **Customizable Reports**: Generates comprehensive reports based on user actions and findings for easy documentation.
- **Integrated Web-Shell Access**: Allows real-time command execution for advanced system interaction during pentesting.
- **Scalability**: Built with modular architecture and scalable design to support increased usage.

## Getting Started

### Prerequisites

- **Python**: Version 3.9 or higher
- **Virtual Environment** (recommended): `venv`
- **Database**: SQLite (included in Python standard library)

## Technologies Used

- **Backend**: Flask, SQLite, Python
- **Frontend**: HTML, CSS, JavaScript (jQuery)
- **NLP**: NLTK for preprocessing and NLP-driven prompts
- **Report Generation**: Automated reporting for comprehensive documentation

## Project Structure
```
Webapp/
│
├── __pycache__/                  # Compiled Python files
├── backup/                       # Backup files
├── js/                           # JavaScript files
├── static/                       # Static files (JavaScript, CSS, images)
│   ├── chatbot.js
│   ├── logo.png
│   └── styles.css
├── templates/                    # HTML templates
│   ├── admin.html
│   ├── chatbot.html
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── session_history.html
│   └── webshell.html
├── admin                         # Admin module
├── chat_history.db               # SQLite database file
├── cve_exploit_search            # Module for CVE search and exploit handling
├── database                      # Database initialization and management
├── error                         # Error handling
├── exploits_and_vulnerabilities_scraper # Web scraper for exploits and vulnerabilities
├── intent_model.pkl              # Serialized intent model for NLP
├── intent_model                  # Intent model code and training
├── intents.xlsx                  # Intent data file for training
├── logo.png                      # Logo file
├── main.py                       # Main application script
├── pentesting_report.pdf         # Sample pentesting report
├── phase_responses.json          # JSON file containing phase responses
├── pt_report_generate            # Report generation module
├── test                          # Test scripts and unit tests
├── url_validator                 # URL validation scripts
├── users.json                    # JSON file for user data
├── webshell                      # Web shell functionality
└── requirements.txt              # Project dependencies

```
