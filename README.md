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
├── __pycache__/
│
├── backup/
│
├── js/
│
├── static/
│   ├── chatbot.js
│   ├── logo.png
│   └── styles.css
│
├── templates/
│   ├── admin.html
│   ├── chatbot.html
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── session_history.html
│   └── webshell.html
│
├── admin
├── chat_history.db
├── cve_exploit_search
├── database
├── error
├── exploits_and_vulnerabilities_scraper
├── intent_model.pkl
├── intent_model
├── intents.xlsx
├── logo.png
├── main.py
├── pentesting_report.pdf
├── phase_responses.json
├── pt_report_generate
├── test
├── url_validator
├── users.json
├── webshell
├── requirements.txt
```
