from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
import json
import nvdlib
import pyxploitdb
from urllib.error import HTTPError
import ast
from pt_report_generate import generate_pdf, prepare_vulnerability_data
import sqlite3
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
import csv

app = Flask(__name__)


# Load phases and their responses from JSON file
def load_phases_from_json(json_file):
    with open(json_file, 'r') as f:
        phases_data = json.load(f)
    return phases_data


phases_json_file = 'phase_responses.json'

# Load phases and their responses
phases = load_phases_from_json(phases_json_file)


nltk.download('punkt')
nltk.download('wordnet')

# Function to preprocess text
def preprocess(text):
    lemmatizer = WordNetLemmatizer()
    tokens = word_tokenize(text.lower())
    lemmatized_tokens = [lemmatizer.lemmatize(token) for token in tokens if token.isalpha()]
    return ' '.join(lemmatized_tokens)

# Load training data
def load_training_data(file_path):
    training_data = []
    with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
        csv_reader = csv.reader(csvfile)
        for row in csv_reader:
            training_data.append((row[0], row[1]))
    return training_data

# Define the file path for the training data CSV file
training_data_file = 'intents.csv'

# Generate or load training data
try:
    training_data = load_training_data(training_data_file)
except FileNotFoundError:
    print("Unable to open training data file")

# Preprocess training data
X_train = [preprocess(text) for text, intent in training_data]
y_train = [intent for text, intent in training_data]

# Create pipeline
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_df=0.9, min_df=2)),
    ('clf', LinearSVC(C=0.5)),
])

# Train the model
pipeline.fit(X_train, y_train)

# Function to test user input against the model and print all intents with matching percentages
def test_user_intent(user_input):
    preprocessed_input = preprocess(user_input)
    intent_scores = pipeline.decision_function([preprocessed_input])[0]
    exp_scores = np.exp(intent_scores - np.max(intent_scores))  # Avoid overflow
    intent_probabilities = exp_scores / np.sum(exp_scores)
    intents = pipeline.classes_

    max_index = np.argmax(intent_probabilities)
    predicted_intent = intents[max_index]
    return predicted_intent


#######################################################################



def search_cves_for_technology(keyword):
    global cve_list, cves_with_exploits, cve_details
    cve_list = []
    cves_with_exploits = []
    cve_details = {}
    temp = []
    
    
    try:
        # Search for CVEs containing the specified keyword
        r = nvdlib.searchCVE(keywordSearch=keyword, limit=1, key='0de04895-bc7a-4779-9614-2917c190199a', delay=0.6)
        
        for eachCVE in r:
            # Check if exploits exist for this CVE
            try:
                p = pyxploitdb.searchCVE(eachCVE.id)
            except HTTPError as e:
                print(f"Error retrieving exploits for CVE {eachCVE.id}: {e}")
                continue
            
            if len(p) > 0:
                cve_list.append(eachCVE)
                cves_with_exploits.append(eachCVE.id)
                print(f"CVE ID: {eachCVE.id}")
                cvss_metrics = eachCVE.score
                cvss_score = cvss_metrics[1]
                cvss_severity = cvss_metrics[2]
                print(f"Score: {cvss_score}")
                print(f"Severity: {cvss_severity}")
                print(f"CVE Link: {eachCVE.url}")
                

                temp.append(eachCVE.descriptions)
                x=temp[0][0]
                z = ''
                z += str(x)
                cve_description = ''
                cve_description += z[25:-2]
                print(f"Description: {cve_description}")
                temp = []

                cve_details.update({"CVE ID" : eachCVE.id ,"Description" : cve_description , "Publish Date" : eachCVE.published , "NVD Link" : eachCVE.url , "Score" : eachCVE.score , "CWE" : eachCVE.cwe , "Refrences" : eachCVE.references , "CPE" : eachCVE.cpe })                                                 
                
                print("-" * 50)
    
    except HTTPError as e:
        print(f"Error retrieving CVEs: {e}")
        

def print_exploits_for_cve(cve_list):
    global exploits_details_less, exploits_links
    exploits_links = []
    exploits_details_less = ''
    if not cve_list:
        print("No CVEs with associated exploits found.")
        return
    
    try:
        for cve in cve_list:
            
            try:
                p = pyxploitdb.searchCVE(cve)
            except HTTPError as e:
                print(f"Error retrieving exploits for CVE {cve}: {e}")
                continue
            
            for exploit in p:
                exploits_details_less = (f"CVE ID: {cve}" + " \n" + f"Exploits: {exploit}")
                print(exploit)
                nvd_link = str(exploit)
                #scrape_exploit_data(nvd_link)
            print("-" * 50)


            # Find the position of 'link=' in the string
            link_start_index = nvd_link.find("link=")

            if link_start_index != -1:
                # Extract the substring starting from the link value
                link_substr = nvd_link[link_start_index + 6:]  # +6 to skip 'link='
                
                # Find the closing quote (') to determine the end of the link value
                link_end_index = link_substr.find("'")
                
                if link_end_index != -1:
                    # Extract the link value
                    extracted_link = link_substr[:link_end_index]
                    exploits_links.append(extracted_link)
                    print("Extracted Link:", extracted_link)
                else:
                    print("Invalid format: Closing quote not found for link value.")
            else:
                print("Invalid format: 'link=' not found in the string.")
    
    except HTTPError as e:
        print(f"Error printing exploits: {e}")

def scrape_exploit_data(url):
    try:
        # Define comprehensive headers to mimic a browser request
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.google.com/',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        # Send a GET request to the URL with custom headers
        response = requests.get(url, headers=headers)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the HTML content of the webpage
            soup = BeautifulSoup(response.content, 'html.parser')

            # Find the <code> element containing the exploit data
            code_element = soup.find('code')

            # Extract the text content of the <code> element
            if code_element:
                exploit_data = code_element.get_text()
                return exploit_data
            else:
                print("No exploit data found for this CVE")
                return None
        else:
            print(f"Failed to retrieve expliot.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

def scrape_exploit_data(url):
    global exploit_full_code
    exploit_full_code = ''
    try:
        # Define comprehensive headers to mimic a browser request
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.google.com/',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        # Send a GET request to the URL with custom headers
        response = requests.get(url, headers=headers)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the HTML content of the webpage
            soup = BeautifulSoup(response.content, 'html.parser')

            # Find the <code> element containing the exploit data
            code_element = soup.find('code')

            # Extract the text content of the <code> element
            if code_element:
                exploit_data = code_element.get_text()
                # return exploit_data
                scraped_data = exploit_data
                # Remove \r characters from the scraped data
                cleaned_data = scraped_data.replace('\r', '')

                # Print the cleaned data (formatted with proper line breaks)
                print("Exploit Data:")
                print(cleaned_data)
                exploit_full_code = cleaned_data
                return cleaned_data
            else:
                print("No exploit data found for this CVE")
                return None
        else:
            print(f"Failed to retrieve expliot.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None



#######################################################################



# Define function to get theme color based on phase
def get_theme_color(phase):
    theme_colors = {
        1: '#C3DBFF',  # Blue
        4: '#C9FFC3',  # Green
        2: '#FFFDC3',  # Yellow
        3: '#FFCAC3'   # Red
    }
    return theme_colors.get(phase, '#A8DEFF')  # Default to blue if phase not found


# Initial state and phase
current_phase = 1
previous_intent = None

chat_history = []


    
# Route to serve chatbot.html
@app.route('/')
def home():
    global generate_report
    generate_report = 0
    
    create_database()
    return render_template('chatbot.html')



# SQLite database setup
DATABASE = 'chat_history.db'

def create_database():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS chat_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender TEXT,
                  message TEXT,
                  timestamp TEXT)''')
    conn.commit()
    conn.close()

@app.route('/save_chat', methods=['POST'])
def save_chat():
    try:
        data = request.get_json()
        chat_history = data.get('chatHistory', [])

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        for entry in chat_history:
            sender = entry.get('sender')
            message = entry.get('message')
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            c.execute('''INSERT INTO chat_history (sender, message, timestamp)
                         VALUES (?, ?, ?)''', (sender, message, timestamp))

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Chat saved successfully!'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/chathistory')
def chat_history():
    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''SELECT sender, message, timestamp FROM chat_history ORDER BY timestamp DESC''')
        chat_history = c.fetchall()
        conn.close()
        return render_template('chathistory.html', chat_history=chat_history)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500




@app.route('/new_chat')
def new_chat():
    global current_phase, previous_intent
    current_phase = 1
    previous_intent = None

    # Redirect to the root URL to reload the chat page
    return redirect(url_for('index'))

# Route to receive and process messages
@app.route('/process', methods=['POST'])
def process():
    global current_phase, previous_intent, generate_report
    global target, technologies

    # Initialize variables if they are not already initialized
    if 'target' not in globals():
        target = None
    if 'technologies' not in globals():
        technologies = None


    user_message = request.form['user_input']

    response = ""

    # Predict intent probabilities from the user's message
    detected_intent = test_user_intent(user_message)
    
    if previous_intent == 'target_select' and current_phase == 1:
        target = user_message
        #test(target)
        previous_intent = None
        theme_color = get_theme_color(current_phase)
        return jsonify({'bot_response': "Target is selected : " + target, 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})


    if previous_intent == 'select_technology' and current_phase == 2:
        technologies = user_message
        #test(technologies)
        previous_intent = None
        theme_color = get_theme_color(current_phase)
        return jsonify({'bot_response': "Testing this technology : " + technologies, 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})
        

    if previous_intent == 'show_exploits' and detected_intent.lower() == 'affirmation' and current_phase == 3:
        #exploit(technologies)
        previous_intent = None
        theme_color = get_theme_color(current_phase)
        return jsonify({'bot_response': "Showing exploiting for " + technologies + " xxxxxxxxx ",  'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})
    if previous_intent == 'show_exploits' and detected_intent.lower() == 'negation' and current_phase == 3:
        #exploit(technologies)
        previous_intent = None
        theme_color = get_theme_color(current_phase)
        return jsonify({'bot_response': "What other action would you like to perform? ", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})


    if detected_intent.lower() == 'end' and current_phase == 4 and generate_report == 0:
        theme_color = get_theme_color(current_phase)
        return jsonify({'bot_response': "Are you sure you want to exit without generating report? ", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})    
    if (previous_intent == 'end' or previous_intent == 'next_phase') and detected_intent.lower() == 'affirmation' and current_phase == 4:
        #generate_report()
        previous_intent = None
        theme_color = get_theme_color(current_phase)
        return jsonify({'bot_response': "Generating report ...", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})
    if (previous_intent == 'end' or previous_intent == 'next_phase')and detected_intent.lower() == 'negation' and current_phase == 4:
        previous_intent = None
        theme_color = get_theme_color(current_phase)
        return jsonify({'bot_response': "Exiting Remediation and Documentation phase. Penetration testing complete.", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})




    
                
    if user_message.lower() == 'exit':
        current_phase = 1
        previous_intent = None
        response = phases[str(current_phase)]['responses']['start']
        
    else: 
        if str(current_phase) in phases:
            phase_responses = phases[str(current_phase)]['responses']        
            
            # Check if the detected intent matches the intent to proceed to the next phase
            if detected_intent.lower() == 'next_phase':
                if current_phase == 1 and not target:
                    previous_intent = None
                    theme_color = get_theme_color(current_phase)
                    return jsonify({'bot_response': "Please choose target first", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})

                if current_phase == 2 and not technologies:
                    previous_intent = None
                    theme_color = get_theme_color(current_phase)
                    return jsonify({'bot_response': "Please choose a web technology to test first", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})

                if current_phase == 4 and generate_report == 0:
                    theme_color = get_theme_color(current_phase)
                    return jsonify({'bot_response': "Do you want to generate report before ending pentest", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})


                if current_phase < 4:
                    current_phase =  current_phase + 1
                    if current_phase == 1:
                        theme_color = get_theme_color(current_phase)
                        return jsonify({'bot_response': "Welcome to Scanning and Recon phase. How can I help you?", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})
                    if current_phase == 2:
                        theme_color = get_theme_color(current_phase)
                        return jsonify({'bot_response': "Welcome to Enumeration phase. How can I help you?", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})
                    if current_phase == 3:
                        theme_color = get_theme_color(current_phase)
                        return jsonify({'bot_response': "Welcome to Exploitation phase. How can I help you?", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})
                    if current_phase == 4:
                        theme_color = get_theme_color(current_phase)
                        return jsonify({'bot_response': "Welcome to Remediation and Documentation phase. How can I help you?", 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})
                        
                else:
                    response = "Congrats, Penetration testing is already complete!"

            # Check if the detected intent has a specific response for the current phase
            elif detected_intent.lower() in phase_responses:
                response = phase_responses[detected_intent.lower()]
            else:
                response = "I'm sorry, I was unable to get that, please choose something else. "

                
                if current_phase == 1:
                    response += "Options for this phase include target selection, and how to perform scanning using tools (osint scan, nmap scan, google dorks). "
                    if target:
                        response += "Do you want to perform more actions or move on to next phase? "
                if current_phase == 2:
                    response += "Options for this phase include selection of technology(to test) , enumeration of sub-domains, enumeration of web application functions, probing directories, identifying web components, discovering web technologies, enumerating server side technologies etc. "
                    if technologies:
                        response += "Do you want to perform more actions or move on to next phase? "
                if current_phase == 3:
                    response += "Options for this phase include displaying exploits selected vulnerability, printing further details for these exploits etc "
                if current_phase == 4:
                    response += "Options for this phase include generate report, suggest mitigations and end pentest"
                

        # Store the current intent as the previous intent
        previous_intent = detected_intent.lower()
        
#######################################################################

        #print CVEs
        if current_phase == 2 and detected_intent.lower() == "show_vulnerabilities":
            try:
                search_cves_for_technology(technologies)
                
                filtered_details = list(cve_details.items())[:2]
                details = ""

                # Iterate over the first two pairs and print them
                for key, value in filtered_details:
                    details += f"<br><b>{key} :</b> {value}"

                response += details
                
            except:
                response += " Select Technology First!!"





        #show exploits
        if current_phase == 3 and detected_intent.lower() == "show_exploits":
            try:
                print_exploits_for_cve(cves_with_exploits)
                
                
                details = ""
                details += exploits_details_less

                response += details
                
            except:
                response += " Unable to print exploits , or either no vulnerability selected!!"

        #print exploits
        if current_phase == 3 and detected_intent.lower() == "exploit_details":
            try:
                scrape_exploit_data(exploits_links[0])
                                
                
                details = ""
                details += exploit_full_code

                response += details
                
            except:
                response += " Unable to print exploits , or either no vulnerability selected!!"

                


        #generate report        
        if current_phase == 4 and detected_intent.lower() == "generate_report":
            generate_pdf("pentesting_report.pdf", prepare_vulnerability_data(cve_details))
            response += " Your report has been generated"
            report_generated = 1

#######################################################################
    try:
        print("target: "+ target)
    except:
        pass
    try:
        print("tech: "+ technologies)
    except:
        pass
    theme_color = get_theme_color(current_phase)
    return jsonify({'bot_response': response, 'previous_intent': previous_intent, 'phase': current_phase, 'theme_color': theme_color})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
