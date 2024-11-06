import numpy as np
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
import csv
import nltk

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

# Main function to take user input and output the matched intent
if __name__ == "__main__":
    while True:
        user_input = input("Please enter your query: ")
        matched_intent = test_user_intent(user_input)
        print(f"The matched intent is: {matched_intent}")
