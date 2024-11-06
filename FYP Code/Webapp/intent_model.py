import pandas as pd
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense
import numpy as np

# Load training data from CSV file
def load_training_data(csv_file):
    df = pd.read_csv(csv_file)
    input_texts = df['InputText'].tolist()
    output_labels = df['Intent'].tolist()
    return input_texts, output_labels

# Define file path to the CSV training data
csv_file_path = 'intents_data.csv'

# Load training data
input_texts, output_labels = load_training_data(csv_file_path)

# Define intents and count occurrences
intents = list(set(output_labels))
intent_counts = {intent: output_labels.count(intent) for intent in intents}

# Calculate target number of samples per intent (balanced)
max_samples_per_intent = min(intent_counts.values())

# Generate balanced training data
balanced_input_texts = []
balanced_output_labels = []

for intent in intents:
    samples = [input_texts[i] for i in range(len(output_labels)) if output_labels[i] == intent]
    selected_samples = samples[:max_samples_per_intent]
    balanced_input_texts.extend(selected_samples)
    balanced_output_labels.extend([intent] * len(selected_samples))

# Tokenize input texts
tokenizer = Tokenizer()
tokenizer.fit_on_texts(balanced_input_texts)
input_sequences = tokenizer.texts_to_sequences(balanced_input_texts)

# Pad sequences to ensure uniform input size
max_len = max(len(seq) for seq in input_sequences)
input_sequences_padded = pad_sequences(input_sequences, maxlen=max_len, padding='post')

# Convert output labels to categorical format
output_labels_unique = list(set(balanced_output_labels))
output_label_index = {label: idx for idx, label in enumerate(output_labels_unique)}
output_labels_encoded = [output_label_index[label] for label in balanced_output_labels]
output_labels_onehot = tf.keras.utils.to_categorical(output_labels_encoded)

# Define the model
model = Sequential()
model.add(Embedding(input_dim=len(tokenizer.word_index) + 1, output_dim=100, input_length=max_len))
model.add(LSTM(128))
model.add(Dense(len(output_labels_unique), activation='softmax'))

# Compile the model
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# Train the model
model.fit(input_sequences_padded, output_labels_onehot, epochs=30)

# Function to predict intent probabilities from a given sentence
def predict_intent_probabilities(sentence):
    # Tokenize and pad the input sentence
    sequence = tokenizer.texts_to_sequences([sentence])
    sequence_padded = pad_sequences(sequence, maxlen=max_len, padding='post')
    
    # Predict the intent probabilities using the trained model
    prediction = model.predict(sequence_padded)[0]  # Get the first (and only) prediction result
    return prediction

# Example usage
while True:
    user_input = input("User: ")
    if user_input.lower() in ['exit', 'quit', 'stop']:
        print("Bot: Goodbye!")
        break
    
    intent_probabilities = predict_intent_probabilities(user_input)
    
    # Find the index of the intent with the highest probability
    predicted_intent_index = np.argmax(intent_probabilities)
    predicted_intent = output_labels_unique[predicted_intent_index]
    predicted_probability = intent_probabilities[predicted_intent_index] * 100
    
    # Print the predicted intent and its probability
    print(f"Predicted Intent: '{predicted_intent}' with probability {predicted_probability:.2f}%")

