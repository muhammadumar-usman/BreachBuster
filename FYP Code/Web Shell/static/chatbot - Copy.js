// Global variable to store chat history
var chatHistory = [];

// Function to send user message and process bot response
function sendMessage() {
    var userInput = document.getElementById('user-input').value;
    document.getElementById('user-input').value = '';

    // Append user's message to chat box
    appendMessage('user', userInput);

    // Add user message to chat history
    chatHistory.push({ sender: 'user', message: userInput });

    // Send user's message to server for processing
    $.ajax({
        url: '/process',
        type: 'POST',
        contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
        data: { user_input: userInput },
        success: function(data) {
            // Simulate typing effect for bot's response
            simulateTyping('bot', data.bot_response);

            // Update theme color based on phase
            updateThemeColor(data.theme_color);

            // Add bot response to chat history
            chatHistory.push({ sender: 'bot', message: data.bot_response });

            // Scroll chat box to bottom after bot response is appended
            scrollChatToBottom();
        },
        error: function(error) {
            console.error('Error:', error);
        }
    });
}

// Function to save chat history to the database
function saveChat() {
    console.log('Saving chat history:', chatHistory);

    // Make a POST request to save chat history to the server
    fetch('/save_chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ chatHistory: chatHistory })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Failed to save chat history');
        }
        return response.json();
    })
    .then(data => {
        console.log('Chat history saved successfully:', data);

        // Display a popup confirmation message
        alert('Chat has been saved successfully!');
    })
    .catch(error => {
        console.error('Error saving chat history:', error);
    });
}

// Function to execute when the page is fully loaded
window.onload = function() {
    // Define an initial greeting message
    var greetingMessage = "Hello! Welcome to BreachBuster. I am your personal pentesting assistant. Following 4 steps of pentest i.e Scanning and Reconnaisance, Enummeration, Exploitation, and Remediadtion & Documnentation, this pentest will be divided into multiple tasks. You are currently in the first phase of pentesting i.e. Scanning and Reconnaisance. Not sure what to do? Simply type help! Let me know I may assist you in your pentest? ";

    // Append the greeting message as a bot message when the page loads
    simulateTyping('bot', greetingMessage);
};

// Helper function to check if the user has scrolled up
function userHasScrolledUp(element) {
    return element.scrollHeight > element.clientHeight && element.scrollTop > 0;
}

// Example function to trigger a new chat session
function startNewChat() {
    // Make a request to the server to reset intents and change phase
    fetch('/new_chat')
        .then(response => {
            // Reload the page after the server responds
            window.location.reload();
        })
        .catch(error => {
            console.error('Error starting new chat:', error);
        });
}

// Function to simulate typing effect
function simulateTyping(sender, message) {
    var chatBox = document.getElementById('chat-box');
    var typingMessage = document.createElement('div');
    typingMessage.className = sender === 'bot' ? 'bot-message typing-animation' : 'user-message typing-animation';

    var words = message.split(' ');
    var currentWord = 0;

    // Animate writing word by word
    var typingInterval = setInterval(function() {
        if (currentWord < words.length) {
            typingMessage.textContent += words[currentWord] + ' ';
            currentWord++;
        } else {
            clearInterval(typingInterval);
            typingMessage.classList.remove('typing-animation');
            appendMessage(sender, message); // Append finalized message
            scrollChatToBottom(); // Scroll chat box to bottom
        }
    }, 50);

    // Append the typing animation element to chat box
    chatBox.appendChild(typingMessage);
}

// Function to update theme color
function updateThemeColor(color) {
    document.documentElement.style.setProperty('--primary-color', color);
}

// Function to append a message to the chat box
function appendMessage(sender, message) {
    var chatBox = document.getElementById('chat-box');
    var isScrolledToBottom = chatBox.scrollHeight - chatBox.clientHeight <= chatBox.scrollTop + 1;
    var hasScrolledUp = !userHasScrolledUp(chatBox);

    var messageElem = document.createElement('div');
    messageElem.className = sender === 'bot' ? 'bot-message' : 'user-message';

    // Use innerHTML to render HTML tags like <br>
    messageElem.innerHTML = message;

    if (sender === 'user') {
        chatBox.appendChild(messageElem);
    }

    // Scroll to the bottom after appending the message if conditions are met
    if (isScrolledToBottom || hasScrolledUp) {
        chatBox.scrollTop = chatBox.scrollHeight - chatBox.clientHeight;
    }
}


// Function to scroll chat box to the bottom
function scrollChatToBottom() {
    var chatBox = document.getElementById('chat-box');
    chatBox.scrollTop = chatBox.scrollHeight;
}

// Test with hardcoded message containing <br> tags
appendMessage('bot', 'This is a test<br>message with<br>line breaks.');

document.addEventListener('DOMContentLoaded', function() {
    loadChatSessions();
});

function loadChatSessions() {
    fetch('/api/chatsessions')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const chatSessionList = document.getElementById('chat-session-list');
                chatSessionList.innerHTML = ''; // Clear existing content
                data.sessions.forEach(session => {
                    const sessionItem = document.createElement('div');
                    sessionItem.classList.add('session-item');
                    sessionItem.innerHTML = `<a href="/chathistory/${session[0]}">• PenTest chat# ${session[0]}</a>`;
                    chatSessionList.appendChild(sessionItem);
                });
            } else {
                console.error('Failed to load chat sessions:', data.message);
            }
        })
        .catch(error => {
            console.error('Error fetching chat sessions:', error);
        });
}

function startNewChat() {
    // Functionality to start a new chat
    // Assuming that starting a new chat will create a new session and save it in the database
    fetch('/start_new_chat', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                loadChatSessions();  // Reload chat sessions to include the new one
            } else {
                console.error('Failed to start new chat:', data.message);
            }
        })
        .catch(error => {
            console.error('Error starting new chat:', error);
        });
}


async function logout() {
    try {
        const response = await fetch('/logout', {
            method: 'POST', // Assuming the logout route accepts POST requests
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (response.ok) {
            window.location.href = '/login'; // Redirect to the login page on successful logout
        } else {
            console.error('Logout failed:', response.statusText);
            // Handle error (e.g., show a message to the user)
        }
    } catch (error) {
        console.error('Error during logout:', error);
        // Handle error (e.g., show a message to the user)
    }
}

