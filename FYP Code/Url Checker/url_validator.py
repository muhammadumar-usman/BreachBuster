import requests
from urllib.parse import urlparse, urlunparse

def normalize_url(url):
    """
    Normalize the URL to ensure it includes the scheme (http or https).
    """
    parsed_url = urlparse(url)
    
    if not parsed_url.scheme:
        # Assume http if no scheme is provided
        url = 'http://' + url
        parsed_url = urlparse(url)
    
    # Rebuild the URL to ensure it has a scheme and network location
    return urlunparse(parsed_url)

def is_valid_url(url):
    """
    Check if a URL is valid by sending a web request.
    """
    url = normalize_url(url)
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        # A valid URL should return a status code in the range 200-399
        if 200 <= response.status_code < 400:
            return True
        else:
            print(f"Received status code {response.status_code} for URL '{url}'")
            return False
    except requests.RequestException as e:
        print(f"Request exception: {e}")
        return False

def main():
    url = input("Please enter a URL to check: ").strip()
    if is_valid_url(url):
        print(f"The URL '{url}' is valid.")
    else:
        print(f"The URL '{url}' is not valid.")

if __name__ == "__main__":
    main()
