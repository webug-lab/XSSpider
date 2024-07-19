import sys
import requests
from bs4 import BeautifulSoup

def extract_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = [(input.get('name'), input.get('type', 'text')) for input in form.find_all('input')]
        forms.append((action, method, inputs))
    return forms

def find_all_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    links = [a.get('href') for a in soup.find_all('a', href=True)]
    return links

def check_headers(url):
    response = requests.get(url)
    headers = response.headers
    vulnerabilities = []
    for header, value in headers.items():
        if header.lower() in ['user-agent', 'referer']:
            vulnerabilities.append((header, value))
    return vulnerabilities

def check_cookies(url):
    response = requests.get(url)
    cookies = response.cookies
    vulnerabilities = []
    for cookie in cookies:
        vulnerabilities.append((cookie.name, cookie.value))
    return vulnerabilities

def crawl_and_identify_xss(base_url):
    print(f"Scanning URL: {base_url}")

    # Extract forms and check inputs
    forms = extract_forms(base_url)
    if forms:
        print("Forms found:")
        for action, method, inputs in forms:
            print(f" - Form action: {action}, method: {method}, inputs: {inputs}")
    else:
        print("No forms found.")

    # Check URL parameters
    print("\nChecking URL parameters:")
    url_params = [param.split('=')[0] for param in base_url.split('?')[1:]]
    if url_params:
        print(f" - URL parameters: {url_params}")
    else:
        print("No URL parameters found.")

    # Check headers for potential vulnerabilities
    print("\nChecking headers:")
    headers = check_headers(base_url)
    if headers:
        print(f" - Headers that may be vulnerable: {headers}")
    else:
        print("No vulnerable headers found.")

    # Check cookies for potential vulnerabilities
    print("\n-------------------")
    print("\nChecking cookies //")
    print("\n-------------------\n")
    cookies = check_cookies(base_url)
    if cookies:
        print(f" - Cookies that may be vulnerable: {cookies}")
    else:
        print("No vulnerable cookies found.")

    # Find all links on the page
    links = find_all_links(base_url)
    if links:
        print("\n--------------------------")
        print("\nLinks found on the page //")
        print("\n--------------------------\n")
        for link in links:
            print(f"{link}")
        print("\n")    
    else:
        print("No links found.")

def quitline():
    print('\n:sleep\n')
    sys.exit(0)