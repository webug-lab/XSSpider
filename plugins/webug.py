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
    print("\n:climb\n")

    # Extract forms and check inputs
    forms = extract_forms(base_url)
    if forms:
        print("--------------")
        print("Forms found //")
        print("--------------\n")
        for action, method, inputs in forms:
            print(f"\tForm action: {action}, method: {method}, inputs: {inputs}\n")
    else:
        print("\tNo forms found.")
    print()

    # Check URL parameters
    print("--------------------------")
    print("Checking URL parameters //")
    print("--------------------------\n")
    url_params = [param.split('=')[0] for param in base_url.split('?')[1:]]
    if url_params:
        print(f"\tURL parameters: {url_params}")
    else:
        print("\tNo URL parameters found.")
    print()

    # Check headers for potential vulnerabilities
    print("-------------------")
    print("Checking headers //")
    print("-------------------\n")
    headers = check_headers(base_url)
    if headers:
        print(f"\tHeaders that may be vulnerable: {headers}")
    else:
        print("\tNo vulnerable headers found.")
    print()

    # Check cookies for potential vulnerabilities
    print("-------------------")
    print("Checking cookies //")
    print("-------------------\n")
    cookies = check_cookies(base_url)
    if cookies:
        print(f"\tCookies that may be vulnerable: {cookies}")
    else:
        print("\tNo vulnerable cookies found.")
    print()

    # Find all links on the page
    links = find_all_links(base_url)
    if links:
        print("--------------------------")
        print("Links found on the page //")
        print("--------------------------\n")
        for link in links:
            print(f"\t{link}") 
    else:
        print("\tNo links found.")
    print()

def quitline():
    print('\n:sleep\n')
    sys.exit(0)