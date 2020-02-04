import json
import re
import sys
import urllib3
import requests
from urllib3.exceptions import InsecureRequestWarning


urllib3.disable_warnings(InsecureRequestWarning)

class APIEndpoint:
    def __init__(self, server, verify_ssl=False):
        self.server = server
        self.verify = verify_ssl
        self.token = ''
        self.cookie = ''      

    def login(self, username, password):
        # Our login function.  This will store and return our token
        # value used later in the script.
        print("Logging in to Tenable Security Center")
        data = {'username': username, 'password': password}
        resp = self.connect('POST', 'token', data)
        print(resp)
        if resp is not None:
            self.token = str(resp['token'])

    def logout(self):
        # Destroys token forcing a logout.
        print("Logging out of Tennable Security Center")
        self.connect('DELETE', 'token')
        self.token = ''
        self.cookie = ''

        # For method specify whether its a POST, PUT, DELETE
        # Resource-name eg scan, resource


    def connect(self, method, resource, data=None, stream=False):

        headers = {"Content-Type": "application/json",
                   "Accept": "application/json"
                  }

        if self.token != '':
            headers['X-SecurityCenter'] = self.token

        if self.cookie != '':
            headers['Cookie'] = self.cookie

        # Only convert the data to JSON if there is data.
        if data is not None:
          data = json.dumps(data)

        url = "https://{0}/rest/{1}".format(self.server, resource)
        

        # Our API calls (POST, PUT, DELETE, PATCH, GET)
        try:
            if method == 'POST':
                r = requests.post(url, data=data, headers=headers, verify=self.verify, stream=False, files=None)
            elif method == 'PUT':
                r = requests.put(url, data=data, headers=headers, verify=self.verify)
            elif method == 'DELETE':
                r = requests.delete(url, data=data, headers=headers, verify=self.verify)
            elif method == 'PATCH':
                r = requests.patch(url, data=data, headers=headers, verify=self.verify)
            else:
                r = requests.get(url, params=data, headers=headers, verify=self.verify)

        # Checks for connection error and prints the error.
        except requests.ConnectionError as error:
            print(error)
            return None
    
        if r.headers.get('set-cookie') is not None:
            #print(r.headers.get('set-cookie'))
            match = re.findall("TNS_SESSIONID=[^,]*", r.headers.get('set-cookie'))
            #print(match)
            self.cookie = match[1]
            print(f'Using SessionID: {self.cookie}')

        # Checks the data for a JSON response.  Returns none if no data exists.
        try:
            jsondata = r.json()
        except ValueError as e:
            print(e)
            return None

        # Throws an error message if the error code is not 0.
        if jsondata['error_code'] != 0:
            sys.exit(jsondata['error_msg'])

        # Returns the 'response' section of the JSON data.
        return jsondata['response']
