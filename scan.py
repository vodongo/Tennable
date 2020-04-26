from tennableApi import APIEndpoint
from urllib.request import urlopen


'''
The following methods allow for interaction into the Tenable.sc by directly connecting to Tennable API through Class SecuirtyCenter
'''

class Scan(APIEndpoint):


    def __init__(self, server, verify_ssl=False):

        super().__init__(server, verify_ssl=False)
        self.scanId = ''
        self.scanResultId = ''
        self.name = ''

    def create_scan(self,name,repoid,zoneid,policyid,credentialsid,IPlist):
        
        """
        Handles parsing the keywords and returns a scan definition document
        """

        print("Trying to create a scan document")

        scan_definition = {
            "name": name,
                "type" : "policy",
                "description" : "This is a test job. Adding scan via CB using API",
                "repository" : {
                    "id": repoid
                },
            "zone": {
                "id": zoneid
            },
            "policy":{
                "id": policyid
            },
            "dhcpTracking" : "true",
            "classifyMitigatedAge" : "0",
            "schedule":{
                "type":"template"
            },
            "reports" : [],
            "assets" : [],
            "credentials":
            [{
                "id": credentialsid,
                "name":"TI Security SSH",
                "description":"Updated 4\\11\\2019",
                "type":"ssh"
            }],
            "emailOnLaunch" : "False",
            "emailOnFinish" : "False",
            "timeoutAction" : "rollover",
            "scanningVirtualHosts" : "false",
            "rolloverType" : "template",
            "ipList" : IPlist,
            "maxScanTime" : "unlimited"
        } 

        Response = self.connect('POST', 'scan', scan_definition)
        self.scanId = Response['id']

        print(f'Scan created with a scanId: {self.scanId}')
        return self.scanId

    def launch(self):
        """Launch a scan with scanId
           return: scan result Id. This id is specific to the job referenced in the json as 'id'  not 'scanID'
        """
     
        Response = self.connect('POST', 'scan/{}/launch'.format(self.scanId))
        self.scanResultId = Response['scanResult']["id"]
        print(f'Launcing a scan with scanResultId: {self.scanResultId}')
        
        return self.scanResultId

    def status(self):

        """status
           Pass scanResultId for return when a launch was triggered
           checks status of scan based on status and importStatus parameters in Response json
           Loop through every 30 seconds until the scan in completed and the import is fnished 
        """
                
        while True:

            Response = self.connect('GET', 'scanResult/{}'.format(self.scanResultId))
            Status = Response["status"]
            ImportStatus = Response["importStatus"]

            if  Status =='Completed' and  ImportStatus == 'Finished':
                print (f'Scan {Status} and import {ImportStatus}')
                break
            if  Status == 'Running' or 'Pending' or 'Importing':
                print(f'Scan is {Status}\n Import status: {ImportStatus}')
                time.sleep(30)
      

    def email(self):
        email_dict = {"email": "victor.m.odongo@census.gov"}
        self.connect('POST', 'scanResult/{}/email'.format(self.scanResultId),email_dict)
        print("Email results sent")

    def download(self):

        jobID = 83460
    
        print(f'Downloading scan with ID: {jobID}')

        payload = {       
            'downloadType': 'v2',
           }

        self.connect('POST','scanResult/{}/download'.format(jobID), data=payload,stream=True)
        
   


if __name__ == '__main__':
    tennableInstance = Scan(server='')  
    tennableInstance.login(username="",password="")
    tennableInstance.create_scan(name ='',repoid='',zoneid='',policyid='',credentialsid='',IPlist='')
    tennableInstance.launch()
    tennableInstance.status()
    tennableInstance.download()
    tennableInstance.logout()
