import nvdlib
import pyxploitdb
from urllib.error import HTTPError
import ast

def search_cve_with_exploits(keyword):
    global cve_list, cves_with_exploits, cve_details
    cve_list = []
    cves_with_exploits = []
    cve_details = {}
    temp = []
    
    
    try:
        # Search for CVEs containing the specified keyword
        r = nvdlib.searchCVE(keywordSearch=keyword, limit=1)
        
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
                print(f"Score: {eachCVE.score}")
                

                temp.append(eachCVE.descriptions)
                x=temp[0][0]
                z = ''
                z += str(x)
                cve_description = ''
                cve_description += z[25:-2]
                print(cve_description)

                cve_details.update({"CVE ID" : eachCVE.id ,"Description" : cve_description , "Publish Date" : eachCVE.published , "NVD Link" : eachCVE.url , "Score" : eachCVE.score , "CWE" : eachCVE.cwe , "Refrences" : eachCVE.references , "CPE" : eachCVE.cpe })                                                 
                
                print("-" * 50)
    
    except HTTPError as e:
        print(f"Error retrieving CVEs: {e}")



def print_exploits_for_cve(cve_list):
    global exploits_just_details
    exploits_details_less =''
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
                exploits_just_details = (f"CVE ID: {cve}" + " \n " + f"Exploits: {exploit}")
                print(exploit)
            print("-" * 50)
    
    except HTTPError as e:
        print(f"Error printing exploits: {e}")






search_cve_with_exploits("Apache HTTP Server 2.4.50")

# Example usage: Printing exploits for CVEs with associated exploits
print_exploits_for_cve(cves_with_exploits)
