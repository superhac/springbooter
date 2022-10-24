# springbooter
An enumerator for Spring Boot Eureka and Actuator endpoints

<pre>
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

		  SpringBooter 1.0 / 2022 SuperHac
	An enumerator for Spring Boot Eureka and Actuator endpoints

usage: springbooter.py [OPTION] [FILE]...

An enumerator for Spring Boot Eureka and Actuator endpoints.

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -f [FILTER ...], --filter [FILTER ...]
                        Filter out certain properties from being unsanitized. A space seperated list. e.g. 
			--filter user.security aws.key
  -u URL, --url URL     A single base endpoint to be examined. ex. http://1.1.1.1:6767
  -l FILE, --file FILE  A list of endpoints to be examined. One base url per line. e.g. http://1.1.1.1:6767
  -n, --noheap          Skip downloading the heap file

</pre>

## Features
- Springbooter will grab instances from Eureka endpoints and automaticly add them for Spring Boot Actuator enumeration.
- Spring Boot Actuators 
  - Grab and Analyze endpoint responses looking for data leakage or Exploits
    - Automaticly attempt to unsanitize value(s) found at the /env endpoint
    - Look for exploits
    - Find interesting keys/value pairs.

## Usage
When SpringBooter is executed it will create a base directory, “sb_{UNIXTIMESTAP}” in the CWD.  In that directory it will create another directory named “endpoint-json”, where all the responses from the Spring Boot Actuator endpoints are stored. There will also be a file “alive-endpoints.json” created in the base directory that will contain all the enumerated data from the endpoints in the scan.

Your endpoints for scanning can either be a Eurkea endpoint or an actuator endpoint.  Springbooter will figure it out.

Enumerate a single endpoint:
```
python springbooter.py -u http://endpoint:7777
```

Enumerate a list of hosts from a file:
```
python springbooter.py -l 10.10.10.0-24-hosts.txt
```

Example hosts file:
```
http://10.10.10.1:7777/actuator # spring 2.0
http://10.10.10.2:7585 # spring 1.0
http://10.10.10.3 # Eurkea ... It will figure it out
```

## Example output
Console:
```
python springbooter.py --noheap -u http://10.10.10.10:4545

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

		  SpringBooter 1.0 / 2022 SuperHac
	An enumerator for Spring Boot Eureka and Actuator endpoints

Attempting to connect via Eureka => http://10.10.10.10:4545
  [-] Attempting to retireve JSON response => ttp://10.10.10.10:4545/eureka/apps
    [-] Did not get a JSON response.  Not an Eureka endpoint?
    [-] No Instances Found
    [+] Adding itself as a Spring Boot Actuator ep.
    Instance details:
      (NA)	App: Self - Eurkeka EP                        SBA: http://10.10.10.10:4545

Enumerating Spring Boot Actuator (SBA) Instances

  Fetching SBA @: http://10.10.10.10:4545/env
    [+] Recieved JSON Response.
    [-] Searching for sanitized keys & attempting to desanitize via some class getProperty operation
      [+] Found key [systemProperties -> sun.java.command]:
          Unsanitized value: searchindexingservice-1.1.12-SNAPSHOT.jar --environment=Test 
      [+] Found key [systemEnvironment -> AWS_CONTAINER_CREDENTIALS_RELATIVE_URI]:
          Unsanitized value: /v2/credentials/b5632b0e8-g6df-h5yd-644i-644ae679vcd5
    [+] Searching for indicators of exploit
    [+] JSON saved to(w/unsanitized): ./sb_1666615061.681958/endpoint-json/10.10.10.10-4545-env.json

  Fetching SBA @: http://10.10.10.10:4545/jolokia
    [+] Recieved JSON Response.
      [+] /jolokia found.
      [+] Since the jolokia endpoint responed if the ch.ops.logback.classic MBean is installed you can get RCE.  look at /jolokia/list for confirmation of the MBean.  Reference: https://www.veracode.com/blog/research/exploiting-spring-boot-actuators / Needs a better walkthrough.
    [+] JSON saved to: ./sb_1666615061.681958/endpoint-json/10.10.10.10-4545-jolokia.json
  Fetching SBA @: http://10.10.10.10:4545/jolokia/list
    [+] Recieved JSON Response.
      [+] jolokia/list found.
      [+] Found: ch.qos.logback.classic : The ch.qos.logback.classic MBean is installed which means it is susceptible RCE. Reference: https://www.veracode.com/blog/research/exploiting-spring-boot-actuators / Needs a better walkthrough.
    [+] JSON saved to: ./sb_1666615061.681958/endpoint-json/10.10.10.10-4545-jolokia-list.json

  Fetching SBA @: http://10.10.10.10:4545/trace
    [+] Recieved JSON Response.
      [+] /trace found.
      [+] Searching for interesting fields in /trace .
        [+] fields Found (only displays first found instance):  
        user-agent                python-urllib3/1.26.4
  [+] JSON output from collected instances saved to: ./sb_1666615061.681958/endpoint-json/10.10.10.10-4545-trace.json

  Fetching SBA @: http://10.10.10.10:4545/info
    [+] Recieved JSON Response.
      [+] /info found.
    [+] JSON saved to: ./sb_1666615061.681958/endpoint-json/10.10.10.10-4545-info.json

  Fetching SBA @: http://10.10.10.10:4545/beans
    [+] Recieved JSON Response.
      [+] /beans found.
    [+] JSON saved to: ./sb_1666615061.681958/endpoint-json/10.10.10.10-4545-beans.json

  Fetching SBA @: http://10.10.10.10:4545/mappings
    [+] Recieved JSON Response.
      [+] /mappings found.
    [+] JSON saved to: ./sb_1666615061.681958/endpoint-json/10.10.10.10-4545-mappings.json

  Fetching SBA @: http://10.10.10.10:4545/configprops
    [+] Recieved JSON Response.
      [+] /configprops found.
      [+] Searching for interesting fields in /configprops .
        [+] fields Found (only displays first found instance):  
        key                       None
        password                  None
        secret                    None
        masterToken             ******
        keyPattern                k.d
        clientsecret              ******
        proxyUserName             None
        AWS_CONTAINER_CREDENTIALS_RELATIVE_URI ******
        AWS_REGION                us-east-2
        AWS_EXECUTION_ENV         AWS_ECS_EC2
        AWS_ZONE                  us-east-2a
        user.dir                  /opt/nue844/masterservice
        user.home                 /root
        user.timezone             America/Los_Angeles
        user.name                 root
        user.language             en
        proxyPassword             None
        sessionedClientReconnectIntervalSeconds 1200
        sessions                  STATELESS
        authorizeMode             ROLE
        accountId                 111111111111111
    [+] JSON saved to: ./sb_1666615061.681958/endpoint-json/10.10.10.10-4545-configprops.json

```
alive-endpoints.json:

![image](https://user-images.githubusercontent.com/7942984/197537710-95aab233-990a-48a4-ac7d-2718fc967ea1.png)

