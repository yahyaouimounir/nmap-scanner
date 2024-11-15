============================================================================================================================================ 
#                                                     nmap-scanner web application
============================================================================================================================================ 

This project provides a Docker container running a web application that allows users to scan IP addresses or ranges using the Nmap network scanning tool. The web application provides an easy-to-use interface for initiating scans and viewing results directly in the browser.

# Instructions

## Docker Image Pull Instructions
To use this web application, you can pull the pre-built Docker image and run it on your machine. Follow the instructions below to get started.

## Pull the Docker image:

Run the following command to pull the Docker image from Docker Hub:

#                                           docker pull mouniryy/nmap-scanner:latest

## Run the Docker container:

After pulling the image, you can start the Docker container with the following command:

#                                          docker run -d --network host -p 5000:5000 --volume nmap-scanner:/app mouniryy/nmap-scanner:latest 

This command will run the container in detached mode (-d) and map port 5000 on your host machine to port 5000 inside the container, it also create a volume in the docker container, accessed by docker desktop, to store the saved output in .gradio/flagged/dataset1.csv.

## Access the Web Application:

Once the container is running, open your web browser and go to:

####                                          http://localhost:5000 

You should see the Nmap web interface, where you can input IP addresses and initiate network scans. 


# basic usage 
  ## IP Address:
Enter a single IP address (e.g., 192.168.0.1),or a CIDR notation (e.g., 192.168.0.1/24), or an IP range (e.g., 192.168.0.1-150, or 192.168.0.1-192.168.0.150).
The input will be parsed to support these formats, and the application will automatically detect and scan the specified range or address.

# Scan Type:
Choose the scan type from the dropdown:
    -TCP Connect Scan: A standard TCP scan.
    -TCP SYN Scan: A stealthy scan that attempts to establish a TCP connection.
    -UDP Scan: Scans for open UDP ports.
    -Ping Scan: Pings the hosts to check which ones are alive.
    -Aggressive Scan: Includes OS detection, service versions, and script scanning.
    -No Ping Scan: Disables host discovery, useful for targets that do not respond to ping.

# Port:
Specify the port or range of ports to scan (e.g., 80, 22, or 1-1024). If no port is specified, the default range 1-1024 will be used.
Enable OS Discovery:

# OS detection 
Check this box to enable OS detection. If enabled, Nmap will attempt to detect the operating system of the target machine based on network responses.

# Verbose Level:
Select the verbosity level:
None: No verbosity.
Verbose: Provides basic scan output details.
Verbose Level 2: Provides detailed output with extra scan information.


# Scan Results:

After initiating the scan, the results will be displayed in the Gradio interface, showing details like:
                -Scanned ports and services
                -Service versions (if detected)
                -OS detection (if enabled)
                -Traceroute results (for aggressive scan)
                -Nmap script scan results (for aggressive scan)



# Save Results to File:
After the scan completes, you can save the scan output to a text file within the Docker container.
## Steps to save output:
After the scan is complete, click on the flag button.
This file will be stored inside the Docker volume mounted in:
#                                   nmap-scanner/app/.gradio/flagged/dataset1.csv


### save the file in local machine: 
execute the command below to copy the file stored in docker to the local machine
#                               cp nmap-scanner/app/.gradio/flagged/dataset1.csv <./path/to/the/file>

