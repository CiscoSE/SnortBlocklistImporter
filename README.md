# Stealthwatch Enterprise: Snort Block list Importer

[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/CiscoSE/SnortBlock_listImporter)

## Summary

This is a script to import Snort's Sample IP Block list into a Tag (Host Group) within Stealthwatch Enterprise. This will also optionally create a Custom Security Event (CSE) to alert on traffic to the block listed IPs.

You can find more information on Stealthwatch's APIs on [Cisco DevNet](https://developer.cisco.com/docs/stealthwatch/).

## Requirements

1. Python 3.x
2. Stealthwatch Enterprise 7.0 or higher
    - Updates files and documentation can be found in the Network Visibility and Segementation product category on [software.cisco.com](https://software.cisco.com/download/home/286307082)
3. Stealthwatch Enterprise user credentials with the "Master Admin" role assigned.
    - User roles are configured in the Stealthwatch web interface.  Simply navigate to *Global Settings -> User Management*.

## Configuration File

The ***config.json*** file contains the following variables:

- SNORT_BLOCK_LIST_URL: The URL for the Snort IP Block list. (String)
- SW_ADDRESS: The IP or FQDN of the Stealthwatch SMC. (String)
- SW_USERNAME: The Username to be used to authenticate to Stealthwatch. (String)
- SW_PASSWORD: The Password to be used to authenticate to Stealthwatch. (String)
- SW_TENANT_ID: The Stealthwatch Tenant (Domain) ID to be used. (Integer)
- SW_TAG_ID: The Tag (Host Group) ID for the block list IPs. (Integer)
- SW_CREATE_CSE: Whether a Custom Security Event should be created. (Boolean)
- SW_CSE_ID: The ID of the Custom Security Event. (Integer)

## How To Run

1. Prior to running the script for the first time, copy the ***config.example.json*** to ***config.json***.
    * ```cp config.example.json config.json```
    * **OPTIONAL:** You can manually enter configuration data in the ***config.json*** file if desired. By default, the script will assume it needs to create a Tag (Host Group) and Custom Security Event, unless IDs for each are populated in the ***config.json***.
2. Install the required packages from the ***requirements.txt*** file.
    * ```pip install -r requirements.txt```
    * You'll probably want to set up a virtual environment: [Python 'venv' Tutorial](https://docs.python.org/3/tutorial/venv.html)
    * Activate the Python virtual environment, if you created one.
3. Run the script with ```python snort_blocklist_importer.py```

> If you didn't manually enter configuration data, you'll get prompted for the Stealthwatch IP/FQDN, Username, and Password. The script will store these credentials in the ***config.json*** file for future use. **This means you probably want to make the ***config.json*** file read-only. You probably will also want to create unique credentials for scripting/API purposes.**

The script will automatically try to determine your Stealthwatch Tenant ID, and store that in the ***config.json*** file as well.

By default, the script will cache downloaded block list data from Snort for one hour to prevent creating too many requests. (You'll get greylisted if you make too many requests for the URL)

## Docker Container

This script is Docker friendly, and can be deployed as a container.

To build the container, run the script once to populate the ***config.json*** file, or manually populate the configuration variables.

Once the ***config.json*** file is populated, run the following command to build the container:

- ```docker build -t snort-block-list-importer .```

You can then run the container as a daemon with the following command:

- ```docker run -d --name snort-block-list-importer snort-block-list-importer```
