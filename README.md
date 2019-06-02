# Talos Blacklist Importer

## Summary

This is a script to import Cisco Talos's IP Blacklist into a Tag (Host Group) within Stealthwatch.  This will also optionally create a Custom Security Event (CSE) to alert on traffic to the blacklisted IPs.

## Requirements

1. Must have Python 3.x installed.
2. Install the required packages from the *requirements.txt* file.

    * You'll probably want to set up a virtual environment: [Python 'venv' Tutorial](https://docs.python.org/3/tutorial/venv.html)

    * ```pip install -r requirements.txt```
3. Must have API access to Stealthwatch.

## How To Run

1. Copy the *config.example.json* to *config.json*.
    * ```cp config.example.json config.json```
    * **Optional:** you can manually enter configuration data in the *config.json* file. The script will assume it needs to create a Tag (Host Group) and Custom Security Event, unless one is populated in the *config.json*.
3. Run the script with ```python TalosBlacklistImporter.py```

> If you didn't manually enter configuration data, you'll get prompted for the Stealthwatch IP/FQDN, Username, and Password. The script will store these credentials in the *config.json* file for future use. **This means you probably want to make the *config.json* file read-only. You probably will also want to create unique credentials for scripting/API purposes.**

The script will automatically try to determine your Stealthwatch Tenant ID, and store that in the *config.json* file as well.

The script will cache downloaded data from Talos for one hour to prevent creating too many requests. (You'll get greylisted if you make too many requests for the URL)
