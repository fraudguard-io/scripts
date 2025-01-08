# FraudGuard.io Blacklist/Whitelist CLI Tool

The FraudGuard.io CLI tool allows you to interact with your custom blacklist and whitelist directly via the FraudGuard.io API. You can add, remove, and list IPs with ease, automating your IP management workflows.

## Features

- Add IPs: Add one or more IP addresses to the blacklist or whitelist.
- Remove IPs: Remove one or more IP addresses from the blacklist or whitelist.
- List IPs: Retrieve and view all IPs in the blacklist or whitelist.
- Handles Large Lists: Supports paginated requests for lists containing more than 1000 IPs.
- IPv4/IPv6 Support: Manage IPv4 and IPv6 addresses independently when adding, removing, or listing IPs.
- IP Validation: Skips invalid IP addresses (format) and warns the user.
- Pre-Check for Existence: Skips adding already-existing IPs and warns about non-existent IPs during removal.

## Prerequisites

1. Python 3:
   - Ensure Python 3 is installed on your system. You can check by running `python3 --version`.

2. Dependencies:
   - Install the `requests` library using `pip3 install requests`.

3. FraudGuard.io Credentials:
   - Obtain your API username and password from FraudGuard.io.
   - Create a configuration file at `~/.fraudguard-cli-config` with the following content:

```
USERNAME=your_api_key_username
PASSWORD=your_api_key_password
```

## Usage

### Add IPs
Add one or more IP addresses to the blacklist or whitelist.
- python3 fraudguard-cli.py add --list blacklist --ips 192.168.1.1 10.0.0.1
- python3 fraudguard-cli.py add --list whitelist --ips 192.168.1.1 10.0.0.1

### Remove IPs
Remove one or more IP addresses from the blacklist or whitelist.
- python3 fraudguard-cli.py remove --list blacklist --ips 192.168.1.1 10.0.0.1
- python3 fraudguard-cli.py remove --list whitelist --ips 192.168.1.1 10.0.0.1

### List IPs
Retrieve all IPs in the blacklist or whitelist.
- python3 fraudguard-cli.py list --list blacklist
- python3 fraudguard-cli.py list --list whitelist

## Notes

- The CLI supports paginated requests for large lists with more than 1000 IPs using the offset parameter.
- Ensure your credentials are correct and stored securely in the configuration file.

## FraudGuard.io API Documentation

Here are the links to the relevant API documentation:

- [POST to Custom Blacklist](https://docs.fraudguard.io/#post-to-custom-blacklist)
- [POST to Custom Whitelist](https://docs.fraudguard.io/#post-to-custom-whitelist)
- [DELETE from Custom Blacklist](https://docs.fraudguard.io/#delete-from-custom-blacklist)
- [DELETE from Custom Whitelist](https://docs.fraudguard.io/#delete-from-custom-whitelist)
- [GET Custom Blacklist](https://docs.fraudguard.io/#get-custom-blacklist)
- [GET Custom Whitelist](https://docs.fraudguard.io/#get-custom-whitelist)

## Support

For questions or assistance, contact FraudGuard.io at [hello@fraudguard.io](mailto:hello@fraudguard.io). 

---

Sign up for a **14-day free trial** and explore FraudGuard.io's features at [FraudGuard.io](https://fraudguard.io).