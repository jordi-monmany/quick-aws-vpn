# Quick AWS VPN

A Bash script for automated deployment and management of AWS Client VPN endpoints with an integrated NAT gateway to the public Internet. Quick AWS VPN streamlines the process of setting up VPN connections to AWS environments without the need to launch any EC2 instances.

## Description

**Quick AWS VPN** automates the complex process of setting up and managing AWS Client VPN endpoints, handling everything from VPC creation to certificate management and OpenVPN client configuration. It creates a complete VPN infrastructure with proper networking configuration, including VPCs, subnets, internet gateways, NAT gateways, and all necessary route tables and permissions. The only main requirement is having a working AWS CLI setup and an AWS account with sufficient permissions. 

This tool is designed to enable an on-premises host to reach the Internet through an AWS gateway, providing a convenient VPN solution. It includes integrated PKI certificate management with authentication and encryption for easy VPN connections.

Although highly automated a robust knowledge on networking and AWS functioning is required to understand the financial costs and security implications derived from the actions performed by the program. Due to the high cost of running the AWS resources instantiated by the program its use should be limited to short lived, sporadic, low volume data transfer connections.

### Disclaimer

This program is in an **alpha version**. It is incomplete and may contain bugs. The software is provided **AS IS** without any warranty of any kind, either expressed or implied. You assume all risks associated with the use of the software. Only deployment to testing environments shall be considered. This software is proprietary and no license rights are granted. Execution of this program is not authorized without prior written consent from the author. Users must understand the associated risks and ensure compliance with their security requirements before deployment. The author shall not be liable for any damages or financial losses arising from the use of this program. More information is provided in ensuing sections of this document.

## Key Features

- **Automated AWS VPN Infrastructure Creation**: Quickly set up all necessary AWS resources, including VPC, subnets, internet gateway, NAT gateway, permissions and route tables.
- **Integrated PKI Certificate Management**: Automatically generate and register the required certificates for VPN authentication or provide your own.
- **NAT Gateway Configuration**: Enable internet access through a NAT gateway on a purpose-built AWS VPC without launching any EC2 instances.
- **Secure VPN Endpoint Deployment**: Deploy AWS Client VPN endpoints with ease.
- **OpenVPN Client Configuration Generation**: Generate all necessary client configuration files for easy setup and optionally install them.
- **Comprehensive Resource Cleanup**: Streamline the termination and clean up of all associated AWS resources when they are no longer needed.
- **State Management**: Persist and manage the state of VPN deployments for easy tracking and management.
- **Detailed Logging and Resource Tracking**: Maintain logs of all operations and track AWS resources associated with the VPN.

## Requirements

- **Bash Shell Environment**: The script is written for the Bash shell version 4.3 or later.
- **AWS CLI**: Installed and configured with appropriate credentials and permissions for VPC, Client VPN, networking, security and certificate management.
- **OpenSSL**: For PKI certificate generation and management.
- **jq**: A lightweight and flexible command-line JSON processor.
- **OpenVPN Client Software**: For connecting to the VPN endpoint.
- **uuidgen**: For generating unique identifiers.

## Installation

1. **Clone the Repository**

   Clone the repository to your local machine:

   ```bash
   git clone https://github.com/yourusername/quick-aws-vpn.git
   ```

2. **Navigate to the Directory**

   ```bash
   cd quick-aws-vpn
   ```

3. **Ensure Dependencies are Installed**

   Make sure you have the required tools ("bash >= 4.3" "aws" "openssl" "jq" "uuidgen" "readlink") installed on your system. If not, install them using your package manager.

4. **Make the Script Executable**

   ```bash
   chmod u+x quick-aws-vpn.sh
   ```

## Usage

```bash
./quick-aws-vpn.sh [options] <action>
```

### Options

| Option | Description |
|--------|-------------|
| `-h` | Show help message. |
| `-v` | Increment verbosity level; one level for each -v present in the arguments; can be used up to three times (`-vvv`). |
| `-q` | Suppress non-essential output. |
| `-f` | Skip all safety confirmation checks and automatically answer yes to all questions. |
| `-d VALUE` | Specify working directory (default: current directory). |
| `-p VALUE` | Specify PKI directory where sensitive cryptographic authentication files (`root-ca.pem`, `vpn-server.key`, `vpn-server.crt`, `vpn-client.key`, and `vpn-client.crt`) will be picked from or automatically created if missing (default: `<working directory>/pki`). |
| `-r VALUE` | Specify AWS region. |

### Actions

| Action | Description |
|--------|-------------|
| `create` | Create a new AWS VPN, including all necessary remote resources (VPCs, subnets, gateways, PKI files). |
| `install` | Install OpenVPN configuration and authentication files for the current VPN to `/etc/openvpn/client/`. |
| `terminate` | Terminate all AWS resources associated with the persisted VPN remotely. |
| `purge` | Archive the current VPN state file and remove all local files. |
| `exists` | Check if a persisted VPN exists in the specified working directory. |
| `info` | Display main properties of the persisted VPN (ID, status, region, VPC, etc.). |
| `history` | Show chronological logs of operations performed on the persisted VPN. |
| `sync` | Overwrite the local properties for all tracked AWS resources associated to the persisted VPN with their remote values. |
| `remote-resources` | List remote search results for the main AWS resources associated with the persisted VPN. |
| `region-remote-resources` | List remote search results for the main AWS resources created by this program in the selected region. |
| `trace-region-remote-resources` | List remote search results for the main AWS resources created by this program in the selected region with their tagging information. |
### Examples

- **Create a New VPN**

  ```bash
  ./quick-aws-vpn.sh create
  ```

  This command will initiate the creation of a new VPN, setting up all required AWS resources and generating PKI certificates if they do not exist.

- **Create a New VPN on a specific region**

  ```bash
  ./quick-aws-vpn.sh -r us-east-1 create
  ```

  This command will initiate the creation of a new VPN on "us-east-1" AWS region, setting up all required AWS resources and generating PKI certificates if they do not exist.

- **Install VPN Client Files**

  ```bash
  sudo ./quick-aws-vpn.sh install
  ```

  This action installs the OpenVPN client configuration and certificates to your system's OpenVPN directory, allowing you to connect to the VPN.

- **Display VPN Information**

  ```bash
  ./quick-aws-vpn.sh info
  ```

  Displays key information about the VPN, such as its status, region, and associated AWS resources.

- **Show Operation History**

  ```bash
  ./quick-aws-vpn.sh history
  ```

  Provides a chronological log of all operations performed on the VPN.

- **List Remote AWS Resources**

  ```bash
  ./quick-aws-vpn.sh remote-resources
  ```

  Lists main AWS resources associated with the VPN using remote AWS calls.

- **Terminate the VPN**

  ```bash
  ./quick-aws-vpn.sh terminate
  ```

  Terminates all AWS resources previously created by the program and associated with the VPN to prevent incurring in additional costs.

- **Purge Local Files**

  ```bash
  ./quick-aws-vpn.sh purge
  ```

  Archives the VPN state file and removes all local work files related to the VPN.

- **List Remote AWS Resources in the specified region**

  ```bash
  ./quick-aws-vpn.sh -r us-east-1 region-remote-resources
  ```

  Lists main AWS resources created by the program on "us-east-1" AWS region using remote AWS calls.

## Important Notices

### Liability Disclaimer

This program is in an **alpha version**. It is incomplete and may contain bugs. The software is provided **AS IS** without any warranty of any kind, either expressed or implied. You assume all risks associated with the use of the software. Only deployment to testing environments shall be considered. The author shall not be liable for any damages or financial losses arising from the use of this program.


### AWS Cost Warning

**Warning:** This program may cause significant AWS related financial costs. Always ensure proper termination of resources when they are no longer needed, and manually verify their removal to avoid unexpected charges. Due to the high cost of running the AWS resources instantiated by the program its use should be limited to short lived, sporadic, low volume data transfer connections. You are responsible for estimating the expenses for the intended or unintended actions of the program and any AWS related financial costs incurred by the use of this program.

### Security Notice

The program generates, self-signs and handles **sensitive unencrypted cryptographic authentication files**. Users must understand the associated risks and ensure compliance with their security requirements before deployment. Handle all PKI files with care and store them securely.

## License and Usage Restrictions

---

**PROPRIETARY SOFTWARE - ALL RIGHTS RESERVED**

© 2024 Jordi Monmany Badia. All rights reserved.

This software is proprietary and confidential. No license rights are granted, and distribution is strictly prohibited. Execution of this program is not authorized without prior written consent from the author.

**Usage Restrictions:**

- **Unauthorized Use Prohibited**: You may not use, modify, copy, distribute, or make any other use of this software without prior written consent.
- **No Distribution**: Sharing this software in any form, including via public repositories or file-sharing platforms, is strictly prohibited.
- **No Modification**: You may not reverse engineer, decompile, or create derivative works based on this software.
- **Non-AI Training**: All the copyrighted material including the source code shall not be used to develop or train any artificial intelligence or machine learning models, or to create derivative works, without the prior written consent of the author.

---

## Licensing Inquiries

Interested parties wishing to obtain a license or authorization to use this program are encouraged to contact the author at the email address provided below.

---

**Contact Information**

- **Author**: Jordi Monmany Badia
- **Email**: [jmonmany@distributedsoft.net](mailto:jmonmany@distributedsoft.net)

---
