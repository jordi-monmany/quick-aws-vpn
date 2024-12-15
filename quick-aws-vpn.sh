#!/bin/bash

# Copyright (c) Jordi Monmany Badia
# All rights reserved. This software is proprietary and confidential.
# It may not be used, modified, or distributed without the express written consent of Jordi Monmany Badia.

# Check if the Bash version is 4.3 or higher
if [ "${BASH_VERSINFO[0]}" -lt 4 ] || ([ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 3 ]); then
    echo "This script requires Bash version 4.3 or higher."
    exit 1
fi

set -euo pipefail

# Enable debug mode (uncomment if needed)
# set -x

# Script info
SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_NAME
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
readonly SCRIPT_DIR
SCRIPT_VERSION="0.1.0-alpha"
readonly SCRIPT_VERSION
SCRIPT_STATE_VERSION="0.1.2"
readonly SCRIPT_STATE_VERSION
SCRIPT_AUTHOR="jmonmany@distributedsoft.net"
readonly SCRIPT_AUTHOR
SCRIPT_CREATED="2024-11-25"
SCRIPT_REQUIRED=("aws" "openssl" "jq" "uuidgen" "readlink" "date" "sudo")
readonly SCRIPT_CREATED
SCRIPT_DESCRIPTION="Script for quickly creating, installing and managing AWS VPNs with a NAT gateway to the public Internet without requiring EC2 instances"
readonly SCRIPT_DESCRIPTION
SCRIPT_WARNING="This program is provided AS IS with ABSOLUTELY NO WARRANTY. No license rights are granted, and distribution is strictly prohibited. Execution of this program is not authorized without prior written consent from the author. This program is an Alpha Version. It is incomplete, may contain bugs and may cause significant financial losses if used without proper supervision, particularly during the creation and termination of AWS resources. To obtain the necessary license rights, including authorization to execute the program, or for further information, please contact the author."
readonly SCRIPT_WARNING
MAX_VERBOSITY=3
readonly MAX_VERBOSITY
SCRIPT_USAGE=$(
    cat <<EOF
Usage: $SCRIPT_NAME [options] <action>

Options:
    -h       Show this help message
    -v       Increment verbosity level, one level for each -v present in the arguments can be used up to three times ('-vvv')
    -q       Suppress non-essential output
    -f       Skip all safety confirmation checks and automatically answer yes to all questions
    -d VALUE Specify working directory (default: current directory)
    -p VALUE Specify PKI directory where sensitive cryptographic authentication files ('root-ca.pem', 'vpn-server.key', 'vpn-server.crt', 'vpn-client.key' and 'vpn-client.crt') will be picked from or automatically created if missing; (default: <working directory>/pki)
    -r VALUE Specify AWS region

Actions:
    create                         Create a new AWS VPN, including all necessary remote resources (VPCs, subnets, gateways, PKI files)
    install                        Install OpenVPN configuration and authentication files for the current VPN to '/etc/openvpn/client/'
    terminate                      Terminate all AWS resources associated with the persisted VPN remotely
    purge                          Archive the current VPN state file and remove all local files
    exists                         Check if a persisted VPN exists in the specified working directory
    info                           Display main properties of the persisted VPN (ID, status, region, VPC, etc.)
    history                        Show chronological logs of operations performed on the persisted VPN
    sync                           Overwrite the local properties for all tracked AWS resources associated to the persisted VPN with their remote values
    remote-resources               List remote search results for the main AWS resources associated with the persisted VPN
    region-remote-resources        List remote search results for the main AWS resources created by this program in the selected region
    trace-region-remote-resources  List remote search results for the main AWS resources created by this program in the selected region with their tagging information
EOF
)
readonly SCRIPT_USAGE
SCRIPT_HELP=$(
    cat <<EOF
$SCRIPT_NAME version $SCRIPT_VERSION
Copyright (C) 2024 by $SCRIPT_AUTHOR

$SCRIPT_WARNING

$SCRIPT_DESCRIPTION

$SCRIPT_USAGE
EOF
)
readonly SCRIPT_HELP

# This lines can only be invalidated after obtaining written consent form the author 
echo "${SCRIPT_WARNING}" # This line can only be invalidated after obtaining written consent form the author 
exit 1 # This line can only be invalidated after obtaining written consent form the author 

# Configuration and state management
program_id="quick-aws-vpn"
verbosity=0
program_out=/dev/stdout
verbose_1_out=/dev/null
verbose_2_out=/dev/null
verbose_3_out=/dev/null
interactive_out=/dev/stderr
diagnostic_out=/dev/stderr
progress_out=/dev/stdout
continuous_progress_out=/dev/stderr
error_out=/dev/stderr
warning_out=/dev/stderr
quiet=0
force=0
region=
region_opt=
work_dir="./${program_id}"
default_pki_dir=
pki_dir=
econf_dir=
state_dir=
archive_state_dir=
current_state_file=
valid_user_actions=("create" "install" "terminate" "purge" "exists" "info" "history" "sync" "remote-resources" "region-remote-resources" "trace-region-remote-resources")
action=
declare -a action_args
tag_prefix="${program_id//-/_}"
install_files_name_prefix="${program_id}"
declare -a aws_command_opts
declare -a exit_warning_messages

# Utility function to prepend an item ($2) to an array ($1)
prepend_to_array() {
    local -n arr=$1 # Use nameref for the array
    local new_item=$2
    arr=("$new_item" "${arr[@]}")
}

# Print function
io_print_program() { printf '%b\n' "$*" >$program_out; }
io_print_program_abating() { if [ "${quiet}" == "0" ]; then printf '%b\n' "$*" >$program_out; fi; }
io_print_error() { printf '%b\n' "$*" >$error_out; }
io_print_warning() { printf '%b\n' "$*" >$warning_out; }
io_print_diagnostic() { if [ "${quiet}" == "0" ]; then printf '%b\n' "$*" >$diagnostic_out; fi; }
io_print_interactive() { printf '%b\n' "$*" >$interactive_out; }
io_print_header() { io_print_program_abating "$@"; }
io_print_progress() { if [ "${quiet}" == "0" ]; then printf '%b\n' "$*" >$progress_out; fi; }
io_print_continuous_progress() { if [ "${quiet}" == "0" ]; then printf '%b\n' "$*" >$continuous_progress_out; fi; }
# io_print_continuous_progress() { if [ "${quiet}" == "0" ]; then printf '\033[0;33m''%b\n''\033[0m' "$*" >$continuous_progress_out; fi; }
io_print_waiting_progress() { shift && io_print_continuous_progress "$@"; }

# Log functions
log_error() { printf '[ERROR] %b\n' "$*" >$error_out; }
log_info() { if [[ "${verbosity}" -gt 2 ]]; then printf '[INFO] %b\n' "$*" >$error_out; fi; }
log_debug() { if [[ "${verbosity}" -gt 3 ]]; then printf '[DEBUG] %b\n' "$*" >$error_out; fi; }

# Output help information
print_help() {
    io_print_program "$SCRIPT_HELP"
}

# Output usage information
print_usage() {
    io_print_diagnostic "$SCRIPT_USAGE"
    io_print_diagnostic "\n${SCRIPT_WARNING}"
}

# Cleanup functions
cleanup() {
    local exit_code=$?
    exit_warning_message_buff=
    for exit_warning_message in "${exit_warning_messages[@]}"; do
        if [ -z "$exit_warning_message" ]; then continue; fi
        # If this is the first message append it and go to the next message
        if [ -z "$exit_warning_message_buff" ]; then
            exit_warning_message_buff="${exit_warning_message}"
            continue
        fi
        # If the message begins with a new line and append a white space if not
        if [[ "$exit_warning_message" =~ ^$'\n' ]]; then
            exit_warning_message_buff="${exit_warning_message_buff}${exit_warning_message}"
        else
            exit_warning_message_buff="${exit_warning_message_buff} ${exit_warning_message}"
        fi
    done
    if [ -n "$exit_warning_message_buff" ]; then io_print_warning "${exit_warning_message_buff}"; fi
    if [ "$exit_code" != "0" ]; then io_print_error "${BASH_SOURCE[0]}: lines ${BASH_LINENO[*]} with status $exit_code"; fi
    # Add cleanup tasks here
    log_debug "Performing cleanup..."
    trap - EXIT
    exit $exit_code
}

# Set trap for cleanup
trap 'cleanup' EXIT

# Check if all required dependencies are available
missing_deps=()
for required_cmd in "${SCRIPT_REQUIRED[@]}"; do
    if ! command -v "$required_cmd" >/dev/null 2>&1; then
        missing_deps+=("$required_cmd")
    fi
done

# If any dependencies are missing, print error and exit
if [ ${#missing_deps[@]} -ne 0 ]; then
    io_print_error "Error: Missing required dependencies: ${missing_deps[*]}"
    exit 1
fi

# Parse options
while getopts ":hvqfd:pr:" opt; do
    case $opt in
    h)
        action="help"
        ;;
    v)
        if [ $verbosity -lt $MAX_VERBOSITY ]; then
            verbosity=$((verbosity + 1))
        fi
        ;;
    q)
        quiet=1
        ;;
    f)
        force=1
        ;;
    d)
        if ! [ -z "${OPTARG}" ]; then
            work_dir="$OPTARG"
        fi
        ;;
    p)
        if ! [ -z "${OPTARG}" ]; then
            pki_dir="$OPTARG"
        fi
        ;;
    r)
        if ! [ -z "${OPTARG}" ]; then
            region_opt="$OPTARG"
        fi
        ;;
    \?)
        io_print_error "Invalid option: -$OPTARG"
        exit 1
        ;;
    :)
        io_print_error "Option -$OPTARG requires an argument."
        exit 1
        ;;
    esac
done

if [ $verbosity -ge 1 ]; then
    quiet=0
    verbose_1_out=/dev/stdout
fi
if [ $verbosity -ge 2 ]; then
    verbose_2_out=/dev/stdout
fi
if [ $verbosity -ge 3 ]; then
    verbose_3_out=/dev/stdout
fi
log_info "Verbosity set to: $verbosity"

if [ -n "$region_opt" ]; then
    region="$region_opt"
    log_info "Region set to region option value: ${region_opt}"
fi

# Shift arguments past parsed options
shift $((OPTIND - 1))
log_debug "Arguments pending to process: $*"

# Parse for the action unless it is already set
if [ -z "$action" ] && [ $# -gt 0 ]; then
    # Extract action and remaining arguments
    for valid_action in "${valid_user_actions[@]}"; do
        if [[ $valid_action == "$1" ]]; then
            action="$1"
            shift
            action_args=("$@")
            break
        fi
    done
fi

if [ -z "$action" ]; then
    io_print_error "Error: <action> is required."
    print_usage
    exit 1
fi

main() {
    log_info "Starting script execution for action: ${action}..."
    case "$action" in
    help)
        print_help
        ;;
    create)
        create_vpn
        ;;
    install)
        install_vpn_client_files
        ;;
    terminate)
        terminate_vpn
        ;;
    purge)
        purge_vpn
        ;;
    exists)
        print_vpn_exists_check
        ;;
    info)
        print_vpn_info
        ;;
    history)
        print_vpn_logs
        ;;
    sync)
        sync_vpn
        ;;
    remote-resources)
        list_vpn_resources
        ;;
    region-remote-resources)
        list_region_resources
        ;;
    trace-region-remote-resources)
        trace_region_resources
        ;;
    *)
        io_print_error "No action performed."
        exit 1
        ;;
    esac
    log_info "Script execution completed successfully"
}

# Common init routine for actions that require storage and VPN state support
setup() {
    # Set state derived from options
    work_dir="$(realpath -m "$work_dir")"
    default_pki_dir="${work_dir}/pki"
    if [ -z "$pki_dir" ]; then
        pki_dir="${default_pki_dir}"
    else
        pki_dir="$(realpath -m "$pki_dir")"
    fi
    econf_dir="${work_dir}/econf"
    state_dir="${work_dir}/state"
    archive_state_dir="${work_dir}/astate"

    if ! [ -d "${work_dir}" ]; then
        mkdir "${work_dir}"
    fi
    if ! [ -d "${pki_dir}" ]; then
        mkdir "${pki_dir}"
        chmod 700 "${pki_dir}"
    fi
    if ! [ -d "${econf_dir}" ]; then
        mkdir "${econf_dir}"
        chmod 700 "${econf_dir}"
    fi
    if [[ ! -d "${state_dir}" ]]; then
        mkdir "${state_dir}"
        chmod 700 "${state_dir}"
    fi
    if [[ ! -d "${archive_state_dir}" ]]; then
        mkdir "${archive_state_dir}"
        chmod 700 "${archive_state_dir}"
    fi

    script_state_version="$SCRIPT_STATE_VERSION"
    script_version="$SCRIPT_VERSION"
    uuid=""
    creation_epoch=""
    modification_epoch=""
    status=""
    availability_zone=""
    vpc_id=""
    vpc_status=""
    public_subnet_id=""
    public_subnet_status=""
    private_subnet_id=""
    private_subnet_status=""
    internet_gateway_id=""
    internet_gateway_status=""
    nat_gateway_id=""
    nat_gateway_status=""
    allocation_id=""
    allocation_status=""
    public_routetable_id=""
    public_routetable_status=""
    private_routetable_id=""
    private_routetable_status=""
    public_routetable_association_id=""
    public_routetable_association_status=""
    private_routetable_association_id=""
    private_routetable_association_status=""
    server_cert_arn=""
    server_cert_status=""
    client_vpn_endpoint_id=""
    client_vpn_endpoint_status=""
    target_network_association_id=""
    target_network_association_status=""
    endpoint_private_ingress_authorization_status=""
    endpoint_private_default_route_status=""
    security_group_id=""
    security_group_status=""
    declare -a state_logs=()
}

# Set filesystem location for the VPN persisted state
resolve_state_file() {
    current_state_file="${state_dir}/vpn-state.json"
}

# Persist relevant information on the VPN and its associated AWS resources
save_state() {
    # Create state JSON with all relevant variables
    cat >"$current_state_file" <<EOF
{
    "script_state_version": "${SCRIPT_STATE_VERSION}",
    "script_version": "${SCRIPT_VERSION}",
    "uuid": "${uuid}",
    "creation_epoch": "${creation_epoch}",
    "modification_epoch": "$(date +%s)",
    "status": "${status}",
    "region": "${region}",
    "availability_zone": "${availability_zone}",
    "vpc_id": "${vpc_id}",
    "vpc_status": "${vpc_status}",
    "public_subnet_id": "${public_subnet_id}",
    "public_subnet_status": "${public_subnet_status}",
    "private_subnet_id": "${private_subnet_id}",
    "private_subnet_status": "${private_subnet_status}",
    "internet_gateway_id": "${internet_gateway_id}",
    "internet_gateway_status": "${internet_gateway_status}",
    "nat_gateway_id": "${nat_gateway_id}",
    "nat_gateway_status": "${nat_gateway_status}",
    "allocation_id": "${allocation_id}",
    "allocation_status": "${allocation_status}",
    "public_routetable_id": "${public_routetable_id}",
    "public_routetable_status": "${public_routetable_status}",
    "private_routetable_id": "${private_routetable_id}",
    "private_routetable_status": "${private_routetable_status}",
    "public_routetable_association_id": "${public_routetable_association_id}",
    "public_routetable_association_status": "${public_routetable_association_status}",
    "private_routetable_association_id": "${private_routetable_association_id}",
    "private_routetable_association_status": "${private_routetable_association_status}",
    "server_cert_arn": "${server_cert_arn}",
    "server_cert_status": "${server_cert_status}",
    "client_vpn_endpoint_id": "${client_vpn_endpoint_id}",
    "client_vpn_endpoint_status": "${client_vpn_endpoint_status}",
    "target_network_association_id": "${target_network_association_id}",
    "target_network_association_status": "${target_network_association_status}",
    "endpoint_private_ingress_authorization_status": "${endpoint_private_ingress_authorization_status}",
    "endpoint_private_default_route_status": "${endpoint_private_default_route_status}",
    "security_group_id": "${security_group_id}",
    "security_group_status": "${security_group_status}",
    "logs": $(jq -c -n '$ARGS.positional' --args "${state_logs[@]}")
}
EOF
    chmod -c 600 "$current_state_file" >$verbose_2_out
    log_debug "State saved to: '${current_state_file}'"
}

# Load information on the VPN and its associated AWS resources
load_state() {
    resolve_state_file
    if [ ! -f "$current_state_file" ]; then
        io_print_error "Error: No state file found at '${current_state_file}'"
        exit 1
    fi

    # Load variables from JSON using jq
    script_state_version=$(jq -r '.script_state_version' "$current_state_file")
    script_version=$(jq -r '.script_version' "$current_state_file")
    uuid=$(jq -r '.uuid' "$current_state_file")
    creation_epoch=$(jq -r '.creation_epoch' "$current_state_file")
    modification_epoch=$(jq -r '.modification_epoch' "$current_state_file")
    status=$(jq -r '.status' "$current_state_file")
    region=$(jq -r '.region' "$current_state_file")
    availability_zone=$(jq -r '.availability_zone' "$current_state_file")
    vpc_id=$(jq -r '.vpc_id' "$current_state_file")
    vpc_status=$(jq -r '.vpc_status' "$current_state_file")
    public_subnet_id=$(jq -r '.public_subnet_id' "$current_state_file")
    public_subnet_status=$(jq -r '.public_subnet_status' "$current_state_file")
    private_subnet_id=$(jq -r '.private_subnet_id' "$current_state_file")
    private_subnet_status=$(jq -r '.private_subnet_status' "$current_state_file")
    internet_gateway_id=$(jq -r '.internet_gateway_id' "$current_state_file")
    internet_gateway_status=$(jq -r '.internet_gateway_status' "$current_state_file")
    nat_gateway_id=$(jq -r '.nat_gateway_id' "$current_state_file")
    nat_gateway_status=$(jq -r '.nat_gateway_status' "$current_state_file")
    allocation_id=$(jq -r '.allocation_id' "$current_state_file")
    allocation_status=$(jq -r '.allocation_status' "$current_state_file")
    public_routetable_id=$(jq -r '.public_routetable_id' "$current_state_file")
    public_routetable_status=$(jq -r '.public_routetable_status' "$current_state_file")
    private_routetable_id=$(jq -r '.private_routetable_id' "$current_state_file")
    private_routetable_status=$(jq -r '.private_routetable_status' "$current_state_file")
    public_routetable_association_id=$(jq -r '.public_routetable_association_id' "$current_state_file")
    public_routetable_association_status=$(jq -r '.public_routetable_association_status' "$current_state_file")
    private_routetable_association_id=$(jq -r '.private_routetable_association_id' "$current_state_file")
    private_routetable_association_status=$(jq -r '.private_routetable_association_status' "$current_state_file")
    server_cert_arn=$(jq -r '.server_cert_arn' "$current_state_file")
    server_cert_status=$(jq -r '.server_cert_status' "$current_state_file")
    client_vpn_endpoint_id=$(jq -r '.client_vpn_endpoint_id' "$current_state_file")
    client_vpn_endpoint_status=$(jq -r '.client_vpn_endpoint_status' "$current_state_file")
    target_network_association_id=$(jq -r '.target_network_association_id' "$current_state_file")
    target_network_association_status=$(jq -r '.target_network_association_status' "$current_state_file")
    endpoint_private_ingress_authorization_status=$(jq -r '.endpoint_private_ingress_authorization_status' "$current_state_file")
    endpoint_private_default_route_status=$(jq -r '.endpoint_private_default_route_status' "$current_state_file")
    security_group_id=$(jq -r '.security_group_id' "$current_state_file")
    security_group_status=$(jq -r '.security_group_status' "$current_state_file")
    readarray -t state_logs < <(jq -r '.logs[]' "$current_state_file")
    # log_debug "Loaded state logs: ${state_logs[*]}"

    log_info "State loaded from: '${current_state_file}' created by version $script_state_version"
}

# Add message to state logs and save the state
update_state() {
    update_message="$1"
    if [ -n "${update_message}" ]; then
        io_print_progress "${update_message}"
        state_logs+=("[$(date +%s)] ${update_message}")
    fi
    save_state
}

# Set AWS CLI command options dependent on the state and option arguments
resolve_aws_command_ops() {
    aws_command_opts=()
    if [ -n "$region" ]; then
        aws_command_opts+=("--region" "$region")
    fi
}

# Print message from argument '$1' then ask for yes/no confirmation and exit the program if input is not equal to 'yes'
perform_user_confirmation() {
    if [ $force -lt 1 ]; then
        io_print_interactive "$1"
        io_print_interactive "Do you want to proceed with the operation? (yes/no)"
        read -r response

        # Check the user's input
        if [ "$response" != "yes" ]; then
            io_print_program "Operation cancelled by user"
            exit
        fi
    fi
}

resolve_certs_cns() {
    cert_cn_domain="${program_id}.local"
    root_cert_cn="rootca.aws.${cert_cn_domain}"
    server_cert_cn="server.aws.${cert_cn_domain}"
    client_cert_cn="client.aws.${cert_cn_domain}"
}

# Create an AWS VPN including all the necessary remote resources
create_vpn() {
    setup
    resolve_aws_command_ops

    perform_user_confirmation "The next operation will remotly create multiple AWS resources that will incur significant costs if left running."
    perform_user_confirmation "The next operation may generate, self-sign, store and upload sensitive, unprotected cryptographic authentication files. Proceed only if you fully understand the associated risks and confirm that they align with your security requirements."

    uuid=$(uuidgen)
    creation_epoch=$(date +%s)

    resolve_state_file

    if [ -f "$current_state_file" ]; then
        io_print_error "Error: State file already exists at '${current_state_file}'"
        return 1
    fi

    exit_warning_messages+=("WARNING: The operation did not complete successfully. The application state and output may be undefined. Please, terminate the VPN and manually verify the removal of AWS resources and any sensitive files to prevent potential issues. Afterwards you may run 'sync' and 'terminate' as an additional check.")

    status="creating"
    update_state "Started creation of AWS VPN '${uuid}'"

    if [ -z "$region" ]; then
        region="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-availability-zones --query 'AvailabilityZones[0].[RegionName] | [0]' | jq -r)"
    fi
    availability_zone="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-availability-zones --query 'AvailabilityZones[0].[ZoneName] | [0]' | jq -r)"

    exit_warning_messages+=("Multiple AWS resources have been created, which will incur significant costs if left running. Please, ensure that you understand the associated costs. Terminate the resources when they are no longer needed, and manually verify their removal to avoid unexpected charges.")
    exit_warning_messages+=("Sensitive, unprotected cryptographic authentication files remain in '${pki_dir}' that may be needed by the 'install' action or for manual placement in the appropriate OpenVPN configuration locations. Please, ensure you understand the associated risks and take the necessary actions for compliance with your security requirements.")

    resolve_certs_cns
    if [ ! -f "${pki_dir}/root-ca.key" ] && [ ! -f "${pki_dir}/root-ca.srl" ] && [ ! -f "${pki_dir}/root-ca.pem" ] && [ ! -f "${pki_dir}/vpn-server.key" ] && [ ! -f "${pki_dir}/vpn-server.crt" ] && [ ! -f "${pki_dir}/vpn-server.csr" ] && [ ! -f "${pki_dir}/vpn-client.key" ] && [ ! -f "${pki_dir}/vpn-client.crt" ] && [ ! -f "${pki_dir}/vpn-client.csr" ]; then
        openssl genrsa -out "${pki_dir}/root-ca.key" 2048 >$verbose_1_out
        openssl req -x509 -new -nodes -key "${pki_dir}/root-ca.key" -sha256 -days 1024 -out "${pki_dir}/root-ca.pem" -subj "/CN=${root_cert_cn}" >$verbose_1_out
        openssl genrsa -out "${pki_dir}/vpn-server.key" 2048 >$verbose_1_out
        openssl req -new -key "${pki_dir}/vpn-server.key" -out "${pki_dir}/vpn-server.csr" -subj "/CN=${server_cert_cn}" -addext "keyUsage = digitalSignature, keyEncipherment" -addext "extendedKeyUsage = serverAuth" >$verbose_1_out
        openssl x509 -req -in "${pki_dir}/vpn-server.csr" -CA "${pki_dir}/root-ca.pem" -CAkey "${pki_dir}/root-ca.key" -CAcreateserial -out "${pki_dir}/vpn-server.crt" -days 500 -sha256 -copy_extensions copy >$verbose_1_out
        openssl x509 -in "${pki_dir}/vpn-server.crt" -text -noout | grep -A 1 "Key Usage" >$verbose_2_out
        openssl genrsa -out "${pki_dir}/vpn-client.key" 2048 >$verbose_1_out
        openssl req -new -key "${pki_dir}/vpn-client.key" -out "${pki_dir}/vpn-client.csr" -subj "/CN=${client_cert_cn}" -addext "keyUsage = digitalSignature" -addext "extendedKeyUsage = clientAuth" >$verbose_1_out
        openssl x509 -req -in "${pki_dir}/vpn-client.csr" -CA "${pki_dir}/root-ca.pem" -CAkey "${pki_dir}/root-ca.key" -CAcreateserial -out "${pki_dir}/vpn-client.crt" -days 500 -sha256 -copy_extensions copy >$verbose_1_out
        openssl x509 -in "${pki_dir}/vpn-client.crt" -text -noout | grep -A 1 "Key Usage" >$verbose_2_out
        update_state "Local PKI files created in: '${pki_dir}'"
    else
        update_state "Local PKI files found in: '${pki_dir}'"
    fi
    server_cert_arn="$(aws --no-cli-pager "${aws_command_opts[@]}" acm import-certificate --certificate "fileb://${pki_dir}/vpn-server.crt" --private-key "fileb://${pki_dir}/vpn-server.key" --certificate-chain "fileb://${pki_dir}/root-ca.pem" --tags Key=${tag_prefix}_Uuid,Value="//${uuid}/" Key=${tag_prefix}_Purpose,Value="//vpn/" --query "CertificateArn" | jq -r)"
    server_cert_status="created"
    update_state "Resource created: server_cert_arn='${server_cert_arn}'"
    aws --no-cli-pager "${aws_command_opts[@]}" acm list-certificates --query "CertificateSummaryList[?DomainName==\`${server_cert_cn}\`].CertificateArn" >$verbose_1_out
    #aws --no-cli-pager "${aws_command_opts[@]}" acm import-certificate --certificate "fileb://${pki_dir}/root-ca.pem" --tags "[{Key=${tag_prefix}_Uuid,Value=//${uuid}/},{Key=${tag_prefix}_Purpose,Value=//vpn/}]"

    vpc_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications "ResourceType=vpc,Tags=[{Key=${tag_prefix}_Uuid,Value=//${uuid}/},{Key=${tag_prefix}_Purpose,Value=//vpn/}]" --query 'Vpc.VpcId' | jq -r)"
    vpc_status="created"
    update_state "Resource created: vpc_id='${vpc_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-vpcs --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" >$verbose_1_out

    public_subnet_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-subnet --vpc-id "${vpc_id}" --cidr-block 10.0.1.0/24 --availability-zone "${availability_zone}" --tag-specifications "ResourceType=subnet,Tags=[{Key=${tag_prefix}_Uuid,Value=//${uuid}/},{Key=${tag_prefix}_Purpose,Value=//vpn/},{Key=${tag_prefix}_Purpose1,Value=//public/}]" --query 'Subnet.SubnetId' | jq -r)"
    public_subnet_status="created"
    update_state "Resource created: public_subnet_id='${public_subnet_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-subnets --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//public/" >$verbose_1_out

    private_subnet_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-subnet --vpc-id "${vpc_id}" --cidr-block 10.0.2.0/24 --availability-zone "${availability_zone}" --tag-specifications "ResourceType=subnet,Tags=[{Key=${tag_prefix}_Uuid,Value=//${uuid}/},{Key=${tag_prefix}_Purpose,Value=//vpn/},{Key=${tag_prefix}_Purpose1,Value=//private/}]" --query 'Subnet.SubnetId' | jq -r)"
    private_subnet_status="created"
    update_state "Resource created: private_subnet_id='${private_subnet_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-subnets --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//private/" >$verbose_1_out

    internet_gateway_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-internet-gateway --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=${tag_prefix}_Uuid,Value=//${uuid}/},{Key=${tag_prefix}_Purpose,Value=//vpn/}]" --query 'InternetGateway.InternetGatewayId' | jq -r)"
    internet_gateway_status="created"
    update_state "Resource created: internet_gateway_id='${internet_gateway_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-internet-gateways --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" >$verbose_1_out

    aws --no-cli-pager "${aws_command_opts[@]}" ec2 attach-internet-gateway --vpc-id "${vpc_id}" --internet-gateway-id "${internet_gateway_id}" >$verbose_1_out

    public_routetable_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-route-table --vpc-id "${vpc_id}" --tag-specifications "ResourceType=route-table,Tags=[{Key=${tag_prefix}_Uuid,Value=//${uuid}/},{Key=${tag_prefix}_Purpose,Value=//vpn/},{Key=${tag_prefix}_Purpose1,Value=//public/}]" --query 'RouteTable.RouteTableId' | jq -r)"
    public_routetable_status="created"
    update_state "Resource created: public_routetable_id='${public_routetable_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-route-tables --filters Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//public/" >$verbose_1_out

    private_routetable_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-route-table --vpc-id "${vpc_id}" --tag-specifications "ResourceType=route-table,Tags=[{Key=${tag_prefix}_Uuid,Value=//${uuid}/},{Key=${tag_prefix}_Purpose,Value=//vpn/},{Key=${tag_prefix}_Purpose1,Value=//private/}]" --query 'RouteTable.RouteTableId' | jq -r)"
    private_routetable_status="created"
    update_state "Resource created: private_routetable_id='${private_routetable_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-route-tables --filters Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//private/" >$verbose_1_out

    aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-route --route-table-id "${public_routetable_id}" --destination-cidr-block 0.0.0.0/0 --gateway-id "${internet_gateway_id}" >$verbose_1_out

    public_routetable_association_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 associate-route-table --route-table-id "${public_routetable_id}" --subnet-id "${public_subnet_id}" --query 'AssociationId' | jq -r)"
    public_routetable_association_status="created"
    update_state "Resource created: public_routetable_association_id='${public_routetable_association_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-route-tables --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//public/" --query 'RouteTables[*].Associations' >$verbose_1_out

    allocation_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 allocate-address --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=${tag_prefix}_Uuid,Value=//${uuid}/},{Key=${tag_prefix}_Purpose,Value=//vpn/}]" --query 'AllocationId' | jq -r)"
    allocation_status="created"
    update_state "Resource created: allocation_id='${allocation_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-addresses --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" >$verbose_1_out

    nat_gateway_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-nat-gateway --subnet-id "${public_subnet_id}" --allocation-id "${allocation_id}" --tag-specifications "ResourceType=natgateway,Tags=[{Key=${tag_prefix}_Uuid,Value=//${uuid}/},{Key=${tag_prefix}_Purpose,Value=//vpn/}]" --query 'NatGateway.NatGatewayId' | jq -r)"
    nat_gateway_status="created"
    update_state "Resource created: nat_gateway_id='${nat_gateway_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-nat-gateways --filter Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" >$verbose_1_out
    wait_i=0
    until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-nat-gateways --nat-gateway-ids "${nat_gateway_id}" --query 'NatGateways[*].State | [0]' | jq -r) = "available" ]]; do
        io_print_waiting_progress $wait_i "Waiting for Nat GateWay creation to complete."
        wait_i=$((wait_i + 1))
        sleep 2
    done

    aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-route --route-table-id "${private_routetable_id}" --destination-cidr-block 0.0.0.0/0 --gateway-id "${nat_gateway_id}" >$verbose_1_out

    private_routetable_association_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 associate-route-table --route-table-id "${private_routetable_id}" --subnet-id "${private_subnet_id}" --query 'AssociationId' | jq -r)"
    private_routetable_association_status="created"
    update_state "Resource created: private_routetable_association_id='${private_routetable_association_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-route-tables --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//private/" --query 'RouteTables[*].Associations' >$verbose_1_out
    wait_i=0
    until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-route-tables --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//private/" --query 'RouteTables[*].Associations[0].AssociationState.State | [0]' | jq -r) = "associated" ]]; do
        io_print_waiting_progress $wait_i "Waiting for Client Vpn Target Network Association to complete."
        wait_i=$((wait_i + 1))
        sleep 2
    done

    client_vpn_endpoint_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-client-vpn-endpoint --client-cidr-block 10.10.0.0/22 --server-certificate-arn "${server_cert_arn}" --authentication-options "Type=certificate-authentication,MutualAuthentication={ClientRootCertificateChainArn=${server_cert_arn}}" --connection-log-options 'Enabled=false' --dns-servers 10.10.0.2 --transport-protocol udp --vpc-id "${vpc_id}" --description "VPN" --tag-specifications "ResourceType=client-vpn-endpoint,Tags=[{Key=${tag_prefix}_Uuid,Value=//${uuid}/},{Key=${tag_prefix}_Purpose,Value=//vpn/}]" --query 'ClientVpnEndpointId' | jq -r)"
    client_vpn_endpoint_status="created"
    update_state "Resource created: client_vpn_endpoint_id='${client_vpn_endpoint_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-endpoints --filter Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" >$verbose_1_out
    wait_i=0
    until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-endpoints --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --query 'ClientVpnEndpoints[*].Status.Code | [0]' | jq -r) = "pending-associate" ]]; do
        io_print_waiting_progress $wait_i "Waiting for Client Vpn Endpoint creation to complete."
        wait_i=$((wait_i + 1))
        sleep 2
    done

    target_network_association_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 associate-client-vpn-target-network --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --subnet-id "${private_subnet_id}" --query 'AssociationId' | jq -r)"
    target_network_association_status="created"
    update_state "Resource created: target_network_association_id='${target_network_association_id}'"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-target-networks --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --filter Name=target-network-id,Values="${private_subnet_id}" >$verbose_1_out
    wait_i=0
    until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-target-networks --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --association-id "${target_network_association_id}" --query 'ClientVpnTargetNetworks[*].Status.Code | [0]' | jq -r) = "associated" ]]; do
        io_print_waiting_progress $wait_i "Waiting for Client Vpn Target Network association to complete."
        wait_i=$((wait_i + 1))
        sleep 2
    done

    aws --no-cli-pager "${aws_command_opts[@]}" ec2 authorize-client-vpn-ingress --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --target-network-cidr 10.0.0.0/16 --authorize-all-groups >$verbose_1_out
    endpoint_private_ingress_authorization_status="created"
    update_state "Resource created: Client Vpn Ingress Rule authorization completed"
    wait_i=0
    until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-authorization-rules --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --filters Name=destination-cidr,Values="10.0.0.0/16" --query 'AuthorizationRules[*].Status.Code | [0]' | jq -r) = "active" ]]; do
        io_print_waiting_progress $wait_i "Waiting for Client Vpn Ingress Rule authorization to complete."
        wait_i=$((wait_i + 1))
        sleep 2
    done

    aws --no-cli-pager "${aws_command_opts[@]}" ec2 authorize-client-vpn-ingress --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --target-network-cidr 0.0.0.0/0 --authorize-all-groups >$verbose_1_out
    wait_i=0
    until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-authorization-rules --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --filters Name=destination-cidr,Values="0.0.0.0/0" --query 'AuthorizationRules[*].Status.Code | [0]' | jq -r) = "active" ]]; do
        io_print_waiting_progress $wait_i "Waiting for Internet Ingress Rule authorization to complete."
        wait_i=$((wait_i + 1))
        sleep 2
    done

    aws --no-cli-pager "${aws_command_opts[@]}" ec2 create-client-vpn-route --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --destination-cidr-block 0.0.0.0/0 --target-vpc-subnet-id "${private_subnet_id}" >$verbose_1_out
    endpoint_private_default_route_status="created"
    update_state "Resource created: Client Vpn Route createion completed"
    aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-routes --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --filters Name=destination-cidr,Values="0.0.0.0/0" >$verbose_1_out
    wait_i=0
    until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-routes --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --filters Name=destination-cidr,Values="0.0.0.0/0" --query 'Routes[*].Status.Code | [0]' | jq -r) = "active" ]]; do
        io_print_waiting_progress $wait_i "Waiting for Client Vpn Route createion to complete."
        wait_i=$((wait_i + 1))
        sleep 2
    done


    security_group_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-security-groups --filters "Name=vpc-id,Values=${vpc_id}" --query 'SecurityGroups[*].GroupId | [0]' | jq -r)"
    security_group_status="inherited"
    update_state "Resource inherited: security_group_id='${security_group_id}'"

    aws --no-cli-pager "${aws_command_opts[@]}" ec2 export-client-vpn-client-configuration --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --output text >"${econf_dir}/client.ovpn"
    cat <<EOF >>"${econf_dir}/client.ovpn"
ca /etc/openvpn/pki/${install_files_name_prefix}-client-root-ca.pem
cert /etc/openvpn/pki/${install_files_name_prefix}-client.crt
key /etc/openvpn/pki/${install_files_name_prefix}-client.key
EOF
    update_state "Local OpenVPN config file created at: '${econf_dir}/client.ovpn'"

    status="active"
    update_state "Completed creation of AWS VPN successfully"
    unset exit_warning_messages[0]
}

# Install OpenVPN configuration and sensitive cryptographic authentication files
install_vpn_client_files() {
    setup
    load_state

    perform_user_confirmation "The next operation will install OpenVPN configuration and sensitive, unprotected cryptographic authentication files for the current VPN at '/etc/openvpn/client/'."

    io_print_progress "Started installation of AWS VPN '${uuid}' OpenVPN config and PKI files"

    exit_warning_messages+=("WARNING: The operation did not complete successfully. The application state and output may be undefined. Please, manually verify the results and possibly try executing the operation again.")
    exit_warning_messages+=("Sensitive, unprotected cryptographic authentication files remain in '${pki_dir}'. Some of these files have been copied to '/etc/openvpn/pki/' and these may be needed by OpenVPN. Please, ensure you understand the associated risks and take the necessary actions for compliance with your security requirements.")

    # verbosity_flags=( "-v" )
    # if [ "$quiet" == "1" ]; then verbosity_flags=(); fi
    sudo mkdir -v -p /etc/openvpn/pki >$verbose_1_out
    sudo cp -v "${pki_dir}/root-ca.pem" "/etc/openvpn/pki/${install_files_name_prefix}-client-root-ca.pem" >$verbose_1_out
    sudo cp -v "${pki_dir}/vpn-client.crt" "/etc/openvpn/pki/${install_files_name_prefix}-client.crt" >$verbose_1_out
    sudo cp -v "${pki_dir}/vpn-client.key" "/etc/openvpn/pki/${install_files_name_prefix}-client.key" >$verbose_1_out
    sudo chmod -v 600 "/etc/openvpn/pki/${install_files_name_prefix}-client.key" >$verbose_1_out
    sudo chown -v root:root "/etc/openvpn/pki/${install_files_name_prefix}-client.key" >$verbose_1_out
    sudo cp -v "${econf_dir}/client.ovpn" "/etc/openvpn/client/${install_files_name_prefix}-client.conf" >$verbose_1_out

    unset exit_warning_messages[0]
    io_print_progress "Completed installation of AWS VPN OpenVPN config and PKI files successfully"
    io_print_progress "Issue 'sudo systemctl start openvpn-client@${install_files_name_prefix}-client.service' to start the client"
}

# Terminate the AWS resources associated to the persisted VPN remotley
terminate_vpn() {
    setup
    load_state
    resolve_aws_command_ops

    perform_user_confirmation "The next operation will permanently remove all AWS resources associated to the current VPN and created by ${program_id}. All services dependent on the current VPN and its resources will stop working."

    exit_warning_messages+=("WARNING: The operation did not complete successfully. The application state and output may be undefined. You may run 'sync' and 'terminate' again as an additional check after performing the necessary manual interventions.")
    exit_warning_messages+=("Please, manually verify that all unneeded AWS resources have been properly terminated and manually remove those still active to avoid unnecessary charges.")

    status="terminating"
    update_state "Started termination of AWS VPN '${uuid}'"


    if [ "${endpoint_private_default_route_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 delete-client-vpn-route --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --destination-cidr-block 0.0.0.0/0 --target-vpc-subnet-id "${private_subnet_id}" >$verbose_1_out
        wait_i=0
        until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-routes --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --filters Name=destination-cidr,Values="0.0.0.0/0" --query 'Routes[*].Status.Code | [0]' | jq -r) = "null" ]]; do
            io_print_waiting_progress $wait_i "Waiting for Client Vpn Route deletion to complete."
            wait_i=$((wait_i + 1))
            sleep 2
        done
        endpoint_private_default_route_status="terminated"
        update_state "Resource terminated: Client VPN Route deletion completed"
    fi
    if [ "${endpoint_private_ingress_authorization_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 revoke-client-vpn-ingress --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --target-network-cidr 10.0.0.0/16 --revoke-all-groups >$verbose_1_out
        wait_i=0
        until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-authorization-rules --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --filters Name=destination-cidr,Values="10.0.0.0/16" --query 'AuthorizationRules[*].Status.Code | [0]' | jq -r) = "null" ]]; do
            io_print_waiting_progress $wait_i "Waiting for Client Vpn Ingress Rule revokation to complete."
            wait_i=$((wait_i + 1))
            sleep 2
        done
        endpoint_private_ingress_authorization_status="terminated"
        update_state "Resource terminated: Client Vpn Ingress Rule deletion completed"
    fi
    if [ "${target_network_association_status}" == "created" ] && [ "${client_vpn_endpoint_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 disassociate-client-vpn-target-network --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --association-id "${target_network_association_id}" >$verbose_1_out
        wait_i=0
        until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-target-networks --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --association-id "${target_network_association_id}" --query 'ClientVpnTargetNetworks[*].Status.Code | [0]' | jq -r) = "null" ]]; do
            io_print_waiting_progress $wait_i "Waiting for Client Vpn Target Network disassociation to complete."
            wait_i=$((wait_i + 1))
            sleep 2
        done
        target_network_association_status="terminated"
        update_state "Resource terminated: target_network_association_id='${target_network_association_id}'"
    fi
    if [ "${client_vpn_endpoint_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 delete-client-vpn-endpoint --client-vpn-endpoint-id "${client_vpn_endpoint_id}" >$verbose_1_out
        wait_i=0
        until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-endpoints --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --query 'ClientVpnEndPoints[*].Status.Code | [0]' 2>/dev/null | jq -r) = "null" ]] || [[ -z $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-endpoints --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --query 'ClientVpnEndPoints[*].Status.Code | [0]' 2>/dev/null | jq -r) ]]; do
            io_print_waiting_progress $wait_i "Waiting for Client Vpn Endpoint deletion to complete."
            wait_i=$((wait_i + 1))
            sleep 2
        done
        client_vpn_endpoint_status="terminated"
        update_state "Resource terminated: client_vpn_endpoint_id='${client_vpn_endpoint_id}'"
    fi
    if [ "${server_cert_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" acm delete-certificate --certificate-arn "${server_cert_arn}" >$verbose_1_out
        server_cert_status="terminated"
        update_state "Resource terminated: server_cert_arn='${server_cert_arn}'"
    fi
    if [ "${private_routetable_association_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 disassociate-route-table --association-id "${private_routetable_association_id}" >$verbose_1_out
        private_routetable_association_status="terminated"
        update_state "Resource terminated: private_routetable_association_id='${private_routetable_association_id}'"
    fi
    if [ "${nat_gateway_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 delete-nat-gateway --nat-gateway-id "${nat_gateway_id}" >$verbose_1_out
        wait_i=0
        until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-nat-gateways --nat-gateway-ids "${nat_gateway_id}" --query 'NatGateways[*].State | [0]' | jq -r) = "deleted" ]]; do
            io_print_waiting_progress $wait_i "Waiting for Nat GateWay deletion to complete."
            wait_i=$((wait_i + 1))
            sleep 2
        done
        nat_gateway_status="terminated"
        update_state "Resource terminated: nat_gateway_id='${nat_gateway_id}'"
    fi
    if [ "${allocation_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 release-address --allocation-id "${allocation_id}" >$verbose_1_out
        allocation_status="terminated"
        update_state "Resource terminated: allocation_id='${allocation_id}'"
    fi
    if [ "${public_routetable_association_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 disassociate-route-table --association-id "${public_routetable_association_id}" >$verbose_1_out
        public_routetable_association_status="terminated"
        update_state "Resource terminated: public_routetable_association_id='${public_routetable_association_id}'"
    fi
    if [ "${public_routetable_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 delete-route-table --route-table-id "${public_routetable_id}" >$verbose_1_out
        public_routetable_status="terminated"
        update_state "Resource terminated: public_routetable_id='${public_routetable_id}'"
    fi
    if [ "${private_routetable_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 delete-route-table --route-table-id "${private_routetable_id}" >$verbose_1_out
        private_routetable_status="terminated"
        update_state "Resource terminated: private_routetable_id='${private_routetable_id}'"
    fi
    if [ "${internet_gateway_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 detach-internet-gateway --internet-gateway-id "${internet_gateway_id}" --vpc-id "${vpc_id}" >$verbose_1_out
        #wait_i=0 ; until [[ $(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-internet-gateways --internet-gateway-ids ${AWSVPN_INTERNETGATEWAY_ID} --query 'InternetGateways[*].Attachments[*].State | [0]' | jq -r) = "detached" ] ; do io_print_periodic_progress "Waiting for Internet GateWay detach to complete." ; wait_i=$((wait_i+1)) ; sleep 2 ; done
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 delete-internet-gateway --internet-gateway-id "${internet_gateway_id}" >$verbose_1_out
        internet_gateway_status="terminated"
        update_state "Resource terminated: internet_gateway_id='${internet_gateway_id}'"
    fi
    if [ "${public_subnet_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 delete-subnet --subnet-id "${public_subnet_id}" >$verbose_1_out
        public_subnet_status="terminated"
        update_state "Resource terminated: public_subnet_id='${public_subnet_id}'"
    fi
    if [ "${private_subnet_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 delete-subnet --subnet-id "${private_subnet_id}" >$verbose_1_out
        private_subnet_status="terminated"
        update_state "Resource terminated: private_subnet_id='${private_subnet_id}'"
    fi
    if [ "${vpc_status}" == "created" ]; then
        aws --no-cli-pager "${aws_command_opts[@]}" ec2 delete-vpc --vpc-id "${vpc_id}" >$verbose_1_out
        vpc_status="terminated"
        update_state "Resource terminated: vpc_id='${vpc_id}'"
    fi

    status="terminated"
    update_state "Completed termination of AWS VPN successfully"
    unset exit_warning_messages[0]
}

# Remove associated filesystem resources to the persisted VPN on the working directory and archive the VPN state file
purge_vpn() {
    setup
    load_state

    if [ "$status" != "terminated" ]; then
        io_print_error "Can not purge the VPN from storage if it has not been properly terminated"
        exit 1
    fi

    io_print_progress "Started purgation of AWS VPN '${uuid}'"

    perform_user_confirmation "The next operation will archive the current vpn state file and permanently remove all the files inside '${state_dir}', '${default_pki_dir}' and '${econf_dir}'"

    exit_warning_messages+=("WARNING: The operation did not complete successfully. The application state and output may be undefined. Please, try executing the operation again and then manually ensure the removal of local resources and any sensitive files.")

    if [ -f "$current_state_file" ]; then
        mv -vf "$current_state_file" "${archive_state_dir:?}/vpn-state-${uuid}.json" >$verbose_1_out
        io_print_program_abating "Archived state file: '${current_state_file}' to: '${archive_state_dir:?}/vpn-state-${uuid}.json'"
    fi

    rm -vf "${default_pki_dir:?}/root-ca."{key,pem,srl} >$verbose_1_out
    rm -vf "${default_pki_dir:?}/vpn-server."{key,crt,csr} >$verbose_1_out
    rm -vf "${default_pki_dir:?}/vpn-client."{key,crt,csr} >$verbose_1_out
    io_print_program_abating "Removed PKI directory files: '${pki_dir}'"

    if [ -f "${econf_dir:?}/client.ovpn" ]; then rm -vf "${econf_dir:?}/client.ovpn" >$verbose_1_out; fi
    io_print_program_abating "Removed external configuration directory files: '${econf_dir}'"

    unset exit_warning_messages[0]
    io_print_progress "Completed purgation of AWS VPN successfully"
}

# List main AWS resources associated to the persisted VPN remotely
list_vpn_resources() {
    if [ -n "$region_opt" ]; then
        io_print_error "Error: Region option is not compatible with this action"
        exit 1
    fi
    setup
    load_state
    resolve_aws_command_ops
    io_print_header "ARNs of existing or recently deleted AWS resources associated to AWS VPN '${uuid}':"
    aws --no-cli-pager "${aws_command_opts[@]}" resourcegroupstaggingapi get-resources --tag-filters Key=${tag_prefix}_Uuid,Values="//${uuid}/" --query 'ResourceTagMappingList[*].ResourceARN' | jq -r '.[]'
}

# Overwrite the persisted ID property ($1) with the specified value ($2) after validation and overwrite the status property ($3) if the persisted value is invalid
sync_property() {
    local -n resource_id="$1"
    r_resource_id_value=$2
    local -n resource_status="$3"
    log_debug "sync_property: ${1}: ${resource_id} > ${r_resource_id_value} | status: ${resource_status}"
    if [ -n "$r_resource_id_value" ] && [ "$r_resource_id_value" != "null" ]; then
        p_resource_id_value=$resource_id
        if [ "$r_resource_id_value" != "$p_resource_id_value" ]; then
            resource_id="$r_resource_id_value"
            update_state "ID updated: ${1}='${p_resource_id_value}' > ${1}='${r_resource_id_value}'"
        fi
    fi
    if [ -z "$resource_status" ] || [ "$resource_status" == "null" ]; then
        p_resource_status_value="$resource_status"
        resource_status="created"
        update_state "Status updated: ${3}='${p_resource_status_value}' > ${3}='created'"
    fi
}

# Overwrite the persisted properties for all tracked AWS resources associated to the persisted VPN with their remote values
sync_vpn() {
    setup
    load_state
    resolve_aws_command_ops

    perform_user_confirmation "The next operation will overwrite the persisted properties for all tracked AWS resources associated to the current VPN with the remote values provided by AWS."

    exit_warning_messages+=("WARNING: The operation did not complete successfully. The application state may be undefined. Please, try executing the operation again and then manually ensure the correctness of the state data.")

    update_state "Started syncing of AWS VPN '${uuid}'"

    resolve_certs_cns

    local r_server_cert_arn="$(aws --no-cli-pager "${aws_command_opts[@]}" acm list-certificates --query "CertificateSummaryList[?DomainName==\`${server_cert_cn}\`].CertificateArn | [0]" | jq -r)"
    sync_property "server_cert_arn" "$r_server_cert_arn" "server_cert_status"
    local r_vpc_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-vpcs --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" --query 'Vpcs[*].VpcId | [0]' | jq -r)"
    sync_property "vpc_id" "$r_vpc_id" "vpc_status"
    local r_public_subnet_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-subnets --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//public/" --query 'Subnets[*].SubnetId | [0]' | jq -r)"
    sync_property "public_subnet_id" "$r_public_subnet_id" "public_subnet_status"
    local r_private_subnet_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-subnets --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//private/" --query 'Subnets[*].SubnetId | [0]' | jq -r)"
    sync_property "private_subnet_id" "$r_private_subnet_id" "private_subnet_status"
    local r_internet_gateway_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-internet-gateways --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" --query 'InternetGateways[*].InternetGatewayId | [0]' | jq -r)"
    sync_property "internet_gateway_id" "$r_internet_gateway_id" "internet_gateway_status"
    local r_public_routetable_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-route-tables --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//public/" --query 'RouteTables[*].RouteTableId | [0]' | jq -r)"
    sync_property "public_routetable_id" "$r_public_routetable_id" "public_routetable_status"
    local r_private_routetable_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-route-tables --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//private/" --query 'RouteTables[*].RouteTableId | [0]' | jq -r)"
    sync_property "private_routetable_id" "$r_private_routetable_id" "private_routetable_status"
    local r_public_routetable_association_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-route-tables --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//public/" --query 'RouteTables[*].Associations[0].RouteTableAssociationId | [0]' | jq -r)"
    sync_property "public_routetable_association_id" "$r_public_routetable_association_id" "public_routetable_association_status"
    local r_allocation_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-addresses --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" --query 'Addresses[*].AllocationId | [0]' | jq -r)"
    sync_property "allocation_id" "$r_allocation_id" "allocation_status"
    local r_nat_gateway_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-nat-gateways --filter Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" --query 'NatGateways[?State!=`deleted`].NatGatewayId | [0]' | jq -r)"
    sync_property "nat_gateway_id" "$r_nat_gateway_id" "nat_gateway_status"
    local r_private_routetable_association_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-route-tables --filters Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" Name=tag:${tag_prefix}_Purpose1,Values="//private/" --query 'RouteTables[*].Associations[0].RouteTableAssociationId | [0]' | jq -r)"
    sync_property "private_routetable_association_id" "$r_private_routetable_association_id" "private_routetable_association_status"
    local r_client_vpn_endpoint_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-endpoints --filter Name=tag:${tag_prefix}_Uuid,Values="//${uuid}/" Name=tag:${tag_prefix}_Purpose,Values="//vpn/" --query 'ClientVpnEndpoints[*].ClientVpnEndpointId | [0]' | jq -r)"
    sync_property "client_vpn_endpoint_id" "$r_client_vpn_endpoint_id" "client_vpn_endpoint_status"
    local r_target_network_association_id="$(aws --no-cli-pager "${aws_command_opts[@]}" ec2 describe-client-vpn-target-networks --client-vpn-endpoint-id "${client_vpn_endpoint_id}" --filter Name=target-network-id,Values="${private_subnet_id}" --query 'ClientVpnTargetNetworks[*].AssociationId | [0]' | jq -r)"
    sync_property "target_network_association_id" "$r_target_network_association_id" "target_network_association_status"

    update_state "Completed syncing of AWS VPN successfully"
    unset exit_warning_messages[0]
}

# List main AWS resources created by this program on the selected region remotely
list_region_resources() {
    resolve_aws_command_ops
    io_print_header "ARNs of existing or recently deleted AWS resources created by ${program_id} in the selected region:"
    aws --no-cli-pager "${aws_command_opts[@]}" resourcegroupstaggingapi get-resources --tag-filters Key=${tag_prefix}_Purpose,Values="//vpn/" --query 'ResourceTagMappingList[*].ResourceARN' | jq -r '.[]'
}

# List main AWS resources created by this program on the selected region remotely with their tagging information included
trace_region_resources() {
    io_print_header "Existing or recently deleted AWS resources created by ${program_id} in the selected region:"
    resolve_aws_command_ops
    aws --no-cli-pager "${aws_command_opts[@]}" resourcegroupstaggingapi get-resources --tag-filters Key=${tag_prefix}_Purpose,Values="//vpn/" --query 'ResourceTagMappingList[*]' | jq -r '.[]'
}

# Output logs for the persisted VPN
print_vpn_logs() {
    setup
    load_state
    io_print_header "History of AWS VPN '${uuid}':"
    for state_log in "${state_logs[@]}"; do
        if [[ "$state_log" =~ \[([0-9]+)\]\ *(.*) ]]; then
            epoch="${BASH_REMATCH[1]}"   # The captured group for the epoch (inside brackets)
            message="${BASH_REMATCH[2]}" # The captured group for the rest of the message

            # Convert the UNIX epoch to a readable date and time
            human_readable_date=$(date -d "@$epoch")

            # Display the result
            io_print_program "[${human_readable_date}] $message"
        else
            io_print_error "Invalid Format: ${state_log}"
            exit 1
        fi
    done
}

# Output main properties of the persisted VPN
print_vpn_info() {
    setup
    load_state
    io_print_header "Info for AWS VPN '${uuid}':"
    io_print_program "UUID: ${uuid}"
    io_print_program "State Version: ${script_state_version}"
    io_print_program "Script Version: ${script_version}"
    io_print_program "Status: ${status}"
    io_print_program "Region: ${region}"
    io_print_program "Availability Zone: ${availability_zone}"
    io_print_program "VPC ID: ${vpc_id}"
    io_print_program "VPC Status: ${vpc_status}"
    io_print_program "VPN Client Endpoint ID: ${client_vpn_endpoint_id}"
    io_print_program "VPN Client Endpoint Status: ${client_vpn_endpoint_status}"
    io_print_program "Internet Gateway ID: ${internet_gateway_id}"
    io_print_program "Internet Gateway Status: ${internet_gateway_status}"
    io_print_program "Server Certificate ARN: ${server_cert_arn}"
    io_print_program "Server Certificate Status: ${server_cert_status}"
    io_print_program "Creation Date: $(date -d "@$creation_epoch")"
    io_print_program "Last Modification Date: $(date -d "@$modification_epoch")"
}

# Output check result for persisted VPN presence in the specified working directory
print_vpn_exists_check() {
    setup
    io_print_header "Check for persisted AWS VPN:"
    resolve_state_file
    if [ -f "$current_state_file" ]; then
        io_print_program "A persisted VPN was found"
    else
        io_print_program "No persisted VPN was found"
    fi
}


main
