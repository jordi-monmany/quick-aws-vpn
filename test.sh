#!/bin/bash

### Created by Jordi Monmany Badia ( jordi-monmany ) on 2024-11-25

set -euo pipefail

# Colors
COLOR_OFF='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'

if ! [ -t 1 ]; then
COLOR_OFF=""
COLOR_RED=""
COLOR_GREEN=""
COLOR_YELLOW=""
fi

io_print_pass() { printf "${COLOR_GREEN}"'[PASS] %b'"${COLOR_OFF}"'\n' "$*"; }
io_print_fail() { printf "${COLOR_RED}"'[FAIL] %b'"${COLOR_OFF}"'\n' "$*"; }


play_alert_sound() {
    pactl upload-sample /usr/share/sounds/freedesktop/stereo/complete.oga test-alert && pactl play-sample test-alert
}

comprehensive_test() {
    echo "Comprehensive test started"
    region=$1
    quiet=$2
    force=$3
    sudo -B -v || exit
    mkdir -p ./test/customdir
    echo "Running: exists"
    exists0=$(./quick-aws-vpn.sh -q -d ./test/customdir exists)
    echo "$exists0"
    echo "Running: region-remote-resources"
    ./quick-aws-vpn.sh ${region} ${quiet} -d ./test/customdir region-remote-resources
    echo "Running: create"
    ./quick-aws-vpn.sh ${region} ${quiet} ${force} -d ./test/customdir create
    echo "Running: remote-resources"
    resources0=$(./quick-aws-vpn.sh -q -d ./test/customdir remote-resources)
    echo "$resources0"
    echo "Running: region-remote-resources"
    ./quick-aws-vpn.sh ${region} ${quiet} -d ./test/customdir region-remote-resources
    echo "Running: exists"
    exists1=$(./quick-aws-vpn.sh -q -d ./test/customdir exists)
    echo "$exists1"
    echo "Running: info"
    info0=$(./quick-aws-vpn.sh -q -d ./test/customdir info)
    echo "$info0"
    echo "Running: sync"
    sync0=$(./quick-aws-vpn.sh ${region} ${force} -q -d ./test/customdir sync)
    echo "$sync0"
    echo "Running: history"
    ./quick-aws-vpn.sh ${quiet} -d ./test/customdir history
    echo "Removing files in /etc/openvpn/"
    sudo -B rm -vf /etc/openvpn/client/quick-aws-vpn-client.conf
    sudo -B rm -vf /etc/openvpn/pki/*
    echo "Running: install"
    ./quick-aws-vpn.sh ${quiet} ${force} -d ./test/customdir install
    echo "Testing vpn connection"
    sudo -B systemctl start openvpn-client@quick-aws-vpn-client.service
    sleep 2
    ip_0=$(wget -q -O- 'http://ipecho.net/plain')
    echo "IP0: ${ip_0}"
    sudo -B systemctl stop openvpn-client@quick-aws-vpn-client.service
    sleep 1
    ip_1=$(wget -q -O- 'http://ipecho.net/plain')
    echo "IP1: ${ip_1}"
    echo "Running: terminate"
    ./quick-aws-vpn.sh ${quiet} ${force} -d ./test/customdir terminate
    echo "Running: remote-resources"
    ./quick-aws-vpn.sh ${quiet} -d ./test/customdir remote-resources
    echo "Running: info"
    info1=$(./quick-aws-vpn.sh -q -d ./test/customdir info)
    echo "$info1"
    echo "Running: history"
    ./quick-aws-vpn.sh ${quiet} -d ./test/customdir history
    echo "Running: purge"
    ./quick-aws-vpn.sh ${quiet} ${force} -d ./test/customdir purge
    echo "Running: exists"
    exists2=$(./quick-aws-vpn.sh -q -d ./test/customdir exists)
    echo "$exists2"
    # purge_test=0
    # [ ! -f "./test/customdir/state/vpn-state.json" ] || purge_test=1
    echo "Removing test data directory"
    rm -rf ./test/customdir
    echo "Running: region-remote-resources"
    ./quick-aws-vpn.sh ${region} ${quiet} -d ./test/customdir region-remote-resources
    if [ "$exists0" == "No persisted VPN was found" ]; then
        io_print_pass "Test for 1st exists action passed"
    else
        io_print_fail "Test for 1st exists action failed"
    fi
    if [ $(echo "$resources0" | wc -l) -eq 10 ]; then
        io_print_pass "Test for 1st remote-resources action passed"
    else
        io_print_fail "Test for 1st remote-resources action failed"
    fi
    if [ "$exists1" == "A persisted VPN was found" ]; then
        io_print_pass "Test for 2nd exists action passed"
    else
        io_print_fail "Test for 2nd exists action failed"
    fi
    if [[ "$info0" =~ $'\n'"Status: active"$'\n' ]]; then
        io_print_pass "Test for 1st info action passed"
    else
        io_print_fail "Test for 1st info action failed"
    fi
    if [[ "$info1" =~ $'\n'"Status: terminated"$'\n' ]]; then
        io_print_pass "Test for 2nd info action passed"
    else
        io_print_fail "Test for 2nd info action failed"
    fi
    if [ "$exists2" == "No persisted VPN was found" ]; then
        io_print_pass "Test for 3d exists action passed"
    else
        io_print_fail "Test for 3d exists action failed"
    fi
    if [ "$ip_0" != "$ip_1" ]; then
        io_print_pass "Test for VPN connection passed"
    else
        io_print_fail "Test for VPN connection failed"
    fi
    echo "Comprehensive test completed"
}

cleanup_after_error() {
    echo "Cleanup after error started"
    region=$1
    quiet=$2
    force=$3
    echo "Running: exists"
    ./quick-aws-vpn.sh ${quiet} -d ./test/customdir exists
    echo "Running: info"
    ./quick-aws-vpn.sh ${quiet} -d ./test/customdir info
    echo "Running: history"
    ./quick-aws-vpn.sh ${quiet} -d ./test/customdir history
    echo "Running: region-remote-resources"
    ./quick-aws-vpn.sh ${region} ${quiet} -d ./test/customdir region-remote-resources
    echo "Running: terminate"
    ./quick-aws-vpn.sh ${quiet} ${force} -d ./test/customdir terminate
    echo "Running: history"
    ./quick-aws-vpn.sh ${quiet} -d ./test/customdir history
    echo "Running: info"
    ./quick-aws-vpn.sh ${quiet} -d ./test/customdir info
    echo "Running: purge"
    ./quick-aws-vpn.sh ${quiet} ${force} -d ./test/customdir purge
    echo "Running: region-remote-resources"
    ./quick-aws-vpn.sh ${region} ${quiet} -d ./test/customdir region-remote-resources
    echo "Running: exists"
    ./quick-aws-vpn.sh ${quiet} -d ./test/customdir exists
    echo "Removing test data directory"
    rm -rf ./test/customdir
    echo "Cleanup after error completed"
}

# comprehensive_test "" "-q" "-f"
# cleanup_after_error "" "-q" "-f"
# comprehensive_test "-r eu-west-3" "-q" ""
# comprehensive_test "-r eu-west-3" "" ""
# comprehensive_test "-r eu-west-3" "-v" "-f"
comprehensive_test "-r eu-west-3" "" "-f"
# comprehensive_test "-r eu-west-3" "-q" "-f"
# cleanup_after_error "-r eu-west-3" "-q" "-f"
# cleanup_after_error "-r eu-west-3" "" "-f"

# source ./quick-aws-vpn.sh -v -d ./test/customdir terminate
# source ./quick-aws-vpn.sh -r eu-west-3 -d ./test/customdir create
