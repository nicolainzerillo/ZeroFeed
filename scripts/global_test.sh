#!/usr/bin/env bash
# ZeroFeed Global Multi-Region Subscriber Benchmark & Test Harness
# Launches ephemeral subscriber Fly Machines worldwide and measures stream telemetry.

set -euo pipefail

# Default configuration
DEFAULT_REGIONS="fra,nrt,syd,iad,gru"
RELAY_SERVER="zerofeed-relay.fly.dev:8443"
CHANNEL_CODE="zerofeed-global-bench-$(date +%s)"
FLY_APP="zerofeed-relay"
FLY_IMAGE="registry.fly.io/zerofeed-relay:deployment-01KZBA0Q3K3P0W4RQRKGY25T3R"
USE_QUIC=1
AUTO_PUB=0
BENCH_SIZE_MB=50
SPAWNED_MACHINES=()

# Color formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

usage() {
    cat <<EOF
ZeroFeed Global Multi-Region Test Runner

Usage:
  ./scripts/global_test.sh [options]

Options:
  -r, --regions REGIONS   Comma-separated Fly.io regions (default: ${DEFAULT_REGIONS})
  -c, --channel CODE      Shared passphrase/channel code (default: auto-generated)
  -s, --server ADDRESS    Relay server address (default: ${RELAY_SERVER})
  -a, --app APP_NAME      Fly.io application name (default: ${FLY_APP})
      --image IMAGE       Docker image to use for Fly Machines (default: ${FLY_IMAGE})
      --size MB           Size in MB of random data payload for benchmark (default: ${BENCH_SIZE_MB})
      --tcp               Use raw TCP instead of QUIC (default: QUIC enabled)
      --pub               Automatically launch local publisher after subscribers are ready
  -h, --help              Show this help message

Examples:
  ./scripts/global_test.sh --regions "fra,nrt,syd" --channel "my-secret-feed"
  ./scripts/global_test.sh --pub --size 100 --regions "fra,nrt,syd,iad,gru"
EOF
    exit 0
}

# Parse command line flags
REGIONS_LIST="${DEFAULT_REGIONS}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--regions)
            REGIONS_LIST="$2"
            shift 2
            ;;
        -c|--channel)
            CHANNEL_CODE="$2"
            shift 2
            ;;
        -s|--server)
            RELAY_SERVER="$2"
            shift 2
            ;;
        -a|--app)
            FLY_APP="$2"
            shift 2
            ;;
        --image)
            FLY_IMAGE="$2"
            shift 2
            ;;
        --size)
            BENCH_SIZE_MB="$2"
            shift 2
            ;;
        --tcp)
            USE_QUIC=0
            shift
            ;;
        --pub)
            AUTO_PUB=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Error: Unknown argument: $1${NC}"
            usage
            ;;
    esac
done

cleanup() {
    echo -e "\n${YELLOW}[!] Cleaning up spawned Fly Machines...${NC}"
    for machine_id in "${SPAWNED_MACHINES[@]}"; do
        echo -e "${CYAN}Stopping & destroying Fly Machine: ${machine_id}${NC}"
        fly machine stop "${machine_id}" -a "${FLY_APP}" --force >/dev/null 2>&1 || true
        fly machine destroy "${machine_id}" -a "${FLY_APP}" --force >/dev/null 2>&1 || true
    done
    echo -e "${GREEN}[✓] Cleanup complete.${NC}"
}
trap cleanup EXIT INT TERM

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}   ZeroFeed Global Multi-Region Subscriber Harness   ${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "Relay Server : ${CYAN}${RELAY_SERVER}${NC}"
echo -e "Channel Code : ${CYAN}${CHANNEL_CODE}${NC}"
echo -e "Protocol     : ${CYAN}$([ ${USE_QUIC} -eq 1 ] && echo 'QUIC (UDP 8443)' || echo 'TCP')${NC}"
echo -e "Target Regions: ${CYAN}${REGIONS_LIST}${NC}"
echo -e "Fly App      : ${CYAN}${FLY_APP}${NC}"
echo -e "Fly Image    : ${CYAN}${FLY_IMAGE}${NC}"
echo -e "Bench Size   : ${CYAN}${BENCH_SIZE_MB} MB${NC}"
echo -e "${BLUE}====================================================${NC}\n"

# Verify fly CLI is installed
if ! command -v fly &> /dev/null; then
    echo -e "${RED}Error: 'fly' CLI tool is not installed or not in PATH.${NC}"
    echo "Please install it via: curl -L https://fly.io/install.sh | sh"
    exit 1
fi

# Construct zerofeed command flags for subscriber machines
# Inside Fly.io 6PN network, subscriber connects via internal mesh zerofeed-relay.internal:8443
INT_RELAY_SERVER="zerofeed-relay.internal:8443"
if [[ "${RELAY_SERVER}" != "zerofeed-relay.fly.dev:8443" ]]; then
    INT_RELAY_SERVER="${RELAY_SERVER}"
fi

SUB_FLAGS="-c ${CHANNEL_CODE} -r ${INT_RELAY_SERVER}"
if [ "${USE_QUIC}" -eq 1 ]; then
    SUB_FLAGS="${SUB_FLAGS} --quic"
fi

IFS=',' read -ra REGIONS <<< "${REGIONS_LIST}"
for region in "${REGIONS[@]}"; do
    region_clean=$(echo "${region}" | xargs)
    echo -e "${YELLOW}[+] Deploying Subscriber Machine in region: ${CYAN}${region_clean}${NC}..."

    # Spawn Fly Machine with 512MB RAM to prevent OOM kill from Go mlockall
    OUTPUT=$(fly machine run "${FLY_IMAGE}" \
        -a "${FLY_APP}" \
        --region "${region_clean}" \
        --vm-memory 512 \
        --entrypoint "/zerofeed sub ${SUB_FLAGS}" \
        --detach \
        2>&1) || {
            echo -e "${RED}Failed to spawn machine in ${region_clean}: ${OUTPUT}${NC}"
            continue
        }

    MACHINE_ID=$(echo "${OUTPUT}" | grep -iE 'machine id:' | awk '{print $3}' || true)
    if [ -z "${MACHINE_ID}" ]; then
        MACHINE_ID=$(echo "${OUTPUT}" | grep -oE '[a-z0-9]{14}' | head -n 1 || true)
    fi

    if [ -n "${MACHINE_ID}" ]; then
        SPAWNED_MACHINES+=("${MACHINE_ID}")
        echo -e "${GREEN}[✓] Machine ${MACHINE_ID} running in ${region_clean}.${NC}"
    else
        echo -e "${YELLOW}Started machine in ${region_clean}. Output: ${OUTPUT}${NC}"
    fi
done

echo -e "\n${GREEN}[✓] All ${#SPAWNED_MACHINES[@]} subscriber machines launched successfully.${NC}"

if [ "${AUTO_PUB}" -eq 1 ]; then
    echo -e "\n${BLUE}[*] Generating ${BENCH_SIZE_MB} MB random payload and starting local publisher benchmark...${NC}"
    
    # Ensure binary exists
    if [ ! -f "bin/zerofeed" ]; then
        echo -e "${YELLOW}Building bin/zerofeed...${NC}"
        go build -tags quic -o bin/zerofeed main.go
    fi

    START_TIME=$(date +%s.%N)
    
    # Generate random stream and pipe to publisher
    dd if=/dev/urandom bs=1M count="${BENCH_SIZE_MB}" status=none | \
        ./bin/zerofeed pub -c "${CHANNEL_CODE}" -r "${RELAY_SERVER}" $([ ${USE_QUIC} -eq 1 ] && echo '--quic')
    
    END_TIME=$(date +%s.%N)
    ELAPSED=$(awk "BEGIN {print ${END_TIME} - ${START_TIME}}")
    MBPS=$(awk "BEGIN {print (${BENCH_SIZE_MB} * 8) / ${ELAPSED}}")
    MB_SEC=$(awk "BEGIN {print ${BENCH_SIZE_MB} / ${ELAPSED}}")

    echo -e "\n${GREEN}====================================================${NC}"
    echo -e "${GREEN}   PUBLISHER BENCHMARK RESULTS                     ${NC}"
    echo -e "${GREEN}====================================================${NC}"
    echo -e "Payload Transferred : ${CYAN}${BENCH_SIZE_MB} MB${NC}"
    echo -e "Time Elapsed        : ${CYAN}${ELAPSED} seconds${NC}"
    echo -e "Throughput Speed    : ${CYAN}${MB_SEC} MB/s (${MBPS} Mbps)${NC}"
    echo -e "${GREEN}====================================================${NC}"

    echo -e "\n${BLUE}[*] Waiting 5s for subscribers to complete processing logs...${NC}"
    sleep 5
else
    echo -e "\n${BLUE}[*] Subscribers are waiting for stream on channel: ${CYAN}${CHANNEL_CODE}${NC}"
    echo -e "Start local publisher with:"
    echo -e "  ${CYAN}go run -tags quic main.go pub -c \"${CHANNEL_CODE}\" -r \"${RELAY_SERVER}\"$([ ${USE_QUIC} -eq 1 ] && echo ' --quic')${NC}"
    echo -e "\nPress CTRL+C to stop all global subscriber machines."
    
    # Wait for user signal
    while true; do
        sleep 2
    done
fi
