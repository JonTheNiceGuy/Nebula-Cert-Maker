#!/usr/bin/env bash
# Template from: https://betterdev.blog/minimal-safe-bash-script-template/

set -Eeuo pipefail

nebula_cert_bin="/usr/sbin/nebula-cert"

usage() {
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v] [-f] -p param_value arg1 [arg2...]

Script description here.

Available options:

-h, --help             Print this help and exit
-v, --verbose          Print script debug info
-n, --name ""      (*) Name of the device to which the certificate will be issued
-i, --ip ""            An integer to add to the base of the subnet (assuming 
                         192.0.2.0/24, add 1 = 192.0.2.1/24)
-d, --index ""         Index of the subnet that the CA will permit
-f, --fqdn_root "" (+) The DNS suffix to add to the DNS names (e.g. example.org)
-c, --cert_path ""     The path to the CA certificate and key
-l, --lighthouse       Add the group "Lighthouse" to this certificate
-s, --server           Add the group "Server" to this certificate
-w, --workstation      Add the group "Workstation" to this certificate
-g, --group ""     (+) Add a group to this certificate

(*) Required setting
(+) Multiple options can be supplied
EOF
}

# shellcheck disable=SC2034
setup_colors() {
  if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
    NOFORMAT='\033[0m' RED='\033[0;31m' GREEN='\033[0;32m' ORANGE='\033[0;33m' BLUE='\033[0;34m' PURPLE='\033[0;35m' CYAN='\033[0;36m' YELLOW='\033[1;33m' BOLD='\033[1m' DIM='\033[2m' ITALIC='\033[3m' UNDERLINE='\033[4m' BLINK='\033[5m'
  else
    NOFORMAT='' RED='' GREEN='' ORANGE='' BLUE='' PURPLE='' CYAN='' YELLOW='' BOLD='' DIM='' ITALIC='' UNDERLINE='' BLINK=''
  fi
}

msg() {
  echo >&2 -e "${1-}"
}

warn() {
  local msg=$1
  msg "[WARNING] ${PURPLE}$msg${NOFORMAT}"
}

error() {
  local msg=$1
  local code=${2-1}
  msg "[ERROR] ${RED}$msg${NOFORMAT}"
  exit "$code"
}

parse_params() {
  # default values of variables set from params
  name=''
  ip=''
  group=()
  cert_path="/root/nebula"
  fqdn_root=()
  subnet=""

  while :; do
    case "${1-}" in
    -h | --help) usage ;;
    -v | --verbose) set -x ;;
    --no-color) NO_COLOR=1 ;;
    -n | --name)
      [ -n "$name" ] && error "Name already defined once in this command. For safety sake, aborting here."
      name="${2-}"
      shift
      ;;
    -i | --ip)
      [ -n "$ip" ] && error "IP already defined once in this command. For safety sake, aborting here."
      ip="${2-}"
      shift
      ;;
    -d | --index)
      [ -n "$subnet" ] && error "Nebula Certificate Subnet index to use already defined once in this command. For safety sake, aborting here."
      subnet=$(( 0 + "${2-}" ))
      shift
      ;;
    -f | --fqdn_root)
      exists=0
      for i in "${!fqdn_root[@]}"
      do
        if [ "${fqdn_root[$i]}" == "${2-}" ]
        then
          exists=1
        fi
      done
      [ "$exists" -eq 0 ] && fqdn_root+=("${2-}")
      shift
      ;;
    -c | --cert_path)
      cert_path="${2-}"
      shift
      ;;
    -l | --lighthouse)
      exists=0
      for i in "${!group[@]}"
      do
        if [ "${group[$i]}" == "Lighthouse" ]
        then
          exists=1
        fi
      done
      [ "$exists" -eq 0 ] && group+=("Lighthouse")
      ;;
    -s | --server)
      exists=0
      for i in "${!group[@]}"
      do
        if [ "${group[$i]}" == "Server" ]
        then
          exists=1
        fi
      done
      [ "$exists" -eq 0 ] && group+=("Server")
      ;;
    -w | --workstation)
      exists=0
      for i in "${!group[@]}"
      do
        if [ "${group[$i]}" == "Workstation" ]
        then
          exists=1
        fi
      done
      [ "$exists" -eq 0 ] && group+=("Workstation")
      ;;
    -g | --group)
      exists=0
      for i in "${!group[@]}"
      do
        if [ "${group[$i]}" == "${2-}" ]
        then
          exists=1
        fi
      done
      [ "$exists" -eq 0 ] && group+=("${2-}")
      shift
      ;;
    -?*) error "Unknown option: $1" ;;
    *) break ;;
    esac
    shift
  done

  # check required params and arguments
  [[ -z "${name-}" ]] && error "Missing required parameter: name (use -n or --name followed by the value)"

  return 0
}

# shellcheck disable=SC2206
# Source: https://gist.github.com/thom-nic/2556a6cc3865fba6330f61b802438c05/340312b15993115e2c206b2f61ce3820b4129b27
# With tweaks!
cidr_iter() {
  # create array containing network address and subnet
  local network=(${1//\// })
  # split network address by dot
  local iparr=(${network[0]//./ })
  # if no mask given it's the same as /32
  local mask=32
  [[ $((${#network[@]})) -gt 1 ]] && mask=${network[1]}

  # convert dot-notation subnet mask or convert CIDR to an array like (255 255 255 0)
  local maskarr
  if [[ ${mask} = '\.' ]]; then  # already mask format like 255.255.255.0
    maskarr=("${mask//./ }")
  else                           # assume CIDR like /24, convert to mask
    if [[ $((mask)) -lt 8 ]]; then
      maskarr=($((256-2**(8-mask))) 0 0 0)
    elif  [[ $((mask)) -lt 16 ]]; then
      maskarr=(255 $((256-2**(16-mask))) 0 0)
    elif  [[ $((mask)) -lt 24 ]]; then
      maskarr=(255 255 $((256-2**(24-mask))) 0)
    elif [[ $((mask)) -lt 32 ]]; then
      maskarr=(255 255 255 $((256-2**(32-mask))))
    elif [[ ${mask} == 32 ]]; then
      maskarr=(255 255 255 255)
    fi
  fi

  # correct wrong subnet masks (e.g. 240.192.255.0 to 255.255.255.0)
  [[ ${maskarr[2]} == 255 ]] && maskarr[1]=255
  [[ ${maskarr[1]} == 255 ]] && maskarr[0]=255

  # generate list of ip addresses
  local bytes=(0 0 0 0)
  local subnet_start=""
  local ip_range=()
  for i in $(seq 0 $((255-maskarr[0]))); do
    bytes[0]="$(( i+(iparr[0] & maskarr[0]) ))"
    for j in $(seq 0 $((255-maskarr[1]))); do
      bytes[1]="$(( j+(iparr[1] & maskarr[1]) ))"
      for k in $(seq 0 $((255-maskarr[2]))); do
        bytes[2]="$(( k+(iparr[2] & maskarr[2]) ))"
        for l in $(seq 1 $((255-maskarr[3]))); do
          bytes[3]="$(( l+(iparr[3] & maskarr[3]) ))"
          [ -z "${subnet_start}" ] && subnet_start="$(printf "%d.%d.%d.%d\n" "${bytes[@]}")"
          ip_range+=("$(printf "%d.%d.%d.%d\n" "${bytes[@]}")")
        done
      done
    done
  done
  result="${ip_range[$(( $2 % ${#ip_range[@]}))]}/${mask}"
}

setup_colors
parse_params "$@"

[ -e "${name}.crt" ] && error "Certificate has already been created." 2

ca_key_path="$cert_path/ca.key"
ca_cert_path="$cert_path/ca.crt"
fqdn=""

if [ ! -e "$cert_path" ]
then
  error "Certificate Path does not exist." 255
fi

if [[ ! -r "$ca_key_path" && ! -r "$ca_cert_path" ]]
then
  error "CA Certificate or CA Key either do not exist, or you can't read them." 254
fi

if [ ${#fqdn_root[@]} -eq 0 ]
then
  warn "You have not specified a FQDN and one is not configured. Using the CA Name as the FQDN suffix. You may need to recreate this certificate if you are expecting to be able to do FQDN lookups."
  IFS=',' read -r -a fqdn_root <<< "$(nebula-cert print -json -path "$ca_cert_path" | jq -c .details.name -r)"
fi

for i in "${!fqdn_root[@]}"
do
  [ -n "${fqdn}" ] && fqdn="${fqdn},"
  fqdn="${fqdn}${name}.${fqdn_root[$i]}"
done

ranges=()
for range in $("${nebula_cert_bin}" print -json -path "$ca_cert_path" | jq -c .details.ips[] -r)
do
  ranges+=("$range")
done

[ ${#ranges[@]} -eq 0 ] && ranges=("10.44.88.0/24")
[ -z "$subnet" ] && subnet=0

if [ $subnet -gt ${#ranges[@]} ]
then
  defined_ranges=""
  for i in "${!ranges[@]}"
  do
    [ -n "${defined_ranges}" ] && defined_ranges="${defined_ranges},"
    defined_ranges="${defined_ranges}${ranges[$i]}"
  done
  error "Specified subnet index is greater than the defined ranges: ${defined_ranges}" 253
fi

if [ -z "${ip}" ]
then
  # Source: https://linuxhint.com/convert_hexadecimal_decimal_bash/
  ip="$(( 16#$(echo -n "${2}" | md5sum -z | cut -c-14) ))"
fi

cidr_iter "${ranges[$subnet]}" "$(( ip - 1 ))"
real_ip="${result}"

used_ips=()
for cert_file in *.crt
do
  json="$("${nebula_cert_bin}" print -json -path "${cert_file}")"
  if echo "${json}" | grep '"isCa":false' >/dev/null 2>/dev/null
  then
    IFS=',' read -r -a used_ip_array <<< "$(echo "${json}" | jq -c .details.ips[] -r)"
    for i in "${!used_ip_array[@]}"
    do
      used_ips+=("${used_ip_array[$i]}:${cert_file}")
    done
  fi
done

for an_ip in "${!used_ips[@]}"
do
  if [[ "${used_ips[$an_ip]}" =~ ^${real_ip}: ]]
  then
    error "The allocated IP conflicts with an existing IP: ${used_ips[$an_ip]}" 5
  fi
done

msg "${RED}Read parameters:${NOFORMAT}"
msg "- name: ${fqdn}"
msg "- ip: ${real_ip}"
for i in "${!group[@]}"
do
  msg "- group: ${group[$i]}"
done

group_list=""
for i in "${!group[@]}"
do
  [ -n "$group_list" ] && group_list="${group_list},"
  group_list="${group_list}${group[$i]}"
done

echo "${nebula_cert_bin}" sign -ca-crt "$ca_cert_path" -ca-key "$ca_key_path" -groups "${group_list}" -ip "${real_ip}" -name "${fqdn}" -out-crt "${name}.crt" -out-key "${name}.key"
"${nebula_cert_bin}" sign -ca-crt "$ca_cert_path" -ca-key "$ca_key_path" -groups "${group_list}" -ip "${real_ip}" -name "${fqdn}" -out-crt "${name}.crt" -out-key "${name}.key"