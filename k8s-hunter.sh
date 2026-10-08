#!/bin/bash



#########################################

# K8-HUNTER

# Kubernetes Attack Surface Scanner

#########################################



set -o pipefail



RED='\033[0;31m'

GREEN='\033[0;32m'

YELLOW='\033[1;33m'

BLUE='\033[0;34m'

NC='\033[0m'



CONTEXT=""

NAMESPACE=""



usage() {

    echo

    echo "Usage:"

    echo "  $0 --context <context> [--namespace <namespace>]"

    echo

    echo "Examples:"

    echo "  $0 --context dev"

    echo "  $0 --context dev --namespace payments"

    exit 1

}



while [[ $# -gt 0 ]]; do

    case "$1" in

        -c|--context)

            CONTEXT="$2"

            shift 2

            ;;

        -n|--namespace)

            NAMESPACE="$2"

            shift 2

            ;;

        *)

            usage

            ;;

    esac

done



[[ -z "$CONTEXT" ]] && usage



if ! command -v kubectl >/dev/null 2>&1; then

    echo "[ERROR] kubectl not found"

    exit 1

fi



banner() {



echo -e "${GREEN}"



cat << "EOF"



██╗  ██╗ █████╗       ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗

██║ ██╔╝██╔══██╗      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗

█████╔╝ ╚█████╔╝█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝

██╔═██╗ ██╔══██╗╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗

██║  ██╗╚█████╔╝      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║

╚═╝  ╚═╝ ╚════╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝



         Kubernetes Attack Surface Scanner



      RBAC • Pods • Secrets • Service Accounts

       HostPath • HostNetwork • PrivEsc Paths



EOF



echo -e "${NC}"

}



k() {

    kubectl --context "$CONTEXT" "$@"

}



section() {

    echo

    echo -e "${BLUE}============================================================${NC}"

    echo -e "${BLUE}$1${NC}"

    echo -e "${BLUE}============================================================${NC}"

}



cani() {



    local verb="$1"

    local resource="$2"

    local ns="$3"

    local result



    result=$(kubectl --context "$CONTEXT" auth can-i "$verb" "$resource" -n "$ns" 2>/dev/null)



    result=$(echo "$result" | head -n1 | xargs)



    case "$result" in

        yes*) echo "yes" ;;

        no*) echo "no" ;;

        *) echo "-" ;;

    esac

}



colorize() {

    case "$1" in

        yes)

            echo -e "${RED}yes${NC}"

            ;;

        no)

            echo -e "${GREEN}no${NC}"

            ;;

        *)

            echo "-"

            ;;

    esac

}



command -v clear >/dev/null 2>&1 && clear

banner



echo "[+] Context   : $CONTEXT"



if [[ -n "$NAMESPACE" ]]; then

    echo "[+] Namespace : $NAMESPACE"

else

    echo "[+] Namespace : ALL"

fi



echo "[+] Started   : $(date)"

echo



if [[ -n "$NAMESPACE" ]]; then

    NSLIST="$NAMESPACE"

else

    NSLIST=$(k get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

fi

##################################################
# Cluster Policies
##################################################

section "Cluster Policies"

CLUSTERPOLICIES=$(k get clusterpolicies 2>/dev/null)

if [[ -n "$CLUSTERPOLICIES" ]]; then
    echo "$CLUSTERPOLICIES"
else
    echo "No cluster policies found or access denied"
fi


section "Dangerous Permission Matrix"

printf '%-25s %-15s %-15s %-15s %-15s\n' \
"Namespace" \
"Pods" \
"Exec" \
"Secrets" \
"PortFwd"

for ns in $NSLIST
do
    PODS=$(cani create pods "$ns")
    EXEC=$(cani create pods/exec "$ns")
    SECRETS=$(cani get secrets "$ns")
    PORT=$(cani create pods/portforward "$ns")

    PODS_C=$(colorize "$PODS")
    EXEC_C=$(colorize "$EXEC")
    SECRETS_C=$(colorize "$SECRETS")
    PORT_C=$(colorize "$PORT")

    printf '%-25s %-25b %-25b %-25b %-25b\n' \
        "$ns" \
        "$PODS_C" \
        "$EXEC_C" \
        "$SECRETS_C" \
        "$PORT_C"
done


section "Critical Findings"



for ns in $NSLIST

do

    PODS=$(cani create pods "$ns")

    EXEC=$(cani create pods/exec "$ns")

    SECRETS=$(cani get secrets "$ns")

    PORT=$(cani create pods/portforward "$ns")

	echo -e "${GREEN}---Verify These Manually!---"

    [[ "$PODS" == "yes" ]] && \

        echo -e "${RED}[CRITICAL]${NC} Create Pods -> $ns"



    [[ "$EXEC" == "yes" ]] && \

        echo -e "${RED}[CRITICAL]${NC} Pod Exec -> $ns"



    [[ "$SECRETS" == "yes" ]] && \

        echo -e "${RED}[CRITICAL]${NC} Read Secrets -> $ns"



    [[ "$PORT" == "yes" ]] && \

        echo -e "${RED}[CRITICAL]${NC} Port Forward -> $ns"



    [[ "$PODS" == "yes" && "$EXEC" == "yes" ]] && \

        echo -e "${YELLOW}[HIGH]${NC} Create Pod + Exec -> $ns"



    [[ "$PODS" == "yes" && "$SECRETS" == "yes" ]] && \

        echo -e "${YELLOW}[HIGH]${NC} Create Pod + Secrets -> $ns"



    [[ "$PODS" == "yes" && "$EXEC" == "yes" && "$SECRETS" == "yes" ]] && \

        echo -e "${RED}[CRITICAL]${NC} Full Attack Chain -> $ns"

done



section "Service Accounts"



if [[ -n "$NAMESPACE" ]]; then

    k get sa -n "$NAMESPACE" 2>/dev/null

else

    k get sa -A 2>/dev/null

fi



section "Pods + Service Accounts"



if [[ -n "$NAMESPACE" ]]; then

    k get pods -n "$NAMESPACE" \

        -o custom-columns="POD:.metadata.name,SA:.spec.serviceAccountName" \

        2>/dev/null

else

    k get pods -A \

        -o custom-columns="NAMESPACE:.metadata.namespace,POD:.metadata.name,SA:.spec.serviceAccountName" \

        2>/dev/null

fi



section "Cluster Role Bindings"



k get clusterrolebindings \

    -o custom-columns="NAME:.metadata.name,ROLE:.roleRef.name" \

    2>/dev/null



section "Cluster-Admin Bindings"



CLUSTERADMINS=$(k get clusterrolebindings \

    -o custom-columns="NAME:.metadata.name,ROLE:.roleRef.name" \

    2>/dev/null | grep cluster-admin)



if [[ -n "$CLUSTERADMINS" ]]; then

    echo "$CLUSTERADMINS"

else

    echo -e "${GREEN}No visible cluster-admin bindings${NC}"

fi



section "HostPath Mounts"



HOSTPATH=$(k get pods -A -o yaml 2>/dev/null | grep -i "hostPath:")



if [[ -n "$HOSTPATH" ]]; then

    echo "$HOSTPATH"

else

    echo -e "${GREEN}No hostPath mounts found${NC}"

fi



section "Privileged Containers"



PRIV=$(k get pods -A -o yaml 2>/dev/null | grep -i "privileged:")



if [[ -n "$PRIV" ]]; then

    echo "$PRIV"

else

    echo -e "${GREEN}No privileged containers found${NC}"

fi



section "Host Networking"



HOSTNET=$(k get pods -A -o yaml 2>/dev/null | grep -i "hostNetwork:")



if [[ -n "$HOSTNET" ]]; then

    echo "$HOSTNET"

else

    echo -e "${GREEN}No hostNetwork pods found${NC}"

fi



section "Summary"



echo -e "${RED}CRITICAL${NC} = Directly exploitable permissions"

echo -e "${YELLOW}HIGH${NC}     = Interesting attack paths"

echo -e "${GREEN}INFO${NC}     = No obvious issues detected"



echo

echo -e "${GREEN}[+] Scan Complete${NC}"
