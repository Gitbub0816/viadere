#!/bin/bash
# Prints the recent console and system log lines of a Container Apps job or app from Log Analytics (ingestion lags 1-5 minutes).
# Usage: SUB_ID=... bash Infra/azure/cloudshell/job-logs.sh job-viadere-dbadmin [hours]
set -uo pipefail
source "$(dirname "$0")/common.sh"
NAME="${1:-}"; HOURS="${2:-3}"
[ -n "$NAME" ] || fail "usage: job-logs.sh <job or app name> [hours]"
[[ "$NAME" =~ ^[a-z0-9-]{3,40}$ ]] || fail "invalid name"
[[ "$HOURS" =~ ^[0-9]{1,3}$ ]] || fail "invalid hours"
[ -z "${SUB_ID:-}" ] || az account set --subscription "$SUB_ID" || fail "az account set"
WS="$(az monitor log-analytics workspace show -g rg-viadere-stg-ops -n log-viadere-stg --query customerId -o tsv)" || fail "workspace"
az monitor log-analytics query -w "$WS" -o tsv --analytics-query "
union isfuzzy=true ContainerAppConsoleLogs, ContainerAppSystemLogs, ContainerAppConsoleLogs_CL, ContainerAppSystemLogs_CL
| where TimeGenerated > ago(${HOURS}h)
| extend who = strcat(column_ifexists('JobName', ''), column_ifexists('ContainerAppName', ''), column_ifexists('ContainerJobName_s', ''), column_ifexists('ContainerAppName_s', ''))
| where who has '$NAME'
| extend line = strcat(column_ifexists('Log', ''), column_ifexists('Log_s', ''), column_ifexists('Reason', ''), ' ', column_ifexists('Msg', ''), column_ifexists('Message', ''))
| project TimeGenerated, Type, line
| order by TimeGenerated asc
| take 200" || fail "query (logs can take a few minutes to arrive; retry shortly)"
