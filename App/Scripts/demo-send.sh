#!/bin/bash
# Sends a real Viadere interaction from the staging demo business (Atlas Demo) to a connected phone, through the business API.
# Bodies are generated from ViadereCore's request types (BusinessSendMessageRequest / IssueInteractionRequest).
#
#   export VIADERE_DEMO_KEY=vdk_live_...        # from: ViadereServer staging-demo --issue-key (or the script asks, input hidden)
#   export VIADERE_SUBJECT=sub_...               # from: ViadereServer staging-demo (connected customers)
#   App/Scripts/demo-send.sh message|signin|payment|confirm|choose|status [--api https://viadere-api.cksites.dev]
set -uo pipefail
KIND="${1:-}"; API="https://viadere-api.cksites.dev"
[ "${2:-}" = "--api" ] && API="${3:?--api needs a URL}"
case "$KIND" in message|signin|payment|confirm|choose|status) ;; *)
  echo "usage: $0 message|signin|payment|confirm|choose|status"; exit 1;; esac
if [ -z "${VIADERE_DEMO_KEY:-}" ]; then read -rsp "Atlas Demo API key (hidden): " VIADERE_DEMO_KEY; echo; fi
[[ "${VIADERE_DEMO_KEY}" == vdk_live_* ]] || { echo "the key must start with vdk_live_"; exit 1; }
SUB="${VIADERE_SUBJECT:?set VIADERE_SUBJECT=sub_... (run staging-demo to list it)}"
[[ "$SUB" =~ ^sub_[A-Za-z0-9_-]{43}$ ]] || { echo "VIADERE_SUBJECT does not look like sub_ plus 43 characters"; exit 1; }
IDEM="demo-$(date +%s)-$RANDOM"
NOW="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
COMMON='"allowedChannels":["nativePush","inApp"],"idempotencyKey":"'"$IDEM"'","priority":"normal","subjectRef":"'"$SUB"'"'
case "$KIND" in
  message) PATH_="/v1/business/messages"
    BODY='{"body":"Your table is ready. We saved you a seat by the window.","idempotencyKey":"'"$IDEM"'","subjectRef":"'"$SUB"'"}' ;;
  signin) PATH_="/v1/business/interactions"
    BODY='{'"$COMMON"',"kind":"authenticate","purpose":"security","sensitivity":"high","ttlSeconds":300,"payload":{"service":"Atlas Demo online banking","device":"Chrome on Mac","approximateLocation":"Phoenix, AZ","attemptedAt":"'"$NOW"'","riskIndicators":[]},"requestedActions":[{"id":"approve","label":"It'"'"'s me","role":"approve"},{"id":"deny","label":"Not me","role":"deny"}]}' ;;
  payment) PATH_="/v1/business/interactions"
    BODY='{'"$COMMON"',"kind":"authorize","purpose":"transactional","sensitivity":"high","ttlSeconds":300,"payload":{"actionDescription":"Card payment","amount":{"currency":"USD","value":"84.20"},"merchant":"Juniper Coffee","location":"Tempe, AZ","riskIndicators":[]},"requestedActions":[{"id":"approve","label":"Approve","role":"approve"},{"id":"deny","label":"Decline","role":"deny"}]}' ;;
  confirm) PATH_="/v1/business/interactions"
    BODY='{'"$COMMON"',"kind":"confirm","purpose":"accountService","sensitivity":"standard","ttlSeconds":3600,"payload":{"title":"Confirm your appointment","details":"Tue 3:30 PM, Atlas Demo downtown","reference":"APT-2041"},"requestedActions":[{"id":"confirm","label":"Confirm","role":"confirm"},{"id":"decline","label":"Reschedule","role":"decline"}]}' ;;
  choose) PATH_="/v1/business/interactions"
    BODY='{'"$COMMON"',"kind":"choose","purpose":"accountService","sensitivity":"standard","ttlSeconds":3600,"payload":{"prompt":"How should we deliver your order?","options":[{"id":"pickup","label":"Pick up"},{"id":"deliver","label":"Deliver"}],"allowsMultiple":false},"requestedActions":[]}' ;;
  status) PATH_="/v1/business/interactions"
    BODY='{'"$COMMON"',"kind":"status","purpose":"transactional","sensitivity":"standard","ttlSeconds":86400,"payload":{"title":"Order shipped","body":"Arriving Thursday by 8 PM."},"requestedActions":[]}' ;;
esac
# The key goes to curl on stdin (a header file), never on the command line where `ps` could show it.
printf 'Authorization: Bearer %s\n' "$VIADERE_DEMO_KEY" | curl -sS -w '\nHTTP %{http_code}\n' "$API$PATH_" \
  -H @- -H "Content-Type: application/json" -H "Idempotency-Key: $IDEM" --data "$BODY"
