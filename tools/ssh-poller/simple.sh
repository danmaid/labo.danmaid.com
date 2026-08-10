#!/bin/bash
set -u

HOST="${1:-192.168.1.121}"
USER="mon"
PASSWORD="monmon"

PROMPT="/${USER}#"

IDLE_TIMEOUT=5
MARGIN_MINUTES=10

LIST_COMMAND='show logging application | include gc/gc_app.log | include current | nomore'
READ_COMMAND_TEMPLATE='show logging application {FILE} | include GC | nomore'

source ./functions.sh

# main
log "CONNECTING"
coproc SSH {
    sshpass -p "$PASSWORD" ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USER@$HOST"
}
CLI_OUT=${SSH[0]}
CLI_IN=${SSH[1]}

log "WAITING INITIAL PROMPT"
initial_output="$(expect_prompt "$PROMPT")"
dump "INITIAL OUTPUT" "$initial_output"

## file list
log "COLLECTING GC FILE LIST"
send "$LIST_COMMAND"
list_output="$(expect_prompt "$PROMPT")"
dump "LIST OUTPUT" "$list_output"

declare -a files=()
declare -A groups
latest=""
while IFS= read -r line
do
    line="${line//$'\r'/}"
    [[ $line =~ gc/gc_app\.log\.([0-9]{14})\. ]] || continue
    gen="${BASH_REMATCH[1]}"
    set -- $line
    file="${!#}"
    groups["$gen"]+="$file"$'\n'

    if [[ -z $latest || "$gen" > "$latest" ]]
    then
        latest="$gen"
    fi
done <<< "$list_output"

log "LATEST GENERATION: $latest"
if [[ -n $latest ]]
then
    while IFS= read -r file
    do
        [[ -n $file ]] && files+=("$file")
    done <<< "${groups[$latest]}"
fi
log "SELECTED FILES: ${files[*]}"

# read files
cutoff_epoch=$(date -d "${MARGIN_MINUTES} minutes ago" +%s)

for file in "${files[@]}"
do
    log "COLLECTING FILE: $file"
    cmd="${READ_COMMAND_TEMPLATE//\{FILE\}/$file}"
    printf 'FILE(Q)=[%q]\n' "$file" >&2
    printf 'CMD(Q)=[%q]\n' "$cmd" >&2
    send "$cmd"
    body="$(expect_prompt "$PROMPT")"
    dump "FILE OUTPUT ($file)" "$body"

    while IFS= read -r line
    do
        [[ $line =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+\+[0-9]{4}) ]] || continue
        ts="${BASH_REMATCH[1]}"
        epoch=$(date -d "$ts" +%s 2>/dev/null) || continue
        (( epoch >= cutoff_epoch )) || continue
        printf '%s\n' "$line"
    done <<< "$body"
done

log "DISCONNECTING"
send "exit"
wait || true
