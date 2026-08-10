log() {
    printf '%s\n' "$*" >&2
}

dump() {
    local title="$1"
    local body="$2"
    {
        echo "----- BEGIN ${title} -----"
        printf '%s\n' "$body"
        echo "----- END ${title} -----"
    } >&2
}

send() {
    log "SEND: $1"
    printf '%s\n' "$1" >&"$CLI_IN"
}

expect_prompt() {
    local pattern="$1"
    local buffer=""
    local ch
    log "WAIT: $pattern"

    while true
    do
        if IFS= read -r -N1 -t "$IDLE_TIMEOUT" -u "$CLI_OUT" ch
        then
            buffer+="$ch"

            case "$buffer" in
                *"$pattern"*)
                    dump "WAIT RESULT" "$buffer"
                    printf '%s' "$buffer"
                    return 0
                    ;;
            esac
        else
            log "IDLE TIMEOUT"
            dump "TIMEOUT BUFFER" "$buffer"
            printf '%s' "$buffer"
            return 1
        fi
    done
}
