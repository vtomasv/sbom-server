#!/bin/sh
set -eu
umask 077

usage() {
    cat <<'EOF'
Usage:
  pki.sh init-ca OUTPUT_DIR NAME
  pki.sh issue-server CA_DIR OUTPUT_DIR DNS:HOST [DNS:HOST|IP:ADDRESS ...]
  pki.sh issue-client CA_DIR OUTPUT_DIR NAME

The output directory must be new and its parent must exist.
Validity in days can be set with SBOM_PKI_CA_DAYS (3650),
SBOM_PKI_SERVER_DAYS (365), and SBOM_PKI_CLIENT_DAYS (90).
EOF
}

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

check_name() {
    case "$1" in
        ''|*[!A-Za-z0-9_.-]*) fail 'Name must use ASCII letters, digits, dots, underscores or hyphens.' ;;
    esac
    [ "${#1}" -le 64 ] || fail 'Name must contain at most 64 characters.'
}

check_days() {
    case "$1" in
        ''|0*|*[!0-9]*|?????*) fail 'Validity must be an integer from 1 to 9999 days.' ;;
    esac
}

cleanup() {
    rm -f "$output_dir/ca.crt" "$output_dir/ca.key" \
        "$output_dir/server.crt" "$output_dir/server.key" \
        "$output_dir/client.crt" "$output_dir/client.key" \
        "$output_dir/openssl.cnf" "$output_dir/request.csr"
    rmdir "$output_dir"
}

create_output() {
    case "$1" in
        /*) output_dir=$1 ;;
        '') fail 'An output directory is required.' ;;
        *) output_dir=$PWD/$1 ;;
    esac
    mkdir -m 700 "$output_dir" || fail 'Cannot create the output directory.'
    trap cleanup 0
    trap 'exit 1' HUP INT TERM

    config=$output_dir/openssl.cnf
    cat > "$config" <<'EOF'
[req]
distinguished_name = subject

[subject]
EOF
}

complete_output() {
    rm -f "$config" "$output_dir/request.csr"
    chmod 644 "$output_dir/$1.crt"
    trap - 0 HUP INT TERM
    printf 'Created %s\n' "$output_dir/$1.crt"
}

create_key() {
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$output_dir/$1.key"
}

init_ca() {
    check_name "$2"
    days=${SBOM_PKI_CA_DAYS:-3650}
    check_days "$days"
    create_output "$1"
    cat >> "$config" <<'EOF'

[certificate]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
    create_key ca
    serial=$(openssl rand -hex 16)
    openssl req -new -x509 -sha256 -days "$days" -set_serial "0x$serial" \
        -key "$output_dir/ca.key" -subj "/CN=$2" -config "$config" \
        -extensions certificate -out "$output_dir/ca.crt"
    complete_output ca
}

check_ca() {
    ca_dir=$1
    [ -r "$ca_dir/ca.crt" ] && [ -r "$ca_dir/ca.key" ] || fail 'CA certificate and key are required.'
    openssl x509 -in "$ca_dir/ca.crt" -noout -checkend "$((days * 86400))" >/dev/null || \
        fail 'The CA must remain valid for the requested certificate lifetime.'
}

write_leaf_extensions() {
    cat >> "$config" <<EOF

[certificate]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = $1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
EOF
}

write_sans() {
    printf 'subjectAltName = @alt_names\n\n[alt_names]\n' >> "$config"
    index=0
    for san do
        value=${san#*:}
        case "$san" in
            DNS:*)
                case "$value" in
                    ''|*[!A-Za-z0-9.-]*|.*|*..*|*.) fail "Invalid DNS SAN: $value" ;;
                esac
                type=DNS
                ;;
            IP:*)
                case "$value" in
                    ''|*[!A-Fa-f0-9:.]*) fail "Invalid IP SAN: $value" ;;
                esac
                type=IP
                ;;
            *) fail "Expected a DNS: or IP: SAN: $san" ;;
        esac
        index=$((index + 1))
        printf '%s.%s = %s\n' "$type" "$index" "$value" >> "$config"
    done
}

sign_leaf() {
    create_key "$1"
    serial=$(openssl rand -hex 16)
    openssl req -new -sha256 -config "$config" -subj "/CN=$2" \
        -key "$output_dir/$1.key" -out "$output_dir/request.csr"
    openssl x509 -req -sha256 -days "$days" -set_serial "0x$serial" \
        -in "$output_dir/request.csr" -CA "$ca_dir/ca.crt" -CAkey "$ca_dir/ca.key" \
        -extfile "$config" -extensions certificate -out "$output_dir/$1.crt"
    openssl verify -CAfile "$ca_dir/ca.crt" -purpose "$3" "$output_dir/$1.crt"
    complete_output "$1"
}

issue_server() {
    days=${SBOM_PKI_SERVER_DAYS:-365}
    check_days "$days"
    check_ca "$1"
    create_output "$2"
    shift 2
    write_leaf_extensions serverAuth
    write_sans "$@"
    sign_leaf server sbom-server sslserver
}

issue_client() {
    check_name "$3"
    days=${SBOM_PKI_CLIENT_DAYS:-90}
    check_days "$days"
    check_ca "$1"
    create_output "$2"
    write_leaf_extensions clientAuth
    sign_leaf client "$3" sslclient
}

case "${1:-}" in
    init-ca) [ "$#" -eq 3 ] || { usage >&2; exit 2; }; shift; init_ca "$@" ;;
    issue-server) [ "$#" -ge 4 ] || { usage >&2; exit 2; }; shift; issue_server "$@" ;;
    issue-client) [ "$#" -eq 4 ] || { usage >&2; exit 2; }; shift; issue_client "$@" ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac
