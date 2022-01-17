#!iRule
# Decrypt TLS Traffic

# grep Session-ID /var/log/ltm | sed 's/.*\(RSA.*\)/\1/' > /var/tmp/SSLDUMP.pmsk

when CLIENTSSL_HANDSHAKE {
    if { [IP::addr [IP::client_addr] equals 1.1.1.1] } {
        log local0.info "Client Side: RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
    }
}

when SERVERSSL_HANDSHAKE {
    if { [IP::addr [IP::client_addr] equals 1.1.1.1] } {
	log local0.info "Server Side: RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
    }
}

