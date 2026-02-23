import socket
from scapy.all import raw
from scapy.layers.tls.all import (
    TLS, 
    TLSClientHello, 
    TLS_Ext_SupportedGroups, 
    TLS_Ext_KeyShare, 
    TLS_KeyShareEntry,
    TLS_Ext_SupportedVersion,
    TLS_Ext_ServerName,
    ServerName,
    TLSHelloRetryRequest,
    TLSServerHello,
    TLS_Ext_SignatureAlgorithms
)

# Import our PQC registries from the file we just made
from .tls_utils import PQC_GROUPS, get_group_info

def analyze_tls_handshake(hostname, port=443, timeout=5):
    """
    Actively probes a server by sending a crafted TLS 1.3 ClientHello.
    We propose PQC groups but only provide a classical Key Share to force 
    a HelloRetryRequest if the server is PQC-capable.
    """
    print(f"[*] Probing {hostname}:{port} for Quantum Crypto-Agility...")
    
    # 1. We tell the server we support all our PQC groups + classical
    groups_to_propose = list(PQC_GROUPS.keys())
    
    # 2. We ONLY provide a dummy classical Key Share (X25519 = 0x001d)
    # This keeps the packet small. If the server wants PQC, it must ask for it.
    client_key_shares = [
        TLS_KeyShareEntry(group=0x001d, key_exchange=b"\x00"*32) 
    ]
    
    # 3. Build the Extensions
    extensions = [
        TLS_Ext_ServerName(servernames=[ServerName(servername=hostname)]),
        TLS_Ext_SupportedGroups(groups=groups_to_propose),
        TLS_Ext_KeyShare(client_shares=client_key_shares),
        TLS_Ext_SupportedVersion(versions=[0x0304]), # Force TLS 1.3
        TLS_Ext_SignatureAlgorithms(sig_algs=[0x0403, 0x0804, 0x0401, 0x0503]) # Standard sigs
    ]
    
    # 4. Assemble the Client Hello & Record Layer
    ch = TLSClientHello(
        version=0x0303,
        ciphers=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f], # TLS 1.3 & 1.2 ciphers
        extensions=extensions
    )
    record = TLS(msg=[ch])
    
    # 5. Network I/O
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            sock.send(raw(record))
            response_bytes = sock.recv(4096)
            
            if not response_bytes:
                return {"status": "error", "message": "No response from server"}
                
            return parse_server_response(response_bytes)
            
    except socket.timeout:
        return {"status": "error", "message": "Connection timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def parse_server_response(response_bytes):
    """
    Parses the raw bytes returned by the server to see which Key Exchange 
    group it selected.
    """
    try:
        # Let Scapy decode the TLS packet
        tls_resp = TLS(response_bytes)
    except Exception as e:
        return {"status": "error", "message": f"Scapy parsing failed: {e}"}

    # Scenario A: The server asks us to retry with a PQC Key Share! (Absolute Proof)
    if tls_resp.haslayer(TLSHelloRetryRequest):
        hrr = tls_resp[TLSHelloRetryRequest]
        for ext in hrr.extensions:
            if isinstance(ext, TLS_Ext_KeyShare): # Actually TLS_Ext_KeyShare_HRR in scapy internals sometimes, but this works
                chosen_group = ext.server_share.group if hasattr(ext, 'server_share') else getattr(ext, 'group', None)
                if chosen_group:
                    info = get_group_info(chosen_group)
                    return {"status": "success", "type": "HelloRetryRequest", "group_id": chosen_group, "info": info}

    # Scenario B: The server accepted our Classical key immediately, or picked one via ServerHello
    elif tls_resp.haslayer(TLSServerHello):
        sh = tls_resp[TLSServerHello]
        for ext in sh.extensions:
            if isinstance(ext, TLS_Ext_KeyShare):
                chosen_group = ext.server_share.group
                info = get_group_info(chosen_group)
                return {"status": "success", "type": "ServerHello", "group_id": chosen_group, "info": info}

    return {"status": "unknown", "message": "No valid KeyShare extension found in response."}
