import socket
import os
from scapy.all import raw
from scapy.layers.tls.all import *
from .tls_utils import PQC_GROUPS, get_group_info

def analyze_tls_handshake(hostname, port=443, timeout=5):
    """
    Actively probes a server by sending a crafted TLS 1.3 ClientHello.
    """
    groups_to_propose = list(PQC_GROUPS.keys())
    
    dummy_key = os.urandom(32)
    client_key_shares = [
        KeyShareEntry(group=0x001d, key_exchange=dummy_key) 
    ]
    
    tls_extensions = [
        TLS_Ext_ServerName(servernames=[ServerName(servername=hostname.encode('utf-8'))]),
        TLS_Ext_SupportedGroups(groups=groups_to_propose),
        TLS_Ext_KeyShare_CH(client_shares=client_key_shares),
        TLS_Ext_SupportedVersion_CH(versions=[0x0304]),
        TLS_Ext_SignatureAlgorithms(sig_algs=[0x0403, 0x0804, 0x0401, 0x0503])
    ]
    
    ch = TLSClientHello(
        version=0x0303,
        ciphers=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
        ext=tls_extensions
    )
    record = TLS(msg=[ch])
    
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            sock.send(raw(record))
            response_bytes = sock.recv(8192) 
            
            if not response_bytes:
                return {"status": "error", "message": "No response from server"}
                
            return parse_server_response(response_bytes)
            
    except socket.timeout:
        return {"status": "error", "message": "Connection timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def parse_server_response(response_bytes):
    """
    Parses the response using Scapy, with a fallback to Deep Byte Inspection.
    """
    try:
        tls_resp = TLS(response_bytes)
    except Exception as e:
        return {"status": "error", "message": f"Scapy parsing failed: {e}"}

    if tls_resp.haslayer(TLSAlert):
        alert = tls_resp[TLSAlert]
        if alert.descr == 70: # protocol_version
            return {
                "status": "success", 
                "type": "TLS Alert 70 (Protocol Version Rejected)", 
                "group_id": None, 
                "info": {"name": "Legacy TLS (1.2 or lower)", "status": "Vulnerable (No TLS 1.3)", "grade": "F"}
            }
        elif alert.descr == 40: # handshake_failure
            return {
                "status": "success", 
                "type": "TLS Alert 40 (Handshake Failure)", 
                "group_id": None, 
                "info": {"name": "Incompatible Ciphers", "status": "Vulnerable (Rejected modern params)", "grade": "F"}
            }
        return {"status": "error", "message": f"Server aborted. TLS Alert Code: {alert.descr}"}

    HRR_MAGIC = b'\xcf!\xadt\xe5\x9aa\x11\xbe\x1d\x8c\x02\x1ee\xb8\x91\xc2\xa2\x11\x16z\xbb\x8c^\x07\x9e\t\xe2\xc8\xa83\x9c'

    # --- ATTEMPT 1: Scapy Clean Parsing ---
    sh = None
    if tls_resp.haslayer(TLSServerHello):
        sh = tls_resp[TLSServerHello]
    else:
        current = tls_resp
        while current:
            if current.haslayer(Raw):
                try:
                    hs = TLSHandshakes(current[Raw].load)
                    if hs.haslayer(TLSServerHello):
                        sh = hs[TLSServerHello]
                        break
                except: pass
            current = current.payload

    if sh:
        is_hrr = (getattr(sh, 'random', b'') == HRR_MAGIC)
        chosen_group = None
        
        if hasattr(sh, 'ext') and sh.ext:
            for ext in sh.ext:
                if ext.type == 51: # KeyShare ID
                    if hasattr(ext, 'group'): chosen_group = ext.group
                    elif hasattr(ext, 'server_share'): chosen_group = ext.server_share.group
        
        if chosen_group:
            info = get_group_info(chosen_group)
            msg_type = "HelloRetryRequest (PQC Active Probe Success)" if is_hrr else "ServerHello (Accepted classical key)"
            return {"status": "success", "type": msg_type, "group_id": chosen_group, "info": info}

    # --- ATTEMPT 2: Deep Byte Inspection ---
    is_hrr_raw = HRR_MAGIC in response_bytes
    if is_hrr_raw:
        idx = response_bytes.find(b'\x00\x33\x00\x02')
        if idx != -1:
            group_id_bytes = response_bytes[idx+4 : idx+6]
            group_id = int.from_bytes(group_id_bytes, byteorder='big')
            info = get_group_info(group_id)
            return {"status": "success", "type": "HelloRetryRequest (Deep Byte Inspection)", "group_id": group_id, "info": info}

    # --- ATTEMPT 3: Legacy Fallback Detection ---
    return {
        "status": "success", 
        "type": "ServerHello (Legacy TLS / No KeyShare)", 
        "group_id": None, 
        "info": {
            "name": "N/A", 
            "status": "Vulnerable (TLS 1.2 or Classical Only)", 
            "grade": "F"
        }
    }