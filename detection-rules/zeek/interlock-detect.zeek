##! Interlock RAT Detection — Zeek site script (v2)
##! Author: Makhan Singh — Seneca Polytechnic, SPR600 Security Monitoring
##! File:   /opt/zeek/share/zeek/site/interlock-detect.zeek
##!
##! Reference: The DFIR Report — KongTuke FileFix Leads to New Interlock RAT Variant
##!   https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/

@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/frameworks/notice

module InterlockDetect;

export {
    redef enum Notice::Type += {
        ## --- Notice types (names PRESERVED for backward compatibility) ---
        Interlock_C2_Beacon,         # GET /cmd  (lab Flask C2)
        Interlock_Data_Exfil,        # POST /exfil  (lab Flask C2)
        Interlock_PS_Download,       # .ps1 in URI
        Interlock_PowerShell_UA,     # PowerShell User-Agent in HTTP
        Interlock_Lab_C2_Beacon_Post,   # POST /beacon
        Interlock_Lab_C2_Result,        # POST /result

    };

    ## Internal servers / DCs that should never initiate RDP toward workstations.
    ## Lab has only one DC (Goku-mak = 10.0.10.200). Add additional servers as
    ## the environment grows.
    const dc_servers: set[addr] = { 10.0.10.200 } &redef;
}


# ======================================================================
# DETECTIONS 
# ======================================================================

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    # C2 command poll (GET /cmd)
    if (method == "GET" && /\/cmd/ in original_URI)
        NOTICE([$note=Interlock_C2_Beacon,
                $msg=fmt("C2 beacon: %s -> %s %s", c$id$orig_h, method, original_URI),
                $conn=c, $identifier=cat(c$id$orig_h)]);

    # Data exfiltration (POST /exfil)
    if (method == "POST" && /\/exfil/ in original_URI)
        NOTICE([$note=Interlock_Data_Exfil,
                $msg=fmt("Data exfil: %s -> %s", c$id$orig_h, original_URI),
                $conn=c]);

    # PowerShell script download (.ps1 in URI)
    if (/\.ps1/ in original_URI)
        NOTICE([$note=Interlock_PS_Download,
                $msg=fmt("PowerShell download: %s -> %s", c$id$orig_h, original_URI),
                $conn=c]);

    # lab Flask C2 — POST /beacon (not covered in v1)
    if (method == "POST" && /\/beacon/ in original_URI)
        NOTICE([$note=Interlock_Lab_C2_Beacon_Post,
                $msg=fmt("Lab C2 beacon: %s -> %s", c$id$orig_h, original_URI),
                $conn=c, $identifier=cat(c$id$orig_h)]);

    # lab Flask C2 — POST /result (not covered in v1)
    if (method == "POST" && /\/result/ in original_URI)
        NOTICE([$note=Interlock_Lab_C2_Result,
                $msg=fmt("Lab C2 result: %s -> %s", c$id$orig_h, original_URI),
                $conn=c, $identifier=cat(c$id$orig_h)]);

    }
}
