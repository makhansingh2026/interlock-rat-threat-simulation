##! Interlock RAT Detection — Zeek site script (v2)
##! Author: Makhan Singh — Seneca Polytechnic, SPR600 Security Monitoring
##! File:   /opt/zeek/share/zeek/site/interlock-detect.zeek
##!
##! What changed in v2
##! ------------------
##! Original Notice types (Interlock_C2_Beacon, Interlock_Data_Exfil,
##! Interlock_PS_Download, Interlock_PowerShell_UA) and their original message
##! format strings are PRESERVED so the existing lab manual, project report,
##! and notice.log dashboards still reference accurate names. Rule logic for
##! these four was refined (suppression intervals, established-flow checks)
##! without changing what conceptually triggers them.
##!
##! v2 also adds new Notice types for technique-based detections that catch
##! the real-world KongTuke -> Interlock RAT campaign documented by The DFIR
##! Report (July 2025) — most importantly Cloudflare Tunnel C2 detection.
##!
##! Loaded by appending `@load interlock-detect.zeek` to local.zeek.
##! Deploy with: zeekctl check && zeekctl deploy && zeekctl status
##!
##! Notice types raised here are written to /opt/zeek/logs/current/notice.log
##! and pair with the Suricata SIDs and Wazuh rules of the same name.
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
        ## --- ORIGINAL Notice types (names PRESERVED for backward compatibility) ---
        Interlock_C2_Beacon,         # GET /cmd  (lab Flask C2)
        Interlock_Data_Exfil,        # POST /exfil  (lab Flask C2)
        Interlock_PS_Download,       # .ps1 in URI
        Interlock_PowerShell_UA,     # PowerShell User-Agent in HTTP

        ## --- NEW IN V2: lab-specific endpoints not covered in v1 ---
        Interlock_Lab_C2_Beacon_Post,   # POST /beacon
        Interlock_Lab_C2_Result,        # POST /result

        ## --- NEW IN V2: technique-based detections (real-world Interlock IOCs) ---
        Interlock_BareIP_Script_Download,
        Interlock_PowerShell_Encoded_Command,
        Interlock_PowerShell_IEX_Downloader,
        Interlock_Cloudflare_Tunnel_DNS,
        Interlock_Cloudflare_Tunnel_TLS,
        Interlock_Workers_Dev_TLS,
        Interlock_RDP_Reverse_Direction,
        Interlock_RDP_Nonstandard_Port,
        Interlock_Archive_Upload,
    };

    ## Internal servers / DCs that should never initiate RDP toward workstations.
    const dc_servers: set[addr] = { 10.0.10.200, 10.0.10.201, 10.0.10.202 } &redef;
}

# ----------------------------------------------------------------------
# Pattern definitions (compiled once at load time)
# ----------------------------------------------------------------------

const bare_ip_host_pattern   = /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$/;
const script_ext_pattern     = /\.(ps1|hta|vbs|js|exe|dll|bat|cmd)(\?|$)/;
const archive_ext_pattern    = /\.(zip|rar|7z|tar\.gz|tgz)(\?|$)/;
const encoded_command_pattern = /-(e|en|enc|enco|encod|encode|encodedCommand)[ \t]+[A-Za-z0-9+\/=]{30,}/;
const iex_pattern            = /(IEX|Invoke-Expression)[^a-zA-Z].{0,200}New-Object.{0,80}Net\.WebClient/;
const ps_hidden_bypass_pattern = /-w(indowstyle)?[ \t]+hidden.{0,200}-e(xecutionpolicy)?[ \t]*p?[ \t]*bypass/i;

# ----------------------------------------------------------------------
# Notice suppression intervals (prevents duplicate alerts during a campaign)
# ----------------------------------------------------------------------

redef Notice::type_suppression_intervals += {
    [InterlockDetect::Interlock_PowerShell_UA]              = 5 min,
    [InterlockDetect::Interlock_PS_Download]                = 5 min,
    [InterlockDetect::Interlock_BareIP_Script_Download]     = 5 min,
    [InterlockDetect::Interlock_Cloudflare_Tunnel_DNS]      = 10 min,
    [InterlockDetect::Interlock_Cloudflare_Tunnel_TLS]      = 10 min,
    [InterlockDetect::Interlock_Workers_Dev_TLS]            = 10 min,
    [InterlockDetect::Interlock_RDP_Reverse_Direction]      = 5 min,
    [InterlockDetect::Interlock_RDP_Nonstandard_Port]       = 5 min,
};

# ======================================================================
# ORIGINAL DETECTIONS (Notice type names + msg format PRESERVED)
# ======================================================================

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    # ORIGINAL: C2 command poll (GET /cmd)
    if (method == "GET" && /\/cmd/ in original_URI)
        NOTICE([$note=Interlock_C2_Beacon,
                $msg=fmt("C2 beacon: %s -> %s %s", c$id$orig_h, method, original_URI),
                $conn=c, $identifier=cat(c$id$orig_h)]);

    # ORIGINAL: Data exfiltration (POST /exfil)
    if (method == "POST" && /\/exfil/ in original_URI)
        NOTICE([$note=Interlock_Data_Exfil,
                $msg=fmt("Data exfil: %s -> %s", c$id$orig_h, original_URI),
                $conn=c]);

    # ORIGINAL: PowerShell script download (.ps1 in URI)
    if (/\.ps1/ in original_URI)
        NOTICE([$note=Interlock_PS_Download,
                $msg=fmt("PowerShell download: %s -> %s", c$id$orig_h, original_URI),
                $conn=c]);

    # NEW IN V2: lab Flask C2 — POST /beacon (not covered in v1)
    if (method == "POST" && /\/beacon/ in original_URI)
        NOTICE([$note=Interlock_Lab_C2_Beacon_Post,
                $msg=fmt("Lab C2 beacon: %s -> %s", c$id$orig_h, original_URI),
                $conn=c, $identifier=cat(c$id$orig_h)]);

    # NEW IN V2: lab Flask C2 — POST /result (not covered in v1)
    if (method == "POST" && /\/result/ in original_URI)
        NOTICE([$note=Interlock_Lab_C2_Result,
                $msg=fmt("Lab C2 result: %s -> %s", c$id$orig_h, original_URI),
                $conn=c, $identifier=cat(c$id$orig_h)]);

    # NEW IN V2: bare-IP host fetching scripts (no DNS = suspicious)
    if ( c?$http && c$http?$host
         && bare_ip_host_pattern in c$http$host
         && script_ext_pattern in original_URI )
    {
        NOTICE([$note=Interlock_BareIP_Script_Download,
                $msg=fmt("Bare-IP script fetch (no DNS): %s -> %s%s",
                         c$id$orig_h, c$http$host, original_URI),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$http$host)]);
    }

    # NEW IN V2: compressed archive upload over HTTP POST (potential exfil)
    if (method == "POST" && archive_ext_pattern in original_URI)
    {
        NOTICE([$note=Interlock_Archive_Upload,
                $msg=fmt("Archive upload from %s -> %s%s",
                         c$id$orig_h, c$id$resp_h, original_URI),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
    }
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    # ORIGINAL: PowerShell User-Agent in HTTP request
    if (is_orig && name == "USER-AGENT" && /PowerShell/ in value)
        NOTICE([$note=Interlock_PowerShell_UA,
                $msg=fmt("PowerShell UA from %s", c$id$orig_h),
                $conn=c]);
}

# ======================================================================
# NEW IN V2: HTTP body inspection (PowerShell payload patterns)
# ======================================================================

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    # Encoded PowerShell command (-enc / -EncodedCommand) on the wire
    if (encoded_command_pattern in data)
    {
        NOTICE([$note=Interlock_PowerShell_Encoded_Command,
                $msg=fmt("PowerShell -EncodedCommand seen in HTTP stream: %s -> %s",
                         c$id$orig_h, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
    }

    # Inline IEX downloader pattern delivered in HTTP response
    if (!is_orig && iex_pattern in data)
    {
        NOTICE([$note=Interlock_PowerShell_IEX_Downloader,
                $msg=fmt("PowerShell IEX downloader pattern in HTTP response: %s <- %s",
                         c$id$orig_h, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$resp_h)]);
    }

    # Hidden + Bypass flag chain in HTTP body
    if (!is_orig && ps_hidden_bypass_pattern in data)
    {
        NOTICE([$note=Interlock_PowerShell_Encoded_Command,
                $msg=fmt("PowerShell hidden+bypass flag chain in HTTP body: %s <- %s",
                         c$id$orig_h, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$resp_h, "hidden_bypass")]);
    }
}

# ======================================================================
# NEW IN V2: Command and Control — Cloudflare infrastructure abuse
# ======================================================================

event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count)
{
    # Cloudflare Tunnel — highest-value real-world Interlock IOC.
    # Active campaigns rotate *.trycloudflare.com subdomains weekly.
    if (/\.trycloudflare\.com$/ in to_lower(query))
    {
        NOTICE([$note=Interlock_Cloudflare_Tunnel_DNS,
                $msg=fmt("Cloudflare Tunnel DNS query: %s -> %s",
                         c$id$orig_h, query),
                $conn=c,
                $identifier=cat(c$id$orig_h, query)]);
    }
}

event ssl_extension_server_name(c: connection, is_client: bool,
                                names: string_vec)
{
    for (i in names)
    {
        local sni = to_lower(names[i]);

        if (/\.trycloudflare\.com$/ in sni)
        {
            NOTICE([$note=Interlock_Cloudflare_Tunnel_TLS,
                    $msg=fmt("Cloudflare Tunnel TLS SNI: %s -> %s [SNI=%s]",
                             c$id$orig_h, c$id$resp_h, sni),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, sni)]);
        }

        if (/\.workers\.dev$/ in sni)
        {
            NOTICE([$note=Interlock_Workers_Dev_TLS,
                    $msg=fmt("Cloudflare Workers TLS SNI: %s -> %s [SNI=%s]",
                             c$id$orig_h, c$id$resp_h, sni),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, sni)]);
        }
    }
}

# ======================================================================
# NEW IN V2: Lateral movement
# ======================================================================

event connection_established(c: connection)
{
    # Reverse RDP from a server/DC to a workstation
    if (c$id$orig_h in dc_servers && c$id$resp_p == 3389/tcp)
    {
        NOTICE([$note=Interlock_RDP_Reverse_Direction,
                $msg=fmt("Reverse RDP from server %s to workstation %s",
                         c$id$orig_h, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
    }
}

# RDP negotiated on a non-3389 port via the X.224 / mstshash cookie pattern.
# Catches port-forward pivots like Kali -> Goku-mak:33890 -> Krillin-mak:3389
# without hard-coding the specific lab port number.
event mstshash_seen(c: connection, value: string) &priority=-5
{
    if (c$id$resp_p != 3389/tcp)
    {
        NOTICE([$note=Interlock_RDP_Nonstandard_Port,
                $msg=fmt("RDP negotiated on non-standard port %d: %s -> %s [cookie=%s]",
                         c$id$resp_p, c$id$orig_h, c$id$resp_h, value),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, c$id$resp_p)]);
    }
}
