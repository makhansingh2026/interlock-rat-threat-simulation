##! Interlock RAT Detection — Zeek site script
##! Source: lab manual §5.3 — /opt/zeek/share/zeek/site/interlock-detect.zeek
##!
##! Loaded by appending `@load interlock-detect.zeek` to local.zeek.
##! Deploy with: zeekctl check && zeekctl deploy && zeekctl status
##!
##! Notice types raised here are written to /opt/zeek/logs/current/notice.log
##! and pair with the Suricata SIDs and Wazuh rules of the same name.

@load base/protocols/http

module InterlockDetect;

export {
    redef enum Notice::Type += {
        Interlock_C2_Beacon,
        Interlock_Data_Exfil,
        Interlock_PS_Download,
        Interlock_PowerShell_UA
    };
}

event http_request(c: connection, method: string,
    original_URI: string, unescaped_URI: string, version: string)
{
    if (method == "GET" && /\/cmd/ in original_URI)
        NOTICE([$note=Interlock_C2_Beacon,
            $msg=fmt("C2 beacon: %s -> %s %s", c$id$orig_h, method, original_URI),
            $conn=c, $identifier=cat(c$id$orig_h)]);

    if (method == "POST" && /\/exfil/ in original_URI)
        NOTICE([$note=Interlock_Data_Exfil,
            $msg=fmt("Data exfil: %s -> %s", c$id$orig_h, original_URI),
            $conn=c]);

    if (/\.ps1/ in original_URI)
        NOTICE([$note=Interlock_PS_Download,
            $msg=fmt("PowerShell download: %s -> %s", c$id$orig_h, original_URI),
            $conn=c]);
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if (is_orig && name == "USER-AGENT" && /PowerShell/ in value)
        NOTICE([$note=Interlock_PowerShell_UA,
            $msg=fmt("PowerShell UA from %s", c$id$orig_h),
            $conn=c]);
}
