rule HighRiskIP
{
    meta:
        description = "Detects traffic from known high-risk IP addresses"
        severity = "high"
    strings:
        $ip1 = "45.143.220.13"
        $ip2 = "103.27.124.82"
        $ip3 = "185.232.67.6"
    condition:
        any of ($ip*)
}

rule SuspiciousPortScan
{
    meta:
        description = "Detects repeated scanning on sensitive ports"
        severity = "medium"
    strings:
        $port1 = "22"
        $port2 = "23"
        $port3 = "3389"
    condition:
        any of ($port*)
}

rule ICMPFloodAttempt
{
    meta:
        description = "Detects possible ICMP flood attempts"
        severity = "high"
    strings:
        $icmp1 = "type=8 code=0"
        $icmp2 = "ICMP Echo Request"
    condition:
        any of ($icmp*)
}

rule BruteForceSSH
{
    meta:
        description = "Detects multiple failed SSH login attempts"
        severity = "high"
    strings:
        $ssh1 = "Failed password for"
        $ssh2 = "authentication failure"
    condition:
        any of ($ssh*)
}

rule MaliciousPayloadPattern
{
    meta:
        description = "Generic malicious pattern match in payload"
        severity = "critical"
    strings:
        $mal1 = "wget http://malicious"
        $mal2 = "curl -O http://danger"
        $mal3 = "bash -c"
    condition:
        any of ($mal*)
}

rule DNSExfiltration
{
    meta:
        description = "Detects DNS tunneling or data exfiltration via DNS"
        severity = "medium"
    strings:
        $dns1 = ".data."
        $dns2 = ".cmd."
        $dns3 = ".exfil."
    condition:
        any of ($dns*)
}
