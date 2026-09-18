import json
DS = {"type": "prometheus", "uid": "efdqq22ymisqod"}
pid = [0]
def nid(): pid[0]+=1; return pid[0]
def tgt(expr, legend=None):
    t = {"datasource": DS, "expr": expr, "refId": "A"}
    if legend: t["legendFormat"] = legend
    return t
def stat(title, expr, x, y, w=4, h=4, unit="none"):
    return {"id": nid(),"type":"stat","title":title,"datasource":DS,
        "gridPos":{"h":h,"w":w,"x":x,"y":y},"targets":[tgt(expr)],
        "fieldConfig":{"defaults":{"unit":unit,"color":{"mode":"thresholds"},
            "thresholds":{"mode":"absolute","steps":[{"color":"green","value":None}]}},"overrides":[]},
        "options":{"reduceOptions":{"calcs":["lastNotNull"]},"colorMode":"value","graphMode":"area","textMode":"auto","justifyMode":"auto"}}
def ts(title, targets, x, y, w=12, h=8, unit="none", stack=False):
    return {"id": nid(),"type":"timeseries","title":title,"datasource":DS,
        "gridPos":{"h":h,"w":w,"x":x,"y":y},"targets":targets,
        "fieldConfig":{"defaults":{"unit":unit,"custom":{"drawStyle":"line",
            "fillOpacity":40 if stack else 15,"stacking":{"mode":"normal" if stack else "none"},
            "lineWidth":2,"showPoints":"never"}},"overrides":[]},
        "options":{"legend":{"displayMode":"list","placement":"bottom"},"tooltip":{"mode":"multi"}}}
def row(title, y): return {"id":nid(),"type":"row","title":title,"collapsed":False,"gridPos":{"h":1,"w":24,"x":0,"y":y},"panels":[]}

P=[]; y=0
# Overview
P.append(row("Overview", y)); y+=1
P += [stat("Active calls","sbc_active_calls",0,y),
      stat("Active WebRTC","sbc_active_webrtc_calls",4,y),
      stat("Registrations","sbc_active_registrations",8,y),
      stat("RTP ports in use","sbc_allocated_rtp_ports",12,y),
      stat("Last CDR age","time() - sbc_last_cdr_written_timestamp_seconds",16,y,unit="s"),
      stat("Uptime","sbc_uptime_seconds",20,y,unit="s")]
y+=4
# Calls
P.append(row("Calls & registrations", y)); y+=1
P.append(ts("Call rate (per min)",[
    tgt("rate(sbc_calls_total[5m])*60","attempted"),
    tgt("rate(sbc_calls_connected_total[5m])*60","connected"),
    tgt("rate(sbc_calls_failed_total[5m])*60","failed"),
    tgt("rate(sbc_calls_terminated_total[5m])*60","terminated (BYE)"),
],0,y,unit="cpm"))
P.append(ts("Call outcome ratio",[
    tgt("rate(sbc_calls_connected_total[5m]) / clamp_min(rate(sbc_calls_total[5m]),0.0001)","connected %"),
    tgt("rate(sbc_calls_failed_total[5m]) / clamp_min(rate(sbc_calls_total[5m]),0.0001)","failed %"),
],12,y,unit="percentunit"))
y+=8
P.append(ts("Active sessions (trend)",[
    tgt("sbc_active_calls","calls"),
    tgt("sbc_active_webrtc_calls","webrtc"),
    tgt("sbc_active_registrations","registrations"),
],0,y))
P.append(ts("REGISTER rate (per min)",[tgt("rate(sbc_registrations_total[5m])*60","successful REGISTER")],12,y,unit="cpm"))
y+=8
# SIP traffic
P.append(row("SIP traffic", y)); y+=1
P.append(ts("SIP requests by method (rate/s)",[tgt("rate(sbc_sip_requests_by_method[5m])","{{method}}")],0,y,unit="reqps",stack=True))
P.append(ts("SIP responses by code (rate/s)",[tgt("rate(sbc_sip_responses_by_code[5m])","{{code}}")],12,y,unit="reqps",stack=True))
y+=8
P.append(ts("SIP total throughput (rate/s)",[
    tgt("rate(sbc_sip_requests_total[5m])","requests"),
    tgt("rate(sbc_sip_responses_total[5m])","responses"),
],0,y,unit="reqps"))
P.append(ts("SIP error responses (rate/s)",[
    tgt("rate(sbc_sip_4xx_total[5m])","4xx"),
    tgt("rate(sbc_sip_5xx_total[5m])","5xx"),
],12,y,unit="reqps"))
y+=8
# Security
P.append(row("Security & anti-fraud", y)); y+=1
P.append(ts("Auth (rate/s)",[
    tgt("rate(sbc_auth_challenges_total[5m])","challenges"),
    tgt("rate(sbc_auth_failures_total[5m])","failures"),
],0,y,unit="reqps"))
P.append(ts("Blocked (rate/s)",[
    tgt("rate(sbc_spam_blocked_total[5m])","spam (unregistered INVITE)"),
    tgt("rate(sbc_dos_blocked_total[5m])","dos (rate limit)"),
    tgt("rate(sbc_acl_denied_total[5m])","acl"),
],12,y,unit="reqps"))
y+=8
# Anti-fraud (Phase E)
P.append(row("Anti-fraud (fail2ban / IRSF / limits)", y)); y+=1
P.append(ts("Bans & drops (rate/s)",[
    tgt("rate(sbc_security_bans_total[5m])","bans issued"),
    tgt("rate(sbc_security_ban_drops_total[5m])","banned-source drops"),
],0,y,unit="reqps"))
P.append(ts("Fraud blocks (rate/s)",[
    tgt("rate(sbc_security_destination_blocked_total[5m])","destination blocked (IRSF)"),
    tgt("rate(sbc_security_user_limit_rejections_total[5m])","user-limit rejections"),
],12,y,unit="reqps"))
y+=8
# Media
P.append(row("Media", y)); y+=1
P.append(ts("RTP throughput (packets/s)",[
    tgt("rate(sbc_rtp_packets_total[5m])","rtp forwarded"),
    tgt("rate(sbc_transcoded_packets_total[5m])","transcoded"),
],0,y,unit="pps"))
P.append(ts("SRTP (packets/s)",[
    tgt("rate(sbc_srtp_encrypted_total[5m])","encrypted"),
    tgt("rate(sbc_srtp_decrypted_total[5m])","decrypted"),
],12,y,unit="pps"))
y+=8
# Trunks — fed by real calls (sbc/trunk_state.rs) and OPTIONS health checks
P.append(row("Trunks", y)); y+=1
P += [stat("Trunks up","sum(sbc_trunk_up)",0,y,w=4),
      stat("Trunks down","count(sbc_trunk_up == 0) or vector(0)",4,y,w=4),
      stat("Trunk registrations failing","count(sbc_trunk_registered == 0) or vector(0)",8,y,w=4),
      stat("Calls on trunks","sum(sbc_trunk_active_calls)",12,y,w=4),
      stat("Setup p95 (30m)","histogram_quantile(0.95, sum(rate(sbc_call_setup_seconds_bucket[30m])) by (le))",16,y,w=4,unit="s"),
      stat("Duration p50 (1h)","histogram_quantile(0.5, sum(rate(sbc_call_duration_seconds_bucket[1h])) by (le))",20,y,w=4,unit="s")]
y+=4
P += [ts("Trunk health (1 = answers OPTIONS) and availability (router selects it)",[tgt("sbc_trunk_up","{{trunk}} up"),tgt("sbc_trunk_available","{{trunk}} available")],0,y),
      ts("Active calls per trunk",[tgt("sbc_trunk_active_calls","{{trunk}}")],12,y,stack=True)]
y+=8
P += [ts("Outbound ASR per trunk (30m)",[tgt('sum by (trunk)(rate(sbc_trunk_calls_total{direction="outbound",outcome="answered"}[30m])) / sum by (trunk)(rate(sbc_trunk_calls_total{direction="outbound"}[30m]))',"{{trunk}}")],0,y,unit="percentunit"),
      ts("Finished calls per trunk by direction/outcome (/min)",[tgt("sum by (trunk, direction, outcome)(rate(sbc_trunk_calls_total[5m])) * 60","{{trunk}} {{direction}} {{outcome}}")],12,y,stack=True)]
y+=8
# Health
P.append(row("Health", y)); y+=1
P += [stat("Last CDR age","time() - sbc_last_cdr_written_timestamp_seconds",0,y,w=6,unit="s"),
      stat("RTP timeouts (total)","sbc_rtp_timeouts_total",6,y,w=6),
      stat("SIP parse errors (total)","sbc_sip_parse_errors_total",12,y,w=6),
      stat("Failed calls (total)","sbc_calls_failed_total",18,y,w=6)]
y+=4
P += [stat("CDR write errors","sum(sbc_cdr_write_errors_total) or vector(0)",0,y,w=6),
      stat("CDR queue","sbc_cdr_queue_length",6,y,w=6),
      stat("CDRs written (total)","sbc_cdrs_written_total",12,y,w=6),
      stat("CDRs purged (total)","sbc_cdrs_purged_total",18,y,w=6)]
y+=4
P += [stat("Config store available","sbc_store_available",0,y,w=6),
      stat("Last store backup age","time() - sbc_store_backup_last_success_timestamp_seconds",6,y,w=6,unit="s"),
      stat("Store backup failures (24h)","increase(sbc_store_backup_failures_total[1d])",12,y,w=6),
      stat("Last backup size","sbc_store_backup_last_bytes",18,y,w=6,unit="bytes")]
y+=4
# A steady rate here means a trunk's Min-SE floor is above [security]
# session_expires: the SBC pays a 422 round trip on every call until it is raised.
P += [stat("Session-timer 422 retries (total)","sbc_session_timer_422_retries_total",0,y,w=6)]
y+=4

dash={"uid":"nixi-sbc-overview","title":"NIXI SBC — Overview","tags":["sbc","nixi"],
    "timezone":"browser","schemaVersion":39,"version":4,"refresh":"30s",
    "time":{"from":"now-6h","to":"now"},"editable":True,"panels":P}
print(json.dumps(dash,indent=2))
