"""Ready-to-run KQL hunting queries for Microsoft Defender XDR / Microsoft Sentinel."""

from __future__ import annotations

from emailicioso.core.models import Address, HuntingQuery, IOCSet, ParsedEmail

MAX_ITEMS = 50


def kql_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'


def kql_list(values: list[str]) -> str:
    vals = list(dict.fromkeys(v for v in values if v))[:MAX_ITEMS]
    return "dynamic([" + ", ".join(kql_string(v) for v in vals) + "])"


def build_queries(
    parsed: ParsedEmail,
    sender: Address | None,
    iocs: IOCSet,
    network_message_id: str = "",
    lookback: str = "30d",
) -> list[HuntingQuery]:
    q: list[HuntingQuery] = []
    mid = parsed.message_id.strip()
    sender_addr = sender.address if sender else ""
    sender_dom = sender.domain if sender else ""
    subject = parsed.subject.strip()

    if mid or network_message_id:
        conds = []
        if network_message_id:
            conds.append(f"NetworkMessageId == {kql_string(network_message_id)}")
        if mid:
            conds.append(f"InternetMessageId == {kql_string(mid)}")
        q.append(HuntingQuery(
            "This exact message in the tenant",
            "Every copy of this message, who received it and where it was delivered.",
            f"""EmailEvents
| where Timestamp > ago({lookback})
| where {' or '.join(conds)}
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, SenderMailFromAddress,
          SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes,
          DetectionMethods, LatestDeliveryAction, LatestDeliveryLocation
| order by Timestamp desc""",
            ["EmailEvents"],
        ))

    if sender_addr or subject:
        conds = []
        if sender_addr:
            conds.append(f"SenderFromAddress =~ {kql_string(sender_addr)}")
            conds.append(f"SenderMailFromAddress =~ {kql_string(sender_addr)}")
        if subject:
            conds.append(f"Subject == {kql_string(subject)}")
        q.append(HuntingQuery(
            "Campaign: same sender or subject",
            "Other messages from the same sender or with the same subject, grouped to size the campaign.",
            f"""EmailEvents
| where Timestamp > ago({lookback})
| where {' or '.join(conds)}
| summarize Messages = count(), Recipients = dcount(RecipientEmailAddress),
            RecipientList = make_set(RecipientEmailAddress, 100),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by SenderFromAddress, Subject, DeliveryAction, DeliveryLocation
| order by Messages desc""",
            ["EmailEvents"],
        ))

    if sender_dom:
        q.append(HuntingQuery(
            "Everything from the sender domain",
            "All mail from the sender's domain (From or envelope), useful for lookalike domains.",
            f"""EmailEvents
| where Timestamp > ago({lookback})
| where SenderFromDomain =~ {kql_string(sender_dom)} or SenderMailFromDomain =~ {kql_string(sender_dom)}
| summarize Messages = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 20)
            by SenderFromAddress, DeliveryAction
| order by Messages desc""",
            ["EmailEvents"],
        ))

    if iocs.domains:
        doms = kql_list(iocs.domains)
        q.append(HuntingQuery(
            "Messages containing the same URL domains",
            "Messages whose body links to any of the extracted domains, with delivery status.",
            f"""let IocDomains = {doms};
EmailUrlInfo
| where Timestamp > ago({lookback})
| where UrlDomain in~ (IocDomains)
| join kind=inner (EmailEvents | where Timestamp > ago({lookback})) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url, DeliveryAction, DeliveryLocation
| order by Timestamp desc""",
            ["EmailUrlInfo", "EmailEvents"],
        ))
        q.append(HuntingQuery(
            "Who clicked the links",
            "Safe Links click telemetry for the extracted domains (IsClickedThrough = went past the warning).",
            f"""let IocDomains = {doms};
UrlClickEvents
| where Timestamp > ago({lookback})
| extend Host = tostring(parse_url(Url).Host)
| where Host in~ (IocDomains) or Url has_any (IocDomains)
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, Workload, NetworkMessageId
| order by Timestamp desc""",
            ["UrlClickEvents"],
        ))
        q.append(HuntingQuery(
            "Endpoint connections to the domains",
            "Devices that resolved/connected to the extracted domains (proxy, browser, malware callbacks).",
            f"""let IocDomains = {doms};
DeviceNetworkEvents
| where Timestamp > ago({lookback})
| where RemoteUrl has_any (IocDomains)
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Processes = make_set(InitiatingProcessFileName, 10)
            by DeviceName, RemoteUrl, RemoteIP
| order by LastSeen desc""",
            ["DeviceNetworkEvents"],
        ))

    if iocs.ips:
        ips = kql_list(iocs.ips)
        q.append(HuntingQuery(
            "Mail and endpoint activity for the IPs",
            "Messages sent from the extracted IPs and devices talking to them.",
            f"""let IocIps = {ips};
union
  (EmailEvents | where Timestamp > ago({lookback}) | where SenderIPv4 in (IocIps) or SenderIPv6 in (IocIps)
   | project Timestamp, Source = "EmailEvents", Ip = coalesce(SenderIPv4, SenderIPv6),
             Detail = strcat(SenderFromAddress, " -> ", RecipientEmailAddress, " | ", Subject)),
  (DeviceNetworkEvents | where Timestamp > ago({lookback}) | where RemoteIP in (IocIps)
   | project Timestamp, Source = "DeviceNetworkEvents", Ip = RemoteIP,
             Detail = strcat(DeviceName, " | ", InitiatingProcessFileName, " | ", RemoteUrl))
| order by Timestamp desc""",
            ["EmailEvents", "DeviceNetworkEvents"],
        ))

    if iocs.hashes:
        hashes = kql_list([h["sha256"] for h in iocs.hashes])
        q.append(HuntingQuery(
            "Attachments: delivery and execution",
            "Who received the attachments and whether the files appeared or ran on any device.",
            f"""let IocSha256 = {hashes};
union
  (EmailAttachmentInfo | where Timestamp > ago({lookback}) | where SHA256 in (IocSha256)
   | project Timestamp, Source = "EmailAttachmentInfo", FileName, SHA256,
             Who = RecipientEmailAddress, Detail = SenderFromAddress),
  (DeviceFileEvents | where Timestamp > ago({lookback}) | where SHA256 in (IocSha256)
   | project Timestamp, Source = "DeviceFileEvents", FileName, SHA256, Who = DeviceName, Detail = FolderPath),
  (DeviceProcessEvents | where Timestamp > ago({lookback}) | where SHA256 in (IocSha256)
   | project Timestamp, Source = "DeviceProcessEvents", FileName, SHA256, Who = DeviceName, Detail = ProcessCommandLine)
| order by Timestamp desc""",
            ["EmailAttachmentInfo", "DeviceFileEvents", "DeviceProcessEvents"],
        ))

    if q and (mid or network_message_id):
        cond = (f"NetworkMessageId == {kql_string(network_message_id)}" if network_message_id
                else f"InternetMessageId == {kql_string(mid)}")
        q.append(HuntingQuery(
            "Post-delivery events (ZAP, moves, deletions)",
            "Zero-hour auto purge, admin remediation or user actions on this message after delivery.",
            f"""EmailPostDeliveryEvents
| where Timestamp > ago({lookback})
| join kind=inner (EmailEvents | where Timestamp > ago({lookback}) | where {cond}
                   | distinct NetworkMessageId) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, Action, ActionType, ActionTrigger, ActionResult, DeliveryLocation
| order by Timestamp desc""",
            ["EmailPostDeliveryEvents", "EmailEvents"],
        ))
    return q
