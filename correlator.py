"""
* Copyright 2018 Amanda Strnad <amanda.strnad@baesystems.com>
*
* This software was developed by BAE Systems, the University of Cambridge
* Computer Laboratory, and Memorial University under DARPA/AFRL contract
* FA8650-15-C-7558 (“CADETS”), as part of the DARPA Transparent Computing
* (TC) research program.
*
"""

'''
Socket Correlation
'''

class Correlator(object):

    window = 0
    known_correlations = {}

    def __init__(self, time_window):
        self.window = time_window

    def event_filter(self, json_record):
        if not json_record:
            return False
        if json_record["event"] in [
                "fbt:kernel:cc_conn_init:",
                "audit:event:aue_accept:", "audit:event:aue_connect:",
                "audit:event:aue_recvfrom:", "audit:event:aue_recvmsg:",
                "audit:event:aue_sendto:", "audit:event:aue_sendmsg:",
                "udp:kernel:none:"]:
            return True
        return False

    def key_event(self, json_record):
        if json_record["event"] == "fbt:kernel:cc_conn_init:":
            self.cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("so_uuid", None)
            return ((json_record["faddr"], json_record["fport"]), json_record)
        if json_record["event"] == "audit:event:aue_accept:":
            self.cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("ret_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            return ((json_record["faddr"], json_record["fport"]), json_record)
        if json_record["event"] == "audit:event:aue_connect:":
            self.cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                return ((json_record["faddr"], json_record["fport"]), json_record)
            else:
                return (None, json_record)
        if json_record["event"] == "audit:event:aue_recvfrom:":
            self.cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                return ((json_record["faddr"], json_record["fport"]), json_record)
            else:
                return (None, json_record)
        if json_record["event"] == "audit:event:aue_recvmsg:":
            self.cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                return ((json_record["faddr"], json_record["fport"]), json_record)
            else:
                return (None, json_record)
        if json_record["event"] == "audit:event:aue_sendto:":
            self.cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                return ((json_record["faddr"], json_record["fport"]), json_record)
            else:
                return (None, json_record)
        if json_record["event"] == "udp:kernel:none:":
            self.cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("so_uuid", None)
            return ((json_record["faddr"], json_record["fport"]), json_record)

        return (None, json_record)

    def cleanup_record(self, json_record):
        json_record.pop("event", None)
        json_record.pop("host", None)
        json_record.pop("fd", None)
        json_record.pop("retval", None)
        json_record.pop("cpu_id", None)
        json_record.pop("uid", None)
        json_record.pop("pid", None)
        json_record.pop("ppid", None)
        json_record.pop("tid", None)
        json_record.pop("subjthruuid", None)
        json_record.pop("subjprocuuid", None)


    def link_events(self, event, keyed_events):
        links = []
        local_port = event.get("lport", None)
        local_addr = event.get("laddr", None)
        if not local_port or not local_addr:
            return links

        json_records = dict(keyed_events).get((local_addr, local_port), [])
        if json_records:
            for record in json_records:
                if abs(record["time"] - event["time"]) < self.window:
                    if (event["uuid"], record["uuid"]) not in self.known_correlations:
                        self.known_correlations[(event["uuid"], record["uuid"])] = True
                        links.append((event["uuid"], record["uuid"], "connected sockets"))
        return links
