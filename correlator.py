'''
Socket Correlation
'''

from collections import defaultdict

class Correlator(object):

    window = 0
    known_correlations = {}
    key_events = defaultdict(list)

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
        """
        Takes a json record and returns a tuple (key address information, record)
        """
        if json_record["event"] == "fbt:kernel:cc_conn_init:":
            cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("so_uuid", None)
#             print(self.key_events[(json_record["faddr"], json_record["fport"])])
#             print(json_record)
            self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
#             print(self.key_events[(json_record["faddr"], json_record["fport"])])
        if json_record["event"] == "audit:event:aue_accept:":
            cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("ret_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        if json_record["event"] == "audit:event:aue_connect:":
            cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        if json_record["event"] == "audit:event:aue_recvfrom:":
            cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        if json_record["event"] == "audit:event:aue_recvmsg:":
            cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        if json_record["event"] == "audit:event:aue_sendto:":
            cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        if json_record["event"] == "udp:kernel:none:":
            cleanup_record(json_record)
            json_record["uuid"] = json_record.pop("so_uuid", None)
            self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
#         return json_record



    def link_events(self, event):
        """
        Takes an event and a map from key uuids to events.
        Returns a list of 5-tuples, consisting of
        (host1, uuid1, host2, uuid2, reason for correlation)
        """

        keyed_events = self.key_events
        links = []
        local_port = event.get("lport", None)
        local_addr = event.get("laddr", None)
        if not local_port or not local_addr:
            return links

        json_records = keyed_events[(local_addr, local_port)]
#         json_records = dict(keyed_events).get((local_addr, local_port), [])
#         print(self.key_events)
#         print(len(json_records))
        if json_records:
            for record in json_records:
                if abs(record["time"] - event["time"]) < self.window:
                    if (event["uuid"], record["uuid"]) not in self.known_correlations:
                        self.known_correlations[(event["uuid"], record["uuid"])] = True
                        links.append((event["host"], event["uuid"], record["host"], record["uuid"], "connected sockets"))
        return links

def cleanup_record(json_record):
    """
    Takes a cadets json event and removes irrelevant parts
    """
    return
    json_record.pop("event", None)
    json_record.pop("fd", None)
    json_record.pop("retval", None)
    json_record.pop("cpu_id", None)
    json_record.pop("uid", None)
    json_record.pop("pid", None)
    json_record.pop("ppid", None)
    json_record.pop("tid", None)
    json_record.pop("subjthruuid", None)
    json_record.pop("subjprocuuid", None)

