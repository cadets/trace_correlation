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
        """ Return True if the event may be used in correlation """

        if not json_record:
            return False
        if json_record.get("event", "") in [
                "fbt:kernel:cc_conn_init:",
#                 "udp:kernel:none:",
                "audit:event:aue_accept:", "audit:event:aue_connect:",
                "audit:event:aue_recvfrom:", "audit:event:aue_recvmsg:",
                "audit:event:aue_sendto:", "audit:event:aue_sendmsg:"]:
            return True
        return False

    def key_event(self, json_record):
        """
        Takes a json record and returns a tuple (key address information, record)
        """
        if not json_record:
            return
        cleanup_record(json_record)
        if json_record["event"] == "fbt:kernel:cc_conn_init:":
            json_record["uuid"] = json_record.pop("so_uuid", None)
            self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        elif json_record["event"] == "audit:event:aue_accept:":
            json_record["uuid"] = json_record.pop("ret_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        elif json_record["event"] == "audit:event:aue_connect:":
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        elif json_record["event"] == "audit:event:aue_recvfrom:":
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        elif json_record["event"] == "audit:event:aue_recvmsg:":
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        elif json_record["event"] == "audit:event:aue_sendto:":
            json_record["uuid"] = json_record.pop("arg_objuuid1", None)
            json_record["faddr"] = json_record.pop("address", None)
            json_record["fport"] = json_record.pop("port", None)
            if json_record.get("faddr") and json_record.get("fport"):
                self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)
        elif json_record["event"] == "udp:kernel:none:":
            json_record["uuid"] = json_record.pop("so_uuid", None)
            self.key_events[(json_record["faddr"], json_record["fport"])].append(json_record)



    def link_events(self, event):
        """
        Takes an event and a map from key uuids to events.
        Returns a list of 5-tuples, consisting of
        (host1, uuid1, host2, uuid2, reason for correlation)
        """

        if not event:
            return []

        local_port = event.get("lport")
        local_addr = event.get("laddr")
        if not local_port or not local_addr or not event.get("uuid"):
            return []

        links = []
        for record in self.key_events[(local_addr, local_port)]:
            if abs(record["time"] - event["time"]) < self.window:
                if (event["uuid"], record["uuid"]) not in self.known_correlations:
                    self.known_correlations[(event["uuid"], record["uuid"])] = True
                    links.append((max(record["time"], event["time"]),
                                  event["host"], event["uuid"],
                                  record["host"], record["uuid"],
                                  "connected sockets"))
        return links

def cleanup_record(json_record):
    """
    Takes a cadets json event and removes irrelevant parts

    Useful for debugging (since it reduces data to look at), but not for
    normal use.
    """
#     json_record.pop("event", None)
#     json_record.pop("fd", None)
#     json_record.pop("retval", None)
#     json_record.pop("cpu_id", None)
#     json_record.pop("uid", None)
#     json_record.pop("pid", None)
#     json_record.pop("ppid", None)
#     json_record.pop("tid", None)
#     json_record.pop("subjthruuid", None)
#     json_record.pop("subjprocuuid", None)
    return
