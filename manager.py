import copy
import logging
import time
import pprint

class Syncer(object):

    def __init__(self):
        self.slots = 0
        self.uids = []
        self.reader_data = {}

    def clear(self):
        self.reader_data = {}

    def setSlots(self, slots):
        self.slots = slots
        #self.sections = {}
        #for section in range(0, self.slots/self.slots_per_packet):
        #    self.sections[section] = {
        #        "start": section*self.slots_per_packet,
        #        "end": ((section+1)*self.slots_per_packet)-1,
        #        "lastrequested": None,
        #        "lastreceived": None
        #        }

    def receivedSlot(self, slot, uid):
        self.reader_data[slot] = uid

    def setUids(self, uids):
        self.uids = uids

    def check(self):
        missing = []
        for slot in range(0, self.slots):
            if not self.reader_data.has_key(slot):
                missing.append(slot)
        if len(missing) == 0:
            return True
        else:
            return False

    def changes(self):
        target_data = copy.deepcopy(self.reader_data)
        uids = copy.deepcopy(self.uids)

        logging.debug("changes(), %d slots" % (self.slots))

        for slot in range(0, self.slots):
            if target_data[slot] == "FFFFFFFFFFFFFF":
                target_data[slot] = ""
            if target_data[slot].lstrip("0") == "":
                target_data[slot] = ""
            if target_data[slot] in uids:
                logging.debug("slot %s: keep %s" % (slot, target_data[slot]))
                uids.remove(target_data[slot])
            else:
                target_data[slot] = ""

        for slot in range(0, self.slots):
            if len(uids) == 0:
                logging.debug("no more uids to add")
                break
            if target_data[slot] == "":
                target_data[slot] = uids.pop()
                logging.debug("setting slot %s = %s" % (slot, target_data[slot]))

        if len(uids) > 0:
            logging.warning("out of slots, uids=%r" % (uids))

        output = []
        #for slot in range(0, self.slots):
        #    if target_data[slot] != self.reader_data[slot]:
        #        print "sending %s = %s" % (slot, target_data[slot])
        #        output.append({"type": "databaseset", "slot": slot, "uid": target_data[slot]})

        changelist = {}
        for slot in range(0, self.slots):
            if target_data[slot] != self.reader_data[slot]:
                changelist[slot] = target_data[slot]
                logging.info("change slot %d: %s -> %s" % (slot, self.reader_data[slot], target_data[slot]))
                if len(changelist.keys()) >= 128:
                    output.append({"type": "databaseset", "slots": changelist})
                    changelist = {}

        if len(changelist.keys()) > 0:
            output.append({"type": "databaseset", "slots": changelist})

        logging.debug("changes() returning %r" % (output))
        return output

class Reader(object):

    def __init__(self, readerid, database, addr,
                 sync_interval=3600, amqp_outbound=None, auth_logger=None,
                 token_sighting_queue=None, send_anonymous=False, mqtt_outbound=None):
        self.readerid = readerid
        self.database = database
        self.addr = addr
        self.sync_interval = sync_interval
        self.amqp_outbound = amqp_outbound
        self.mqtt_outbound = mqtt_outbound
        self.auth_logger = auth_logger
        self.token_sighting_queue = token_sighting_queue
        self.send_anonymous = send_anonymous

        self.database_timestamp = self.database.timestamp()
        self.reader_name = self.database.reader_name(readerid)
        self.mqtt_readerid = self.database.reader_id(readerid)

        self.syncer = Syncer()
        self.vars = {}
        self.var_timestamps = {}
        self.cards = {}
        self.card_timestamps = {}

        self.sync_scheduled = True
        self.sync_waiting_for_data_since = None
        self.sync_changes_pending = False
        self.send_amqp_status = False

        logging.info("%s: connected from %s:%s" % (readerid, addr[0], addr[1]))

    def event(self, event_type, data):
        if event_type == "hello":
            return self.event_hello()
        elif event_type == "authrequest":
            return self.event_authrequest(data)
        elif event_type == "databasedump":
            return self.event_databasedump(data)
        elif event_type == "variables":
            return self.event_variables(data)
        else:
            return []

    def event_hello(self):
        return [{"type": "helloreply"}]

    def event_variables(self, data):
        oldvars = {}
        for k, vnew in data.items():
            if k == "type":
                continue
            oldvars[k] = self.vars.get(k, None)
            self.vars[k] = vnew
            self.var_timestamps[k] = time.time()
        for k, vnew in data.items():
            if k == "type":
                continue
            if vnew != oldvars[k]:
                self._variable_changed(k, oldvars[k], vnew)
        if self.send_amqp_status and self.amqp_outbound:
            m = {"door": self.reader_name}
            if self.vars["snibUnlockActive"] is False:
                m["locked"] = True
            else:
                m["locked"] = False
            m["state"] = self.vars["doorState"]
            self.amqp_outbound.put(("door.status", m))
            self.send_amqp_status = False
        return []

    def _variable_changed(self, k, vold, vnew):
        if self.mqtt_outbound:
            if k not in ["authUid", "millis", "macAddress", "chipId", "flashChipId"]:
                self.mqtt_outbound.put(("%s/var/%s" % (self.mqtt_readerid, k), vnew, True))
        if k == "authState":
            if vnew in ["local-granted", "local-denied", "network-granted", "network-denied"]:
                uid = self.vars.get("authUid", None)
                authorized, name, token_name, private = self.database.auth(self.readerid, uid)
                message = {
                    "uid": uid,
                    "name": name,
                    "token": token_name,
                    "authorizedByDatabase": authorized,
                    "reader": self.readerid,
                    "door": self.reader_name
                }
                if vnew.startswith("local-"):
                    message["type"] = "local"
                elif vnew.startswith("network-"):
                    message["type"] = "network"
                if vnew.endswith("-granted"):
                    message["authorized"] = True
                elif vnew.endswith("-denied"):
                    message["authorized"] = False
                if message["authorized"] != message["authorizedByDatabase"]:
                    message["conflict"] = True
                    logging.warning(self.readerid + ": auth - uid=%(uid)s name=%(name)r token=%(token)r type=%(type)s authorized=%(authorized)s authorizedByDatabase=%(authorizedByDatabase)s!" % message)
                else:
                    logging.info(self.readerid + ": auth - uid=%(uid)s name=%(name)r token=%(token)r type=%(type)s authorized=%(authorized)s" % message)
                if self.auth_logger:
                    self.auth_logger.write(message)
                if self.amqp_outbound:
                    if authorized == True:
                        if private:
                            if self.send_anonymous:
                                self.amqp_outbound.put(("door.swipe", {"door": self.reader_name, "reader": "nfc", "name": "Anonymous", "token": "Anonymous", "authorized": True, "auth_type": message["type"]}))
                        else:
                            self.amqp_outbound.put(("door.swipe", {"door": self.reader_name, "reader": "nfc", "name": name, "token": token_name, "authorized": True, "auth_type": message["type"]}))
                    else:
                        self.amqp_outbound.put(("door.swipe", {"door": self.reader_name, "reader": "nfc", "uid": uid, "authorized": False, "auth_type": message["type"]}))
                if self.mqtt_outbound:
                    if authorized == True:
                        if private:
                            if self.send_anonymous:
                                self.mqtt_outbound.put(("%s/auth" % (self.mqtt_readerid), {"door": self.reader_name, "reader": "nfc", "name": "Anonymous", "token": "Anonymous", "authorized": True, "auth_type": message["type"]}, False))
                        else:
                            self.mqtt_outbound.put(("%s/auth" % (self.mqtt_readerid), {"door": self.reader_name, "reader": "nfc", "name": name, "token": token_name, "authorized": True, "auth_type": message["type"]}, False))
                    else:
                        self.mqtt_outbound.put(("%s/auth" % (self.mqtt_readerid), {"door": self.reader_name, "reader": "nfc", "uid": uid, "authorized": False, "auth_type": message["type"]}, False))
                if self.token_sighting_queue:
                    self.token_sighting_queue.put({"door": self.reader_name, "uid": uid, "authorized": authorized})
        if k == "millis":
            if vold is None:
                pass
            elif vnew < vold:
                # new millis is less than old value
                # assume that a restart has occurred
                # trigger database refresh
                self.sync_scheduled = True
                logging.info("%s: restart detected, scheduling a sync" % (self.readerid))
        if k in ["snibUnlockActive", "doorState"]:
            self.send_amqp_status = True
        #if vold is None:
        #    return
        if k in ["batteryAdc", "batteryVoltage", "millis"]:
            return
        logging.info("%s: %s = %s -> %s" % (self.readerid, k, vold, vnew))

    def event_authrequest(self, data):
        uid = data['uid']
        authorized, name, token, private = self.database.auth(self.readerid, uid)
        if authorized:
            return [{"type": "authresponse", "authorized": True, "uid": uid}]
        else:
            return [{"type": "authresponse", "authorized": False, "uid": uid}]

    def event_databasedump(self, data):
        for slot, uid in data["data"].items():
            self.cards[slot] = uid
            self.card_timestamps[slot] = time.time()
            self.syncer.receivedSlot(slot, uid)
        return []

    def outgoing(self):
        #for k in sorted(self.vars.keys()):
        #    print "%s=%s" % (k, self.vars[k]),
        #print
        #print "cards: ",
        #for k in sorted(self.cards.keys()):
        #    if self.cards[k] != "":
        #        print "%s" % (self.cards[k]),
        #print

        if self.database.timestamp() > self.database_timestamp:
            if self.sync_scheduled is False:
                logging.info("%s: database has been reloaded, scheduling a sync" % (self.readerid))
                self.sync_scheduled = True

        #if time.time()-self.lastDatabaseRequest > self.sync_interval and self.sync_requested is False:
        #    logging.info("%s: last sync was more than %s seconds ago, scheduling another sync" % (self.readerid, self.sync_interval))
        #    self.sync_scheduled = time.time()

        if self.vars.has_key("cardDatabaseSize"):
            if self.sync_scheduled:
                self.syncer.setSlots(self.vars["cardDatabaseSize"])
                self.lastDatabaseRequest = time.time()
                self.database_timestamp = self.database.timestamp()
                logging.info("%s: sync - requesting database from reader" % (self.readerid))
                yield {"type": "databaserequest", "start": 0, "end": self.vars["cardDatabaseSize"]-1}
                self.sync_waiting_for_data_since = time.time()
                self.sync_scheduled = False
                #self.sync_requested = False
                #self.sync_in_progress = True

            if self.sync_waiting_for_data_since:
                waiting = False
                for slot in range(0, self.vars["cardDatabaseSize"]):
                    if self.card_timestamps.get(slot, 0) < self.lastDatabaseRequest:
                        waiting = True
                if waiting is False:
                    logging.info("%s: sync - all data received from reader" % (self.readerid))
                    self.sync_waiting_for_data_since = None
                    #print "sync: sending changes"
                    changes = 0
                    self.syncer.setUids(self.database.cards_for_reader(self.readerid))
                    for response in self.syncer.changes():
                        changes += len(response["slots"])
                        #print "sync: %r" % (response)
                        yield response
                    #self.lastDatabaseCheck = time.time()
                    #self.sync_in_progress = False
                    if changes > 0:
                        logging.info("%s: sync - %s change(s) made, scheduling re-sync to verify" % (self.readerid, changes))
                        self.sync_scheduled = True
                        self.sync_changes_pending = True
                    else:
                        if self.sync_changes_pending:
                            logging.info("%s: sync - 0 changes made, committing" % (self.readerid))
                            yield {"type": "commiteeprom"}
                            self.sync_changes_pending = False
                        else:
                            logging.info("%s: sync - 0 changes made" % (self.readerid))
                    #print "sync: %d changes sent" % (changes)
                else:
                    if time.time()-self.sync_waiting_for_data_since > 10:
                        logging.warning("%s: sync - timeout waiting for data from reader, scheduling a new sync" % (self.readerid))
                        self.sync_scheduled = True
