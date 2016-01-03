import json
import logging
import os
import string
import ConfigParser

class CardDatabase(object):

    def __init__(self, cards_filename, readers_filename):
        self.cards_filename = cards_filename
        self.readers_filename = readers_filename
        self.cards_filetime = None
        self.readers_filetime = None
        self.data = None
        self.reload()

    def _load_cards(self):
        data = {}
        c = ConfigParser.ConfigParser()
        c.read(self.cards_filename)
        for name in c.sections():
            data[name] = {"cards": {}, "groups": [], "private": False}
            if c.has_option(name, "groups"):
                data[name]["groups"] = c.get(name, "groups").strip().split()
            if c.has_option(name, "private"):
                data[name]["private"] = c.getboolean(name, "private")
                logging.info("user %s private=%s" % (name, data[name]["private"]))
            for uid in c.options(name):
                if len(uid) == 8 or len(uid) == 14:
                    if uid not in ["groups", "private"]:
                        data[name]["cards"][uid.upper()] = c.get(name, uid)
        return data

    def _load_readers(self):
        data = {}
        c = ConfigParser.ConfigParser()
        c.read(self.readers_filename)
        for readerid in c.sections():
            data[readerid] = {"name": readerid, "groups": [], "settings": {}}
            for option in c.options(readerid):
                if option.lower() == "name":
                    data[readerid]["name"] = c.get(readerid, "name")
                elif option.lower() == "groups":
                    data[readerid]["groups"] = c.get(readerid, "groups").strip().split()
                else:
                    data[readerid]["settings"][option] = c.get(readerid, option)
        return data

    def reload(self):
        new_cards_filetime = os.path.getmtime(self.cards_filename)
        new_readers_filetime = os.path.getmtime(self.readers_filename)
        new_data = {"people": self._load_cards(), "readers": self._load_readers()}
        self.data = new_data
        self.cards_filetime = new_cards_filetime
        self.readers_filetime = new_readers_filetime
        logging.debug("database reloaded")
        logging.debug(json.dumps(self.data, indent=2))

    def autoreload(self):
        if self.cards_filetime is None or self.readers_filetime is None:
            logging.debug("loading database (first time)")
            self.reload()
        else:
            new_cards_filetime = os.path.getmtime(self.cards_filename)
            new_readers_filetime = os.path.getmtime(self.readers_filename)
            if new_cards_filetime != self.cards_filetime or new_readers_filetime != self.readers_filetime:
                logging.debug("database changed, reloading")
                self.reload()

    def timestamp(self):
        return max(self.cards_filetime, self.readers_filetime)

    def auth(self, reader, uid):
        uid = uid.upper()
        logging.debug("attempting to authorize %s on reader %s" % (uid, reader))
        allowed_groups = self.data["readers"][reader]["groups"]
        logging.debug("allowed groups for reader %s are %r" % (reader, allowed_groups))
        for person in self.data["people"].keys():
            for card in self.data["people"][person]["cards"].keys():
                token_name = self.data["people"][person]["cards"][card]
                if uid == card:
                    logging.debug("uid %s belongs to %s (%s)" % (uid, person, token_name))
                    for group in self.data["people"][person]["groups"]:
                        if group in allowed_groups:
                            logging.info("uid %s (%s) is authorized to use reader %s via group %s" % (uid, person, reader, group))
                            private = self.data["people"][person]["private"]
                            return True, person, token_name, private
        logging.info("uid %s is not authorized to use reader %s" % (uid, reader))
        return False, None, None, None

    def cards_for_reader(self, reader):
        uids = {}
        groups = self.data["readers"][reader]["groups"]
        for person in self.data["people"].keys():
            for group in self.data["people"][person]["groups"]:
                if group in groups:
                    #logging.debug("adding %s to reader %s (group %s)" % (person, reader, group))
                    for uid in self.data["people"][person]["cards"].keys():
                        uids[uid] = True
        return sorted(uids.keys())

    def reader_name(self, reader):
        return self.data["readers"][reader].get("name", reader)

    def reader_settings(self, reader):
        return self.data["readers"][reader]["settings"]
