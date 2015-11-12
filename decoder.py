import struct
import logging
import pprint

data_variables = {
  # STATIC READ-ONLY
  0x01: ["macAddress", ">6B", "%02X:%02X:%02X:%02X:%02X:%02X"],
  0x02: ["chipId", ">I", "%08X"],
  0x03: ["flashChipId", ">I", "%08X"],
  0x04: ["flashChipSize", ">I", None],
  0x05: ["flashChipSpeed", ">I", None],
  0x06: ["cardDatabaseSize", ">H", None],
  # DYNAMIC READ-ONLY
  0x21: ["freeHeap", ">I", None],
  0x22: ["millis", ">I", None],
  0x23: ["doorState", ">B", {0: "closed", 1: "open"}],
  0x24: ["exitButtonState", ">B", {0: "up", 1: "down", 2: "longpress"}],
  0x25: ["snibButtonState", ">B", {0: "up", 1: "down", 2: "longpress"}],
  0x26: ["powerMode", ">B", {0: "mains", 1: "battery"}],
  0x27: ["batteryVoltage", ">H", 100.0],
  0x28: ["exitUnlockActive", ">B", {0: False, 1: True}],
  0x29: ["snibUnlockActive", ">B", {0: False, 1: True}],
  0x2A: ["cardUnlockActive", ">B", {0: False, 1: True}],
  #0x2B: ["lastAuthState", ">B", {0: "idle", 1: "swiped", 2: "network-granted", 3: "network-denied", 4: "local-granted", 5: "local-denied"}],
  0x2C: ["authUid", ">B7B", lambda uidlen, *uid: ("%02X"*len(uid) % uid)[0:uidlen*2]],
  0x2D: ["batteryAdc", ">H", None],
  0x2E: ["doorAjar", ">B", {0: False, 1: True}],
  0x2F: ["eepromChangesPending", ">B", {0: False, 1: True}],
  0x30: ["pn532ResetCount", ">H", None],
  0x31: ["secondsOffline", ">H", None],
  0x32: ["connectionCount", ">H", None],
  # DYNAMIC WRITABLE
  0x41: ["authState", ">B", {0: "idle", 1: "swiped", 2: "network-granted", 3: "network-denied", 4: "local-granted", 5: "local-denied", 6: "proxy-granted"}],
  0x42: ["snibEnabled", ">B", {0: False, 1: True}],
  0x43: ["exitEnabled", ">B", {0: False, 1: True}],
  0x44: ["doorForced", ">B", {0: False, 1: True}],
  # PERSISTENT WRITABLE
  0x61: ["cardUnlockTime", ">B", None],
  0x62: ["exitUnlockMinTime", ">B", 100.0],
  0x63: ["exitUnlockMaxTime", ">B", None],
  0x64: ["snibUnlockTime", ">H", None],
  0x65: ["pn532CheckInterval", ">B", None],
  0x66: ["authNetworkResendInterval", ">B", 1000.0],
  0x67: ["authNetworkTimeout", ">B", 10.0],
  0x68: ["voltageScaleMultiplier", ">H", None],
  0x69: ["voltageScaleDivider", ">H", None],
  0x6A: ["voltageRisingThreshold", ">H", 100.0],
  0x6B: ["voltageFallingThreshold", ">H", 100.0],
  0x6C: ["voltageCheckInterval", ">B", None],
  0x6D: ["cardPresentTimeout", ">B", 100.0],
  0x6E: ["longPressTime", ">B", 10.0],
  0x6F: ["systemInfoInterval", ">B", None],
  0x70: ["statusMinInterval", ">B", 10.0],
  0x71: ["statusMaxInterval", ">B", 10.0],
  0x72: ["doorAlarmTime", ">B", None],
  0x73: ["errorSoundsEnabled", ">B", {0: False, 1: True}],
  0x74: ["allowSnibOnBattery", ">B", {0: False, 1: True}],
  0x75: ["helloFastInterval", ">B", 100.0],
  0x76: ["helloSlowInterval", ">B", None],
  0x77: ["helloResponseTimeout", ">B", None],
}

def reverse_data_variables(fwd):
    rev = {}
    for i in fwd.keys():
        name = fwd[i][0].lower()
        fmt = fwd[i][1]
        process = fwd[i][2]
        if process is None:
            rev[name] = [i, fmt, None]
        elif type(process) in [int, float]:
            rev[name] = [i, fmt, process]
        elif type(process) is dict:
            revdict = {}
            for k, v in process.items():
                revdict[v] = k
            rev[name] = [i, fmt, revdict]
        else:
            logging.debug("cannot reverse variable %s" % (name))
    return rev

rev_data_variables = reverse_data_variables(data_variables)
#pprint.pprint(rev_data_variables)

def decode_var(data):
    var_type = ord(data[0])
    name, fmt, process = data_variables[var_type]
    required_length = struct.calcsize(fmt)
    unpacked = struct.unpack(fmt, data[1:required_length+1])
    remaining = data[required_length+1:]
    if process is None:
        # treat as number
        return (name, unpacked[0], remaining)
    elif type(process) in [int, float]:
        # treat as a divider
        return (name, unpacked[0]/process, remaining)
    elif type(process) in [str, unicode]:
        # treat as a format string
        return (name, process % unpacked, remaining)
    elif type(process) is dict:
        # treat as lookup table
        return (name, process[unpacked[0]], remaining)
    else:
        # treat as function
        return (name, process(*unpacked), remaining)

def encode_var(name, value):
    if value.lower() == 'true':
        value = True
    elif value.lower() == 'false':
        value = False
    else:
        value = float(value)
    var_code, fmt, process = rev_data_variables[name.lower()]
    if process is None:
        # treat as number
        return struct.pack("B", var_code) + struct.pack(fmt, value)
    elif type(process) in [int, float]:
        # treat as a divider
        return struct.pack("B", var_code) + struct.pack(fmt, value*process)
    elif type(process) is dict:
        # treat as lookup table
        return struct.pack("B", var_code) + struct.pack(fmt, process[value])

def encode_packet(data):
    if data["type"] == "helloreply":
        return chr(0x80)
    if data["type"] == "authresponse":
        if data["authorized"]:
            output = chr(0x91)+chr(2)
        else:
            output = chr(0x91)+chr(3)
        return output
    if data["type"] == "databaserequest":
        #print data
        output = chr(0x95) + struct.pack(">HH", data["start"], data["end"])
        return output
    if data["type"] == "databaseset":
        output = chr(0x93)
        for slot in data["slots"].keys():
            output = output + struct.pack(">H", int(slot)) + chr(len(data["slots"][slot])/2) + dehexify(data["slots"][slot])
        return output
    if data["type"] == "commiteeprom":
        output = chr(0x94)
        return output
    if data["type"] == "variableset":
        output = ""
        for k, v in data.iteritems():
            if k != "type":
                chunk = encode_var(k, v)
                if chunk:
                    output = output + chr(0x97) + chunk
        return output

def decode_packet(data):
    if data[0] == chr(0):
        return {"type": "hello", "clientid": data[1:].rstrip(chr(0))}
    elif data[0] == chr(1):
        cmd, padding1, padding2, padding3, chipId, flashChipId, flashChipSize, flashChipSpeed, freeHeap, cardDatabaseSize, padding4, millis = struct.unpack(">BBBBIIIIIHHI", data[0:32])
        output = {
            "type": "systeminfo",
            "chipId": "%08X" % (chipId),
            "flashChipId": "%08X" % (flashChipId),
            "flashChipSize": flashChipSize,
            "flashChipSpeed": flashChipSpeed,
            "freeHeap": freeHeap,
            "cardDatabaseSize": cardDatabaseSize,
            "millis": millis
            }
        return output
    elif data[0] == chr(2):
        cmd, inputBits, stateBits, authState, batteryVoltage, uidLen = struct.unpack(">BBBBHB", data[0:7])
        output = {
            "type": "status",
            "batteryVoltage": batteryVoltage/100.0,
            "authState": authState,
            "uid": None,
            "lowPowerMode": False,
            "snibEnabled": False,
            "unlockedByExit": False,
            "unlockedBySnib": False,
            "unlockedByCard": False,
            "exitRequest": False,
            "snibPressed": False,
            "snibLongPressed": False,
            "doorOpen": False
            }
        if stateBits & 16:
            output["lowPowerMode"] = True
        if stateBits & 8:
            output["snibEnabled"] = True
        if stateBits & 4:
            output["unlockedByExit"] = True
        if stateBits & 2:
            output["unlockedBySnib"] = True
        if stateBits & 1:
            output["unlockedByCard"] = True
        if inputBits & 8:
            output["snibLongPressed"] = True
        if inputBits & 4:
            output["snibPressed"] = True
        if inputBits & 2:
            output["exitRequest"] = True
        if inputBits & 1:
            output["doorOpen"] = True
        if uidLen>0 and uidLen<=7:
            output['uid'] = hexify(data[7:7+uidLen])
        return output
    elif data[0] == chr(3):
        uidLen = ord(data[1])
        if uidLen>0 and uidLen<=7:
            return {
                "type": "authrequest",
                "uid": hexify(data[2:2+uidLen])
            }
    elif data[0] == chr(4):
        data2 = data[1:]
        output = {"type": "databasedump", "data": {}}
        while len(data2) >= 9:
            slot, uidlen, uid = struct.unpack(">HB7s", data2[0:10])
            #print slot, uidlen, hexify(uid, sep="-")
            slot = int(slot)
            uid = uid[0:uidlen]
            output["data"][slot] = hexify(uid)
            data2 = data2[10:]
        return output
    elif data[0] == chr(5):
        # stream of variables
        data2 = data[1:]
        output = {"type": "variables"}
        while len(data2) > 0:
            try:
                k, v, data2 = decode_var(data2)
                output[k] = v
            except Exception, e:
                logging.exception("Exception while decoding %s (ignoring remaining data)" % (hexify(data2, sep="-")))
                return output
        return output

def hexify(data, sep=""):
    output = []
    for d in data:
        output.append("%02X" % (struct.unpack("B", d)))
    return sep.join(output)

def dehexify(data):
    data2 = data
    output = ""
    while len(data2) > 0:
        output = output + chr(int(data2[0:2], base=16))
        data2 = data2[2:]
    return output
