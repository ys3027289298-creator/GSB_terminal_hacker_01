"""Offline terminal defense game core.

Fixed seed, CMD instruction dispatch, JSON save/load archives.
"""

import json
import random

DEFAULT_SEED = 57
DEFAULT_CAPACITY = 10


def _rng_state_to_json(state):
    version, internal, gauss = state
    return {"version": version, "internal": list(internal), "gauss": gauss}


def _rng_state_from_json(data):
    return (data["version"], tuple(data["internal"]), data["gauss"])


class TerminalDefense:
    def __init__(self, seed=DEFAULT_SEED, capacity=DEFAULT_CAPACITY):
        self.seed = seed
        self.time = 0
        self.max_capacity = capacity
        self.capacity = capacity
        self.packet_queue = []
        self.processed_packets = set()
        self.block_rules = set()
        self.routes = {}
        self.patching = None
        self.applied_patches = set()
        self.alert_level = 0
        self.alert_history = []
        self.tokens = {}
        self.connections = []
        self.challenges = []
        self.audit = []
        self._rng = random.Random(seed)

    # -- random challenge sequence ------------------------------------
    def next_challenge(self):
        value = self._rng.randrange(1, 1000000)
        self.challenges.append(value)
        return value

    # -- packet intake --------------------------------------------------
    def inject(self, packet_id, kind, source):
        packet = {"id": packet_id, "kind": kind, "source": source}
        self.packet_queue.append(packet)
        return packet

    # -- one packet per time step ---------------------------------------
    def tick(self):
        self.time += 1
        if not self.packet_queue:
            result = None
            self.audit.append(["idle", self.time])
        else:
            packet = self.packet_queue.pop(0)
            result = self._process_packet(packet)
        if self.patching is not None:
            self.patching["remaining"] -= 1
            if self.patching["remaining"] <= 0:
                self.applied_patches.add(self.patching["id"])
                self.audit.append(["patch_applied", self.patching["id"], self.time])
                self.patching = None
        return result

    def _process_packet(self, packet):
        packet_id = packet["id"]
        if packet_id in self.processed_packets:
            self.audit.append(["duplicate", packet_id, self.time])
            return "duplicate"
        self.processed_packets.add(packet_id)
        source = packet["source"]
        if source in self.block_rules:
            self.audit.append(["blocked", packet_id, self.time])
            return "blocked"
        kind = packet["kind"]
        if kind == "intrusion":
            if self.capacity <= 0:
                self.audit.append(["capacity_exhausted", packet_id, self.time])
                return "rejected"
            self.capacity -= 1
            self.audit.append(["intrusion_absorbed", packet_id, self.time])
            return "absorbed"
        if kind == "connection":
            if self.patching is not None:
                self.audit.append(["connection_refused_patching", packet_id, self.time])
                return "refused"
            self.connections.append(source)
            self.routes.setdefault(source, {"source": source, "active": True})
            self.audit.append(["connected", packet_id, self.time])
            return "connected"
        self.audit.append(["delivered", packet_id, self.time])
        return "delivered"

    # -- block rules: exact address match -------------------------------
    def block(self, address):
        self.block_rules.add(address)
        if address in self.routes:
            self.routes[address]["active"] = False
        self.audit.append(["block", address, self.time])

    def unblock(self, address):
        self.block_rules.discard(address)
        if address in self.routes:
            self.routes[address]["active"] = True
        self.audit.append(["unblock", address, self.time])

    def is_blocked(self, address):
        return address in self.block_rules

    # -- patches ----------------------------------------------------------
    def patch(self, patch_id, duration=1):
        if patch_id in self.applied_patches:
            self.audit.append(["patch_skipped", patch_id, self.time])
            return "skipped"
        if self.patching is not None:
            self.audit.append(["patch_busy", patch_id, self.time])
            return "busy"
        self.patching = {"id": patch_id, "remaining": duration}
        self.audit.append(["patch_started", patch_id, self.time])
        return "started"

    # -- alerts -----------------------------------------------------------
    def set_alert(self, level):
        self.alert_level = level
        self.alert_history.append({"time": self.time, "level": level})
        self.audit.append(["alert", level, self.time])

    # -- tokens -------------------------------------------------------------
    def issue_token(self, token_id, ttl):
        self.tokens[token_id] = self.time + ttl
        self.audit.append(["token_issued", token_id, self.time])

    def token_valid(self, token_id):
        expiry = self.tokens.get(token_id)
        return expiry is not None and self.time < expiry

    # -- CMD instruction dispatch -----------------------------------------
    def cmd(self, line):
        parts = line.split()
        name = parts[0]
        args = parts[1:]
        if name == "tick":
            return self.tick()
        if name == "inject":
            self.inject(args[0], args[1], args[2])
            return "queued"
        if name == "block":
            self.block(args[0])
            return "ok"
        if name == "unblock":
            self.unblock(args[0])
            return "ok"
        if name == "patch":
            duration = int(args[1]) if len(args) > 1 else 1
            return self.patch(args[0], duration)
        if name == "alert":
            self.set_alert(int(args[0]))
            return "ok"
        if name == "token":
            self.issue_token(args[0], int(args[1]))
            return "ok"
        if name == "auth":
            return "valid" if self.token_valid(args[0]) else "expired"
        if name == "challenge":
            return str(self.next_challenge())
        if name == "save":
            self.save(args[0])
            return "saved"
        if name == "load":
            self.load(args[0])
            return "loaded"
        raise ValueError("unknown command: %s" % name)

    # -- JSON archive -------------------------------------------------------
    def save(self, path):
        state = {
            "seed": self.seed,
            "time": self.time,
            "max_capacity": self.max_capacity,
            "capacity": self.capacity,
            "packet_queue": list(self.packet_queue),
            "processed_packets": sorted(self.processed_packets),
            "block_rules": sorted(self.block_rules),
            "routes": self.routes,
            "patching": self.patching,
            "applied_patches": sorted(self.applied_patches),
            "alert_level": self.alert_level,
            "alert_history": self.alert_history,
            "tokens": self.tokens,
            "connections": list(self.connections),
            "challenges": list(self.challenges),
            "audit": [list(event) for event in self.audit],
            "rng_state": _rng_state_to_json(self._rng.getstate()),
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)

    def load(self, path):
        with open(path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        self.seed = state["seed"]
        self.time = state["time"]
        self.max_capacity = state["max_capacity"]
        self.capacity = state["capacity"]
        self.packet_queue = list(state["packet_queue"])
        self.processed_packets = set(state["processed_packets"])
        self.block_rules = set(state["block_rules"])
        self.routes = dict(state["routes"])
        self.patching = state["patching"]
        self.applied_patches = set(state["applied_patches"])
        self.alert_level = state["alert_level"]
        self.alert_history = list(state["alert_history"])
        self.tokens = dict(state["tokens"])
        self.connections = list(state["connections"])
        self.challenges = list(state["challenges"])
        self.audit = [list(event) for event in state["audit"]]
        self._rng = random.Random(self.seed)
        self._rng.setstate(_rng_state_from_json(state["rng_state"]))
        return self
