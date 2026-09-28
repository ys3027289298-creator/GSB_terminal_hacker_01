import json
import os
import tempfile
import unittest

from terminal.core import TerminalDefense


class TerminalDefenseTest(unittest.TestCase):
    def setUp(self):
        self.game = TerminalDefense()

    def _archive_path(self):
        handle, path = tempfile.mkstemp(suffix=".json")
        os.close(handle)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    # 1. The same intrusion packet must not drain firewall capacity twice.
    def test_duplicate_intrusion_deducts_capacity_once(self):
        self.game.inject("p1", "intrusion", "10.0.0.9")
        self.game.inject("p1", "intrusion", "10.0.0.9")
        self.assertEqual(self.game.tick(), "absorbed")
        self.assertEqual(self.game.capacity, self.game.max_capacity - 1)
        self.assertEqual(len(self.game.packet_queue), 1)
        self.assertEqual(self.game.tick(), "duplicate")
        self.assertEqual(self.game.capacity, self.game.max_capacity - 1)

    # 2. Block rules must match the exact address, not a prefix.
    def test_block_rule_matches_exact_address_only(self):
        self.game.block("10.0.0.1")
        self.game.inject("p1", "intrusion", "10.0.0.11")
        self.assertEqual(self.game.tick(), "absorbed")
        self.assertEqual(self.game.capacity, self.game.max_capacity - 1)
        self.game.inject("p2", "intrusion", "10.0.0.1")
        self.assertEqual(self.game.tick(), "blocked")
        self.assertEqual(self.game.capacity, self.game.max_capacity - 1)

    # 3. New connections are refused while a patch is installing.
    def test_connections_refused_while_patching(self):
        self.assertEqual(self.game.patch("fix-1", duration=2), "started")
        self.game.inject("c1", "connection", "192.168.1.5")
        self.assertEqual(self.game.tick(), "refused")
        self.assertEqual(self.game.connections, [])
        self.game.inject("c2", "connection", "192.168.1.6")
        self.assertEqual(self.game.tick(), "refused")
        self.assertEqual(self.game.patching, None)
        self.game.inject("c3", "connection", "192.168.1.7")
        self.assertEqual(self.game.tick(), "connected")
        self.assertEqual(self.game.connections, ["192.168.1.7"])

    # 4. Lowering the alert level must keep the alert history.
    def test_alert_history_kept_when_level_drops(self):
        self.game.set_alert(3)
        self.game.set_alert(1)
        self.assertEqual(self.game.alert_level, 1)
        self.assertEqual(len(self.game.alert_history), 2)
        self.assertEqual(self.game.alert_history[0]["level"], 3)
        self.assertEqual(self.game.alert_history[1]["level"], 1)

    # 5. Applied patches must not run again after a restart.
    def test_applied_patch_not_reapplied_after_reload(self):
        path = self._archive_path()
        self.assertEqual(self.game.patch("fix-1", duration=1), "started")
        self.game.tick()
        self.assertIn("fix-1", self.game.applied_patches)
        self.game.save(path)
        restored = TerminalDefense().load(path)
        self.assertEqual(restored.patch("fix-1", duration=1), "skipped")
        self.assertIsNone(restored.patching)
        self.assertEqual(restored.applied_patches, {"fix-1"})

    # 6. A token is invalid at exactly its expiry time, not one second later.
    def test_token_expires_at_exact_boundary(self):
        self.game.issue_token("tok", ttl=2)
        self.assertTrue(self.game.token_valid("tok"))
        self.game.tick()
        self.assertTrue(self.game.token_valid("tok"))
        self.game.tick()
        self.assertFalse(self.game.token_valid("tok"))

    # 7. Revoking a block rule must restore the route.
    def test_unblock_restores_route(self):
        self.game.inject("c1", "connection", "172.16.0.2")
        self.game.tick()
        self.assertTrue(self.game.routes["172.16.0.2"]["active"])
        self.game.block("172.16.0.2")
        self.assertFalse(self.game.routes["172.16.0.2"]["active"])
        self.game.unblock("172.16.0.2")
        self.assertTrue(self.game.routes["172.16.0.2"]["active"])
        self.assertFalse(self.game.is_blocked("172.16.0.2"))

    # 8. Saved state must include the random challenge sequence.
    def test_save_preserves_challenge_sequence(self):
        path = self._archive_path()
        reference = TerminalDefense()
        expected = [self.game.next_challenge() for _ in range(3)]
        for _ in range(3):
            reference.next_challenge()
        self.game.save(path)
        with open(path, "r", encoding="utf-8") as handle:
            archive = json.load(handle)
        self.assertEqual(archive["challenges"], expected)
        restored = TerminalDefense().load(path)
        self.assertEqual(restored.challenges, expected)
        self.assertEqual(restored.next_challenge(), reference.next_challenge())

    # Boundary: an empty time step advances the clock and touches nothing.
    def test_empty_traffic_tick(self):
        self.assertIsNone(self.game.tick())
        self.assertEqual(self.game.time, 1)
        self.assertEqual(self.game.capacity, self.game.max_capacity)
        self.assertEqual(self.game.processed_packets, set())

    # Boundary: at full load the next intrusion is rejected, not absorbed.
    def test_full_capacity_boundary(self):
        game = TerminalDefense(capacity=2)
        game.inject("p1", "intrusion", "10.1.1.1")
        game.inject("p2", "intrusion", "10.1.1.2")
        game.inject("p3", "intrusion", "10.1.1.3")
        self.assertEqual(game.tick(), "absorbed")
        self.assertEqual(game.tick(), "absorbed")
        self.assertEqual(game.capacity, 0)
        self.assertEqual(game.tick(), "rejected")
        self.assertEqual(game.capacity, 0)


if __name__ == "__main__":
    unittest.main()
