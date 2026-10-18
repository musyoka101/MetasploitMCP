"""Run directly with the locked Python, outside pytest's global dependency mocks.

Actual MCP tools/FastMCP/pymetasploit3 are used. Only RPC transport is replaced;
no framework service, target, listener, session or executable payload is created.
"""

import asyncio
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import msgpack
from fastmcp import Client
from pymetasploit3.msfrpc import JobManager, ModuleManager, SessionManager

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import MetasploitMCP as server


WINDOWS = "windows/meterpreter/reverse_tcp"
LINUX = "linux/x64/meterpreter/reverse_tcp"
FIXTURE_BYTES = b"inert dependency regression fixture; not a payload"


def option(kind, default=None):
    return {"type": kind, "default": default, "required": False,
            "advanced": False, "evasion": False}


class RecordingRPC:
    """Metadata fixtures plus scalar-only transport; SDK objects are not mocked."""

    def __init__(self):
        self.modules = ModuleManager(self)
        self.jobs = JobManager(self)
        self.sessions = SessionManager(self)
        self.executions = []

    def call(self, method, args=None, raw=False):
        args = args or []
        if method == "module.info":
            return {"default_target": 0, "fullname": "/".join(args)}
        if method == "module.options":
            metadata = {"LHOST": option("string"), "LPORT": option("integer"),
                        "ExitOnSession": option("bool", False), "RHOSTS": option("string"),
                        "SESSION": option("integer")}
            if args[0] == "payload":
                metadata["AutoLoadExtensions"] = option(
                    "array", ["priv", "stdapi"] if args[1] == WINDOWS else ["stdapi"])
            if args[0] in ("auxiliary", "post"):
                metadata["FixtureArray"] = option("array", ["a", "b"])
            return deepcopy(metadata)
        if method == "module.target_compatible_payloads":
            return {"payloads": [WINDOWS, LINUX]}
        if method == "job.list":
            return {}
        if method == "session.list":
            return {"1": {"type": "fixture"}}
        if method == "module.execute":
            options = args[2]
            self.executions.append(deepcopy(args))
            print(json.dumps({"method": method, "arguments": args}))
            for key, value in options.items():
                if not isinstance(value, (str, int, float, bool, type(None))):
                    return {"error": True, "error_message":
                            f"Invalid module option value for {key}: must be a scalar"}
            if args[0] == "payload":
                assert raw
                return msgpack.packb({b"payload": FIXTURE_BYTES})
            return {"job_id": 7, "uuid": None}
        raise AssertionError(f"Unexpected RPC call: {method} {args}")


class RpcArrayRegression(unittest.TestCase):
    def setUp(self):
        self.rpc = RecordingRPC()
        self.temp = tempfile.TemporaryDirectory(prefix="msf-array-", dir="/tmp/opencode")
        self.addCleanup(self.temp.cleanup)
        self.patches = [patch.object(server, "_msf_client_instance", self.rpc),
                        patch.object(server, "PAYLOAD_SAVE_DIR", self.temp.name)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def tool(self, name, arguments):
        async def call():
            async with Client(server.mcp) as client:
                result = await client.call_tool(name, arguments)
                return json.loads(result.content[0].text)
        return asyncio.run(call())

    def test_listener_defaults_windows_and_linux(self):
        for payload, expected in ((WINDOWS, "priv,stdapi"), (LINUX, "stdapi")):
            with self.subTest(payload=payload):
                result = self.tool("start_listener", {"payload_type": payload,
                                   "lhost": "127.0.0.1", "lport": 4444})
                self.assertIn(result["status"], ("success", "warning"), result)
                self.assertEqual(self.rpc.executions[-1][2]["AutoLoadExtensions"], expected)

    def test_listener_explicit_array_override(self):
        options = {"AutoLoadExtensions": ["stdapi", "priv"]}
        result = self.tool("start_listener", {"payload_type": WINDOWS, "lhost": "127.0.0.1",
                          "lport": 4444, "additional_options": options})
        self.assertIn(result["status"], ("success", "warning"), result)
        self.assertEqual(self.rpc.executions[-1][2]["AutoLoadExtensions"], "stdapi,priv")
        self.assertEqual(options, {"AutoLoadExtensions": ["stdapi", "priv"]})

    def test_array_scalar_strings_preserved(self):
        for value in ("stdapi,priv", "123", "true", ""):
            with self.subTest(value=value):
                payload = self.rpc.modules.use("payload", WINDOWS)
                asyncio.run(server._set_module_options(payload, {"AutoLoadExtensions": value}))
                self.assertEqual(payload.runoptions["AutoLoadExtensions"], value)

    def test_existing_empty_override_omission(self):
        for value in ("", []):
            with self.subTest(value=value):
                result = self.tool("start_listener", {"payload_type": WINDOWS, "lhost": "127.0.0.1",
                                  "lport": 4444, "additional_options": {"AutoLoadExtensions": value}})
                self.assertIn(result["status"], ("success", "warning"), result)
                self.assertNotIn("AutoLoadExtensions", self.rpc.executions[-1][2])

    def test_rpc_exploit_defaults(self):
        result = self.tool("run_exploit", {"module_name": "multi/handler", "options": {},
                          "payload_name": WINDOWS, "payload_options": {"LHOST": "127.0.0.1", "LPORT": 4444},
                          "run_as_job": True})
        self.assertIn(result["status"], ("success", "warning"), result)
        self.assertEqual(self.rpc.executions[-1][2]["AutoLoadExtensions"], "priv,stdapi")

    def test_generate_payload_defaults_and_override(self):
        for extra, expected in (({}, "priv,stdapi"),
                                ({"AutoLoadExtensions": ["stdapi"]}, "stdapi")):
            with self.subTest(extra=extra):
                result = self.tool("generate_payload", {"payload_type": WINDOWS, "format_type": "raw",
                                   "options": {"LHOST": "127.0.0.1", "LPORT": 4444, **extra},
                                   "output_filename": "inert.txt"})
                self.assertEqual(result["status"], "success", result)
                self.assertEqual(self.rpc.executions[-1][2]["AutoLoadExtensions"], expected)
                self.assertEqual(Path(result["server_save_path"]).read_bytes(), FIXTURE_BYTES)

    def test_reject_untyped_or_nested_lists(self):
        for options in ({"RHOSTS": ["127.0.0.1"]},
                        {"AutoLoadExtensions": [["priv"]]},
                        {"AutoLoadExtensions": [{"extension": "priv"}]},
                        {"AutoLoadExtensions": [1]},
                        {"AutoLoadExtensions": ["priv,stdapi"]},
                        {"AutoLoadExtensions": {"extension": "priv"}}):
            with self.subTest(options=options):
                payload = self.rpc.modules.use("payload", WINDOWS)
                with self.assertRaises(ValueError):
                    asyncio.run(server._set_module_options(payload, options))
        self.assertEqual(self.rpc.executions, [])

    def test_existing_scalar_conversion_and_defaults(self):
        payload = self.rpc.modules.use("payload", WINDOWS)
        original = deepcopy(payload.optioninfo("AutoLoadExtensions"))
        asyncio.run(server._set_module_options(payload, {"LPORT": "4444", "ExitOnSession": "true"}))
        self.assertEqual(payload.runoptions["LPORT"], 4444)
        self.assertIs(payload.runoptions["ExitOnSession"], True)
        self.assertEqual(payload.runoptions["AutoLoadExtensions"], "priv,stdapi")
        self.assertEqual(payload.optioninfo("AutoLoadExtensions"), original)

    def test_auxiliary_and_post_array_defaults(self):
        for kind in ("auxiliary", "post"):
            with self.subTest(kind=kind):
                arguments = {"module_name": "fixture", "options": {}, "run_as_job": True}
                if kind == "post":
                    arguments["session_id"] = 1
                result = self.tool(f"run_{kind}_module", arguments)
                self.assertEqual(result["status"], "success", result)
                self.assertEqual(self.rpc.executions[-1][2]["FixtureArray"], "a,b")


if __name__ == "__main__":
    unittest.main(verbosity=2)
