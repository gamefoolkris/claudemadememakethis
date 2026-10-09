
from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import os
import pty
import signal
import socket
import struct
import subprocess
import termios
import threading
import math
import ssl
import tempfile
from pathlib import Path

from aiohttp import web, WSMsgType


class Socket:
    def __init__(self):
        self.host = None
        self.port = None
        self.shell = None
        self.directory = None
        self.routes = []

        self._thread = None
        self._loop = None
        self._runner = None
        self._site = None
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._error = None
        self._clients = set()
        self._started = False

        self._ssl_context = None
        self._cert_tempdir = None

        self._stdout = bytearray()
        self._stdout_lock = threading.Lock()

    def _configure_signature(self, signature):
        # Falsey values disable TLS.
        if not signature:
            return None

        cert = None
        key = None

        if isinstance(signature, (list, tuple)):
            if len(signature) != 2:
                raise ValueError("Invalid signature")

            cert, key = signature

        elif isinstance(signature, dict):
            if set(signature.keys()) != {"cert", "key"}:
                raise ValueError("Invalid signature")

            cert = signature["cert"]
            key = signature["key"]

        else:
            # Any truthy value that isn't an array or object
            # requests a self-signed certificate.
            self._cert_tempdir = tempfile.TemporaryDirectory(
                prefix="xterm-tls-"
            )

            cert = os.path.join(self._cert_tempdir.name, "cert.pem")
            key = os.path.join(self._cert_tempdir.name, "key.pem")

            try:
                subprocess.run(
                    [
                        "openssl", "req",
                        "-x509",
                        "-newkey", "rsa:2048",
                        "-nodes",
                        "-keyout", key,
                        "-out", cert,
                        "-days", "365",
                        "-subj", "/CN=localhost",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
            except Exception:
                self._cert_tempdir.cleanup()
                self._cert_tempdir = None
                raise

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=str(Path(cert).expanduser()),
            keyfile=str(Path(key).expanduser()),
        )

        return context

    @property
    def running(self):
        return self._started and not self._closed.is_set()

    def start(
        self,
        shell="/bin/zsh",
        directory="~",
        routes=None,
        host="127.0.0.1",
        port=18237,
        signature=None,
    ):
        """Start the terminal server and block until it is ready.

        routes is a list of [filesystem_path, URL_route] pairs.
        Filesystem paths are relative to the Python process's current
        working directory unless they are absolute paths.
        """
        if self._started or self._thread is not None:
            raise RuntimeError("This XTerm.Socket is already running")

        shell_path = Path(shell).expanduser().resolve()
        if not shell_path.is_file() or not os.access(shell_path, os.X_OK):
            raise FileNotFoundError(f"Shell is not executable: {shell_path}")

        working_directory = Path(directory).expanduser().resolve()
        if not working_directory.is_dir():
            raise NotADirectoryError(
                f"Working directory does not exist: {working_directory}"
            )

        normalized_routes = []
        for item in routes or []:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise ValueError(
                    "Each route must be [filesystem_path, URL_route]"
                )

            source, url_route = item
            source_path = Path(source).expanduser()
            if not source_path.is_absolute():
                source_path = Path.cwd() / source_path
            source_path = source_path.resolve()

            url_route = "/" + str(url_route).strip("/")
            if url_route == "//":
                url_route = "/"

            if not source_path.exists():
                raise FileNotFoundError(
                    f"Static path does not exist: {source_path}"
                )
            if not source_path.is_file() and not source_path.is_dir():
                raise ValueError(f"Not a file or directory: {source_path}")

            normalized_routes.append((source_path, url_route))

        # More specific URL mappings should be checked first.
        normalized_routes.sort(key=lambda item: len(item[1]), reverse=True)

        self._ssl_context = self._configure_signature(signature)
        self.host = host
        self.port = int(port)
        self.shell = str(shell_path)
        self.directory = str(working_directory)
        self.routes = normalized_routes

        self._ready.clear()
        self._closed.clear()
        self._error = None

        self._thread = threading.Thread(
            target=self._thread_main,
            name=f"XTerm-{host}:{port}",
            daemon=True,
        )
        self._thread.start()

        if not self._ready.wait(timeout=10):
            self.stop()
            raise TimeoutError("Terminal server did not start in time")

        if self._error:
            error = self._error
            self.stop()
            raise error

        self._started = True
        return self

    def stop(self):
        """Stop the server and terminate active terminal sessions."""
        if self._thread is None:
            return

        loop = self._loop
        if loop is not None and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(
                self._shutdown(), loop
            )
            try:
                future.result(timeout=5)
            except Exception:
                pass

            loop.call_soon_threadsafe(loop.stop)

        if self._thread is not threading.current_thread():
            self._thread.join(timeout=5)

        self._started = False
        self._thread = None
        self._loop = None

    def _thread_main(self):
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(self._serve())
        except Exception as exc:
            self._error = exc
            self._ready.set()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()

            with contextlib.suppress(Exception):
                loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )

            loop.close()
            self._closed.set()

    async def _serve(self):
        app = web.Application()
        app.router.add_get("/ws", self._websocket)
        app.router.add_route("*", "/{url_path:.*}", self._static)

        self._runner = web.AppRunner(app)
        await self._runner.setup()

        self._site = web.TCPSite(
            self._runner,
            self.host,
            self.port,
            ssl_context=self._ssl_context,
        )
        await self._site.start()
        self._ready.set()

        while not self._closed.is_set():
            await asyncio.sleep(0.1)

        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None

    async def _static(self, request):
        """Serve explicitly mapped files and files under mapped directories."""
        url_path = "/" + request.match_info.get("url_path", "")

        for source, route in self.routes:
            if source.is_file():
                if url_path != route:
                    continue
                target = source
            else:
                # A directory mapping serves descendants only.
                # It never automatically serves index.html.
                prefix = route.rstrip("/")

                if prefix == "":
                    relative = url_path.lstrip("/")
                elif url_path.startswith(prefix + "/"):
                    relative = url_path[len(prefix) + 1:]
                else:
                    continue

                if not relative:
                    continue

                # Reject traversal and keep resolution inside the mapped folder.
                root = source.resolve()
                target = (root / relative).resolve()

                try:
                    target.relative_to(root)
                except ValueError:
                    continue

                if not target.is_file():
                    continue

            if target.is_file():
                return web.FileResponse(target)

        raise web.HTTPNotFound()

    async def _websocket(self, request):
        ws = web.WebSocketResponse(
            heartbeat=30,
            max_msg_size=1024 * 1024,
        )
        await ws.prepare(request)
        self._clients.add(ws)

        pid = None
        master_fd = None
        queue = asyncio.Queue()
        loop = asyncio.get_running_loop()

        try:
            pid, master_fd = pty.fork()

            if pid == 0:
                try:
                    os.chdir(self.directory)

                    env = os.environ.copy()
                    env.update({
                        "TERM": "xterm-256color",
                        "COLORTERM": "truecolor",
                        "SHELL": self.shell,
                        "HOME": str(Path.home()),
                    })

                    argv = [os.path.basename(self.shell), "-l"]
                    os.execve(self.shell, argv, env)
                except Exception as exc:
                    os.write(
                        2,
                        f"Could not start shell: {exc}\r\n".encode()
                    )
                    os._exit(127)

            os.set_blocking(master_fd, False)

            def readable():
                try:
                    data = os.read(master_fd, 65536)
                    queue.put_nowait(data if data else None)
                except BlockingIOError:
                    pass
                except OSError:
                    queue.put_nowait(None)

            loop.add_reader(master_fd, readable)

            async def send_output():
                while True:
                    data = await queue.get()
                    if data is None:
                        break
                    await ws.send_bytes(data)

            async def receive_input():
                async for msg in ws:
                    if msg.type == WSMsgType.TEXT:
                        try:
                            event = json.loads(msg.data)
                        except (ValueError, TypeError):
                            continue

                        if event.get("type") == "input":
                            data = event.get("data", "")
                            if isinstance(data, str):
                                await self._write_all(
                                    master_fd,
                                    data.encode("utf-8", errors="replace"),
                                )

                        elif event.get("type") == "resize":
                            try:
                                cols = max(
                                    1, min(int(event.get("cols", 80)), 500)
                                )
                                rows = max(
                                    1, min(int(event.get("rows", 24)), 300)
                                )
                            except (ValueError, TypeError):
                                continue

                            fcntl.ioctl(
                                master_fd,
                                termios.TIOCSWINSZ,
                                struct.pack("HHHH", rows, cols, 0, 0),
                            )

                            with contextlib.suppress(ProcessLookupError):
                                os.killpg(pid, signal.SIGWINCH)

                    elif msg.type in (
                        WSMsgType.CLOSE,
                        WSMsgType.ERROR,
                    ):
                        break

            output_task = asyncio.create_task(send_output())
            input_task = asyncio.create_task(receive_input())

            _, pending = await asyncio.wait(
                {output_task, input_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()

            await asyncio.gather(*pending, return_exceptions=True)

        except (ConnectionError, asyncio.CancelledError, OSError):
            pass

        finally:
            self._clients.discard(ws)

            if master_fd is not None:
                with contextlib.suppress(Exception):
                    loop.remove_reader(master_fd)
                with contextlib.suppress(OSError):
                    os.close(master_fd)

            if pid:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(pid, signal.SIGTERM)
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.kill(pid, signal.SIGTERM)

                for _ in range(20):
                    try:
                        waited, _ = os.waitpid(pid, os.WNOHANG)
                        if waited == pid:
                            break
                    except ChildProcessError:
                        break
                    await asyncio.sleep(0.05)
                else:
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(pid, signal.SIGKILL)
                    with contextlib.suppress(ChildProcessError):
                        os.waitpid(pid, 0)

            if not ws.closed:
                await ws.close()

        return ws

    @staticmethod
    async def _write_all(fd, data):
        """Handle partial and temporarily blocked PTY writes."""
        view = memoryview(data)

        while view:
            try:
                written = os.write(fd, view)
                if written == 0:
                    return
                view = view[written:]
            except BlockingIOError:
                await asyncio.sleep(0.001)
            except OSError:
                return

    async def _shutdown(self):
        for ws in list(self._clients):
            with contextlib.suppress(Exception):
                await ws.close(
                    code=1001,
                    message=b"Terminal server stopping",
                )

        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None

        self._closed.set()

    def exec(self, command):
        """Execute a command and append its stdout to the output buffer.

        Returns the command's combined stdout and stderr as bytes.
        Commands run in a separate shell process, not in a connected
        interactive WebSocket shell.
        """
        if not isinstance(command, str):
            raise TypeError("command must be a string")

        result = subprocess.run(
            [self.shell, "-lc", command],
            cwd=self.directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

        output = result.stdout

        with self._stdout_lock:
            self._stdout.extend(output)

        return output

    def read(self, index, length=None):
        """Read bytes relative to the end of captured command output.

        index=0 addresses the newest byte.
        index=2 addresses the third-newest byte.

        With a valid length >= 1, returns up to that many bytes,
        in their original output order, ending at the requested index.

        With length=None, NaN, or length < 1, returns one byte.
        Returns b'' when the requested position is out of range.
        """
        index = int(index)

        if index < 0:
            return b''

        try:
            invalid_length = (
                length is None
                or (
                    isinstance(length, float)
                    and math.isnan(length)
                )
                or float(length) < 1
            )
        except (TypeError, ValueError, OverflowError):
            invalid_length = True

        if invalid_length:
            length = 1
        else:
            length = int(length)

        with self._stdout_lock:
            end = len(self._stdout) - index

            if end <= 0:
                return b''

            start = max(0, end - length)
            return bytes(self._stdout[start:end])


class _Namespace:
    Socket = Socket


XTerm = _Namespace()
