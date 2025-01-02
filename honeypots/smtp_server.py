from __future__ import annotations

import socket
from base64 import b64decode
from contextlib import suppress
from twisted.internet import reactor
from twisted.internet.protocol import Factory
from twisted.mail.smtp import ESMTP
from honeypots.base_server import BaseServer
from honeypots.helper import check_bytes, server_arguments

class QSMTPServer(BaseServer):
    NAME = "smtp_server"
    DEFAULT_PORT = 25

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomSMTPProtocol(ESMTP):
            def __init__(self, *args, **kwargs):
                fun = None
                try:
                    # don't leak the *actual* hostname
                    fun = socket.getfqdn
                    socket.getfqdn = lambda: "ip-127-0-0-1.ec2.internal"
                    super().__init__(*args, **kwargs)
                finally:
                    if fun:
                        socket.getfqdn = fun
                self.auth_phase = ""
                self.auth_login_user = ""

            def connectionMade(self):  # noqa: N802
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )
                super().connectionMade()

            def state_COMMAND(self, line):
                command, *rest = line.split(b" ")
                arg = rest[0] if rest else None
                data = rest[1] if len(rest) > 1 else None
                if self.auth_phase == "PLAIN":
                    if not self.check_credentials(command):
                        self.sendCode(535, b'5.7.8 Error: authentication failed: authentication failure')
                    self.auth_phase = ""
                    return
                if self.auth_phase == "LOGIN-USER":
                    self.auth_login_user = command
                    self.sendCode(334, b"UGFzc3dvcmQ6")
                    self.auth_phase = "LOGIN-PASS"
                    return
                if self.auth_phase == "LOGIN-PASS":
                    if not self.check_credentials_login(command):
                        self.sendCode(535, b'5.7.8 Error: authentication failed: authentication failure')
                    self.auth_phase = ""
                    self.auth_login_user = ""
                    return
                if command.upper() not in {b"HELO", b"EHLO"}:
                    _q_s.log(
                        {
                            "action": "connection",
                            "src_ip": self.transport.getPeer().host,
                            "src_port": self.transport.getPeer().port,
                            "data": {"command": command, "arg": arg, "data": data},
                        }
                    )
                super().state_COMMAND(line)

            def do_EHLO(self, arg):
                self.sendCode(250, f"ip-127-0-0-1.ec2.internal Hello {arg}\n8BITMIME\nAUTH LOGIN PLAIN\nSTARTTLS".encode())

            def check_credentials(self, arg):
                try:
                    _, username, password = (
                        b64decode(arg.strip())
                        .decode("utf-8", errors="replace")
                        .split("\0")
                    )
                except:
                    return False
                if _q_s.check_login(username, password, self.transport.getPeer().host, self.transport.getPeer().port):
                    self.sendCode(235, b'Authentication successful.')
                    return True

            def check_credentials_login(self, arg):
                try:
                    username = (
                        b64decode(self.auth_login_user.strip())
                        .decode("utf-8", errors="replace")
                    )
                    password = (
                        b64decode(arg.strip())
                        .decode("utf-8", errors="replace")
                    )
                except:
                    return False
                if _q_s.check_login(username, password, self.transport.getPeer().host, self.transport.getPeer().port):
                    self.sendCode(235, b'Authentication successful.')
                    return True

            def ext_AUTH(self, arg):
                if arg.startswith(b"PLAIN "):
                    data = arg.split(b" ")[1]
                    if self.check_credentials(data):
                        return
                if arg == b"PLAIN":
                    self.sendCode(334, b"")
                    self.auth_phase = "PLAIN"
                    return
                if arg == b"LOGIN":
                    self.sendCode(334, b"VXNlcm5hbWU6")
                    self.auth_phase = "LOGIN-USER"
                    return
                self.sendCode(535, b'5.7.8 Error: authentication failed: authentication failure')

        class CustomSMTPFactory(Factory):
            protocol = CustomSMTPProtocol
            portal = None

            def buildProtocol(self, address):  # noqa: N802,ARG002
                p = self.protocol()
                p.portal = self.portal
                p.factory = self
                return p

        factory = CustomSMTPFactory()
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from smtplib import SMTP

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            s = SMTP(_ip, _port)
            s.ehlo()
            s.login(_username, _password)
            s.quit()


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QSMTPserver = QSMTPServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        QSMTPserver.run_server()
