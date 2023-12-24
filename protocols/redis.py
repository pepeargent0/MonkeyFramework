from pyrdp.rdp import RDPClient


class RDIClient:
    def __init__(self, server, username, password, domain="", port=3389):
        self.server = server
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port
        self.client = None

    def connect(self):
        self.client = RDPClient(self.server, self.port)
        self.client.login(self.username, self.password, self.domain)

    def disconnect(self):
        if self.client:
            self.client.disconnect()




