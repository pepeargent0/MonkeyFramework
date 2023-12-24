from smb.SMBConnection import SMBConnection

class SambaClient:
    def __init__(self, server, username=None, password=None):
        self.server = server
        self.username = username
        self.password = password
        self.conn = None
        self.shares = None

    def connect(self):
        self.conn = SMBConnection(self.username, self.password, 'client', self.server, 'your_computer_name')
        self.conn.connect(self.server, 139)

    def list_shares(self):
        if not self.conn:
            raise ValueError("Connection not established. Call connect() first.")

        self.shares = [share.name for share in self.conn.listShares()]
        return self.shares

    def list_files(self, share_name="/"):
        if not self.conn:
            raise ValueError("Connection not established. Call connect() first.")

        file_list = self.conn.listPath(share_name, '/')
        files = [item.filename for item in file_list]
        return files

    def download_file(self, remote_path, local_path):
        if not self.conn:
            raise ValueError("Connection not established. Call connect() first.")

        with open(local_path, "wb") as local_file:
            self.conn.retrieveFile(self.shares[0], remote_path, local_file)

    def close(self):
        if self.conn:
            self.conn.close()