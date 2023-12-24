import time
from dataclasses import dataclass
import concurrent.futures
from tqdm import tqdm
import requests


@dataclass
class Node:
    directory: str
    link: str


class Scrapper:
    def __init__(self, url):
        self.url = url

    @staticmethod
    def _colum_form_document(document):
        with open(document, 'r') as f:
            for column in f:
                if not column.startswith('#'):
                    yield column[:-1]

    def get_directorys(self, file_directory):
        directorys = []
        start_time = time.time()

        with tqdm(desc="Parallel Execution", unit="column") as pbar:
            def update_progress(*_):
                pbar.update()

            with concurrent.futures.ThreadPoolExecutor() as executor:
                # Submit tasks for each column as they are generated
                futures = [executor.submit(self.fetch_directory, column) for column in
                           self._colum_form_document(file_directory)]

                # Process completed tasks as they finish
                for future in concurrent.futures.as_completed(futures):
                    try:
                        directory = future.result()
                        if directory is not None:

                            directorys.append(directory)
                            update_progress()
                    except Exception as e:
                        print(f"Error fetching directory: {e}")

        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Parallel Execution Time: {elapsed_time} seconds")

        return directorys

    def fetch_directory(self, column):
        _link = f'{self.url}/{column}'
        response = requests.get(_link)
        if response.status_code == 200:
            print(_link)
            return Node(column, _link)
        return None

    def get_files(self, file_directory):
        pass
