
from discover.struture import Scrapper

_site = 'http://10.129.230.191'
_file = '/Users/pepeargentoo/directory-list-2.3-small.txt'
scrapper = Scrapper(_site)
scrapper.get_directorys(_file)
