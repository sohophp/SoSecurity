from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED, ZIP_STORED
from struct import pack_into
import sys
import warnings

if len(sys.argv) != 2:
    raise SystemExit('Use an owned local ZIP test directory.')
root = Path(sys.argv[1])
if not root.is_dir():
    raise SystemExit('Use an owned local ZIP test directory.')
warnings.filterwarnings('ignore', message="Duplicate name: 'same'", category=UserWarning)

def write(name, entries):
    with ZipFile(root / (name + '.zip'), 'w', ZIP_DEFLATED) as archive:
        for path, content in entries:
            archive.writestr(path, content)

write('valid', [('sub/', b''), ('sub/file.bin', b'a\x00bcd')])
write('total', [('a', b'aaaa'), ('b', b'bbbb')])
write('traversal', [('../secret', b'x')])
write('absolute', [('/etc/passwd', b'x')])
write('backslash', [('sub\\secret', b'x')])
write('hidden', [('.htaccess', b'x')])
write('trailing_dot', [('report.', b'x')])
write('reserved', [('CON.txt', b'x')])
write('duplicate', [('same', b'a'), ('same', b'b')])
write('case_collision', [('Name', b'a'), ('name', b'b')])
write('nested', [('hidden.dat', b'PK\x03\x04' + b'\x00' * 40)])
write('nested_bzip', [('hidden.dat', b'BZh9' + b'\x00' * 40)])
write('nested_xz', [('hidden.dat', b'\xfd7zXZ\x00' + b'\x00' * 40)])
write('bomb', [('large.txt', b'A' * 5_000_000)])
write('ratio', [('small.txt', b'A' * 200_000)])
write('depth', [('a/b/c/d/e/f/g/h/i.txt', b'x')])
link = ZipInfo('shortcut')
link.create_system = 3
link.external_attr = (0o120777 << 16)
with ZipFile(root / 'symlink.zip', 'w') as archive:
    archive.writestr(link, b'../secret')
write('conflict', [('file', b'x'), ('file/child', b'y')])
write('nul', [('bad_name', b'x')])
nul = root / 'nul.zip'
nul.write_bytes(nul.read_bytes().replace(b'bad_name', b'bad\x00name'))
with ZipFile(root / 'many.zip', 'w', ZIP_STORED) as archive:
    for index in range(5000):
        archive.writestr(f'entry-{index}', b'')
with ZipFile(root / 'exact_entries.zip', 'w', ZIP_STORED) as archive:
    for index in range(100):
        archive.writestr(f'entry-{index}', b'')
with ZipFile(root / 'over_entries.zip', 'w', ZIP_STORED) as archive:
    for index in range(101):
        archive.writestr(f'entry-{index}', b'')
count = bytearray((root / 'valid.zip').read_bytes())
end = count.rfind(b'PK\x05\x06')
pack_into('<HH', count, end + 8, 1, 1)
(root / 'false_count.zip').write_bytes(count)
crc = bytearray((root / 'valid.zip').read_bytes())
central = crc.find(b'PK\x01\x02')
crc[central + 16] ^= 1
(root / 'false_crc.zip').write_bytes(crc)
size = bytearray((root / 'valid.zip').read_bytes())
central = size.find(b'PK\x01\x02', size.find(b'PK\x01\x02') + 4)
pack_into('<I', size, central + 24, 4)
(root / 'false_size.zip').write_bytes(size)
local = (root / 'valid.zip').read_bytes()
(root / 'local_mismatch.zip').write_bytes(local.replace(b'sub/file.bin', b'sub/fale.bin', 1))
offset = bytearray(local)
second = offset.find(b'PK\x01\x02', offset.find(b'PK\x01\x02') + 4)
pack_into('<I', offset, second + 42, 0)
(root / 'reused_local.zip').write_bytes(offset)
