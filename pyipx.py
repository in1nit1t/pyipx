import os
import sys
import zlib
import struct
import shutil
import marshal
import hashlib
import tempfile
from io import BytesIO


class FileType:

    EXE = 1
    ELF = 2
    RAW = 3


class Util:

    @staticmethod
    def compress(raw_bytes):
        return zlib.compress(raw_bytes)

    @staticmethod
    def decompress(raw_bytes):
        return zlib.decompress(raw_bytes)

    @staticmethod
    def make_string(s):
        try:
            return s.decode("utf-8")
        except:
            return s

    @staticmethod
    def get_file_hash(path):
        md5 = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5.update(chunk)
        return md5.hexdigest()

    @staticmethod
    def get_files(directory):
        files = set()
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                file_name = os.path.relpath(full_path, directory)
                file_hash = Util.get_file_hash(full_path)
                files.add((file_name, file_hash))
        return files

    @staticmethod
    def compare_directories(dir1, dir2):
        files1 = Util.get_files(dir1)
        files2 = Util.get_files(dir2)
        return [f[0] for f in files2 - files1]


class Metadata:

    LOW_VERSION_SIZE = 24
    HIGH_VERSION_SIZE = 88
    MAGIC = b"\x4D\x45\x49\x0C\x0B\x0A\x0B\x0E"

    def __init__(self, package_length, toc_offset, toc_length, py_version, py_libname):
        self._package_length = package_length
        self._toc_offset = toc_offset
        self._toc_length = toc_length
        self._py_version = py_version
        self._py_libname = py_libname

    def __len__(self):
        return len(self.to_raw_bytes())

    def get_package_length(self):
        return self._package_length

    def get_toc_offset(self):
        return self._toc_offset

    def get_toc_length(self):
        return self._toc_length

    def get_py_version(self):
        return self._py_version

    def get_py_major_version(self):
        div = 100 if self._py_version >= 100 else 10
        return self._py_version // div

    def get_py_minor_version(self):
        mod = 100 if self._py_version >= 100 else 10
        return self._py_version % mod

    def get_py_libname(self):
        return self._py_libname

    def set_package_length(self, package_length):
        self._package_length = package_length

    def set_toc_offset(self, toc_offset):
        self._toc_offset = toc_offset

    def set_toc_length(self, toc_length):
        self._toc_length = toc_length

    def to_raw_bytes(self):
        return Metadata.MAGIC + struct.pack('!4I', self._package_length, \
            self._toc_offset, self._toc_length, self._py_version) + self._py_libname

    @staticmethod
    def from_raw_bytes(raw):
        low, py_libname = raw[:Metadata.LOW_VERSION_SIZE], raw[Metadata.LOW_VERSION_SIZE:]
        package_length, toc_offset, toc_length, py_version = struct.unpack('!4I', low[len(Metadata.MAGIC):])
        return Metadata(package_length, toc_offset, toc_length, py_version, py_libname)


class Asset:

    def __init__(self, _type, name, compress_flag):
        self._type = _type
        self._name = name
        self._original_data = b''
        self._compressed_data = b''
        self._compress_flag = compress_flag
        self._parent = None

    @staticmethod
    def _dump_raw_file(output_path, data):
        output_path = output_path.replace('\\', os.path.sep).replace('/', os.path.sep).replace("..", "__")
        parent_dir = os.path.dirname(output_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir)
        with open(output_path, "wb") as f:
            f.write(data)

    def _dump_pyc(self, processor, file_path, with_header):
        raw = b''
        if not with_header:
            raw = processor.get_pyc_magic()
            raw += b'\x00' * (processor.get_pyc_header_size() - 4)
        raw += self.get_original_data()
        Asset._dump_raw_file(file_path + ".pyc", raw)

    def _dump_pyz(self, processor, pyz_path):
        output_basedir = pyz_path + "_extracted"
        if not os.path.exists(output_basedir):
            os.makedirs(output_basedir)
        if not processor.py_version_check():
            print("[!] Skipping PYZ extraction")
            return
        with open(pyz_path, "rb") as f:
            assert f.read(4) == b'PYZ\x00'
            _, toc_begin = struct.unpack("!2I", f.read(8))
            f.seek(toc_begin, 0)
            toc = marshal.load(f)
            if isinstance(toc, list):
                toc = dict(toc)
            for file_name, file_attr in toc.items():
                is_package, offset, length = file_attr
                file_name = Util.make_string(file_name).replace("..", "__").replace('.', os.path.sep)
                if is_package:
                    file_name = os.path.join(file_name, "__init__")

                f.seek(offset, 0)
                asset = Asset(b's', file_name, 1)
                asset.set_compressed_data(f.read(length))
                asset.dump(output_basedir, processor)
                asset.set_parent(self)
                processor.add_asset(asset)

    def get_name(self):
        return self._name

    def get_full_name(self):
        asset = self
        name = Util.make_string(asset.get_name())
        if asset.get_type() in b"Mms":
            name += ".pyc"
        while True:
            asset = asset.get_parent()
            if not asset:
                break
            parent_path = Util.make_string(asset.get_name())
            if asset.get_type() in b"Zz":
                parent_path += "_extracted"
            name = os.path.join(parent_path, name)
        return name

    def get_type(self):
        return self._type

    def get_parent(self):
        return self._parent

    def get_original_size(self):
        return len(self.get_original_data())

    def get_compressed_size(self):
        return len(self.get_compressed_data())

    def get_compressed_flag(self):
        return self._compress_flag

    def get_compressed_data(self):
        if not self._compressed_data:
            self._compressed_data = Util.compress(self._original_data)
        return self._compressed_data

    def get_original_data(self):
        if not self._original_data:
            self._original_data = Util.decompress(self._compressed_data)
        return self._original_data

    def set_name(self, name):
        self._name = name

    def set_parent(self, asset):
        self._parent = asset

    def set_original_data(self, original_data):
        self._original_data = original_data

    def set_compressed_data(self, compressed_data):
        self._compressed_data = compressed_data

    def update_original_data(self, original_data):
        self.set_original_data(original_data)
        self.set_compressed_data(b'')

    def dump(self, basedir, processor):
        asset_name = Util.make_string(self._name)
        file_path = os.path.join(basedir, asset_name)
        if self._type in b"od":
            return
        elif self._type == b's':
            self._dump_pyc(processor, file_path, False)
        elif self._type in b"Mm":
            self._dump_pyc(processor, file_path, self.get_original_data()[2:4] == b"\r\n")
        else:
            Asset._dump_raw_file(file_path, self.get_original_data())
            if self._type in b"Zz":
                self._dump_pyz(processor, file_path)


class TocEntry:

    OTHER_FIELDS_SIZE = struct.calcsize("!IIIBc")

    def __init__(self, data_offset, compressed_size, original_size, compress_flag, asset_type, asset_name):
        self._data_offset = data_offset
        self._compressed_size = compressed_size
        self._original_size = original_size
        self._compress_flag = compress_flag
        self._asset_type = asset_type
        self._asset_name = asset_name

    def __len__(self):
        return len(self.to_raw_bytes())

    def get_data_offset(self):
        return self._data_offset

    def get_compressed_size(self):
        return self._compressed_size

    def get_original_size(self):
        return self._original_size

    def get_compress_flag(self):
        return self._compress_flag

    def get_asset_type(self):
        return self._asset_type

    def get_asset_name(self):
        return self._asset_name

    def set_data_offset(self, data_offset):
        self._data_offset = data_offset

    def to_raw_bytes(self):
        entry_size = 4 + TocEntry.OTHER_FIELDS_SIZE + len(self._asset_name) + 1
        entry_size = ((entry_size + 15) // 16) * 16
        raw = struct.pack("!4IBc", entry_size, self._data_offset, \
            self._compressed_size, self._original_size, self._compress_flag, self._asset_type)
        raw += self._asset_name
        return raw.ljust(entry_size, b'\x00')

    @staticmethod
    def from_raw_bytes(raw):
        data_offset, compressed_size, original_size, compress_flag, \
            asset_type = struct.unpack("!3IBc", raw[:TocEntry.OTHER_FIELDS_SIZE])
        asset_name = raw[TocEntry.OTHER_FIELDS_SIZE:].rstrip(b'\x00')
        return TocEntry(data_offset, compressed_size, original_size, compress_flag, asset_type, asset_name)


class Toc:

    def __init__(self):
        self._entries = []

    def __len__(self):
        return len(self._entries)

    def __getitem__(self, idx):
        return self._entries[idx]

    def add_entry(self, toc_entry):
        self._entries.append(toc_entry)

    @staticmethod
    def from_raw_bytes(raw):
        toc = Toc()
        stream = BytesIO(raw)
        parsed, total_size = 0, len(raw)
        while parsed < total_size:
            entry_size, = struct.unpack("!I", stream.read(4))
            toc.add_entry(TocEntry.from_raw_bytes(stream.read(entry_size - 4)))
            parsed += entry_size
        return toc


class Pydata:

    def __init__(self, base, metadata, toc):
        self._base = base
        self._metadata = metadata
        self._toc = toc

    def get_base(self):
        return self._base

    def get_metadata(self):
        return self._metadata

    def assets_count(self):
        return len(self._toc)

    def asset_entry_at(self, idx):
        return self._toc[idx]

    @staticmethod
    def from_metadata(stream, metadata_offset):
        stream.seek(metadata_offset + Metadata.LOW_VERSION_SIZE, 0)
        struct_size = Metadata.HIGH_VERSION_SIZE if b"python" in stream.read(64) else Metadata.LOW_VERSION_SIZE
        stream.seek(metadata_offset, 0)
        metadata_raw = stream.read(struct_size)
        metadata = Metadata.from_raw_bytes(metadata_raw)

        pydata_base = metadata_offset - metadata.get_package_length() + len(metadata)
        stream.seek(pydata_base + metadata.get_toc_offset(), 0)
        toc_raw = stream.read(metadata.get_toc_length())
        toc = Toc.from_raw_bytes(toc_raw)
        return Pydata(pydata_base, metadata, toc)


class Pyipx:

    def __init__(self, file_path):
        self._file_path = file_path

        self._stream = None
        self._pydata = None
        self._file_type = 0
        self._pyc_magic = b''
        self._pyc_header_size = 0
        self._py_major_version = 0
        self._py_minor_version = 0
        self._assets = {}
        self._preload()

    def __del__(self):
        if self._stream:
            self._stream.close()

    @staticmethod
    def _find_metadata(stream):
        stream.seek(0, 2)
        file_size = stream.tell()

        for pos in range(file_size - 4096, -4095, -4096):
            pos = pos if pos >= 0 else 0
            stream.seek(pos, 0)
            buffer = stream.read(4096)
            offset = buffer.rfind(Metadata.MAGIC)
            if offset != -1:
                return pos + offset
        return -1

    @staticmethod
    def _find_metadata_elf(stream):
        from elftools.elf.elffile import ELFFile
        stream.seek(0, 0)
        elf = ELFFile(stream)
        section = elf.get_section_by_name("pydata")
        if section:
            size = section.header.sh_size
            addr = section.header.sh_offset
            stream.seek(addr, 0)
            pydata = BytesIO(stream.read(size))
            return addr + Pyipx._find_metadata(pydata)
        return -1

    def _preload(self):
        self._stream = open(self._file_path, "rb")
        file_magic = self._stream.read(4)
        if b"ELF" in file_magic:
            self._file_type = FileType.ELF
            metadata_offset = Pyipx._find_metadata_elf(self._stream)
        else:
            self._file_type = FileType.EXE if b"MZ" == file_magic[:2] else FileType.RAW
            metadata_offset = Pyipx._find_metadata(self._stream)
        assert metadata_offset != -1, "[!] Can't find metadata in the given file"
        self._pydata = Pydata.from_metadata(self._stream, metadata_offset)
        metadata = self._pydata.get_metadata()
        self._py_major_version = metadata.get_py_major_version()
        self._py_minor_version = metadata.get_py_minor_version()
        self._pyc_magic = self.get_pyc_magic()
        self._pyc_header_size = self.get_pyc_header_size()

    def _update_pyz(self, target):
        toc = []
        offset = 17
        data_raw = b''
        for asset in self._assets.values():
            parent = asset.get_parent()
            if not parent or parent.get_name() != target:
                continue
            data_raw += asset.get_compressed_data()
            asset_name = asset.get_name().replace(os.sep, '.')
            is_package = int("__init__" in asset_name)
            if is_package:
                asset_name = asset_name[:asset_name.rfind("__init__") - 1]
            length = asset.get_compressed_size()
            toc.append((asset_name, (is_package, offset, length)))
            offset += length

        toc_raw = marshal.dumps(toc)
        toc_offset = struct.pack("!I", offset)
        pyz_raw = b"PYZ\x00" + self.get_pyc_magic() + toc_offset + b'\x00' * 5 + data_raw + toc_raw
        self._assets.get(target).update_original_data(pyz_raw)

    def _update_assets(self, extracted_dir, file_delta):
        pyz_updated = set()
        for f in file_delta:
            asset = self._assets.get(f, None)
            if asset:
                print("[*] Asset modified: " + f)
            else:
                print("[*] New asset detected: " + f)
                asset = Asset(b's', '', 1)
                if "_extracted" in f:
                    parent_name = f[:f.rfind("_extracted")]
                    asset_name = f[f.rfind("_extracted") + 11:]
                    asset.set_parent(self._assets.get(parent_name))
                else:
                    asset_name = f
                if '.' in asset_name:
                    asset_name = asset_name[:asset_name.rfind('.')]
                asset.set_name(asset_name)
                self.add_asset(asset)
            with open(os.path.join(extracted_dir, f), "rb") as g:
                asset.update_original_data(g.read()[self.get_pyc_header_size():])
            if asset.get_parent():
                pyz_updated.add(asset.get_parent().get_name())
        for name in pyz_updated:
            self._update_pyz(name)

    def _build_pydata(self):
        offset = 0
        toc_raw = b''
        data_raw = b''
        for name, asset in self._assets.items():
            if asset.get_parent() or asset.get_type() in b"od":
                continue
            flag = asset.get_compressed_flag()
            data = asset.get_compressed_data() if flag else asset.get_original_data()
            entry = TocEntry(offset, len(data), \
                asset.get_original_size(), flag, asset.get_type(), asset.get_name().encode("utf-8"))
            toc_raw += entry.to_raw_bytes()
            data_raw += data
            offset += len(data)
        stub = self._pydata.get_metadata()
        package_length = offset + len(toc_raw) + len(stub)
        metadata = Metadata(package_length, offset, len(toc_raw), stub.get_py_version(), stub.get_py_libname())
        return data_raw + toc_raw + metadata.to_raw_bytes()

    def _pack(self, output_path):
        pydata = self._build_pydata()
        if self._file_type == FileType.EXE:
            offset = self._pydata.get_base()
            with open(output_path, "wb") as f:
                self._stream.seek(0, 0)
                f.write(self._stream.read(offset))
                f.write(pydata)
        elif self._file_type == FileType.ELF:
            tmp_file = "pydata.raw"
            with open(tmp_file, "wb") as f:
                f.write(pydata)
            os.system("objcopy --update-section pydata={0} {1} {2}".format(tmp_file, self._file_path, output_path))
            os.remove(tmp_file)
        else:
            with open(output_path, "wb") as f:
                f.write(pydata)

    def add_asset(self, asset):
        asset_full_name = asset.get_full_name()
        assert asset_full_name not in self._assets
        self._assets[asset_full_name] = asset

    def py_version_check(self):
        result = self._py_major_version == sys.version_info.major \
            and self._py_minor_version == sys.version_info.minor
        if not result:
            print("[!] It is recommended to use Python {0}.{1} to re-run this script".format(self._py_major_version, self._py_minor_version))
        return result

    def get_pyc_magic(self):
        if not self._pyc_magic:
            for i in range(self._pydata.assets_count()):
                entry = self._pydata.asset_entry_at(i)
                if entry.get_asset_type() in b"Zz":
                    self._stream.seek(self._pydata.get_base() + entry.get_data_offset() + 4, 0)
                    self._pyc_magic = self._stream.read(4)
                    break
        return self._pyc_magic

    def get_pyc_header_size(self):
        if not self._pyc_header_size:
            size = 4
            if self._py_major_version >= 3 and self._py_minor_version >= 7:
                size += 12
            else:
                size += 4
                if self._py_major_version >= 3 and self._py_minor_version >= 3:
                    size += 4
            self._pyc_header_size = size
        return self._pyc_header_size

    def extract(self, output_basedir, with_hint):
        if not os.path.exists(output_basedir):
            os.makedirs(output_basedir)

        for i in range(self._pydata.assets_count()):
            entry = self._pydata.asset_entry_at(i)
            self._stream.seek(self._pydata.get_base() + entry.get_data_offset(), 0)
            data = self._stream.read(entry.get_compressed_size())
            compress_flag = entry.get_compress_flag()
            asset = Asset(entry.get_asset_type(), Util.make_string(entry.get_asset_name()), compress_flag)
            if compress_flag:
                asset.set_compressed_data(data)
            else:
                asset.set_original_data(data)
            if with_hint and asset.get_type() == b's':
                print("[*] Maybe entrance: {0}".format(asset.get_full_name()))
            asset.dump(output_basedir, self)
            self.add_asset(asset)

    def repack(self, extracted_dir, output_path):
        temp_dir = tempfile.mkdtemp()
        self.extract(temp_dir, False)

        file_delta = Util.compare_directories(temp_dir, extracted_dir)
        if file_delta:
            self._update_assets(extracted_dir, file_delta)
            self._pack(output_path)
        else:
            print("[?] Nothing changed, skip repackaging")

        shutil.rmtree(temp_dir, True)


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc not in [2, 4]:
        print("Usage: {0} file [dir out]\n".format(os.path.basename(sys.argv[0])))
        print("Options:")
        print("  file\texecutable to extract / repack")
        print("   dir\tdirectory to be repackaged")
        print("   out\trepackage file output path")
        exit()

    pyipx = Pyipx(sys.argv[1])
    if argc == 2:
        pyipx.extract(os.path.abspath(sys.argv[1]) + "_extracted", True)
        print("[+] Extraction finished")
    else:
        pyipx.repack(sys.argv[2], sys.argv[3])
        print("[+] Repackaging finished")
