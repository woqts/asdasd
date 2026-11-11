# Generated Helios launcher. Edit the shared launcher sources, then rebuild.
"""Embedded into the single launcher downloaded by Helios; no login or setup.

The two public artifact pins are injected at build time. Windows CNG verifies
the updater before it runs; the updater verifies the complete script package.
"""
import base64
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

ARTIFACT_PINS = {'artifact-3566145506cdd12bb9d0': 'BEFr41lbxGNysAFZtfe6LM6H6E_7Bw3B2gj7tSWuavEhEFcZXfNFbDoXZeTgn7UUDhna2m728cO9t0k1btHBxgo', 'artifact-1eed55cd12cdf38303bb': 'BGRMMsrdNeFzdTvke-merT7X0xufpaOkYNdJSblrAdNIC7eY4DonI-Riduj3Sd5EmC9DdLtHB9mRHEp-8MDVfsY'}  # Filled by the launcher build, never from a network response.


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('The update download could not be verified. Try again later.')


@contextlib.contextmanager
def _open(opener, request):
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.URLError as error:
        if isinstance(error.reason, ssl.SSLCertVerificationError) and error.reason.verify_code in (9, 10):
            raise RuntimeError('Sync Clock') from error
        raise
    with response:
        yield response


def _decode(value, size):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('Invalid artifact signature encoding.')
    result = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    if len(result) != size or base64.urlsafe_b64encode(result).rstrip(b'=').decode() != value:
        raise ValueError('Invalid artifact signature size.')
    return result


def _signature(payload, signature, key_id):
    point = _decode(ARTIFACT_PINS[key_id], 65)
    if point[0] != 4:
        raise ValueError('Invalid artifact public key.')
    signature = _decode(signature, 64)
    digest = hashlib.sha256(b'OutputSense/release-manifest/v1\0' + payload).digest()
    api = ctypes.WinDLL('bcrypt.dll', winmode=0x800)
    handle = ctypes.c_void_p
    api.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(handle), ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
    api.BCryptImportKeyPair.argtypes = [handle, handle, ctypes.c_wchar_p, ctypes.POINTER(handle), ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    api.BCryptVerifySignature.argtypes = [handle, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    api.BCryptDestroyKey.argtypes = [handle]
    api.BCryptCloseAlgorithmProvider.argtypes = [handle, ctypes.c_ulong]
    algorithm, key = handle(), handle()
    try:
        if api.BCryptOpenAlgorithmProvider(ctypes.byref(algorithm), 'ECDSA_P256', None, 0) < 0:
            raise RuntimeError('Windows signature verification is unavailable.')
        blob = struct.pack('<II', 0x31534345, 32) + point[1:]
        if api.BCryptImportKeyPair(algorithm, None, 'ECCPUBLICBLOB', ctypes.byref(key), blob, len(blob), 0) < 0:
            raise RuntimeError('Windows rejected the artifact public key.')
        if api.BCryptVerifySignature(key, None, digest, len(digest), signature, len(signature), 0) < 0:
            raise ValueError('The script update could not be verified. Try again later.')
    finally:
        if key:
            api.BCryptDestroyKey(key)
        if algorithm:
            api.BCryptCloseAlgorithmProvider(algorithm, 0)


def _fields(pairs):
    result = dict(pairs)
    if len(result) != len(pairs) or any(not isinstance(value, str) for value in result.values()):
        raise ValueError('Invalid release fields.')
    return result


def _manifest(payload, signature, key_id, product):
    if not 0 < len(payload) <= 65536 or not re.fullmatch(rb'[\x20-\x7e\n]+\n', payload):
        raise ValueError('Invalid release metadata.')
    _signature(payload, signature, key_id)
    rows = [json.loads(line, object_pairs_hook=_fields) for line in payload.decode('ascii').splitlines()]
    header, files = rows[0], rows[1:]
    if (header.get('version') != '1' or header.get('audience') != 'outputsense-artifacts'
            or header.get('product') != product or header.get('keyId') != key_id
            or not re.fullmatch(r'[1-9][0-9]{0,15}', header.get('revision', ''))
            or header.get('fileCount') != str(len(files)) or not 2 <= len(files) <= 256):
        raise ValueError('Release metadata belongs to another product.')
    return header, files


def _component(files, kind, path):
    matches = [row for row in files if row.get('kind') == kind and row.get('path') == path]
    if len(matches) != 1:
        raise ValueError('Required signed startup file is missing.')
    row = matches[0]
    if not re.fullmatch(r'[0-9a-f]{64}', row.get('sha256', '')) or not re.fullmatch(r'[1-9][0-9]{0,8}', row.get('size', '')) or int(row['size']) > 67108864:
        raise ValueError('Invalid startup file descriptor.')
    return row


@contextlib.contextmanager
def _hold(path, directory=False):
    api = ctypes.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    api.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
    api.CreateFileW.restype = ctypes.c_void_p
    api.CloseHandle.argtypes = [ctypes.c_void_p]
    api.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    handle = api.CreateFileW(str(path), 0x80 if directory else 0x80000000, 3 if directory else 1, None, 3, 0x00200000 | (0x02000000 if directory else 0), None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), 'Cannot access the script files. Close the script and try again.')
    try:
        info = (ctypes.c_ulong * 13)()
        if not api.GetFileInformationByHandle(handle, info) or info[0] & 0x400 or bool(info[0] & 0x10) != directory or (not directory and info[10] != 1):
            raise ValueError('The script folder could not be verified. Download the launcher into a regular local folder.')
        yield path
    finally:
        api.CloseHandle(handle)


def _matches(path, row):
    with path.open('rb') as source:
        return os.fstat(source.fileno()).st_size == int(row['size']) and hashlib.file_digest(source, 'sha256').hexdigest() == row['sha256']


def _download(opener, url, target, row):
    temporary = None
    try:
        with _open(opener, urllib.request.Request(url, headers={'Cache-Control': 'no-store', 'User-Agent': 'OutputSense/1'})) as response, tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as output:
            temporary = Path(output.name)
            if response.status != 200 or response.headers.get('Content-Length') != row['size']:
                raise ValueError('Unexpected updater download size.')
            digest, count, started = hashlib.sha256(), 0, time.monotonic()
            # Protected startup files can exceed 50 MiB. Allow slow transfers
            # without relaxing the signed size/hash or the socket idle timeout.
            deadline = started + min(1200, max(120, 60 + int(row['size']) / 65536))
            while chunk := response.read(65536):
                count += len(chunk)
                if count > int(row['size']):
                    raise ValueError('Updater download exceeded its signed size.')
                if time.monotonic() > deadline:
                    raise TimeoutError('Startup download timed out. Check your connection and try again.')
                digest.update(chunk)
                output.write(chunk)
            if count != int(row['size']) or digest.hexdigest() != row['sha256']:
                raise ValueError('Updater download failed verification.')
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _installed_manifest(root, product):
    record_path = root / 'bin' / 'update' / 'current'
    if not record_path.exists():
        record_path = root / '.outputsense' / 'current'
    with _hold(record_path) as path, path.open('rb') as source:
        record = source.read(65801)
    if len(record) > 65800:
        raise ValueError('Installed release record is too large.')
    magic, key, signature, payload = record.split(b'\n', 3)
    if magic != b'OutputSense-folder/v1':
        raise ValueError('Invalid installed release record.')
    return _manifest(payload, signature.decode('ascii'), key.decode('ascii'), product)


def helios_runtime():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel.GetModuleHandleW.restype = ctypes.c_void_p
    host = kernel.GetModuleHandleW('cvpython_host.pyd')
    if not host:
        raise RuntimeError('Start this script from Helios.')
    get_root = ctypes.CDLL('cvpython_host.pyd', handle=host).helios_host_get_root_path
    get_root.argtypes = []
    get_root.restype = ctypes.c_char_p
    runtime = get_root()
    if not runtime:
        raise RuntimeError('Helios did not provide its runtime directory.')
    path = Path(runtime.decode('utf-8'))
    if not path.is_absolute():
        raise RuntimeError('Helios did not provide a valid runtime directory.')
    return str(path)


def prepare_script(product, root, environment):
    if product not in ('2k-vision', 'aim-engine', 'mlb', 'cfb', 'nfl', 'pga', 'fc'):
        raise ValueError('Unknown script.')
    origins = {'stage': 'https://outputsense-stage-files.output-sense.workers.dev', 'production': 'https://downloads.outputsense.com'}
    base = origins[environment] + '/v1/releases/' + product
    opener = urllib.request.build_opener(_NoRedirect())
    with _open(opener, urllib.request.Request(base + '/manifest', headers={'Cache-Control': 'no-store', 'User-Agent': 'OutputSense/1'})) as response:
        payload = response.read(65537)
        header, files = _manifest(payload, response.headers['X-OutputSense-Signature'], response.headers['X-OutputSense-Key'], product)
    updater = _component(files, 'updater', 'bin/Updater.exe')
    with contextlib.ExitStack() as held:
        # Retain every ancestor against rename while creating/using local files.
        for parent in reversed((root, *root.parents)):
            held.enter_context(_hold(parent, True))
        binary_root = root / 'bin'
        binary_root.mkdir(exist_ok=True)
        held.enter_context(_hold(binary_root, True))
        metadata = binary_root / 'update'
        metadata.mkdir(exist_ok=True)
        held.enter_context(_hold(metadata, True))
        if (metadata / 'current').exists() or (root / '.outputsense' / 'current').exists():
            previous, _ = _installed_manifest(root, product)
            if int(header['revision']) < int(previous['revision']):
                raise ValueError('The available update is older than your installed release. Try again later.')
        executable = metadata / 'Updater.exe'
        needs_download = True
        if executable.exists():
            with _hold(executable):
                needs_download = not _matches(executable, updater)
        if needs_download:
            installed = binary_root / 'Updater.exe'
            if installed.exists():
                with _hold(installed):
                    if _matches(installed, updater):
                        # A temporary verified copy lets the updater repair its
                        # installed counterpart without overwriting itself.
                        temporary = None
                        try:
                            with tempfile.NamedTemporaryFile(dir=metadata, delete=False) as output, installed.open('rb') as source:
                                temporary = Path(output.name)
                                while chunk := source.read(65536):
                                    output.write(chunk)
                            os.replace(temporary, executable)
                        finally:
                            if temporary is not None:
                                temporary.unlink(missing_ok=True)
                        needs_download = False
            if needs_download:
                _download(opener, base + '/bootstrap', executable, updater)
        with _hold(executable):
            if not _matches(executable, updater):
                raise ValueError('Updater changed before launch.')
            command = [str(executable), '--product', product, '--install-root', str(root), '--from-launcher',
                       '--helios-runtime=' + helios_runtime()]
            if environment == 'stage':
                command.append('--outputsense-stage')
            result = subprocess.run(command, cwd=root, timeout=1200, creationflags=0x08000000, check=False)
        try:
            executable.unlink(missing_ok=True)
        except PermissionError:
            pass  # A concurrent reader still owns it; the next launch retries.
        if result.returncode:
            raise RuntimeError('Script update did not complete. See the updater message and start the script again.')
        installed_header, installed_files = _installed_manifest(root, product)
        if int(installed_header['revision']) < int(header['revision']):
            raise ValueError('Updater did not activate the current release.')
        launcher = _component(installed_files, 'data', 'bin/OutputSenseLauncher.dll')
        # The caller retains this lock until native package verification takes over.
        return launcher

"""Helios worker lifecycle after the automatic signed-file update."""
import ctypes
import os
from pathlib import Path


class VerifiedScriptWorker:
    def __init__(self, product: str, script_file: str, width: int, height: int, *, environment: str = 'production'):
        self._package = None
        self._release_package = None
        self._helios_directory = None
        self._shutdown = None
        self._process = None
        self._result = None
        self._launcher_lock = None
        self._empty = bytearray(1)
        try:
            if environment not in ('production', 'stage'):
                raise ValueError('Unknown Auto Input environment')
            profile = 1 if environment == 'stage' else 0
            root = Path(script_file).resolve().parent
            descriptor = prepare_script(product, root, environment)
            bootstrap_path = root / 'bin' / 'OutputSenseLauncher.dll'
            launcher_lock = _hold(bootstrap_path)
            launcher_lock.__enter__()
            self._launcher_lock = launcher_lock
            if not _matches(bootstrap_path, descriptor):
                raise RuntimeError('The signed script launcher changed before loading.')
            # The static bootstrap imports only Windows system libraries.
            self._bootstrap = ctypes.WinDLL(str(bootstrap_path), winmode=0x800)
            acquire = self._bootstrap.OutputSenseOpenPackage
            acquire.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
            acquire.restype = ctypes.c_void_p
            self._release_package = self._bootstrap.OutputSenseClosePackage
            self._release_package.argtypes = [ctypes.c_void_p]
            self._release_package.restype = None
            helper_path = ctypes.create_unicode_buffer(32768)
            self._package = acquire(product, str(Path(script_file).resolve().parent), helper_path, len(helper_path), profile)
            if not self._package:
                raise RuntimeError("Script file verification failed. Start the script again to repair it.")

            self._helios_directory = os.add_dll_directory(os.path.join(helios_runtime(), "lib"))
            # Exclude the mutable working directory and package-adjacent DLLs.
            # Dependencies belong to Windows or the host's selected runtime.
            self._helper = ctypes.PyDLL(helper_path.value, winmode=0xC00)
            self._helper.r.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            self._helper.r.restype = ctypes.c_int
            self._helper.p.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
            self._helper.p.restype = ctypes.c_int
            self._helper.g.argtypes = []
            self._helper.g.restype = ctypes.c_void_p
            self._helper.x.argtypes = []
            self._helper.x.restype = None
            self._shutdown = self._helper.x
            result = self._helper.r(width, height, str(Path(script_file).resolve().parent).encode("utf-8"), profile)
            if result:
                raise RuntimeError("The script could not start. Close it and try again.")
            self._process, self._result = self._helper.p, self._helper.g
        except Exception:
            self.close()
            raise

    def close(self):
        self._process = self._result = None
        shutdown, self._shutdown = self._shutdown, None
        try:
            if shutdown is not None:
                shutdown()
        finally:
            directory, self._helios_directory = self._helios_directory, None
            try:
                if directory is not None:
                    directory.close()
            finally:
                package, self._package = self._package, None
                if package is not None:
                    self._release_package(package)
                launcher_lock, self._launcher_lock = self._launcher_lock, None
                if launcher_lock is not None:
                    launcher_lock.__exit__(None, None, None)

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass  # Explicit close reports errors; interpreter teardown cannot.

    def process(self, frame):
        if self._process is None:
            raise RuntimeError("The Auto Input script is closed.")
        size = self._process(frame.ctypes.data, frame.shape[1], frame.shape[0], frame.strides[0])
        if size <= 0:
            return frame, self._empty
        result = bytearray(size)
        ctypes.memmove((ctypes.c_ubyte * size).from_buffer(result), self._result(), size)
        return frame, result


AUTO_INPUT_ENVIRONMENT = 'production'

class GCVWorker(VerifiedScriptWorker):
    def __init__(self, width, height):
        super().__init__('2k-vision', __file__, width, height, environment=AUTO_INPUT_ENVIRONMENT)
