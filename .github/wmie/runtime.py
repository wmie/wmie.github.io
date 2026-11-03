"""Reuse exact, globally installed gh-aw tools and digest-pinned Docker images.

The caller supplies download_docker_images.sh from the pinned gh-aw setup
action. No custom npm prefix, agent configuration, or provider retry is used.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time


PACKAGES = {'pi': '@earendil-works/pi-coding-agent', 'codex': '@openai/codex'}
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')
IMAGE = re.compile(
    r'(?P<repository>[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/'
    r'(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*)'
    r'(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]*))?'
    r'@(?P<digest>sha256:[a-f0-9]{64})'
)


class RuntimeFailure(Exception):
    """Only fixed diagnostic codes may cross the subprocess boundary."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise RuntimeFailure('invalid_arguments')


def status(tool, state, started, **fields):
    print(json.dumps({'tool': tool, 'state': state,
                      'seconds': round(time.monotonic() - started, 3), **fields}), flush=True)


def run(command, *, timeout=30, env=None):
    # Child output can include registry URLs, configuration, or credentials.
    # Keep it captured even when a command fails; report only fixed codes.
    try:
        return subprocess.run(command, env=env, capture_output=True, text=True,
                              errors='replace', timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def exact_version(version):
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise RuntimeFailure('invalid_version')
    return version


def global_tool_matches(tool, version):
    root = run(['npm', 'root', '-g'])
    executable = shutil.which(tool)
    if root is None or root.returncode or not executable:
        return False
    try:
        package = (Path(root.stdout.strip()) / PACKAGES[tool]).resolve(strict=True)
        metadata = json.loads((package / 'package.json').read_text())
        if metadata.get('name') != PACKAGES[tool] or metadata.get('version') != version:
            return False
        # A matching unrelated PATH command is insufficient: gh-aw must be
        # able to mount the current Node installation's global npm package.
        if not Path(executable).resolve(strict=True).is_relative_to(package):
            return False
    except (OSError, ValueError, TypeError, AttributeError):
        return False
    result = run([executable, '--version'], timeout=15)
    expected = version if tool == 'pi' else 'codex-cli ' + version
    return result is not None and result.returncode == 0 and result.stdout.strip() == expected


def install(tool, version):
    started = time.monotonic()
    exact_version(version)
    if global_tool_matches(tool, version):
        status(tool, 'reused', started, version=version)
        return
    result = run(['npm', 'install', '--ignore-scripts', '-g', PACKAGES[tool] + '@' + version],
                 timeout=600)
    if result is None or result.returncode:
        raise RuntimeFailure('install_failed')
    if not global_tool_matches(tool, version):
        raise RuntimeFailure('installed_version_mismatch')
    status(tool, 'installed', started, version=version)


def normalize_images(images):
    normalized = []
    aliases = {}
    for image in images:
        match = IMAGE.fullmatch(image) if isinstance(image, str) else None
        if match is None:
            raise RuntimeFailure('invalid_image_pin')
        repository, tag, digest = match.group('repository', 'tag', 'digest')
        registry = repository.split('/', 1)[0]
        if '.' not in registry and ':' not in registry and registry != 'localhost':
            raise RuntimeFailure('unqualified_image')
        alias = repository + ':' + (tag or 'latest')
        if alias in aliases and aliases[alias] != digest:
            raise RuntimeFailure('conflicting_image_alias')
        aliases[alias] = digest
        reference = alias + '@' + digest
        if reference not in normalized:
            normalized.append(reference)
    if not normalized:
        raise RuntimeFailure('images_missing')
    return normalized


def local_aliases(images):
    # Match the normal downloader's AWF :latest aliases on its never path.
    aliases = list(images)
    for image in images:
        match = IMAGE.fullmatch(image)
        repository, digest = match.group('repository', 'digest')
        if repository.startswith('ghcr.io/github/gh-aw-'):
            aliases.append(repository + ':latest@' + digest)
    return normalize_images(aliases)


def cached(images):
    for image in images:
        match = IMAGE.fullmatch(image)
        expected = match.group('repository') + '@' + match.group('digest')
        result = run(['docker', 'image', 'inspect', '--format',
                      '{{range .RepoDigests}}{{println .}}{{end}}', image])
        if result is None or result.returncode or expected not in result.stdout.splitlines():
            return False
    return True


def check_downloader(downloader):
    if not Path(downloader).is_file():
        raise RuntimeFailure('downloader_missing')


def download(downloader, images):
    started = time.monotonic()
    images = normalize_images(images)
    aliases = local_aliases(images)  # Validate every alias before any mutation.
    check_downloader(downloader)
    env = dict(os.environ, GH_AW_DOCKER_IMAGE_PULL_POLICY='never')
    if cached(images):
        result = run(['bash', downloader, *aliases], timeout=600, env=env)
        if result is not None and result.returncode == 0:
            status('images', 'reused', started, count=len(images))
            return
    # Explicitly select the pinned downloader's normal behavior. An ambient
    # pull-policy must never turn a missing/wrong digest into a successful hit.
    env['GH_AW_DOCKER_IMAGE_PULL_POLICY'] = 'always'
    result = run(['bash', downloader, *images], timeout=1200, env=env)
    if result is None or result.returncode:
        raise RuntimeFailure('image_download_failed')
    if not cached(images):
        raise RuntimeFailure('downloaded_digest_mismatch')
    status('images', 'downloaded', started, count=len(images))


def lock_pins(path):
    try:
        with Path(path).open() as source:
            first, second = source.readline(), source.readline()
        if not first.startswith('# gh-aw-metadata: ') or not second.startswith('# gh-aw-manifest: '):
            raise RuntimeFailure('invalid_lock_metadata')
        metadata = json.loads(first.removeprefix('# gh-aw-metadata: '))
        manifest = json.loads(second.removeprefix('# gh-aw-manifest: '))
        if metadata['compiler_version'] != 'v0.93.4':
            raise RuntimeFailure('unsupported_lock_compiler')
        versions = metadata['engine_versions']
        if not isinstance(versions, dict) or set(versions) != set(PACKAGES):
            raise RuntimeFailure('unsupported_lock_engines')
        for version in versions.values():
            exact_version(version)
        containers = manifest['containers']
        if not isinstance(containers, list):
            raise RuntimeFailure('invalid_lock_containers')
        images = []
        for container in containers:
            pinned = container['pinned_image']
            image = normalize_images([pinned])[0]
            declared = normalize_images([container['image'] + '@' + container['digest']])[0]
            if image != declared:
                raise RuntimeFailure('inconsistent_lock_container')
            images.append(image)
        images = normalize_images(images)
        local_aliases(images)
        return versions, images
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise RuntimeFailure('invalid_lock_metadata') from None


def main():
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    installer = commands.add_parser('install')
    installer.add_argument('tool', choices=tuple(PACKAGES))
    installer.add_argument('version')
    images = commands.add_parser('images')
    images.add_argument('--downloader', required=True)
    images.add_argument('images', nargs='+')
    warm = commands.add_parser('warm')
    warm.add_argument('--lock', required=True)
    warm.add_argument('--downloader', required=True)
    warm.add_argument('--dry-run', action='store_true')
    started = time.monotonic()
    tool = 'runtime'
    try:
        args = parser.parse_args()
        tool = args.tool if args.command == 'install' else args.command
        if args.command == 'install':
            install(args.tool, args.version)
        elif args.command == 'images':
            download(args.downloader, args.images)
        else:
            versions, images = lock_pins(args.lock)
            check_downloader(args.downloader)
            if args.dry_run:
                status('warm', 'validated', started, versions=versions, images=len(images))
                return 0
            for engine in PACKAGES:
                install(engine, versions[engine])
            download(args.downloader, images)
            status('warm', 'ready', started, versions=versions, images=len(images))
        return 0
    except RuntimeFailure as error:
        status(tool, 'failed', started, reason=str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
