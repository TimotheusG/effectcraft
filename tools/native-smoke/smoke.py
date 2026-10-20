#!/usr/bin/env python3
"""Bounded, isolated application-entry smoke; Python standard library only.

Runs a supplied built desktop binary (not a library test). Does not record audio.
Use --require-audio only on a runner with a deliberately provisioned output device.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
import wave


def make_fixture(path, seconds=15, rate=48000):
    """Original stereo chirps; MIT OR Apache-2.0, generated instead of stored media."""
    data = bytearray()
    for i in range(int(seconds * rate)):
        t = i / rate
        # Unique phase evolution identifies source position after alignment and wraps.
        data.extend(struct.pack('<hh', int(3276 * math.sin(2 * math.pi * (311*t + 13*t*t))),
                                int(3276 * math.sin(2 * math.pi * (733*t + 19*t*t)))))
    with wave.open(str(path), 'wb') as out:
        out.setparams((2, 2, rate, 0, 'NONE', 'not compressed'))
        out.writeframes(data)


def request(port, method, params=None, timeout=10):
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as connection:
        with connection.makefile('rwb') as stream:
            stream.write((json.dumps({'id': 1, 'method': method, 'params': params or {}})+'\n').encode())
            stream.flush()
            reply = json.loads(stream.readline())
    if not reply.get('ok'):
        raise RuntimeError(f'{method}: {reply}')
    return reply['result']


class App:
    def __init__(self, binary, directory, project=None, prefs=None):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        config = self.directory / 'config'
        config.mkdir()
        if prefs is not None:
            (config/'prefs.json').write_text(json.dumps(prefs), encoding='utf-8')
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.port = reservation.getsockname()[1]
        env = dict(os.environ, EFFECTCRAFT_CONFIG_DIR=str(config))
        env.pop('EFFECTCRAFT_CONTROL_PORT', None)
        args = [str(binary), '--empty', '--control', str(self.port)]
        if project is not None:
            args.append(str(project))
        self.stdout = (self.directory/'stdout.log').open('wb')
        self.stderr = (self.directory/'stderr.log').open('wb')
        flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        self.process = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL,
                                        stdout=self.stdout, stderr=self.stderr, creationflags=flags)
        self.owned_listener = False
        (self.directory/'process.json').write_text(json.dumps({'pid': self.process.pid,
                    'port': self.port, 'binary': str(binary)}, indent=2), encoding='utf-8')
        try:
            deadline = time.monotonic()+60
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError(f'app exited {self.process.returncode}; see {self.directory}')
                try:
                    self.initial = self.call('ui.inspect')
                    if not self._owns_listener():
                        raise RuntimeError('control port is not owned by the child; refusing to drive it')
                    self.owned_listener = True
                    break
                except (OSError, ValueError):
                    if time.monotonic() >= deadline:
                        raise TimeoutError('desktop control never became ready')
                    time.sleep(.1)
        except BaseException:
            self.close()
            raise

    def call(self, method, params=None):
        return request(self.port, method, params)

    def command(self, command, params=None):
        return self.call('engine.execute', {'command': command, 'params': params or {}})

    def _owns_listener(self):
        # Binding an ephemeral port and releasing it for the app has a small race.
        # Verify the child owns the listener before the first mutation or quit.
        if os.name == 'nt':
            output = subprocess.run(['netstat', '-ano', '-p', 'tcp'], capture_output=True,
                        text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in output.stdout.splitlines():
                columns = line.split()
                if (len(columns) == 5 and columns[0] == 'TCP' and
                    columns[1] == f'127.0.0.1:{self.port}' and columns[2].endswith(':0') and
                    columns[-1] == str(self.process.pid)):
                    return True
            return False
        output = subprocess.run(['lsof', '-nP', '-a', '-p', str(self.process.pid),
                    f'-iTCP:{self.port}', '-sTCP:LISTEN'], capture_output=True, timeout=5)
        return output.returncode == 0

    def close(self):
        try:
            if self.process.poll() is None:
                try:
                    if self.owned_listener and self._owns_listener():
                        self.call('app.quit', {'force': True})
                    else:
                        self.process.kill()
                    self.process.wait(timeout=5)
                except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            self.stdout.close()
            self.stderr.close()


def configure(app, loop=False):
    app.call('ui.playback', {'action': 'stop'})
    app.command('playback.settings.set', dict(loop=loop, range='entireDuration', playFrom='rangeStart',
                includeAudio=True, includeVideo=True, cacheBeforePlayback=False, moveTimeToPreviewTime=True))
    app.command('time.set', {'time': 0})


def observe(app, seconds=22, endpoint=True):
    start = time.monotonic()
    app.call('ui.playback', {'action': 'play'})
    rows = []
    while time.monotonic()-start < seconds:
        time.sleep(.2)
        state = app.call('ui.playback', {'action': 'status'})
        rows.append(dict(wall=time.monotonic()-start, **state))
        if endpoint and len(rows) > 3 and not state['playing']:
            break
    app.call('ui.playback', {'action': 'stop'})
    return rows


def check_endpoint(rows, require_audio):
    assert not rows[-1]['playing'], 'did not stop naturally'
    assert abs(rows[-1]['time']-359/24) < .05, rows[-1]
    if require_audio:
        assert any(r['time'] > 12 and r['audio'] and r['playing'] for r in rows), 'audio absent past 12 s'
        assert any(max(r.get('levelsDb', [-99])) > -40 for r in rows), 'silent meters'


def run(binary, out, require_audio):
    out.mkdir(parents=True, exist_ok=False)
    report = dict(binary=str(binary), sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  platform=os.name, require_audio=require_audio, steps={})
    project = out/'smoke.ecproj'
    fixture = out/'stereo-chirp.wav'
    make_fixture(fixture)
    app = None
    try:
        app = App(binary, out/'first')
        report['steps']['startup'] = app.initial
        app.command('comp.new', dict(name='Native smoke', width=160, height=90, frameRate=24, duration=15))
        imported = app.command('file.import', {'paths': [str(fixture)], 'addToComp': True})
        assert not imported.get('errors'), imported
        report['steps']['import'] = imported
        app.command('file.saveAs', {'path': str(project)})
        assert project.is_file()
        render = app.call('render.frame', {'time': 0, 'path': str(out/'frame.png')})
        assert (out/'frame.png').read_bytes()[:8] == b'\x89PNG\r\n\x1a\n'
        report['steps']['render'] = render
        for name in ['first_play', 'replay']:
            configure(app)
            rows = observe(app)
            report['steps'][name] = rows
            check_endpoint(rows, require_audio)
        configure(app, loop=True)
        rows = observe(app, 18, endpoint=False)
        report['steps']['loop'] = rows
        assert any(a['time'] > 14 and b['time'] < 1 for a,b in zip(rows, rows[1:])), 'no loop wrap'
        assert not app.call('ui.playback', {'action':'status'})['playing']
        app.close()
        app = App(binary, out/'second', project)
        report['steps']['project_at_launch'] = app.initial
        assert app.initial.get('activeComp') is not None, app.initial
        configure(app)
        rows = observe(app)
        report['steps']['fresh_process'] = rows
        check_endpoint(rows, require_audio)
        report['passed'] = True
    except BaseException as error:
        report.update(passed=False, error=repr(error))
        raise
    finally:
        if app is not None:
            app.close()
        (out/'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'passed': True, 'report': str(out/'report.json')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path, help='new, isolated evidence directory')
    parser.add_argument('--require-audio', action='store_true')
    args = parser.parse_args()
    run(args.binary.resolve(), args.out.resolve(), args.require_audio)
