#!/usr/bin/env python3

"""Compilation and decompilation utility functions.
"""
import os
import re
import shutil
import signal
import subprocess
import sys
import time

import importlib
config = importlib.import_module('retdec-config')


"""Taken from https://github.com/avast-tl/retdec-regression-tests-framework/blob/master/regression_tests/cmd_runner.py
"""


class CmdRunner:
    """A runner of external commands."""

    def run_cmd(self, cmd, input=b'', timeout=None, input_encoding='utf-8',
                output_encoding='utf-8', strip_shell_colors=True):
        """Runs the given command (synchronously).

        :param list cmd: Command to be run as a list of arguments (strings).
        :param bytes input: Input to be used when running the command.
        :param int timeout: Number of seconds after which the command should be
                            terminated.
        :param str input_encoding: Encode the command's output in this encoding.
        :param str output_encoding: Decode the command's output in this encoding.
        :param bool strip_shell_colors: Should shell colors be stripped from
                                        the output?

        :returns: A triple (`output`, `return_code`, `timeouted`).

        The meaning of the items in the return value are:

        * `output` contains the combined output from the standard outputs and
          standard error,
        * `return_code` is the return code of the command,
        * `timeouted` is either `True` or `False`, depending on whether the
          command has timeouted.

        If `input` is a string (`str`), not `bytes`, it is decoded into `bytes`
        by using `input_encoding`.

        If `output_encoding` is not ``None``, the returned data are decoded in
        that encoding. Also, all line endings are converted to ``'\\n'``, and
        if ``strip_shell_colors`` is ``True``, shell colors are stripped.
        Otherwise, if `output_encoding` is ``None``, the data are directly
        returned as raw bytes without any conversions.

        To disable the timeout, pass ``None`` as `timeout` (the default).

        If the timeout expires before the command finishes, the value of `output`
        is the command's output generated up to the timeout.
        """
        _, output, return_code, timeouted = self._run_cmd(cmd, input, timeout, input_encoding, output_encoding,
                                                          strip_shell_colors, False)

        return output, return_code, timeouted

    def run_measured_cmd(self, command):
        """Runs the given command (synchronously) and measure its time and memory.
        :param list command: Command to be run as a list of arguments (strings).

        :returns: A quadruple (`memory`, `elapsed_time`, `output`, `return_code`).
        """
        cmd = CmdRunner()

        start = time.time()
        memory, output, rc, _ = cmd._run_cmd(command, track_memory=True)
        elapsed = time.time() - start

        return memory, int(elapsed), output, rc

    def _run_cmd(self, cmd, input=b'', timeout=None, input_encoding='utf-8',
                 output_encoding='utf-8', strip_shell_colors=True, track_memory=False):

        def decode(output):
            if output_encoding is not None:
                output = output.decode(output_encoding, errors='replace')
                output = re.sub(r'\r\n?', '\n', output)
                if strip_shell_colors:
                    return re.sub(r'\x1b[^m]*m', '', output)
            return output

        # The communicate() call below expects the input to be in bytes, so
        # convert it unless it is already in bytes.
        if not isinstance(input, bytes):
            input = input.encode(input_encoding)

        memory = 0
        try:
            p = self.start(cmd)
            if track_memory:
                try:
                    import psutil
                    proc = psutil.Process(p.pid)
                    memory = int(proc.memory_info().rss / float(1 << 20))
                except ImportError:
                    memory = 0

            output, _ = p.communicate(input, timeout)
            return memory, decode(output).rstrip(), p.returncode, False
        except subprocess.TimeoutExpired:
            # Kill the process, along with all its child processes.
            p.kill()
            # Finish the communication to obtain the output.
            output, _ = p.communicate()
            return memory, decode(output).rstrip(), p.returncode, True

    def start(self, cmd, discard_output=False, stdout=subprocess.STDOUT):
        """Starts the given command and returns a handler to it.

        :param list cmd: Command to be run as a list of arguments (strings).
        :param bool discard_output: Should the output be discarded instead of
                                    being buffered so it can be obtained later?
        :param int stdout: If discard_output is True, errors will be redirectected
                                    to the stdout param.

        :returns: A handler to the started command (``subprocess.Popen``).

        If the output is irrelevant for you, you should set `discard_output` to
        ``True``.
        """
        # The implementation is platform-specific because we want to be able to
        # kill the children alongside with the process.
        kwargs = dict(
            args=cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL if discard_output else subprocess.PIPE,
            stderr=subprocess.DEVNULL if discard_output else stdout
        )
        if Utils.is_windows():
            return _WindowsProcess(**kwargs)
        else:
            return _LinuxProcess(**kwargs)


class _LinuxProcess(subprocess.Popen):
    """An internal wrapper around ``subprocess.Popen`` for Linux."""

    def __init__(self, **kwargs):
        # To ensure that all the process' children terminate when the process
        # is killed, we use a process group so as to enable sending a signal to
        # all the processes in the group. For that, we attach a session ID to
        # the parent process of the spawned child processes. This will make it
        # the group leader of the processes. When a signal is sent to the
        # process group leader, it's transmitted to all of the child processes
        # of this group.
        #
        # os.setsid is passed in the argument preexec_fn so it's run after
        # fork() and before exec().
        #
        # This solution is based on http://stackoverflow.com/a/4791612.
        kwargs['preexec_fn'] = os.setsid
        super().__init__(**kwargs)

    def kill(self):
        """Kills the process, including its children."""
        os.killpg(self.pid, signal.SIGTERM)


class _WindowsProcess(subprocess.Popen):
    """An internal wrapper around ``subprocess.Popen`` for Windows."""

    def __init__(self, **kwargs):
        # Shell scripts need to be run with 'sh' on Windows. Simply running the
        # script by its path doesn't work. That is, for example, instead of
        #
        #     /path/to/retdec-decompiler.sh
        #
        # we need to run
        #
        #     sh /path/to/retdec-decompiler.sh
        #
        if 'args' in kwargs and kwargs['args'] and kwargs['args'][0].endswith('.sh'):
            kwargs['args'].insert(0, 'sh')
        super().__init__(**kwargs)

    def kill(self):
        """Kills the process, including its children."""
        # Since os.setsid() and os.killpg() are not available on Windows, we
        # have to do this differently. More specifically, we do this by calling
        # taskkill, which also kills the process' children.
        #
        # This solution is based on
        # http://mackeblog.blogspot.cz/2012/05/killing-subprocesses-on-windows-in.html
        cmd = ['taskkill', '/F', '/T', '/PID', str(self.pid)]
        subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Utils:

    @staticmethod
    def tool_exists(tool_name):
        return shutil.which(tool_name) is not None

    @staticmethod
    def remove_file_forced(file):
        if os.path.exists(file):
            os.remove(file)

    @staticmethod
    def remove_dir_forced(path):
        if os.path.exists(path):
            for n in os.listdir(path):
                p = os.path.join(path, n)
                if os.path.isdir(p):
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    os.unlink(p)
            shutil.rmtree(path, ignore_errors=True)

    @staticmethod
    def is_windows():
        return sys.platform in ('win32', 'msys')

    @staticmethod
    def print_error(error):
        """Print error message to stderr.
        """
        print('Error: %s' % error, file=sys.stdout)

    @staticmethod
    def print_warning(warning):
        """Print warning message to stderr.
        """
        # TODO
        #sys.stderr.write('Warning: %s' % warning)
        print('Warning: %s' % warning, file=sys.stdout)

    @staticmethod
    def has_archive_signature(path):
        """Check if file has any ar signature.
        1 argument is needed - file path
        Returns - True if file has ar signature
                  False no signature
        """
        ret = subprocess.call([config.AR, path, '--arch-magic'])
        return ret == 0

    @staticmethod
    def has_thin_archive_signature(path):
        """Check if file has thin ar signature.
        1 argument is needed - file path
        Returns - True if file has thin ar signature
                  False no signature
        """
        ret = subprocess.call([config.AR, path, '--thin-magic'])
        return ret == 0

    @staticmethod
    def is_valid_archive(path):
        """Check if file is an archive we can work with.
        1 argument is needed - file path
        Returns - True if file is valid archive
                  False if file is invalid archive
        """
        # We use our own messages so throw original output away.
        ret = subprocess.call([config.AR, path, '--valid'], stderr=subprocess.STDOUT,
                              stdout=None)

        return ret == 0

    @staticmethod
    def archive_object_count(path):
        """Counts object files in archive.
        1 argument is needed - file path
        Returns - 1 if error occurred
        """
        cmd = CmdRunner()
        output, rc, _ = cmd.run_cmd([config.AR, path, '--object-count'])

        return int(output) if rc == 0 else 1

    @staticmethod
    def archive_list_content(path):
        """Print content of archive.
        1 argument is needed - file path
        """
        cmd = CmdRunner()
        output, _, _ = cmd.run_cmd([config.AR, path, '--list', '--no-numbers'])
        print(output)

    @staticmethod
    def archive_list_numbered_content(path):
        """Print numbered content of archive.
        1 argument is needed - file path
        """
        print('Index\tName')
        cmd = CmdRunner()
        output, _, _ = cmd.run_cmd([config.AR, path, '--list'])
        print(output)

    @staticmethod
    def archive_list_numbered_content_json(path):
        """Print numbered content of archive in JSON format.
        1 argument is needed - file path
        """
        cmd = CmdRunner()
        output, _, _ = cmd.run_cmd([config.AR, path, '--list', '--json'])
        print(output)

    @staticmethod
    def archive_get_by_name(path, name, output):
        """Get a single file from archive by name.
        3 arguments are needed - path to the archive
                               - name of the file
                               - output path
        Returns - False if everything ok
                  True if error
        """
        ret = subprocess.call([config.AR, path, '--name', name, '--output', output],
                              stderr=subprocess.STDOUT, stdout=None)

        return ret != 0

    @staticmethod
    def archive_get_by_index(archive, index, output):
        """Get a single file from archive by index.
        3 arguments are needed - path to the archive
                               - index of the file
                               - output path
        Returns - False if everything ok
                  True if error
        """
        ret = subprocess.call([config.AR, archive, '--index', index, '--output', output],
                              stderr=subprocess.STDOUT, stdout=None)
        return ret != 0

    @staticmethod
    def is_macho_archive(path):
        """Check if file is Mach-O universal binary with archives.
        1 argument is needed - file path
        Returns - True if file is archive
                  False if file is not archive
        """
        ret = subprocess.call([config.EXTRACT, '--check-archive', path],
                              stderr=subprocess.STDOUT, stdout=subprocess.DEVNULL)

        return ret == 0

    @staticmethod
    def is_decimal_number(num):
        """Check string is a valid decimal number.
            1 argument is needed - string to check.
            Returns - 0 if string is a valid decimal number.
                      1 otherwise
        """
        if re.search('^[0-9]+$', str(num)):
            return True
        else:
            return False

    @staticmethod
    def is_hexadecimal_number(num):
        """Check string is a valid hexadecimal number.
            1 argument is needed - string to check.
            Returns - 0 if string is a valid hexadecimal number.
                      1 otherwise
        """
        if re.search('^0x[0-9a-fA-F]+$', str(num)):
            return True
        else:
            return False

    @staticmethod
    def is_number(num):
        """Check string is a valid number (decimal or hexadecimal).
            1 argument is needed - string to check.
            Returns - 0 if string is a valid number.
                      1 otherwise
        """
        if Utils.is_decimal_number(num):
            return True

        if Utils.is_hexadecimal_number(num):
            return True

        return False

    @staticmethod
    def is_decimal_range(num):
        """Check string is a valid decimal range.
            1 argument is needed - string to check.
            Returns - 0 if string is a valid decimal range.
                      1 otherwise
        """
        if re.search('^[0-9]+-[0-9]+$', str(num)):
            return True
        else:
            return False

    @staticmethod
    def is_hexadecimal_range(num):
        """Check string is a valid hexadecimal range
            1 argument is needed - string to check.
            Returns - 0 if string is a valid hexadecimal range
                      1 otherwise
        """
        if re.search('^0x[0-9a-fA-F]+-0x[0-9a-fA-F]+$', str(num)):
            return True
        else:
            return False

    @staticmethod
    def is_range(num):
        """Check string is a valid range (decimal or hexadecimal).
            1 argument is needed - string to check.
            Returns - 0 if string is a valid range
                      1 otherwise
        """
        if Utils.is_decimal_range(num):
            return True

        if Utils.is_hexadecimal_range(num):
            return True

        return False
