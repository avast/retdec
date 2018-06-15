#! /usr/bin/env python3

"""Compilation and decompilation utility functions.
"""
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
from timeit import Timer

import retdec_config as config

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

        try:
            p = self.start(cmd)
            output, _ = p.communicate(input, timeout)
            return decode(output), p.returncode, False
        except subprocess.TimeoutExpired:
            # Kill the process, along with all its child processes.
            p.kill()
            # Finish the communication to obtain the output.
            output, _ = p.communicate()
            return decode(output), p.returncode, True

    def start(self, cmd, discard_output=False):
        """Starts the given command and returns a handler to it.

        :param list cmd: Command to be run as a list of arguments (strings).
        :param bool discard_output: Should the output be discarded instead of
                                    being buffered so it can be obtained later?

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
            stderr=subprocess.DEVNULL if discard_output else subprocess.STDOUT
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


class TimeMeasuredProcess:

    def __init__(self):
        self.output = ''
        self.rc = 0

    def run_cmd(self, args):
        """

        :param args:
        :return: (output, return_code, time)
        """

        def runProcess():
            cmd = CmdRunner()

            self.output, self.rc, _ = cmd.run_cmd(args)

        t = Timer(runProcess)

        return self.output, self.rc, t.timeit(1)


class Utils:

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

    @staticmethod
    def is_windows():
        return sys.platform in ('win32', 'msys')

    @staticmethod
    def get_realpath(path):
        """Prints the real, physical location of a directory or file, relative or
        absolute.
        1 argument is needed
        """
        return str(pathlib.Path(path).resolve())

    @staticmethod
    def print_error(error):
        """Print error message to stderr and die.
        1 argument is needed
        Returns - 1 if number of arguments is incorrect
        """
        # if error is None:
        #    sys.exit(1)

        print('Error: %s' % error, file=sys.stdout)
        # sys.exit(1)

    @staticmethod
    def print_warning(warning):
        """Print warning message to stderr.
        """
        if warning is None:
            return

        sys.stderr.write('Warning: %s' % warning)

    @staticmethod
    def has_archive_signature(path):
        """Check if file has any ar signature.
        1 argument is needed - file path
        Returns - 0 if file has ar signature
                  1 if number of arguments is incorrect
                  2 no signature
        """
        if subprocess.call([config.AR, path, '--arch-magic'], shell=True):
            return 0
        return 2

    @staticmethod
    def has_thin_archive_signature(path):
        """Check if file has thin ar signature.
        1 argument is needed - file path
        Returns - 0 if file has thin ar signature
                  1 if number of arguments is incorrect
                  2 no signature
        """
        if subprocess.call([config.AR, path, '--thin-magic'], shell=True):
            return 0
        return 2

    @staticmethod
    def is_valid_archive(path):
        """Check if file is an archive we can work with.
        1 argument is needed - file path
        Returns - 0 if file is valid archive
                  1 if file is invalid archive
        """
        # We use our own messages so throw original output away.
        return subprocess.call([config.AR, path, '--valid'], shell=True, stderr=subprocess.STDOUT,
                               stdout=None)

    @staticmethod
    def archive_object_count(path):
        """Counts object files in archive.
        1 argument is needed - file path
        Returns - 1 if error occurred
        """
        return subprocess.call([config.AR, path, '--object-count'], shell=True)

    @staticmethod
    def archive_list_content(path):
        """Print content of archive.
        1 argument is needed - file path
        Returns - 1 if number of arguments is incorrect
        """
        return subprocess.call([config.AR, path, '--list', '--no-numbers'], shell=True)

    @staticmethod
    def archive_list_numbered_content(path):
        """Print numbered content of archive.
        1 argument is needed - file path
        Returns - 1 if number of arguments is incorrect
        """
        print('Index\tName')
        return subprocess.call([config.AR, path, '--list'], shell=True)

    @staticmethod
    def archive_list_numbered_content_json(path):
        """Print numbered content of archive in JSON format.
        1 argument is needed - file path
        Returns - 1 if number of arguments is incorrect
        """
        return subprocess.call([config.AR, path, '--list', '--json'], shell=True)

    @staticmethod
    def archive_get_by_name(path, name, output):
        """Get a single file from archive by name.
        3 arguments are needed - path to the archive
                               - name of the file
                               - output path
        Returns - 1 if number of arguments is incorrect
                - 2 if error occurred
        """
        if not subprocess.call([config.AR, path, '--name', name, '--output', output],
                               shell=True, stderr=subprocess.STDOUT, stdout=None):
            return 2

        return 1

    @staticmethod
    def archive_get_by_index(archive, index, output):
        """Get a single file from archive by index.
        3 arguments are needed - path to the archive
                               - index of the file
                               - output path
        Returns - 1 if number of arguments is incorrect
                - 2 if error occurred
        """
        if not subprocess.call([config.AR, archive, '--index', index, '--output', output],
                               shell=True, stderr=subprocess.STDOUT, stdout=None):
            return 2

    @staticmethod
    def is_macho_archive(path):
        """Check if file is Mach-O universal binary with archives.
        1 argument is needed - file path
        Returns - 0 if file is archive
                  1 if file is not archive
        """
        return subprocess.call([config.EXTRACT, '--check-archive', path], shell=True,
                               stderr=subprocess.STDOUT, stdout=subprocess.DEVNULL) != 2

    @staticmethod
    def is_decimal_number(num):
        """Check string is a valid decimal number.
            1 argument is needed - string to check.
            Returns - 0 if string is a valid decimal number.
                      1 otherwise
        """
        regex = '^[0-9]+$'
        if re.search(regex, str(num)):
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
        regex = '^0x[0-9a-fA-F]+$'
        if re.search(regex, str(num)):
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
        regex = '^[0-9]+-[0-9]+$'
        if re.search(regex, str(num)):
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
        regex = '^0x[0-9a-fA-F]+-0x[0-9a-fA-F]+$'
        if re.search(regex, str(num)):
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
