import subprocess
import time

def run_command(command):
    try:
        subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        print(e)

def run_verbose_command(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line, end='')
        process.stdout.close()
        process.wait()
        if process.returncode != 0:
            stderr_output = process.stderr.read()
            raise subprocess.CalledProcessError(process.returncode, command, stderr_output)
    except subprocess.CalledProcessError as e:
        print(f"Command {command} failed with error: {e.stderr}")


def run_verbose_command_with_input(command, input_data):
    try:
        process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        time.sleep(0.5)
        process.stdin.write(input_data)
        process.stdin.close()

        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line, end='')

        process.stdout.close()
        process.wait()

        if process.returncode != 0:
            stderr_output = process.stderr.read()
            print(stderr_output, end='')
            raise subprocess.CalledProcessError(process.returncode, command, stderr_output)

    except subprocess.CalledProcessError as e:
        print(f"Command {command} failed with error: {e.stderr}")
