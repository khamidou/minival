import io
import os
import sys
import tempfile
from flask import Flask, render_template, request

from flask_wtf import FlaskForm
from wtforms import TextAreaField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']


class EvalForm(FlaskForm):
    code = TextAreaField('code', validators=[DataRequired()])


@app.route("/", methods=("GET", "POST",))
def main():
    form = EvalForm()
    if form.validate_on_submit():
        res = execute_in_sandbox(form.code.data)
        return render_template("index.html", form=form, result=res)

    return render_template("index.html", form=form)

def execute_in_sandbox(code):
    tmp_fd, tmp_filename = tempfile.mkstemp(suffix='.py')
    os.close(tmp_fd)

    with open(tmp_filename, 'w+') as fd:
        fd.write('import prctl ; prctl.set_seccomp(True)\n')
        fd.write(code)

    read_pipe, write_pipe = os.pipe()
    pid = os.fork()

    if pid == 0:
        # if fork() -> share environment & everything
        # execve while limiting reads to anything not in /etc, blocking
        # anything else.
        cmd = "/usr/bin/python"

        os.dup2(write_pipe, sys.stdout.fileno())
        os.execv(cmd, [cmd, tmp_filename])
    else:
        os.close(write_pipe)
        os.waitpid(pid, 0)
        ret = []
        while True:
            result = os.read(read_pipe, 32)
            if result == "" or result is None:
                break
            else:
                ret.append(result)

        os.close(read_pipe)
        #os.unlink(tmp_filename)
        return "".join(ret)

if __name__ == "__main__":
    app.run()
