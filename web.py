import os
import sys
import tempfile
import subprocess
from flask import Flask, render_template

from flask_wtf import FlaskForm
from wtforms import TextAreaField, SelectField
from wtforms.validators import DataRequired


app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']
app.config['TEMPLATES_AUTO_RELOAD'] = True


def python_version():
    return "Python {}".format(sys.version.split()[0])


def perl_version():
    return subprocess.check_output(['perl', '-e', 'print "Perl " . $]'])


class EvalForm(FlaskForm):
    code = TextAreaField('Paste your code:', validators=[DataRequired()])
    language = SelectField(
        'Select the language:',
        choices=[('python', python_version()), ('perl', perl_version())])


@app.route("/", methods=("GET", "POST",))
def main():
    form = EvalForm()
    if form.validate_on_submit():
        res = execute_in_sandbox(form.code.data, form.language.data)
        return render_template("index.html", code=form.code.data, form=form, result=res)

    return render_template("index.html", form=form)


def execute_in_sandbox(code, language='python'):
    tmp_fd, tmp_filename = tempfile.mkstemp(suffix='.code')
    os.close(tmp_fd)

    with open(tmp_filename, 'w+') as fd:
        fd.write(code)

    read_pipe, write_pipe = os.pipe()
    pid = os.fork()

    if pid == 0:
        # if fork() -> share environment & everything
        # execve while limiting reads to anything not in /etc, blocking
        # anything else.
        cmd = "seccompctl"

        os.dup2(write_pipe, sys.stdout.fileno())
        os.dup2(write_pipe, sys.stderr.fileno())
        os.execv(cmd, [cmd, language, tmp_filename])
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
        os.unlink(tmp_filename)
        return "".join(ret)


if __name__ == "__main__":
    app.run(host= '0.0.0.0')
