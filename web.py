import prctl
from flask import Flask, render_template, request

from flask_wtf import FlaskForm
from wtforms import TextField
from wtforms.validators import DataRequired

app = Flask(__name__)


class EvalForm(FlaskForm):
    code = TextField('code', validators=[DataRequired()])


@app.route("/")
def hello():
    form = EvalForm()
    return render_template("index.html", form=form)


if __name__ == "__main__":
    app.run()
