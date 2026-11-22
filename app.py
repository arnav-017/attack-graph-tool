from flask import Flask

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")


@app.route("/")
def index():
    return "Attack Graph Tool: backend running"


if __name__ == "__main__":
    app.run(debug=True)
