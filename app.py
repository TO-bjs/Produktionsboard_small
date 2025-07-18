from flask import Flask, render_template, request, redirect, send_from_directory
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
PASSWORD = 'produktion123'

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        password = request.form.get('password')
        if password != PASSWORD:
            return render_template('upload.html', error=True)

        file = request.files['screenshot']
        if file:
            filepath = os.path.join(UPLOAD_FOLDER, 'screenshot.png')
            file.save(filepath)
            return redirect('/upload?success=1')
    return render_template('upload.html', success=request.args.get('success'), error=request.args.get('error'))

@app.route('/anzeige')
def anzeigen():
    return render_template('anzeigen.html')

@app.route('/uploads/screenshot.png')
def get_image():
    return send_from_directory(UPLOAD_FOLDER, 'screenshot.png')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
