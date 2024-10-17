from gevent import monkey
monkey.patch_all()  # This must be the very first thing in the file
# Now import the rest of the modules
import subprocess
import json
import re
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import time

app = Flask(__name__)
socketio = SocketIO(app, async_mode='gevent')  # Ensure threading is enabled

# Function to run a command and get the output
def run_command(command):
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # Redirect stderr to stdout
        text=True,
        shell=True
    )
    return result.stdout

# Background task to run the scan and patching process
def scan_and_patch(image):
    # Extract image name and tag
    image_name_with_tag = image.split('/')[-1]  # e.g., 'nginx:1.21.6'
    image_name_parts = image_name_with_tag.split(':')
    image_name = image_name_parts[0]  # e.g., 'nginx'
    image_tag = image_name_parts[1] if len(image_name_parts) > 1 else 'latest'
    patched_image_tag = f"{image_name}-{image_tag}-patched"

    # Emit stage 1: Running Trivy scan
    socketio.emit('stage_update', {'stage': f'Running Trivy scan on {image_name_with_tag}', 'output': ''})
    
    # Run the first Trivy command
    trivy_command_1 = f"trivy image --vuln-type os --ignore-unfixed {image}"
    trivy_output_1 = run_command(trivy_command_1)
    
    # Get specific lines of the Trivy output
    trivy_output_lines = trivy_output_1.splitlines()
    if len(trivy_output_lines) >= 4:
        truncated_output_1 = "\n".join(trivy_output_lines[3:4])  # Adjust indices as needed
    else:
        truncated_output_1 = trivy_output_1  # If not enough lines, show all output

    # Emit the first lines of the Trivy output
    socketio.emit('stage_update', {'stage': 'Trivy scan completed.', 'output': truncated_output_1})
    time.sleep(1)

    # Stage 2: Running Trivy JSON report generation
    socketio.emit('stage_update', {'stage': 'Generating JSON report...', 'output': ''})
    json_file = f"{image_name_with_tag}.json"
    trivy_command_2 = f"trivy image --vuln-type os --ignore-unfixed -f json -o {json_file} {image}"
    run_command(trivy_command_2)
    socketio.emit('stage_update', {'stage': 'JSON report generated.', 'output': ''})
    time.sleep(1)

    # Emit stage 3: Running Copacetic patching process
    socketio.emit('stage_update', {'stage': 'Patching image with Copacetic...', 'output': ''})

    # Adjust the copa command as per your environment
    copa_command = f"copa patch -i {image} -r {json_file} -t {patched_image_tag} --addr docker-container://buildkitd"

    process = subprocess.Popen(
        copa_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        text=True
    )

    cumulative_output = ''
    for line in iter(process.stdout.readline, ''):
        if line:
            cumulative_output += line
            # Emit the cumulative output to display under the usual output
            socketio.emit('stage_update', {'stage': 'Patching image with Copacetic...', 'output': cumulative_output})
            socketio.sleep(0)  # Allows the Socket.IO server to handle other events
            cumulative_output = ''  # Clear after emitting to prevent duplicates

    process.stdout.close()
    return_code = process.wait()

    # Append the final message to the cumulative output
    final_message = f'\nProcess finished with exit code {return_code}'

    # Emit the final output
    socketio.emit('stage_update', {'stage': 'Patching completed.', 'output': final_message})

    # Emit final stage: Scanning the patched image
    socketio.emit('stage_update', {'stage': 'Scanning the patched image...', 'output': ''})
    patched_image_full_tag = f"{patched_image_tag}"
    trivy_command_last = f"trivy image --vuln-type os --ignore-unfixed {patched_image_full_tag}"
    trivy_output_last = run_command(trivy_command_last)
    socketio.emit('stage_update', {'stage': 'Scan of patched image completed.', 'output': trivy_output_last})

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('start_scan')
def handle_start_scan(data):
    allowed_images = [
        "public.ecr.aws/nginx/nginx:1.21.6",
        "docker.io/library/redis:6.2.6",
        "public.ecr.aws/docker/library/httpd:2.4.48",
        "docker.io/library/postgres:13.4"
    ]
    image = data.get('image', "docker.io/library/nginx:1.21.6")
    if image not in allowed_images:
        emit('stage_update', {'stage': 'Error', 'output': 'Selected image is not allowed.'})
        return
    socketio.start_background_task(scan_and_patch, image)

if __name__ == '__main__':
    socketio.run(app, debug=True)
