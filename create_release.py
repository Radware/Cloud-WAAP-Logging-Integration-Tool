import os
import zipfile


def package_project(version, include_items):
    project_name = 'Cloud-WAAP-Logging-Integration-Tool'  # Change to your actual project name
    base_path = os.path.dirname(__file__)  # Assumes this script is in the project root
    release_folder = os.path.join(base_path, 'releases')
    zip_filename = f"{project_name}_v{version}.zip"
    zip_path = os.path.join(release_folder, zip_filename)

    if not os.path.exists(release_folder):
        os.makedirs(release_folder)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(base_path):
            # Exclude unwanted directories
            dirs[:] = [d for d in dirs if d not in ('__pycache__', '.idea', '.vscode')]

            for file in files:
                file_path = os.path.join(root, file)
                # Only include specified files and directories
                if any(file_path.startswith(os.path.join(base_path, item)) for item in include_items):
                    arcname = os.path.relpath(file_path, base_path)  # Relative path for ZIP
                    zipf.write(file_path, arcname)

    print(f"Package created at: {zip_path}")

# Example usage:
version = '2.1.0'
include_items = ['certifi', 'urllib3', 'cloudwaap_log_utils.py', 'lambda_function.py', 'README.md']  # Add your files and directories
package_project(version, include_items)
