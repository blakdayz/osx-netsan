import os
import json

# Try to import tomllib (Python 3.11+), else use toml (external library)
try:
    import tomllib  # Python 3.11+

    def load_toml_file(filepath):
        """
        Function that loads and parses a TOML file.

        Parameters:
         filepath (str): The path to the TOML file.

        Returns:
         dict: The contents of the TOML file as a dictionary.

        Raises:
         FileNotFoundError: If the provided file path does not exist.
         IOError: If there is an error reading the file.
         tomllib.TOMLDecodeError: If the file content is not valid TOML.
        """
        with open(filepath, "rb") as f:  # Binary mode for tomllib
            return tomllib.load(f)

except ModuleNotFoundError:
    try:
        import toml  # External library

        def load_toml_file(filepath):
            """
            Loads and parses a TOML file.

            Parameters:
            filepath: str
                The path to the TOML file to be loaded.

            Returns:
            dict
                A dictionary representing the parsed contents of the TOML file.

            Raises:
            FileNotFoundError
                If the specified file does not exist.
            PermissionError
                If the file cannot be opened due to permission issues.
            toml.TomlDecodeError
                If there is an error in parsing the TOML file.
            """
            with open(filepath, "r", encoding="utf-8") as f:  # Text mode for toml
                return toml.load(f)

    except ModuleNotFoundError:
        raise ImportError(
            "No TOML parser available. Install the 'toml' package for Python versions < 3.11."
        )


def build_markdown(directory, output_file):
    """
    Generates a Markdown file containing an overview of a project.

    Args:
        directory (str): Path to the directory containing the project files.
        output_file (str): Path to the output Markdown file.
    """
    with open(output_file, "w", encoding="utf-8") as out_md:
        # First, read pyproject.toml and extract project name, description, and readme
        pyproject_path = os.path.join(directory, "pyproject.toml")
        readme_content = ""
        if os.path.isfile(pyproject_path):
            pyproject_data = load_toml_file(pyproject_path)

            # Extract project name, description, and readme file path
            project_name = "Unknown Project Name"
            project_description = "No description available."
            readme_path = None

            if "project" in pyproject_data:
                # PEP 621 standard
                project = pyproject_data["project"]
                project_name = project.get("name", project_name)
                project_description = project.get("description", project_description)
                readme = project.get("readme", None)
                if isinstance(readme, str):
                    readme_path = os.path.join(directory, readme)
                elif isinstance(readme, dict):
                    # Handle table with 'file' key
                    readme_file = readme.get("file")
                    if readme_file:
                        readme_path = os.path.join(directory, readme_file)
            elif "tool" in pyproject_data and "poetry" in pyproject_data["tool"]:
                # If using Poetry
                poetry = pyproject_data["tool"]["poetry"]
                project_name = poetry.get("name", project_name)
                project_description = poetry.get("description", project_description)
                readme = poetry.get("readme", None)
                if readme:
                    readme_path = os.path.join(directory, readme)
            else:
                # Fallback if no project name found
                project_name = "Unknown Project Name"
                project_description = "No description available."

            # Write project name and description
            out_md.write(f"# {project_name}\n\n")
            out_md.write(f"{project_description}\n\n")

            # Include README content if it exists
            if readme_path and os.path.isfile(readme_path):
                out_md.write("---\n\n")
                with open(readme_path, "r", encoding="utf-8") as f:
                    readme_content = f.read()
                out_md.write(readme_content)
                out_md.write("\n\n---\n\n")
            else:
                out_md.write("No README file found or specified.\n\n")

            # Include pyproject.toml contents
            out_md.write("## pyproject.toml\n\n")
            out_md.write("```toml\n")
            with open(pyproject_path, "r", encoding="utf-8") as f:
                pyproject_content = f.read()
            out_md.write(pyproject_content)
            out_md.write("\n```\n\n")
        else:
            out_md.write("# Project Name Unknown\n\n")
            out_md.write("No pyproject.toml file found.\n\n")

        # Now include any .json files and .sh files at the beginning
        json_files = []
        sh_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".json"):
                    filepath = os.path.join(root, file)
                    json_files.append(filepath)
                elif file.endswith(".sh"):
                    filepath = os.path.join(root, file)
                    sh_files.append(filepath)

        for json_file in json_files:
            relative_path = os.path.relpath(json_file, directory)
            out_md.write(f"## {relative_path}\n\n")
            out_md.write("```json\n")
            with open(json_file, "r", encoding="utf-8") as f:
                json_content = f.read()
            out_md.write(json_content)
            out_md.write("\n```\n\n")

        for sh_file in sh_files:
            relative_path = os.path.relpath(sh_file, directory)
            out_md.write(f"## {relative_path}\n\n")
            out_md.write("```bash\n")
            with open(sh_file, "r", encoding="utf-8") as f:
                sh_content = f.read()
            out_md.write(sh_content)
            out_md.write("\n```\n\n")

        # Now process the Python files
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".py"):
                    filepath = os.path.join(root, file)
                    # Read the code from the file
                    with open(filepath, "r", encoding="utf-8") as f:
                        code = f.read()
                    # Write the filename as a heading in the markdown file
                    relative_path = os.path.relpath(filepath, directory)
                    out_md.write(f"## {relative_path}\n\n")
                    # Write the code block
                    out_md.write("```python\n")
                    out_md.write(code)
                    out_md.write("\n```\n\n")


if __name__ == "__main__":
    build_markdown(".", "output.md")
