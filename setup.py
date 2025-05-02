# SPDX-FileCopyrightText: 2025 Thomas Alfroy
#
# SPDX-License-Identifier: GPL-2.0-only

from setuptools import setup, find_packages
import os


def update_library_directory(file_path, replacement :str):
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()

        with open(file_path, "w") as file:
            for line in lines:
                if line.strip().startswith("BGPROUTESMRT_LIBRARY_PATH"):
                    file.write("BGPROUTESMRT_LIBRARY_PATH='{}'\n".format(replacement))
                else:
                    file.write(line)
        print(f"Updated LIBRARY_DIRECTORY in {file_path}")
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except Exception as e:
        print(f"Error updating file: {e}")
        

libdir = os.environ.get("BGPROUTESMRT_LIBRARY_PATH", "/usr/local/lib/")

update_library_directory("pybgproutesmrt/broker.py", libdir)

setup(
    name='pybgproutesmrt',
    version='0.1.2',
    packages=find_packages(),
    install_requires=['requests>=2.24.0'],
    author='Thomas Holterbach and Thomas Alfroy',
    author_email='contact@bgproutes.io',
    description='A Python library to get BGP data from BGProutes',
    url='https://github.com/bgproutes-io/pybgproutesmrt',
    classifiers=[ ],
    python_requires='>=3.6'
)
