from setuptools import setup, find_packages

setup(
    name="com_security_analyzer",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pywin32>=305",
    ],
    python_requires=">=3.7",
)