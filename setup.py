from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="vulnforge",
    version="1.0.0",
    description="VulnForge - A comprehensive vulnerability scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="VulnForge Team",
    url="https://github.com/vulnforge/vulnforge",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "vulnforge=cli:main",
        ],
    },
    python_requires=">=3.11",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Security Professionals",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Vulnerability Scanner",
    ],
)
