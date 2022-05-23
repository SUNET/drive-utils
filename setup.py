import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="drive-utils",
    version="0.2.10",
    author="Micke Nordin",
    author_email="kano@sunet.se",
    description="A small utility package for SUNET Drive",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SUNET/drive-utils",
    project_urls={
        "Bug Tracker": "https://github.com/SUNET/drive-utils/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL-3.0",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
)
