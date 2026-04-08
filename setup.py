from setuptools import find_packages, setup

setup(
    name="palisade",
    version="0.1.0",
    description=(
        "Practical Audit Library for Industrial Security, Asset Discovery, "
        "and Edge Defense"
    ),
    author="Christopher Lusk",
    author_email="clusk@northecho.dev",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    package_data={"palisade": ["py.typed"]},
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=["click>=8.1,<9"],
    entry_points={"console_scripts": ["palisade=palisade.cli:main"]},
)
