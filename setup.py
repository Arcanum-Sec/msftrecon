from setuptools import setup, find_packages

setup(
    name="msftrecon",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'dnspython>=2.4.2',
        'urllib3>=2.1.0'
    ],
    entry_points={
        'console_scripts': [
            'msftrecon=msftrecon.msftrecon:main',
        ],
    },
)