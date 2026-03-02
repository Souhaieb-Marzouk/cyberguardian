"""
CyberGuardian Setup Script
==========================
Installation and distribution configuration.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = (this_directory / "requirements.txt").read_text().strip().split('\n')
requirements = [r.strip() for r in requirements if r.strip() and not r.startswith('#') and not r.startswith('Optional')]

setup(
    name='cyberguardian',
    version='1.0.0',
    author='CyberGuardian Team',
    author_email='cyberguardian@example.com',
    description='Advanced Malware & Anomaly Detection Tool for Windows',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/YOUR_USERNAME/cyberguardian',
    license='MIT',
    
    # Package discovery
    packages=find_packages(),
    
    # Python version requirement
    python_requires='>=3.9',
    
    # Dependencies
    install_requires=[
        'PyQt5>=5.15.0',
        'psutil>=5.9.0',
        'requests>=2.28.0',
        'yara-python>=4.3.0',
        'keyring>=23.9.0',
        'cryptography>=38.0.0',
    ],
    
    # Optional dependencies
    extras_require={
        'windows': [
            'pywin32>=305',
            'WMI>=1.5.1',
            'pythonnet>=3.0.0',
        ],
        'dev': [
            'pytest>=7.0.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'pyinstaller>=6.0.0',
        ],
    },
    
    # Entry points for command-line usage
    entry_points={
        'console_scripts': [
            'cyberguardian=main:main',
        ],
        'gui_scripts': [
            'cyberguardian-gui=main:main',
        ],
    },
    
    # Package data
    package_data={
        '': ['*.png', '*.ico', '*.yar', '*.yara'],
    },
    include_package_data=True,
    
    # Data files to be installed outside packages
    data_files=[
        ('assets', ['assets/icon.png']),
    ],
    
    # Classifiers for PyPI
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: X11 Applications :: Qt',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Security Professionals',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: Microsoft :: Windows :: Windows 10',
        'Operating System :: Microsoft :: Windows :: Windows 11',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Systems Administration',
    ],
    
    # Keywords for searchability
    keywords=[
        'security',
        'malware',
        'detection',
        'antivirus',
        'cybersecurity',
        'threat-detection',
        'yara',
        'virus-total',
        'windows-security',
    ],
    
    # Project URLs
    project_urls={
        'Bug Reports': 'https://github.com/YOUR_USERNAME/cyberguardian/issues',
        'Documentation': 'https://github.com/YOUR_USERNAME/cyberguardian/wiki',
        'Source': 'https://github.com/YOUR_USERNAME/cyberguardian',
    },
)
