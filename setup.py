from setuptools import setup

long_description = """
    Chewie is an EAPOL/802.1x implementation in Python.

    Currently barely works, useful if you have one user and their password is "microphone"

    More information at https://github.com/samrussell/chewie
"""

setup(
    name='chewie',
    description='A bare-bones EAPOL/802.1x implementation',
    long_description=long_description,
    version='0.0.1',
    url='https://github.com/samrussell/chewie',
    author='Sam Russell',
    author_email='sam.h.russell@gmail.com',
    license='Apache2',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3'
    ],
    keywords='802.1x dot1x eap eapol radius authentication aaa',
    packages=['chewie'],
    python_requires='>=3',
    install_requires=[
        'eventlet',
        'netils==0.0.1'
    ]
)
