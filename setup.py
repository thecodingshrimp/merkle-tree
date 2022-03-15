from setuptools import setup, find_packages

setup(
    name='merkletree',
    version='0.1',
    py_modules=['merkletree'],
    packages=find_packages(),
    install_requires=[
        'tqdm',
        'zokrates_pycrypto@git+git://github.com/thecodingshrimp/pycrypto',
        'ethash@git+git://github.com/thecodingshrimp/ethash'
    ]
)
