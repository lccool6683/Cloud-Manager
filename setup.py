from setuptools import setup, find_packages
from setuptools.command.install import install as InstallCommand

class Install(InstallCommand):
    """ Customized setuptools install command which uses pip. """

    def run(self, *args, **kwargs):
        import pip
        pip.main(['install', '.'])
        InstallCommand.run(self, *args, **kwargs)

setup(
    name='CloudManager',
    version='1.0',
    author='Clemens Lo',
    author_email='lsps9140814@gmail.com',
    maintainer='Clemens Lo',
    cmdclass={
        'install': Install,
    },
    packages=find_packages(),
    install_requires=['inquirer','pymongo', 'pycrypto', 'pydrive', 'dropbox'],
    description='Cloud Manager made easy.',
)
