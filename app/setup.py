from setuptools import setup  # isort:skip
from Cython.Build import cythonize  # isort:skip

setup(
    ext_modules=cythonize(["manager.pyx", "gg_wrap.pyx"]),
)
